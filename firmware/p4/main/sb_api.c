#include "sb_api.h"

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"
#include "esp_app_desc.h"
#include "esp_check.h"
#include "esp_event.h"
#include "esp_http_server.h"
#include "esp_https_server.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_random.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/sha256.h"
#include "nvs.h"
#include "sb_api_tls.h"
#include "sb_api_logic.h"
#include "sb_eth.h"
#include "sb_hub_app.h"

#define API_CRED_KEY "credential"
#define API_CRED_LEN SB_API_CRED_LEN
#define API_TOKEN_BYTES 32U
#define API_TOKEN_LEN SB_API_TOKEN_LEN
#define API_MAX_INBOUND SB_API_MAX_INBOUND
#define API_MAX_OUTBOUND 16384U
#define API_LIVE_PERIOD_MS 250U
#define API_START_RETRY_MS 5000U

static const char *TAG = "sb_api";

typedef enum { API_IP_UP = 1, API_IP_DOWN = 2 } api_ip_event_t;

typedef struct {
    httpd_handle_t server;
    int fd;
    uint32_t id;
    bool authenticated;
    bool subscribed;
    uint32_t stream_epoch;
    uint64_t stream_seq;
} ws_session_t;

typedef struct {
    nvs_handle_t nvs;
    sb_api_tls_t tls;
    char hub_id[24];
    uint32_t hub_boot;
    bool claimed;
    uint32_t generation;
    uint8_t token_hash[32];
    httpd_handle_t server;
    bool server_ready, stop_pending;
    ws_session_t *auth_session;
    uint32_t next_session_id;
    bool live_pending;
    QueueHandle_t ip_queue;
    SemaphoreHandle_t lock;
} api_state_t;

typedef struct {
    httpd_handle_t server;
    int fd;
    ws_session_t *session;
    uint32_t session_id;
} hello_work_t;

static api_state_t s_api;

static void base64url(const uint8_t *in, size_t len, char *out)
{
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t i = 0, n = 0;
    while (i + 3 <= len) {
        uint32_t value = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) | in[i + 2];
        out[n++] = alphabet[(value >> 18) & 63];
        out[n++] = alphabet[(value >> 12) & 63];
        out[n++] = alphabet[(value >> 6) & 63];
        out[n++] = alphabet[value & 63];
        i += 3;
    }
    if (i < len) {
        uint32_t value = (uint32_t)in[i] << 16;
        if (i + 1 < len) value |= (uint32_t)in[i + 1] << 8;
        out[n++] = alphabet[(value >> 18) & 63];
        out[n++] = alphabet[(value >> 12) & 63];
        if (i + 1 < len) out[n++] = alphabet[(value >> 6) & 63];
    }
    out[n] = 0;
}

static esp_err_t load_credential(void)
{
    uint8_t record[API_CRED_LEN];
    size_t len = sizeof record;
    esp_err_t err = nvs_get_blob(s_api.nvs, API_CRED_KEY, record, &len);
    if (err == ESP_ERR_NVS_NOT_FOUND) return ESP_OK;
    if (err != ESP_OK) return err;
    if (!sb_api_credential_decode(record, len, &s_api.generation, s_api.token_hash))
        return ESP_ERR_INVALID_VERSION;
    s_api.claimed = true;
    return ESP_OK;
}

static esp_err_t store_new_credential(char token[API_TOKEN_LEN + 1])
{
    uint8_t random[API_TOKEN_BYTES];
    uint8_t hash[32];
    uint8_t record[API_CRED_LEN];
    uint32_t generation = s_api.claimed ? s_api.generation + 1U : 1U;
    if (generation == 0) generation = 1;
    esp_fill_random(random, sizeof random);
    base64url(random, sizeof random, token);
    if (!sb_api_credential_encode(generation, token, record, hash)) {
        mbedtls_platform_zeroize(random, sizeof random);
        mbedtls_platform_zeroize(token, API_TOKEN_LEN + 1);
        return ESP_FAIL;
    }

    esp_err_t err = nvs_set_blob(s_api.nvs, API_CRED_KEY, record, sizeof record);
    if (err == ESP_OK) err = nvs_commit(s_api.nvs);
    if (err == ESP_OK) {
        s_api.claimed = true;
        s_api.generation = generation;
        memcpy(s_api.token_hash, hash, sizeof hash);
    } else {
        mbedtls_platform_zeroize(token, API_TOKEN_LEN + 1);
    }
    mbedtls_platform_zeroize(random, sizeof random);
    mbedtls_platform_zeroize(hash, sizeof hash);
    mbedtls_platform_zeroize(record, sizeof record);
    return err;
}

static bool authenticate_token(const char *token)
{
    return s_api.claimed && sb_api_credential_verify(token, s_api.token_hash);
}

static bool request_authenticated(httpd_req_t *req)
{
    char authorization[API_TOKEN_LEN + 8] = {0};
    size_t len = httpd_req_get_hdr_value_len(req, "Authorization");
    if (len == 0 || len >= sizeof authorization ||
        httpd_req_get_hdr_value_str(req, "Authorization", authorization,
                                    sizeof authorization) != ESP_OK) {
        mbedtls_platform_zeroize(authorization, sizeof authorization);
        return false;
    }
    static const char prefix[] = "Bearer ";
    bool valid = len == sizeof prefix - 1 + API_TOKEN_LEN &&
                 memcmp(authorization, prefix, sizeof prefix - 1) == 0 &&
                 authenticate_token(authorization + sizeof prefix - 1);
    mbedtls_platform_zeroize(authorization, sizeof authorization);
    return valid;
}

static esp_err_t send_json_http(httpd_req_t *req, cJSON *root)
{
    char *text = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!text) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, NULL);
    size_t len = strlen(text);
    if (len > API_MAX_OUTBOUND) {
        cJSON_free(text);
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "response too large");
    }
    httpd_resp_set_type(req, "application/json");
    esp_err_t err = httpd_resp_send(req, text, len);
    cJSON_free(text);
    return err;
}

static esp_err_t send_json_ws(httpd_req_t *req, cJSON *root)
{
    char *text = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!text) return ESP_ERR_NO_MEM;
    size_t len = strlen(text);
    if (len > API_MAX_OUTBOUND) {
        cJSON_free(text);
        return ESP_ERR_INVALID_SIZE;
    }
    httpd_ws_frame_t frame = {
        .type = HTTPD_WS_TYPE_TEXT, .payload = (uint8_t *)text, .len = len};
    esp_err_t err = httpd_ws_send_frame(req, &frame);
    cJSON_free(text);
    return err;
}

static esp_err_t send_json_fd(httpd_handle_t server, int fd, cJSON *root)
{
    char *text = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!text) return ESP_ERR_NO_MEM;
    size_t len = strlen(text);
    if (len > API_MAX_OUTBOUND) {
        cJSON_free(text);
        return ESP_ERR_INVALID_SIZE;
    }
    httpd_ws_frame_t frame = {
        .type = HTTPD_WS_TYPE_TEXT, .payload = (uint8_t *)text, .len = len};
    esp_err_t err = httpd_ws_send_frame_async(server, fd, &frame);
    cJSON_free(text);
    return err;
}

static void add_u64(cJSON *object, const char *name, uint64_t value)
{
    char text[21];
    snprintf(text, sizeof text, "%" PRIu64, value);
    cJSON_AddStringToObject(object, name, text);
}

static cJSON *json_value(const sb_hub_app_value_t *value)
{
    switch (value->type) {
    case SB_V_BOOL:
        return cJSON_CreateBool(value->b);
    case SB_V_I32:
        return cJSON_CreateNumber(value->i);
    case SB_V_U32:
        return cJSON_CreateNumber(value->u);
    case SB_V_F32:
        return cJSON_CreateNumber(value->f);
    case SB_V_ENUM:
        return cJSON_CreateNumber(value->e);
    case SB_V_STR:
        return cJSON_CreateString(value->s.text);
    default:
        return cJSON_CreateNull();
    }
}

static void add_app_string(cJSON *object, const char *name, const sb_hub_app_str_t *value)
{
    if (value->len) cJSON_AddStringToObject(object, name, value->text);
}

static cJSON *json_entity(const sb_hub_app_entity_t *entity)
{
    cJSON *item = cJSON_CreateObject();
    cJSON_AddNumberToObject(item, "entity", entity->entity);
    cJSON_AddNumberToObject(item, "platform", entity->platform);
    cJSON_AddNumberToObject(item, "value_type", entity->value_type);
    cJSON_AddNumberToObject(item, "state_class", entity->state_class);
    cJSON_AddNumberToObject(item, "accuracy", entity->accuracy);
    cJSON_AddNumberToObject(item, "flags", entity->flags);
    add_app_string(item, "object_id", &entity->object_id);
    add_app_string(item, "name", &entity->name);
    add_app_string(item, "unit", &entity->unit);
    add_app_string(item, "device_class", &entity->device_class);
    add_app_string(item, "extra", &entity->extra);
    cJSON_AddItemToObject(item, "value", json_value(&entity->value));
    return item;
}

static cJSON *json_node(const sb_hub_app_node_t *node)
{
    cJSON *root = cJSON_CreateObject();
    char mac[18];
    snprintf(mac, sizeof mac, "%02x:%02x:%02x:%02x:%02x:%02x", node->mac[0], node->mac[1],
             node->mac[2], node->mac[3], node->mac[4], node->mac[5]);
    cJSON_AddNumberToObject(root, "slot", node->slot);
    cJSON_AddNumberToObject(root, "state", node->state);
    cJSON_AddStringToObject(root, "mac", mac);
    add_u64(root, "node_id", node->node_id);
    cJSON_AddNumberToObject(root, "generation", node->generation);
    cJSON_AddBoolToObject(root, "available", node->available);
    add_u64(root, "last_seen_ms", node->last_seen_ms);
    cJSON_AddNumberToObject(root, "rssi", node->rssi);
    cJSON_AddNumberToObject(root, "epoch", node->epoch);
    cJSON_AddNumberToObject(root, "report_interval_s", node->report_interval_s);
    cJSON_AddNumberToObject(root, "boot_reason", node->boot_reason);
    cJSON_AddBoolToObject(root, "has_schema", node->has_schema);
    if (!node->has_schema) return root;
    cJSON_AddNumberToObject(root, "schema_hash", node->schema_hash);
    add_app_string(root, "name", &node->node_name);
    add_app_string(root, "model", &node->model);
    add_app_string(root, "fw_version", &node->fw_version);
    cJSON_AddNumberToObject(root, "entity_count", node->entity_count);
    return root;
}

static cJSON *json_event(const sb_hub_app_event_t *event)
{
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "type", "event");
    add_u64(root, "seq", event->seq);
    cJSON_AddNumberToObject(root, "kind", event->kind);
    cJSON_AddNumberToObject(root, "slot", event->slot);
    cJSON_AddNumberToObject(root, "entity", event->entity);
    cJSON_AddNumberToObject(root, "event_type", event->etype);
    cJSON_AddNumberToObject(root, "pair", event->pair);
    cJSON_AddBoolToObject(root, "available", event->available);
    cJSON_AddBoolToObject(root, "tombstone", event->tombstone);
    add_u64(root, "node_id", event->node_id);
    cJSON_AddNumberToObject(root, "generation", event->generation);
    if (event->kind == SB_EVT_NODE) {
        cJSON_AddBoolToObject(root, "refresh", true);
        cJSON_AddStringToObject(root, "refresh_op", "node.get");
    }
    if (event->has_value) cJSON_AddItemToObject(root, "value", json_value(&event->value));
    if (event->event_id[0]) cJSON_AddStringToObject(root, "event_id", event->event_id);
    return root;
}

static sb_hub_app_api_response_t *hub_call(const sb_hub_app_api_request_t *request)
{
    sb_hub_app_api_response_t *response = calloc(1, sizeof *response);
    if (!response) return NULL;
    if (sb_hub_app_api(request, response) != ESP_OK) {
        free(response);
        return NULL;
    }
    return response;
}

static cJSON *error_json(const char *op, const char *code)
{
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "type", "error");
    if (op) cJSON_AddStringToObject(root, "op", op);
    cJSON_AddStringToObject(root, "code", code);
    return root;
}

static cJSON *result_json(const char *op, int result)
{
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "type", "result");
    cJSON_AddStringToObject(root, "op", op);
    cJSON_AddBoolToObject(root, "ok", result == 0);
    cJSON_AddNumberToObject(root, "result", result);
    return root;
}

static esp_err_t health_handler(httpd_req_t *req)
{
    sb_hub_app_api_request_t request = {.op = SB_HUB_APP_INFO};
    sb_hub_app_api_response_t *response = hub_call(&request);
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "status", response && response->result == 0 ? "ok" : "starting");
    cJSON_AddStringToObject(root, "hub_id", s_api.hub_id);
    cJSON_AddNumberToObject(root, "boot", s_api.hub_boot);
    cJSON_AddBoolToObject(root, "claimed", s_api.claimed);
    free(response);
    return send_json_http(req, root);
}

static esp_err_t version_handler(httpd_req_t *req)
{
    const esp_app_desc_t *app = esp_app_get_description();
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "project", app->project_name);
    cJSON_AddStringToObject(root, "version", app->version);
    cJSON_AddStringToObject(root, "idf", app->idf_ver);
    cJSON_AddStringToObject(root, "api", "v1");
    return send_json_http(req, root);
}

static esp_err_t diagnostics_handler(httpd_req_t *req)
{
    if (!request_authenticated(req)) {
        httpd_resp_set_hdr(req, "WWW-Authenticate", "Bearer");
        return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, NULL);
    }
    sb_hub_app_api_request_t request = {.op = SB_HUB_APP_STATS};
    sb_hub_app_api_response_t *response = hub_call(&request);
    if (!response) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, NULL);
    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "credential_generation", s_api.generation);
    sb_eth_stats_t eth = sb_eth_stats();
    cJSON *network = cJSON_AddObjectToObject(root, "network");
    cJSON_AddBoolToObject(network, "link_up", eth.link_up);
    cJSON_AddNumberToObject(network, "link_ups", eth.link_ups);
    cJSON_AddNumberToObject(network, "link_downs", eth.link_downs);
    cJSON_AddNumberToObject(network, "ip_acquired", eth.ip_acquired);
    cJSON *stats = cJSON_AddObjectToObject(root, "hub");
#define ADD_STAT(name) cJSON_AddNumberToObject(stats, #name, response->stats.name)
    ADD_STAT(rx);
    ADD_STAT(rx_unknown);
    ADD_STAT(rx_bad_mic);
    ADD_STAT(rx_malformed);
    ADD_STAT(rx_bad_epoch);
    ADD_STAT(rx_replay);
    ADD_STAT(rx_duplicate);
    ADD_STAT(rx_new_boot);
    ADD_STAT(acks);
    ADD_STAT(pair_ignored);
    ADD_STAT(pair_done);
    ADD_STAT(pair_failed);
    ADD_STAT(store_fail);
    ADD_STAT(node_errors);
#undef ADD_STAT
    free(response);
    return send_json_http(req, root);
}

static bool json_u32(const cJSON *root, const char *name, uint32_t *out)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(root, name);
    if (!cJSON_IsNumber(item) || item->valuedouble < 0 || item->valuedouble > UINT32_MAX ||
        item->valuedouble != (double)(uint32_t)item->valuedouble)
        return false;
    *out = (uint32_t)item->valuedouble;
    return true;
}

static bool json_slot(const cJSON *root, int8_t *out)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(root, "slot");
    if (!cJSON_IsNumber(item) || item->valuedouble < 0 || item->valuedouble >= SB_HUB_MAX_NODES ||
        item->valuedouble != (double)(int)item->valuedouble)
        return false;
    *out = (int8_t)item->valueint;
    return true;
}

static bool json_u64_string(const cJSON *root, const char *name, uint64_t *out)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(root, name);
    if (!cJSON_IsString(item) || !item->valuestring || !item->valuestring[0] ||
        item->valuestring[0] == '-')
        return false;
    errno = 0;
    char *end = NULL;
    unsigned long long value = strtoull(item->valuestring, &end, 10);
    if (errno || !end || *end) return false;
    *out = (uint64_t)value;
    return true;
}

static bool ws_session_current(const ws_session_t *session)
{
    return session && session->server &&
           httpd_sess_get_ctx(session->server, session->fd) == session &&
           httpd_ws_get_fd_info(session->server, session->fd) == HTTPD_WS_CLIENT_WEBSOCKET;
}

static void clear_ws_session(ws_session_t *session)
{
    if (!session) return;
    if (s_api.auth_session == session) s_api.auth_session = NULL;
    session->authenticated = false;
    session->subscribed = false;
    session->stream_epoch = 0;
    session->stream_seq = 0;
}

static void free_ws_session(void *ctx)
{
    ws_session_t *session = ctx;
    clear_ws_session(session);
    mbedtls_platform_zeroize(session, sizeof *session);
    free(session);
}

static bool ws_is_authenticated(httpd_req_t *req, ws_session_t *session)
{
    return req->sess_ctx == session && ws_session_current(session) && session->authenticated &&
           s_api.auth_session == session;
}

static esp_err_t send_node_entities(httpd_req_t *req, const char *type,
                                    const sb_hub_app_node_t *node)
{
    for (uint8_t i = 0; i < node->entity_count; i++) {
        cJSON *message = cJSON_CreateObject();
        cJSON_AddStringToObject(message, "type", type);
        cJSON_AddNumberToObject(message, "slot", node->slot);
        cJSON_AddNumberToObject(message, "index", i);
        cJSON_AddItemToObject(message, "entity", json_entity(&node->entities[i]));
        esp_err_t err = send_json_ws(req, message);
        if (err != ESP_OK) return err;
    }
    return ESP_OK;
}

static esp_err_t send_stream(httpd_req_t *req, ws_session_t *session, uint32_t epoch,
                             uint64_t after, bool mark_subscribed)
{
    sb_hub_app_api_request_t request = {
        .op = SB_HUB_APP_STREAM_FETCH, .stream_epoch = epoch, .after_seq = after};
    sb_hub_app_api_response_t *response = hub_call(&request);
    if (!response) return send_json_ws(req, error_json("resume", "hub_unavailable"));
    if (response->result != 0) {
        int result = response->result;
        free(response);
        return send_json_ws(req, result_json("resume", result));
    }
    if (response->stream.resync_required) {
        cJSON *root = error_json("resume", "resync_required");
        cJSON_AddNumberToObject(root, "stream_epoch", response->stream.stream_epoch);
        add_u64(root, "latest_seq", response->stream.latest_seq);
        free(response);
        return send_json_ws(req, root);
    }
    esp_err_t err = ESP_OK;
    for (uint8_t i = 0; i < response->stream.count && err == ESP_OK; i++)
        err = send_json_ws(req, json_event(&response->stream.events[i]));
    if (err == ESP_OK) {
        cJSON *root = result_json("resume", 0);
        cJSON_AddNumberToObject(root, "stream_epoch", response->stream.stream_epoch);
        add_u64(root, "latest_seq", response->stream.latest_seq);
        err = send_json_ws(req, root);
    }
    if (err == ESP_OK && mark_subscribed) {
        session->subscribed = true;
        session->stream_epoch = response->stream.stream_epoch;
        session->stream_seq = response->stream.latest_seq;
    }
    free(response);
    return err;
}

static esp_err_t subscribe_ws(httpd_req_t *req, ws_session_t *session)
{
    sb_hub_app_api_request_t info_request = {.op = SB_HUB_APP_INFO};
    sb_hub_app_api_response_t *info = hub_call(&info_request);
    if (!info || info->result != 0) {
        free(info);
        return send_json_ws(req, error_json("subscribe", "hub_unavailable"));
    }
    uint32_t epoch = info->info.stream_epoch;
    uint64_t seq = info->info.stream_seq;
    cJSON *begin = cJSON_CreateObject();
    cJSON_AddStringToObject(begin, "type", "snapshot.begin");
    cJSON_AddNumberToObject(begin, "stream_epoch", epoch);
    add_u64(begin, "stream_seq", seq);
    cJSON_AddNumberToObject(begin, "slots", info->info.max_nodes);
    esp_err_t err = send_json_ws(req, begin);
    uint8_t max_nodes = info->info.max_nodes;
    free(info);

    for (uint8_t slot = 0; slot < max_nodes && err == ESP_OK; slot++) {
        sb_hub_app_api_request_t node_request = {.op = SB_HUB_APP_NODE_GET, .slot = slot};
        sb_hub_app_api_response_t *response = hub_call(&node_request);
        if (!response) {
            err = ESP_FAIL;
            break;
        }
        cJSON *message = cJSON_CreateObject();
        cJSON_AddStringToObject(message, "type", "snapshot.node");
        cJSON_AddNumberToObject(message, "slot", slot);
        cJSON_AddBoolToObject(message, "found", response->node.found);
        if (response->node.found) {
            cJSON_AddItemToObject(message, "node", json_node(&response->node.node));
            err = send_json_ws(req, message);
            if (err == ESP_OK)
                err = send_node_entities(req, "snapshot.entity", &response->node.node);
        } else {
            err = send_json_ws(req, message);
        }
        free(response);
    }
    if (err != ESP_OK) return err;
    cJSON *end = cJSON_CreateObject();
    cJSON_AddStringToObject(end, "type", "snapshot.end");
    cJSON_AddNumberToObject(end, "stream_epoch", epoch);
    add_u64(end, "stream_seq", seq);
    err = send_json_ws(req, end);
    if (err == ESP_OK) err = send_stream(req, session, epoch, seq, true);
    return err;
}

static esp_err_t handle_authenticated_op(httpd_req_t *req, ws_session_t *session,
                                         const char *op, const cJSON *root)
{
    if (strcmp(op, "ping") == 0) {
        cJSON *pong = cJSON_CreateObject();
        cJSON_AddStringToObject(pong, "type", "pong");
        return send_json_ws(req, pong);
    }
    if (strcmp(op, "subscribe") == 0) return subscribe_ws(req, session);
    if (strcmp(op, "resume") == 0) {
        uint32_t epoch;
        uint64_t after;
        if (!json_u32(root, "stream_epoch", &epoch) ||
            !json_u64_string(root, "after_seq", &after))
            return send_json_ws(req, error_json(op, "invalid_request"));
        return send_stream(req, session, epoch, after, true);
    }
    if (strcmp(op, "credential.rotate") == 0) {
        char token[API_TOKEN_LEN + 1] = {0};
        esp_err_t err = store_new_credential(token);
        if (err != ESP_OK) return send_json_ws(req, error_json(op, "store_failed"));
        cJSON *response = result_json(op, 0);
        cJSON_AddNumberToObject(response, "generation", s_api.generation);
        cJSON_AddStringToObject(response, "token", token);
        err = send_json_ws(req, response);
        mbedtls_platform_zeroize(token, sizeof token);
        return err;
    }

    sb_hub_app_api_request_t request = {0};
    if (strcmp(op, "node.get") == 0) {
        request.op = SB_HUB_APP_NODE_GET;
        if (!json_slot(root, &request.slot))
            return send_json_ws(req, error_json(op, "invalid_request"));
    } else if (strcmp(op, "node.add") == 0) {
        request.op = SB_HUB_APP_NODE_ADD;
    } else if (strcmp(op, "node.remove") == 0) {
        request.op = SB_HUB_APP_NODE_REMOVE;
        if (!json_slot(root, &request.slot))
            return send_json_ws(req, error_json(op, "invalid_request"));
    } else if (strcmp(op, "pair.open") == 0) {
        request.op = SB_HUB_APP_PAIR_OPEN;
        if (!json_slot(root, &request.slot) ||
            !json_u32(root, "duration_ms", &request.duration_ms) || request.duration_ms == 0)
            return send_json_ws(req, error_json(op, "invalid_request"));
    } else if (strcmp(op, "pair.close") == 0) {
        request.op = SB_HUB_APP_PAIR_CLOSE;
    } else {
        return send_json_ws(req, error_json(op, "unknown_op"));
    }

    sb_hub_app_api_response_t *response = hub_call(&request);
    if (!response) return send_json_ws(req, error_json(op, "hub_unavailable"));
    cJSON *message = result_json(op, response->result);
    if (request.op == SB_HUB_APP_NODE_GET && response->result == 0) {
        cJSON_AddBoolToObject(message, "found", response->node.found);
        if (response->node.found)
            cJSON_AddItemToObject(message, "node", json_node(&response->node.node));
    } else if (request.op == SB_HUB_APP_NODE_ADD && response->result == 0) {
        char key[23];
        base64url(response->added.key, sizeof response->added.key, key);
        cJSON_AddStringToObject(message, "key", key);
        cJSON_AddItemToObject(message, "node", json_node(&response->added.node));
        mbedtls_platform_zeroize(key, sizeof key);
        mbedtls_platform_zeroize(response->added.key, sizeof response->added.key);
    }
    esp_err_t err = send_json_ws(req, message);
    if (err == ESP_OK && request.op == SB_HUB_APP_NODE_GET && response->result == 0 &&
        response->node.found) {
        err = send_node_entities(req, "node.entity", &response->node.node);
        if (err == ESP_OK) {
            cJSON *end = cJSON_CreateObject();
            cJSON_AddStringToObject(end, "type", "node.end");
            cJSON_AddNumberToObject(end, "slot", response->node.node.slot);
            cJSON_AddNumberToObject(end, "entity_count", response->node.node.entity_count);
            err = send_json_ws(req, end);
        }
    }
    free(response);
    return err;
}

static void hello_work(void *arg)
{
    hello_work_t *work = arg;
    ws_session_t *current = httpd_sess_get_ctx(work->server, work->fd);
    if (current == work->session && current && current->id == work->session_id &&
        ws_session_current(current)) {
        sb_hub_app_api_request_t request = {.op = SB_HUB_APP_INFO};
        sb_hub_app_api_response_t *info = hub_call(&request);
        cJSON *root = cJSON_CreateObject();
        cJSON_AddStringToObject(root, "type", "hello");
        cJSON_AddStringToObject(root, "hub_id", s_api.hub_id);
        cJSON_AddNumberToObject(root, "boot", s_api.hub_boot);
        cJSON_AddBoolToObject(root, "claimed", s_api.claimed);
        cJSON_AddNumberToObject(root, "credential_generation", s_api.generation);
        cJSON_AddNumberToObject(root, "max_inbound", API_MAX_INBOUND);
        if (info && info->result == 0) {
            cJSON_AddNumberToObject(root, "stream_epoch", info->info.stream_epoch);
            add_u64(root, "stream_seq", info->info.stream_seq);
        }
        send_json_fd(work->server, work->fd, root);
        free(info);
    }
    free(work);
}

static esp_err_t websocket_handler(httpd_req_t *req)
{
    int fd = httpd_req_to_sockfd(req);
    if (req->method == HTTP_GET) {
        ws_session_t *session = calloc(1, sizeof *session);
        if (!session) return ESP_ERR_NO_MEM;
        session->server = req->handle;
        session->fd = fd;
        session->id = ++s_api.next_session_id;
        if (session->id == 0) session->id = ++s_api.next_session_id;
        req->sess_ctx = session;
        req->free_ctx = free_ws_session;
        hello_work_t *work = malloc(sizeof *work);
        if (!work) return ESP_ERR_NO_MEM;
        work->server = req->handle;
        work->fd = fd;
        work->session = session;
        work->session_id = session->id;
        esp_err_t err = httpd_queue_work(req->handle, hello_work, work);
        if (err != ESP_OK) free(work);
        return err;
    }

    ws_session_t *session = req->sess_ctx;
    if (!session || session->server != req->handle || session->fd != fd ||
        httpd_sess_get_ctx(req->handle, fd) != session) {
        httpd_sess_trigger_close(req->handle, fd);
        return ESP_ERR_INVALID_STATE;
    }

    httpd_ws_frame_t frame = {0};
    esp_err_t err = httpd_ws_recv_frame(req, &frame, 0);
    if (err != ESP_OK) return err;
    if (frame.len > API_MAX_INBOUND || !frame.final || frame.fragmented) {
        httpd_sess_trigger_close(req->handle, fd);
        return ESP_ERR_INVALID_SIZE;
    }
    uint8_t *payload = calloc(1, frame.len + 1);
    if (!payload) return ESP_ERR_NO_MEM;
    frame.payload = payload;
    if (frame.len) {
        err = httpd_ws_recv_frame(req, &frame, frame.len);
        if (err != ESP_OK) {
            free(payload);
            return err;
        }
    }
    if (frame.type == HTTPD_WS_TYPE_PING) {
        frame.type = HTTPD_WS_TYPE_PONG;
        err = httpd_ws_send_frame(req, &frame);
        free(payload);
        return err;
    }
    if (frame.type == HTTPD_WS_TYPE_PONG) {
        free(payload);
        return ESP_OK;
    }
    if (frame.type == HTTPD_WS_TYPE_CLOSE) {
        clear_ws_session(session);
        err = httpd_ws_send_frame(req, &frame);
        free(payload);
        return err;
    }
    if (frame.type != HTTPD_WS_TYPE_TEXT || memchr(payload, 0, frame.len) != NULL) {
        free(payload);
        return send_json_ws(req, error_json(NULL, "json_text_required"));
    }

    cJSON *root = sb_api_parse_request(payload, frame.len);
    mbedtls_platform_zeroize(payload, frame.len);
    free(payload);
    if (!root) {
        return send_json_ws(req, error_json(NULL, "invalid_json"));
    }
    const cJSON *op_item = cJSON_GetObjectItemCaseSensitive(root, "op");
    if (!cJSON_IsString(op_item) || !op_item->valuestring) {
        cJSON_Delete(root);
        return send_json_ws(req, error_json(NULL, "invalid_request"));
    }
    const char *op = op_item->valuestring;
    if (strcmp(op, "claim") == 0) {
        if (s_api.claimed) {
            err = send_json_ws(req, error_json(op, "already_claimed"));
        } else {
            char token[API_TOKEN_LEN + 1] = {0};
            if (store_new_credential(token) != ESP_OK) {
                err = send_json_ws(req, error_json(op, "store_failed"));
            } else {
                session->authenticated = true;
                s_api.auth_session = session;
                cJSON *response = result_json(op, 0);
                cJSON_AddNumberToObject(response, "generation", s_api.generation);
                cJSON_AddStringToObject(response, "token", token);
                err = send_json_ws(req, response);
            }
            mbedtls_platform_zeroize(token, sizeof token);
        }
    } else if (strcmp(op, "auth") == 0) {
        cJSON *token = cJSON_GetObjectItemCaseSensitive(root, "token");
        ws_session_t *active = s_api.auth_session;
        if (active && !ws_session_current(active)) {
            clear_ws_session(active);
            active = NULL;
        }
        bool other_active = active && active != session && active->authenticated;
        bool valid = cJSON_IsString(token) && authenticate_token(token->valuestring);
        if (cJSON_IsString(token) && token->valuestring)
            mbedtls_platform_zeroize(token->valuestring, strlen(token->valuestring));
        if (other_active) {
            err = send_json_ws(req, error_json(op, "client_busy"));
        } else if (!valid) {
            err = send_json_ws(req, error_json(op, "unauthorized"));
        } else {
            session->authenticated = true;
            s_api.auth_session = session;
            cJSON *response = result_json(op, 0);
            cJSON_AddNumberToObject(response, "generation", s_api.generation);
            err = send_json_ws(req, response);
        }
    } else if (!ws_is_authenticated(req, session)) {
        err = send_json_ws(req, error_json(op, "unauthorized"));
    } else {
        err = handle_authenticated_op(req, session, op, root);
    }
    cJSON_Delete(root);
    return err;
}

static void live_work(void *arg)
{
    (void)arg;
    httpd_handle_t server = s_api.server;
    ws_session_t *session = s_api.auth_session;
    if (server && session && session->server == server && session->authenticated &&
        session->subscribed && ws_session_current(session)) {
        int fd = session->fd;
        sb_hub_app_api_request_t request = {.op = SB_HUB_APP_STREAM_FETCH,
                                            .stream_epoch = session->stream_epoch,
                                            .after_seq = session->stream_seq};
        sb_hub_app_api_response_t *response = hub_call(&request);
        if (response && response->result == 0) {
            esp_err_t err = ESP_OK;
            if (response->stream.resync_required) {
                cJSON *message = error_json("stream", "resync_required");
                cJSON_AddNumberToObject(message, "stream_epoch", response->stream.stream_epoch);
                add_u64(message, "latest_seq", response->stream.latest_seq);
                err = send_json_fd(server, fd, message);
                session->subscribed = false;
            } else {
                for (uint8_t i = 0; i < response->stream.count && err == ESP_OK; i++) {
                    if (!ws_session_current(session) || s_api.auth_session != session ||
                        !session->authenticated) {
                        err = ESP_ERR_INVALID_STATE;
                        break;
                    }
                    err = send_json_fd(server, fd, json_event(&response->stream.events[i]));
                }
                if (err == ESP_OK) {
                    session->stream_epoch = response->stream.stream_epoch;
                    session->stream_seq = response->stream.latest_seq;
                }
            }
            if (err != ESP_OK) {
                // Close rather than leave a silent, unauthenticated socket; the client
                // reconnects and resumes from its last sequence.
                clear_ws_session(session);
                httpd_sess_trigger_close(server, fd);
            }
        }
        free(response);
    } else if (session && (!server || session->server != server || !ws_session_current(session))) {
        clear_ws_session(session);
    }
    xSemaphoreTake(s_api.lock, portMAX_DELAY);
    s_api.live_pending = false;
    xSemaphoreGive(s_api.lock);
}

static esp_err_t start_server(void)
{
    if (s_api.server) return s_api.server_ready ? ESP_OK : ESP_ERR_INVALID_STATE;
    httpd_ssl_config_t config = HTTPD_SSL_CONFIG_DEFAULT();
    config.httpd.stack_size = 16384;
    config.httpd.max_open_sockets = 4;
    config.httpd.max_uri_handlers = 4;
    config.servercert = sb_api_tls_cert_pem(&s_api.tls);
    config.servercert_len = sb_api_tls_cert_pem_len(&s_api.tls);
    config.prvtkey_pem = sb_api_tls_private_key_pem(&s_api.tls);
    config.prvtkey_len = sb_api_tls_private_key_pem_len(&s_api.tls);
    if (!config.servercert || !config.prvtkey_pem) return ESP_ERR_INVALID_STATE;

    httpd_handle_t server = NULL;
    ESP_RETURN_ON_ERROR(httpd_ssl_start(&server, &config), TAG, "start HTTPS server");
    s_api.server = server;
    s_api.server_ready = false;
    s_api.server = server;
    const httpd_uri_t health = {
        .uri = "/api/v1/health", .method = HTTP_GET, .handler = health_handler};
    const httpd_uri_t version = {
        .uri = "/api/v1/version", .method = HTTP_GET, .handler = version_handler};
    const httpd_uri_t diagnostics = {
        .uri = "/api/v1/diagnostics", .method = HTTP_GET, .handler = diagnostics_handler};
    const httpd_uri_t websocket = {.uri = "/api/v1/ws",
                                   .method = HTTP_GET,
                                   .handler = websocket_handler,
                                   .is_websocket = true,
                                   .handle_ws_control_frames = true};
    esp_err_t err = httpd_register_uri_handler(server, &health);
    if (err == ESP_OK) err = httpd_register_uri_handler(server, &version);
    if (err == ESP_OK) err = httpd_register_uri_handler(server, &diagnostics);
    if (err == ESP_OK) err = httpd_register_uri_handler(server, &websocket);
    if (err != ESP_OK) {
        esp_err_t stop_err = httpd_ssl_stop(server);
        if (stop_err == ESP_OK) {
            s_api.server = NULL;
            s_api.stop_pending = false;
        } else {
            s_api.stop_pending = true;
            ESP_LOGE(TAG, "cleanup HTTPS server: %s", esp_err_to_name(stop_err));
        }
        return err;
    }
    s_api.server_ready = true;
    s_api.stop_pending = false;
    ESP_LOGI(TAG, "HTTPS/WSS API listening on port 443");
    return ESP_OK;
}

static bool stop_server(void)
{
    httpd_handle_t server = s_api.server;
    if (!server) return true;
    esp_err_t err = httpd_ssl_stop(server);
    if (err != ESP_OK) {
        s_api.stop_pending = true;
        ESP_LOGE(TAG, "stop HTTPS server: %s", esp_err_to_name(err));
    }
    else {
        s_api.server = NULL;
        s_api.server_ready = false;
        s_api.stop_pending = false;
        ESP_LOGI(TAG, "HTTPS/WSS API stopped");
    }
    return err == ESP_OK;
}

static void api_manager_task(void *arg)
{
    (void)arg;
    api_ip_event_t event;
    TickType_t retry_at = 0;
    for (;;) {
        if (xQueueReceive(s_api.ip_queue, &event, pdMS_TO_TICKS(API_LIVE_PERIOD_MS)) == pdTRUE) {
            if (event == API_IP_UP) {
                retry_at = 0;
            } else {
                s_api.stop_pending = true;
                retry_at = stop_server() ? 0 : xTaskGetTickCount() + pdMS_TO_TICKS(API_START_RETRY_MS);
            }
        }
        TickType_t now = xTaskGetTickCount();
        if (s_api.server && (s_api.stop_pending || !s_api.server_ready) &&
            (retry_at == 0 || (int32_t)(now - retry_at) >= 0)) {
            retry_at = stop_server() ? 0 : now + pdMS_TO_TICKS(API_START_RETRY_MS);
        }
        if (!s_api.server && sb_eth_has_ip() &&
            (retry_at == 0 || (int32_t)(now - retry_at) >= 0)) {
            esp_err_t err = start_server();
            if (err != ESP_OK) {
                ESP_LOGE(TAG, "API unavailable: %s; retrying", esp_err_to_name(err));
                retry_at = now + pdMS_TO_TICKS(API_START_RETRY_MS);
            } else {
                retry_at = 0;
            }
        }
        xSemaphoreTake(s_api.lock, portMAX_DELAY);
        httpd_handle_t server = s_api.server;
        bool queue_live = server && s_api.server_ready && !s_api.live_pending;
        if (queue_live) s_api.live_pending = true;
        xSemaphoreGive(s_api.lock);
        if (queue_live && httpd_queue_work(server, live_work, NULL) != ESP_OK) {
            xSemaphoreTake(s_api.lock, portMAX_DELAY);
            s_api.live_pending = false;
            xSemaphoreGive(s_api.lock);
        }
    }
}

static void on_ip_event(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    (void)arg;
    (void)base;
    (void)data;
    api_ip_event_t event = id == IP_EVENT_ETH_GOT_IP ? API_IP_UP : API_IP_DOWN;
    xQueueOverwrite(s_api.ip_queue, &event);
}

esp_err_t sb_api_start(const char *hub_id, uint32_t hub_boot)
{
    if (!hub_id || !hub_id[0] || s_api.ip_queue) return ESP_ERR_INVALID_ARG;
    memset(&s_api, 0, sizeof s_api);
    s_api.hub_boot = hub_boot;
    if (snprintf(s_api.hub_id, sizeof s_api.hub_id, "%s", hub_id) >= sizeof s_api.hub_id)
        return ESP_ERR_INVALID_ARG;
    ESP_RETURN_ON_ERROR(nvs_open_from_partition("hub_nvs", "server_api", NVS_READWRITE,
                                                &s_api.nvs),
                        TAG, "open API NVS");
    ESP_RETURN_ON_ERROR(load_credential(), TAG, "load API credential");
    ESP_RETURN_ON_ERROR(sb_api_tls_init(&s_api.tls, s_api.nvs, s_api.hub_id), TAG,
                        "load API TLS identity");
    uint8_t fp[32];
    if (sb_api_tls_fingerprint(&s_api.tls, fp) == ESP_OK) {
        char hex[3 * sizeof fp];
        for (size_t i = 0; i < sizeof fp; i++)
            snprintf(hex + 3 * i, 4, "%02X%s", fp[i], i + 1 < sizeof fp ? ":" : "");
        ESP_LOGI(TAG, "TLS certificate SHA-256 %s", hex);
    }
    s_api.ip_queue = xQueueCreate(1, sizeof(api_ip_event_t));
    s_api.lock = xSemaphoreCreateMutex();
    if (!s_api.ip_queue || !s_api.lock) return ESP_ERR_NO_MEM;
    ESP_RETURN_ON_ERROR(esp_event_handler_register(IP_EVENT, IP_EVENT_ETH_GOT_IP, on_ip_event,
                                                   NULL),
                        TAG, "register got-IP manager");
    ESP_RETURN_ON_ERROR(esp_event_handler_register(IP_EVENT, IP_EVENT_ETH_LOST_IP, on_ip_event,
                                                   NULL),
                        TAG, "register lost-IP manager");
    if (xTaskCreate(api_manager_task, "sb_api", 6144, NULL, 5, NULL) != pdPASS)
        return ESP_ERR_NO_MEM;
    if (sb_eth_has_ip()) {
        api_ip_event_t event = API_IP_UP;
        xQueueOverwrite(s_api.ip_queue, &event);
    }
    return ESP_OK;
}
