// P4 platform adapter for the platform-independent sb_hub core.
#include "sb_hub_app.h"

#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "esp_check.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "sb_api.h"
#include "sb_api_logic.h"
#include "sb_mdns.h"
#include "sb_hub.h"

static const char *TAG = "sb_hub_app";

enum { HUB_EV_READY, HUB_EV_RESET, HUB_EV_RX, HUB_EV_SEND_DONE };

typedef struct {
    uint8_t kind;
    uint8_t mac[6];
    uint8_t channel;
    bool ok;
    uint32_t token;
} hub_control_t;

typedef struct {
    uint8_t mac[6];
    int8_t rssi;
    uint16_t len;
    uint8_t data[SB_MAX_FRAME];
} hub_rx_t;

typedef struct {
    QueueHandle_t control_queue, rx_queue, api_queue;
    SemaphoreHandle_t api_mutex, api_done;
    nvs_handle_t nvs;
    sb_hub_t *hub;
    sb_hub_cfg_t cfg;
    uint8_t expected_channel;
    sb_hub_app_api_response_t api_response;
    sb_hub_app_event_t events[SB_HUB_APP_STREAM_CAP];
    uint8_t event_head, event_len;
    uint64_t event_seq;
} hub_app_t;

static hub_app_t s_app;

static uint64_t op_now_ms(void *ctx)
{
    (void)ctx;
    return (uint64_t)(esp_timer_get_time() / 1000);
}

static uint32_t op_unix_time(void *ctx)
{
    (void)ctx;
    time_t now = time(NULL);
    return now > 0 && (uint64_t)now <= UINT32_MAX ? (uint32_t)now : 0;
}

static void op_random(void *ctx, uint8_t *buf, size_t len)
{
    (void)ctx;
    esp_fill_random(buf, len);
}

static int op_radio_send(void *ctx, const uint8_t mac[6], const uint8_t *data, size_t len,
                         uint32_t *token)
{
    (void)ctx;
    return sb_radio_send(mac, data, len, token) == ESP_OK ? 0 : -1;
}

static int op_radio_peer(void *ctx, const uint8_t mac[6], bool add, const uint8_t *lmk)
{
    (void)ctx;
    return sb_radio_peer(mac, add, lmk) == ESP_OK ? 0 : -1;
}

static int op_store_put(void *ctx, const char *key, const void *data, size_t len)
{
    hub_app_t *app = ctx;
    esp_err_t err = nvs_set_blob(app->nvs, key, data, len);
    if (err == ESP_OK) err = nvs_commit(app->nvs);
    if (err != ESP_OK) ESP_LOGE(TAG, "NVS put %s failed: %s", key, esp_err_to_name(err));
    return err == ESP_OK ? 0 : -1;
}

static int op_store_get(void *ctx, const char *key, void *data, size_t cap)
{
    hub_app_t *app = ctx;
    size_t len = cap;
    esp_err_t err = nvs_get_blob(app->nvs, key, data, &len);
    return err == ESP_OK && len <= INT_MAX ? (int)len : -1;
}

static int op_store_del(void *ctx, const char *key)
{
    hub_app_t *app = ctx;
    esp_err_t err = nvs_erase_key(app->nvs, key);
    if (err == ESP_ERR_NVS_NOT_FOUND) return 0;
    if (err == ESP_OK) err = nvs_commit(app->nvs);
    if (err != ESP_OK) ESP_LOGE(TAG, "NVS erase %s failed: %s", key, esp_err_to_name(err));
    return err == ESP_OK ? 0 : -1;
}

static void copy_value(sb_hub_app_value_t *out, const sb_value_t *value)
{
    memset(out, 0, sizeof *out);
    if (!value) return;
    out->type = value->type;
    switch (value->type) {
    case SB_V_BOOL:
        out->b = value->b;
        break;
    case SB_V_I32:
        out->i = value->i;
        break;
    case SB_V_U32:
        out->u = value->u;
        break;
    case SB_V_F32:
        out->f = value->f;
        break;
    case SB_V_ENUM:
        out->e = value->e;
        break;
    case SB_V_STR:
        if (!value->s.p) break;
        out->s.len = value->s.len <= SB_MAX_STR ? value->s.len : SB_MAX_STR;
        memcpy(out->s.text, value->s.p, out->s.len);
        out->s.text[out->s.len] = 0;
        break;
    default:
        break;
    }
}

static void copy_str(sb_hub_app_str_t *out, sb_str_t value)
{
    memset(out, 0, sizeof *out);
    if (!value.p) return;
    out->len = value.len <= SB_MAX_STR ? value.len : SB_MAX_STR;
    memcpy(out->text, value.p, out->len);
    out->text[out->len] = 0;
}

static void op_emit(void *ctx, const sb_hub_evt_t *evt)
{
    hub_app_t *app = ctx;
    sb_hub_app_event_t *copy = &app->events[app->event_head];
    memset(copy, 0, sizeof *copy);
    copy->seq = ++app->event_seq;
    copy->kind = evt->kind;
    copy->slot = evt->slot;
    copy->entity = evt->entity;
    copy->etype = evt->etype;
    copy->pair = evt->pair;
    copy->available = evt->available;
    copy->tombstone = evt->tombstone;
    copy->node_id = evt->node_id;
    copy->generation = evt->generation;
    copy->has_value = evt->value != NULL;
    if (evt->value) copy_value(&copy->value, evt->value);
    if (evt->event_id)
        snprintf(copy->event_id, sizeof copy->event_id, "%s", evt->event_id);
    app->event_head = (uint8_t)((app->event_head + 1) % SB_HUB_APP_STREAM_CAP);
    if (app->event_len < SB_HUB_APP_STREAM_CAP) app->event_len++;

    switch (evt->kind) {
    case SB_EVT_NODE:
        ESP_LOGI(TAG, "node slot=%u changed", evt->slot);
        break;
    case SB_EVT_AVAIL:
        ESP_LOGI(TAG, "node slot=%u %s", evt->slot, evt->available ? "available" : "unavailable");
        break;
    case SB_EVT_PAIR:
        ESP_LOGI(TAG, "pair event=%u slot=%u", evt->pair, evt->slot);
        break;
    case SB_EVT_NODE_ERROR:
        ESP_LOGW(TAG, "node slot=%u error=%u", evt->slot, evt->etype);
        break;
    default:
        break;
    }
}

static const sb_hub_ops_t HUB_OPS = {
    .ctx = &s_app,
    .now_ms = op_now_ms,
    .unix_time = op_unix_time,
    .random = op_random,
    .radio_send = op_radio_send,
    .radio_peer = op_radio_peer,
    .store_put = op_store_put,
    .store_get = op_store_get,
    .store_del = op_store_del,
    .emit = op_emit,
};

static void enqueue_control(const hub_control_t *msg)
{
    if (xQueueSend(s_app.control_queue, msg, 0) != pdTRUE)
        ESP_LOGE(TAG, "hub control queue full, dropped event %u", msg->kind);
}

static void radio_ready(void *ctx, const uint8_t mac[6], uint8_t channel)
{
    (void)ctx;
    hub_control_t msg = {.kind = HUB_EV_READY, .channel = channel};
    memcpy(msg.mac, mac, 6);
    enqueue_control(&msg);
}

static void radio_reset(void *ctx)
{
    (void)ctx;
    hub_control_t msg = {.kind = HUB_EV_RESET};
    enqueue_control(&msg);
}

static void radio_rx(void *ctx, const uint8_t mac[6], int8_t rssi, const uint8_t *data, size_t len)
{
    (void)ctx;
    if (len > sizeof(((hub_rx_t *)0)->data)) return;
    hub_rx_t msg = {.rssi = rssi, .len = (uint16_t)len};
    memcpy(msg.mac, mac, 6);
    memcpy(msg.data, data, len);
    if (xQueueSend(s_app.rx_queue, &msg, 0) != pdTRUE)
        ESP_LOGW(TAG, "hub RX queue full, dropped frame");
}

static void radio_send_done(void *ctx, uint32_t token, bool ok)
{
    (void)ctx;
    hub_control_t msg = {.kind = HUB_EV_SEND_DONE, .ok = ok, .token = token};
    enqueue_control(&msg);
}

static const sb_radio_events_t RADIO_EVENTS = {
    .ctx = &s_app,
    .ready = radio_ready,
    .reset = radio_reset,
    .rx = radio_rx,
    .send_done = radio_send_done,
};

static void handle_ready(const hub_control_t *msg)
{
    if (msg->channel != s_app.expected_channel) {
        ESP_LOGE(TAG, "radio ready on channel %u, expected %u", msg->channel,
                 s_app.expected_channel);
        return;
    }
    if (!s_app.hub) {
        memcpy(s_app.cfg.hub_mac, msg->mac, 6);
        s_app.cfg.channel = msg->channel;
        s_app.hub = sb_hub_create(&s_app.cfg, &HUB_OPS);
        if (!s_app.hub) {
            ESP_LOGE(TAG, "hub creation failed");
            return;
        }
        ESP_LOGI(TAG, "hub ready id=%s boot=%" PRIu32 " channel=%u C6=" MACSTR,
                 s_app.cfg.hub_id, s_app.cfg.hub_boot, msg->channel, MAC2STR(msg->mac));
    } else if (memcmp(s_app.cfg.hub_mac, msg->mac, 6) != 0) {
        ESP_LOGE(TAG, "C6 MAC changed from " MACSTR " to " MACSTR "; refusing stale registry",
                 MAC2STR(s_app.cfg.hub_mac), MAC2STR(msg->mac));
        return;
    }
    sb_hub_radio_ready(s_app.hub);
}

static bool copy_node(int slot, sb_hub_app_node_t *out)
{
    sb_hub_node_view_t view;
    if (!sb_hub_node(s_app.hub, slot, &view) || view.state == SB_NODE_EMPTY) return false;
    memset(out, 0, sizeof *out);
    out->slot = (uint8_t)slot;
    out->state = view.state;
    memcpy(out->mac, view.mac, sizeof out->mac);
    out->epoch = view.epoch;
    out->generation = view.generation;
    out->node_id = view.node_id;
    out->available = view.available;
    out->last_seen_ms = view.last_seen_ms;
    out->rssi = view.rssi;
    out->report_interval_s = view.report_interval_s;
    out->boot_reason = view.boot_reason;
    out->has_schema = view.has_schema;
    out->schema_hash = view.schema_hash;
    if (!view.schema) return true;
    copy_str(&out->node_name, view.schema->node_name);
    copy_str(&out->model, view.schema->model);
    copy_str(&out->fw_version, view.schema->fw_version);
    out->entity_count = view.schema->n <= SB_MAX_ENTITIES ? view.schema->n : SB_MAX_ENTITIES;
    for (uint8_t i = 0; i < out->entity_count; i++) {
        const sb_entity_t *src = &view.schema->e[i];
        sb_hub_app_entity_t *dst = &out->entities[i];
        dst->entity = src->entity;
        dst->platform = src->platform;
        dst->value_type = src->value_type;
        dst->state_class = src->state_class;
        dst->accuracy = src->accuracy;
        dst->flags = src->flags;
        copy_str(&dst->object_id, src->object_id);
        copy_str(&dst->name, src->name);
        copy_str(&dst->unit, src->unit);
        copy_str(&dst->device_class, src->device_class);
        copy_str(&dst->extra, src->extra);
        if (view.values) copy_value(&dst->value, &view.values[i]);
    }
    return true;
}

static void fetch_events(const sb_hub_app_api_request_t *request,
                         sb_hub_app_api_response_t *response)
{
    response->stream.stream_epoch = s_app.cfg.hub_boot;
    response->stream.latest_seq = s_app.event_seq;
    uint8_t oldest = (uint8_t)((s_app.event_head + SB_HUB_APP_STREAM_CAP - s_app.event_len) %
                               SB_HUB_APP_STREAM_CAP);
    uint64_t oldest_seq = s_app.event_len ? s_app.events[oldest].seq : s_app.event_seq + 1;
    if (!sb_api_can_resume(s_app.cfg.hub_boot, request->stream_epoch, request->after_seq,
                           oldest_seq, s_app.event_seq)) {
        response->stream.resync_required = true;
        return;
    }
    for (uint8_t i = 0; i < s_app.event_len; i++) {
        const sb_hub_app_event_t *event =
            &s_app.events[(oldest + i) % SB_HUB_APP_STREAM_CAP];
        if (event->seq > request->after_seq)
            response->stream.events[response->stream.count++] = *event;
    }
}

static void handle_api(const sb_hub_app_api_request_t *request)
{
    sb_hub_app_api_response_t *response = &s_app.api_response;
    memset(response, 0, sizeof *response);
    if (!s_app.hub) {
        response->result = SB_HUB_ERR_INVALID;
        xSemaphoreGive(s_app.api_done);
        return;
    }
    switch (request->op) {
    case SB_HUB_APP_INFO:
        snprintf(response->info.hub_id, sizeof response->info.hub_id, "%s", s_app.cfg.hub_id);
        response->info.hub_boot = s_app.cfg.hub_boot;
        response->info.stream_epoch = s_app.cfg.hub_boot;
        response->info.stream_seq = s_app.event_seq;
        response->info.channel = s_app.cfg.channel;
        response->info.max_nodes = SB_HUB_MAX_NODES;
        for (int i = 0; i < SB_HUB_MAX_NODES; i++) {
            sb_hub_node_view_t view;
            if (sb_hub_node(s_app.hub, i, &view) && view.state != SB_NODE_EMPTY)
                response->info.node_count++;
        }
        break;
    case SB_HUB_APP_STATS:
        response->stats = sb_hub_stats(s_app.hub);
        break;
    case SB_HUB_APP_NODE_GET:
        response->node.found = copy_node(request->slot, &response->node.node);
        if (request->slot < 0 || request->slot >= SB_HUB_MAX_NODES)
            response->result = SB_HUB_ERR_INVALID;
        break;
    case SB_HUB_APP_NODE_ADD: {
        int slot = sb_hub_node_add(s_app.hub, response->added.key);
        response->result = slot < 0 ? slot : 0;
        if (slot >= 0) copy_node(slot, &response->added.node);
        break;
    }
    case SB_HUB_APP_NODE_REMOVE:
        response->result = sb_hub_node_remove(s_app.hub, request->slot);
        break;
    case SB_HUB_APP_PAIR_OPEN:
        if (request->slot < 0 || request->duration_ms == 0 ||
            request->duration_ms > SB_HUB_PAIR_WINDOW_MS)
            response->result = SB_HUB_ERR_INVALID;
        else
            response->result =
                sb_hub_pair_open(s_app.hub, request->slot, request->duration_ms);
        break;
    case SB_HUB_APP_PAIR_CLOSE:
        sb_hub_pair_close(s_app.hub);
        break;
    case SB_HUB_APP_STREAM_FETCH:
        fetch_events(request, response);
        break;
    default:
        response->result = SB_HUB_ERR_INVALID;
        break;
    }
    xSemaphoreGive(s_app.api_done);
}

static void hub_task(void *arg)
{
    (void)arg;
    hub_control_t control;
    hub_rx_t rx;
    sb_hub_app_api_request_t request;
    uint64_t last_tick = op_now_ms(NULL);
    for (;;) {
        if (xQueueReceive(s_app.api_queue, &request, 0) == pdTRUE) {
            handle_api(&request);
        } else if (xQueueReceive(s_app.control_queue, &control, 0) == pdTRUE) {
            switch (control.kind) {
            case HUB_EV_READY:
                handle_ready(&control);
                break;
            case HUB_EV_RESET:
                ESP_LOGW(TAG, "radio unavailable; waiting for reconfiguration");
                break;
            case HUB_EV_SEND_DONE:
                if (s_app.hub)
                    sb_hub_on_send_done(s_app.hub, control.token, control.ok);
                break;
            default:
                break;
            }
        } else if (xQueueReceive(s_app.rx_queue, &rx, pdMS_TO_TICKS(250)) == pdTRUE &&
                   s_app.hub) {
            sb_hub_on_rx(s_app.hub, rx.mac, rx.rssi, rx.data, rx.len);
        }
        uint64_t now = op_now_ms(NULL);
        if (s_app.hub && now - last_tick >= 1000) {
            sb_hub_tick(s_app.hub);
            last_tick = now;
        }
    }
}

static esp_err_t load_identity(void)
{
    uint8_t mac[6];
    ESP_RETURN_ON_ERROR(esp_read_mac(mac, ESP_MAC_BASE), TAG, "read base MAC");
    snprintf(s_app.cfg.hub_id, sizeof s_app.cfg.hub_id, "sb-%02x%02x%02x%02x%02x%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    uint32_t boot = 0;
    esp_err_t err = nvs_get_u32(s_app.nvs, "hub_boot", &boot);
    if (err != ESP_OK && err != ESP_ERR_NVS_NOT_FOUND) return err;
    boot++;
    if (boot == 0) boot = 1;
    ESP_RETURN_ON_ERROR(nvs_set_u32(s_app.nvs, "hub_boot", boot), TAG, "store hub boot");
    ESP_RETURN_ON_ERROR(nvs_commit(s_app.nvs), TAG, "commit hub boot");
    s_app.cfg.hub_boot = boot;
    return ESP_OK;
}

esp_err_t sb_hub_app_start(const sb_radio_cfg_t *radio_cfg)
{
    if (!radio_cfg) return ESP_ERR_INVALID_ARG;
    memset(&s_app, 0, sizeof s_app);
    s_app.expected_channel = radio_cfg->channel;
    ESP_RETURN_ON_ERROR(nvs_flash_init_partition("hub_nvs"), TAG, "init hub NVS");
    ESP_RETURN_ON_ERROR(nvs_open_from_partition("hub_nvs", "server_buddy", NVS_READWRITE,
                                                &s_app.nvs),
                        TAG, "open hub NVS");
    ESP_RETURN_ON_ERROR(load_identity(), TAG, "load identity");
    s_app.control_queue = xQueueCreate(32, sizeof(hub_control_t));
    s_app.rx_queue = xQueueCreate(32, sizeof(hub_rx_t));
    s_app.api_queue = xQueueCreate(SB_HUB_APP_API_QUEUE_LEN, sizeof(sb_hub_app_api_request_t));
    s_app.api_mutex = xSemaphoreCreateMutex();
    s_app.api_done = xSemaphoreCreateBinary();
    if (!s_app.control_queue || !s_app.rx_queue || !s_app.api_queue || !s_app.api_mutex ||
        !s_app.api_done)
        return ESP_ERR_NO_MEM;
    if (xTaskCreate(hub_task, "sb_hub", 8192, NULL, 7, NULL) != pdPASS) return ESP_ERR_NO_MEM;
    ESP_RETURN_ON_ERROR(sb_api_start(s_app.cfg.hub_id, s_app.cfg.hub_boot), TAG, "start API");
    esp_err_t mdns_err = sb_mdns_start(s_app.cfg.hub_id);
    if (mdns_err != ESP_OK)
        ESP_LOGW(TAG, "mDNS unavailable (%s); manual host still works",
                 esp_err_to_name(mdns_err));
    return sb_radio_start(radio_cfg, &RADIO_EVENTS);
}

esp_err_t sb_hub_app_api(const sb_hub_app_api_request_t *request,
                         sb_hub_app_api_response_t *response)
{
    if (!request || !response) return ESP_ERR_INVALID_ARG;
    if (!s_app.api_queue || !s_app.api_mutex || !s_app.api_done) return ESP_ERR_INVALID_STATE;
    if (xSemaphoreTake(s_app.api_mutex, portMAX_DELAY) != pdTRUE) return ESP_FAIL;
    esp_err_t err = ESP_OK;
    if (xQueueSend(s_app.api_queue, request, portMAX_DELAY) != pdTRUE ||
        xSemaphoreTake(s_app.api_done, portMAX_DELAY) != pdTRUE) {
        err = ESP_FAIL;
    } else {
        *response = s_app.api_response;
        memset(&s_app.api_response, 0, sizeof s_app.api_response);
    }
    xSemaphoreGive(s_app.api_mutex);
    return err;
}
