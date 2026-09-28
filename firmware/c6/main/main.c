// C6 co-processor: stock ESP-Hosted transport + Server Buddy ESP-NOW radio.
// The C6 owns its Wi-Fi radio (hosted Wi-Fi feature is disabled); the P4
// drives ESP-NOW through sb_link messages over ESP-Hosted peer data.
//
// Rules: ESP-NOW and peer-data callbacks only copy into a bounded queue; all
// radio calls and all P4-bound sends happen in the worker task.
#include <string.h>

#include "eh_cp_feat_peer_data.h"
#include "esp_check.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_now.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "nvs_flash.h"
#include "sb_link.h"

static const char *TAG = "sb_c6";

enum { EV_CMD, EV_RX };

typedef struct {
    uint8_t kind;
    uint32_t msg_id; // EV_CMD
    uint8_t mac[6];
    int8_t rssi;
    uint8_t channel;
    uint8_t ok;
    uint16_t len;
    uint8_t data[sizeof(sb_link_send_t) + SB_LINK_MAX_FRAME];
} item_t;

#define QUEUE_LEN 32
static QueueHandle_t s_q;
static TaskHandle_t s_worker;
static bool s_radio_up;
static sb_link_status_t s_st = {.ver = SB_LINK_VERSION};
static uint8_t s_sent_mac[6];
static bool s_sent_ok;

static void enqueue(const item_t *it)
{
    if (xQueueSend(s_q, it, 0) != pdTRUE) {
        if (it->kind == EV_RX) s_st.rx_drop++;
        else if (it->kind == EV_CMD && it->msg_id == SB_LINK_H2C_SEND) s_st.tx_drop++;
    }
    UBaseType_t used = QUEUE_LEN - uxQueueSpacesAvailable(s_q);
    if (used > s_st.queue_high_water) s_st.queue_high_water = (uint16_t)used;
}

// ---- callbacks: copy only

static void on_recv(const esp_now_recv_info_t *info, const uint8_t *data, int len)
{
    if (len <= 0 || len > SB_LINK_MAX_FRAME) {
        s_st.rx_drop++;
        return;
    }
    item_t it = {.kind = EV_RX, .len = (uint16_t)len};
    memcpy(it.mac, info->src_addr, 6);
    it.rssi = (int8_t)info->rx_ctrl->rssi;
    it.channel = (uint8_t)info->rx_ctrl->channel;
    memcpy(it.data, data, (size_t)len);
    enqueue(&it);
}

static void on_sent(const esp_now_send_info_t *info, esp_now_send_status_t status)
{
    memcpy(s_sent_mac, info->des_addr, 6);
    s_sent_ok = status == ESP_NOW_SEND_SUCCESS;
    xTaskNotifyGive(s_worker);
}

static void on_host_msg(uint32_t msg_id, const uint8_t *data, size_t len, void *ctx)
{
    item_t it = {.kind = EV_CMD, .msg_id = msg_id};
    if (len > sizeof it.data) len = sizeof it.data; // handlers validate lengths
    it.len = (uint16_t)len;
    memcpy(it.data, data, len);
    enqueue(&it);
}

// ---- worker

static void send_host(uint32_t id, const void *p, size_t n)
{
    esp_err_t err = eh_cp_feat_peer_data_send(id, p, n);
    if (err != ESP_OK) ESP_LOGW(TAG, "to P4 0x%08" PRIx32 " failed: %s", id, esp_err_to_name(err));
}

static void result(uint32_t req, uint32_t token, esp_err_t err)
{
    sb_link_result_t r = {.ver = SB_LINK_VERSION, .req_id = req, .token = token, .err = err};
    send_host(SB_LINK_C2H_RESULT, &r, sizeof r);
}

static void send_status(void)
{
    s_st.radio_up = s_radio_up;
    s_st.uptime_s = (uint32_t)(esp_timer_get_time() / 1000000);
    s_st.heap_min = esp_get_minimum_free_heap_size();
    if (s_radio_up) {
        wifi_second_chan_t second;
        esp_wifi_get_channel(&s_st.channel, &second);
        esp_now_peer_num_t num;
        if (esp_now_get_peer_num(&num) == ESP_OK) s_st.peers = (uint8_t)num.total_num;
    }
    send_host(SB_LINK_C2H_STATUS, &s_st, sizeof s_st);
}

static esp_err_t radio_config(const sb_link_config_t *c)
{
    if (c->channel < 1 || c->channel > 14) return ESP_ERR_INVALID_ARG;
    char cc[3] = {c->country[0], c->country[1], 0};
    if (!s_radio_up) {
        wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
        ESP_RETURN_ON_ERROR(esp_wifi_init(&cfg), TAG, "wifi init");
        ESP_RETURN_ON_ERROR(esp_wifi_set_storage(WIFI_STORAGE_RAM), TAG, "storage");
        ESP_RETURN_ON_ERROR(esp_wifi_set_mode(WIFI_MODE_STA), TAG, "mode");
        ESP_RETURN_ON_ERROR(esp_wifi_set_country_code(cc, false), TAG, "country");
        ESP_RETURN_ON_ERROR(esp_wifi_start(), TAG, "start");
        ESP_RETURN_ON_ERROR(esp_wifi_set_ps(WIFI_PS_NONE), TAG, "ps");
        ESP_RETURN_ON_ERROR(esp_now_init(), TAG, "espnow init");
        ESP_RETURN_ON_ERROR(esp_now_register_recv_cb(on_recv), TAG, "recv cb");
        ESP_RETURN_ON_ERROR(esp_now_register_send_cb(on_sent), TAG, "send cb");
        esp_now_peer_info_t bc = {.channel = 0, .ifidx = WIFI_IF_STA};
        memset(bc.peer_addr, 0xff, 6);
        ESP_RETURN_ON_ERROR(esp_now_add_peer(&bc), TAG, "broadcast peer");
        esp_read_mac(s_st.mac, ESP_MAC_WIFI_STA);
        s_radio_up = true;
    } else {
        ESP_RETURN_ON_ERROR(esp_wifi_set_country_code(cc, false), TAG, "country");
    }
    ESP_RETURN_ON_ERROR(esp_now_set_pmk(c->pmk), TAG, "pmk");
    ESP_RETURN_ON_ERROR(esp_wifi_set_channel(c->channel, WIFI_SECOND_CHAN_NONE), TAG, "channel");
    uint8_t actual;
    wifi_second_chan_t second;
    esp_wifi_get_channel(&actual, &second);
    memcpy(s_st.country, cc, 3);
    ESP_LOGI(TAG, "radio: country=%s channel=%u (requested %u) mac=" MACSTR, cc, actual,
             c->channel, MAC2STR(s_st.mac));
    return actual == c->channel ? ESP_OK : ESP_ERR_INVALID_STATE;
}

static esp_err_t do_send(const item_t *it, sb_link_send_done_t *done)
{
    if (!s_radio_up) return ESP_ERR_INVALID_STATE;
    const sb_link_send_t *s = (const sb_link_send_t *)it->data;
    if (it->len < sizeof *s || s->ver != SB_LINK_VERSION || s->len == 0 ||
        s->len > SB_LINK_MAX_FRAME ||
        it->len != sizeof *s + s->len)
        return ESP_ERR_INVALID_SIZE;
    esp_err_t err = esp_now_send(s->mac, s->data, s->len);
    if (err == ESP_OK) {
        s_st.tx++;
        // ESP-IDF does not guarantee callback ordering for back-to-back sends.
        // Waiting here keeps exactly one ESP-NOW send in flight while RX
        // callbacks continue filling the bounded worker queue.
        ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
        done->ver = SB_LINK_VERSION;
        done->ok = s_sent_ok;
        done->token = s->token;
        memcpy(done->mac, s_sent_mac, 6);
    }
    return err;
}

static esp_err_t do_peer(const item_t *it, bool add)
{
    if (!s_radio_up) return ESP_ERR_INVALID_STATE;
    const sb_link_peer_t *p = (const sb_link_peer_t *)it->data;
    if (it->len != sizeof *p || p->ver != SB_LINK_VERSION) return ESP_ERR_INVALID_SIZE;
    if (!add) return esp_now_is_peer_exist(p->mac) ? esp_now_del_peer(p->mac) : ESP_OK;
    esp_now_peer_info_t info = {.channel = 0, .ifidx = WIFI_IF_STA, .encrypt = p->encrypt != 0};
    memcpy(info.peer_addr, p->mac, 6);
    memcpy(info.lmk, p->lmk, 16);
    return esp_now_is_peer_exist(p->mac) ? esp_now_mod_peer(&info) : esp_now_add_peer(&info);
}

static void worker(void *arg)
{
    static item_t it; // large; keep off the task stack
    for (;;) {
        xQueueReceive(s_q, &it, portMAX_DELAY);
        switch (it.kind) {
        case EV_RX: {
            static uint8_t buf[sizeof(sb_link_rx_t) + SB_LINK_MAX_FRAME];
            sb_link_rx_t *r = (sb_link_rx_t *)buf;
            r->ver = SB_LINK_VERSION;
            memcpy(r->mac, it.mac, 6);
            r->rssi = it.rssi;
            r->channel = it.channel;
            r->len = it.len;
            memcpy(r->data, it.data, it.len);
            s_st.rx++;
            send_host(SB_LINK_C2H_RX, buf, sizeof *r + it.len);
            break;
        }
        case EV_CMD:
            switch (it.msg_id) {
            case SB_LINK_H2C_CONFIG:
                result(it.msg_id, 0, it.len == sizeof(sb_link_config_t) &&
                                             it.data[0] == SB_LINK_VERSION
                                         ? radio_config((const sb_link_config_t *)it.data)
                                         : ESP_ERR_INVALID_VERSION);
                send_status();
                break;
            case SB_LINK_H2C_SEND: {
                sb_link_send_done_t d = {0};
                esp_err_t err = do_send(&it, &d);
                if (err != ESP_OK) {
                    s_st.tx_drop++;
                    if (it.len >= sizeof(sb_link_send_t)) {
                        const sb_link_send_t *s = (const void *)it.data;
                        d = (sb_link_send_done_t){.ver = SB_LINK_VERSION, .ok = false,
                                                .token = s->token};
                        memcpy(d.mac, s->mac, 6);
                    }
                    result(it.msg_id, d.token, err);
                }
                if (!d.ok) s_st.tx_fail++;
                if (d.ver == SB_LINK_VERSION) send_host(SB_LINK_C2H_SEND_DONE, &d, sizeof d);
                break;
            }
            case SB_LINK_H2C_PEER_ADD:
            case SB_LINK_H2C_PEER_DEL: {
                const sb_link_peer_t *p = (const void *)it.data;
                uint32_t token = it.len == sizeof *p ? p->token : 0;
                result(it.msg_id, token,
                       do_peer(&it, it.msg_id == SB_LINK_H2C_PEER_ADD));
                break;
            }
            case SB_LINK_H2C_GET_STATUS:
                send_status();
                break;
            case SB_LINK_H2C_RESTART:
                ESP_LOGW(TAG, "restart requested by P4");
                vTaskDelay(pdMS_TO_TICKS(50));
                esp_restart();
                break;
            }
            break;
        }
    }
}

void app_main(void)
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    s_q = xQueueCreate(QUEUE_LEN, sizeof(item_t));
    xTaskCreate(worker, "sb_radio", 4096, NULL, 10, &s_worker);
    const uint32_t ids[] = {SB_LINK_H2C_CONFIG, SB_LINK_H2C_SEND, SB_LINK_H2C_PEER_ADD,
                            SB_LINK_H2C_PEER_DEL, SB_LINK_H2C_GET_STATUS, SB_LINK_H2C_RESTART};
    for (size_t i = 0; i < sizeof ids / sizeof ids[0]; i++)
        ESP_ERROR_CHECK(eh_cp_feat_peer_data_register_callback(ids[i], on_host_msg, NULL));
    ESP_LOGI(TAG, "ready: sb_link v%d, waiting for P4 CONFIG", SB_LINK_VERSION);
}
