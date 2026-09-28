// P4 side of the C6 ESP-NOW radio (sb_link over ESP-Hosted peer data).
#include "sb_radio.h"

#include <inttypes.h>
#include <string.h>

#include "eh_host_feat_peer_data.h"
#include "esp_event.h"
#include "esp_hosted.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "sb_crypto.h"
#include "sb_link.h"

static const char *TAG = "sb_radio";

typedef struct {
    uint32_t id;
    uint16_t len;
    uint8_t data[sizeof(sb_link_rx_t) + SB_LINK_MAX_FRAME];
} msg_t;

static QueueHandle_t s_q;
static sb_radio_cfg_t s_cfg;
static sb_radio_events_t s_events;
static volatile bool s_need_config = true;
static volatile bool s_ready;
static bool s_config_inflight;
static TickType_t s_config_sent;
static uint32_t s_token;
static SemaphoreHandle_t s_peer_lock, s_peer_done;
static volatile uint32_t s_peer_token;
static volatile esp_err_t s_peer_result;

static void on_c6(uint32_t id, const uint8_t *data, size_t len, void *ctx)
{
    (void)ctx;
    msg_t m = {.id = id, .len = (uint16_t)(len < sizeof m.data ? len : sizeof m.data)};
    memcpy(m.data, data, m.len);
    if (xQueueSend(s_q, &m, 0) != pdTRUE)
        ESP_LOGW(TAG, "event queue full, dropped 0x%08" PRIx32, id);
}

static void on_cp_init(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    (void)arg;
    (void)base;
    (void)id;
    (void)data;
    ESP_LOGW(TAG, "C6 (re)started: radio will be reconfigured");
    s_ready = false;
    s_need_config = true;
    s_config_inflight = false;
    if (s_events.reset) s_events.reset(s_events.ctx);
}

static esp_err_t link_send(uint32_t id, const void *p, size_t n)
{
    esp_err_t err = eh_host_peer_data_send(id, p, n);
    if (err != ESP_OK)
        ESP_LOGW(TAG, "to C6 0x%08" PRIx32 " failed: %s", id, esp_err_to_name(err));
    return err;
}

esp_err_t sb_radio_send(const uint8_t mac[6], const uint8_t *data, size_t len, uint32_t *token)
{
    if (!s_ready) return ESP_ERR_INVALID_STATE;
    if (!mac || !data) return ESP_ERR_INVALID_ARG;
    if (len == 0 || len > SB_LINK_MAX_FRAME) return ESP_ERR_INVALID_SIZE;
    uint8_t buf[sizeof(sb_link_send_t) + SB_LINK_MAX_FRAME];
    sb_link_send_t *s = (sb_link_send_t *)buf;
    s->ver = SB_LINK_VERSION;
    memcpy(s->mac, mac, 6);
    s->token = ++s_token;
    s->len = (uint16_t)len;
    memcpy(s->data, data, len);
    esp_err_t err = link_send(SB_LINK_H2C_SEND, buf, sizeof *s + len);
    if (err == ESP_OK && token) *token = s->token;
    return err;
}

esp_err_t sb_radio_peer(const uint8_t mac[6], bool add, const uint8_t *lmk)
{
    if (!s_ready) return ESP_ERR_INVALID_STATE;
    if (!mac) return ESP_ERR_INVALID_ARG;
    sb_link_peer_t p = {.ver = SB_LINK_VERSION, .encrypt = lmk != NULL};
    memcpy(p.mac, mac, 6);
    if (lmk) memcpy(p.lmk, lmk, 16);
    if (xSemaphoreTake(s_peer_lock, pdMS_TO_TICKS(2000)) != pdTRUE) return ESP_ERR_TIMEOUT;
    s_peer_token = 0; // a late result from the previous request cannot match
    while (xSemaphoreTake(s_peer_done, 0) == pdTRUE) {}
    p.token = ++s_token;
    s_peer_token = p.token;
    esp_err_t err = link_send(add ? SB_LINK_H2C_PEER_ADD : SB_LINK_H2C_PEER_DEL, &p, sizeof p);
    if (err == ESP_OK && xSemaphoreTake(s_peer_done, pdMS_TO_TICKS(2000)) == pdTRUE)
        err = s_peer_result;
    else if (err == ESP_OK)
        err = ESP_ERR_TIMEOUT;
    xSemaphoreGive(s_peer_lock);
    return err;
}

static void configure(void)
{
    sb_link_config_t c = {.ver = SB_LINK_VERSION, .channel = s_cfg.channel};
    memcpy(c.country, s_cfg.country, 2);
    memcpy(c.pmk, SB_PMK, 16);
    if (link_send(SB_LINK_H2C_CONFIG, &c, sizeof c) == ESP_OK) {
        s_need_config = false;
        s_config_inflight = true;
        s_config_sent = xTaskGetTickCount();
    }
}

static void handle(const msg_t *m)
{
    switch (m->id) {
    case SB_LINK_C2H_RESULT: {
        const sb_link_result_t *r = (const void *)m->data;
        if (m->len != sizeof *r || r->ver != SB_LINK_VERSION) break;
        if (r->err == ESP_OK)
            ESP_LOGI(TAG, "C6 ok for 0x%08" PRIx32, r->req_id);
        else
            ESP_LOGW(TAG, "C6 error for 0x%08" PRIx32 ": %s", r->req_id,
                     esp_err_to_name(r->err));
        if (r->req_id == SB_LINK_H2C_CONFIG) {
            s_config_inflight = false;
            s_need_config = r->err != ESP_OK;
        }
        if ((r->req_id == SB_LINK_H2C_PEER_ADD || r->req_id == SB_LINK_H2C_PEER_DEL) &&
            r->token == s_peer_token) {
            s_peer_result = r->err;
            xSemaphoreGive(s_peer_done);
        }
        break;
    }
    case SB_LINK_C2H_STATUS: {
        const sb_link_status_t *s = (const void *)m->data;
        if (m->len != sizeof *s || s->ver != SB_LINK_VERSION) break;
        ESP_LOGI(TAG,
                 "C6 status: radio=%u ch=%u country=%.2s mac=" MACSTR " up=%" PRIu32
                 "s rx=%" PRIu32 " rx_drop=%" PRIu32 " tx=%" PRIu32 " tx_fail=%" PRIu32
                 " tx_drop=%" PRIu32 " heap_min=%" PRIu32 " q_hw=%u peers=%u",
                 s->radio_up, s->channel, s->country, MAC2STR(s->mac), s->uptime_s, s->rx,
                 s->rx_drop, s->tx, s->tx_fail, s->tx_drop, s->heap_min, s->queue_high_water,
                 s->peers);
        if (s->radio_up && s->channel == s_cfg.channel && !s_ready) {
            s_config_inflight = false;
            s_need_config = false;
            s_ready = true;
            if (s_events.ready) s_events.ready(s_events.ctx, s->mac, s->channel);
        } else if (!s->radio_up || s->channel != s_cfg.channel) {
            s_ready = false;
            if (!s_config_inflight) s_need_config = true;
        }
        break;
    }
    case SB_LINK_C2H_SEND_DONE: {
        const sb_link_send_done_t *d = (const void *)m->data;
        if (m->len != sizeof *d || d->ver != SB_LINK_VERSION) break;
        if (!d->ok)
            ESP_LOGW(TAG, "send #%" PRIu32 " to " MACSTR " not delivered", d->token,
                     MAC2STR(d->mac));
        if (s_events.send_done) s_events.send_done(s_events.ctx, d->token, d->ok != 0);
        break;
    }
    case SB_LINK_C2H_RX: {
        const sb_link_rx_t *r = (const void *)m->data;
        if (m->len < sizeof *r || r->ver != SB_LINK_VERSION || r->len > SB_LINK_MAX_FRAME ||
            m->len != sizeof *r + r->len)
            break;
        if (r->channel != s_cfg.channel) {
            ESP_LOGW(TAG, "dropped frame on unexpected channel %u", r->channel);
            break;
        }
        if (s_ready && s_events.rx)
            s_events.rx(s_events.ctx, r->mac, r->rssi, r->data, r->len);
        break;
    }
    default:
        break;
    }
}

static void task(void *arg)
{
    (void)arg;
    static msg_t m;
    TickType_t last_status = 0;
    for (;;) {
        TickType_t now = xTaskGetTickCount();
        if (s_config_inflight && now - s_config_sent >= pdMS_TO_TICKS(3000)) {
            s_config_inflight = false;
            s_need_config = true;
        }
        if (s_need_config && !s_config_inflight) configure();
        if (xQueueReceive(s_q, &m, pdMS_TO_TICKS(1000)) == pdTRUE) handle(&m);
        now = xTaskGetTickCount();
        if (now - last_status >= pdMS_TO_TICKS(30000)) {
            uint8_t v = SB_LINK_VERSION;
            link_send(SB_LINK_H2C_GET_STATUS, &v, 1);
            last_status = now;
        }
    }
}

esp_err_t sb_radio_start(const sb_radio_cfg_t *cfg, const sb_radio_events_t *events)
{
    if (!cfg || cfg->channel < 1 || cfg->channel > 14) return ESP_ERR_INVALID_ARG;
    s_cfg = *cfg;
    s_events = events ? *events : (sb_radio_events_t){0};
    s_q = xQueueCreate(16, sizeof(msg_t));
    s_peer_lock = xSemaphoreCreateMutex();
    s_peer_done = xSemaphoreCreateBinary();
    if (!s_q || !s_peer_lock || !s_peer_done) return ESP_ERR_NO_MEM;
    const uint32_t ids[] = {SB_LINK_C2H_STATUS, SB_LINK_C2H_RX, SB_LINK_C2H_SEND_DONE,
                            SB_LINK_C2H_RESULT};
    for (size_t i = 0; i < sizeof ids / sizeof ids[0]; i++) {
        esp_err_t err = eh_host_peer_data_register(ids[i], on_c6, NULL);
        if (err != ESP_OK) return err;
    }
    ESP_ERROR_CHECK(esp_event_handler_register(ESP_HOSTED_EVENT, ESP_HOSTED_EVENT_CP_INIT,
                                               on_cp_init, NULL));
    return xTaskCreate(task, "sb_radio", 6144, NULL, 8, NULL) == pdPASS ? ESP_OK : ESP_FAIL;
}
