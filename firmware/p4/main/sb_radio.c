// P4 side of the C6 ESP-NOW radio (sb_link over ESP-Hosted peer data).
// Phase 2 feasibility spike: configures the radio, runs a TX self-test, logs
// RX frames and C6 status, and reconfigures after any C6 reset.
#include "sb_radio.h"

#include <string.h>

#include "eh_host_feat_peer_data.h"
#include "esp_event.h"
#include "esp_hosted.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "esp_mac.h"
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
static volatile bool s_need_config = true;
static uint32_t s_token;

static const uint8_t BCAST[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
// Locally administered, never assigned: unicast here must fail at MAC level.
static const uint8_t ABSENT[6] = {0x02, 0x53, 0x42, 0x00, 0x00, 0x01};

static void on_c6(uint32_t id, const uint8_t *data, size_t len, void *ctx)
{
    msg_t m = {.id = id, .len = (uint16_t)(len < sizeof m.data ? len : sizeof m.data)};
    memcpy(m.data, data, m.len);
    if (xQueueSend(s_q, &m, 0) != pdTRUE) ESP_LOGW(TAG, "event queue full, dropped 0x%08" PRIx32, id);
}

static void on_cp_init(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    ESP_LOGW(TAG, "C6 (re)started: radio will be reconfigured");
    s_need_config = true;
}

static esp_err_t link_send(uint32_t id, const void *p, size_t n)
{
    esp_err_t err = eh_host_peer_data_send(id, p, n);
    if (err != ESP_OK) ESP_LOGW(TAG, "to C6 0x%08" PRIx32 " failed: %s", id, esp_err_to_name(err));
    return err;
}

esp_err_t sb_radio_send(const uint8_t mac[6], const uint8_t *data, size_t len, uint32_t *token)
{
    if (len == 0 || len > SB_LINK_MAX_FRAME) return ESP_ERR_INVALID_SIZE;
    uint8_t buf[sizeof(sb_link_send_t) + SB_LINK_MAX_FRAME];
    sb_link_send_t *s = (sb_link_send_t *)buf;
    s->ver = SB_LINK_VERSION;
    memcpy(s->mac, mac, 6);
    s->token = ++s_token;
    s->len = (uint16_t)len;
    memcpy(s->data, data, len);
    if (token) *token = s->token;
    return link_send(SB_LINK_H2C_SEND, buf, sizeof *s + len);
}

esp_err_t sb_radio_peer(const uint8_t mac[6], bool add, const uint8_t *lmk)
{
    sb_link_peer_t p = {.ver = SB_LINK_VERSION, .encrypt = lmk != NULL};
    memcpy(p.mac, mac, 6);
    if (lmk) memcpy(p.lmk, lmk, 16);
    return link_send(add ? SB_LINK_H2C_PEER_ADD : SB_LINK_H2C_PEER_DEL, &p, sizeof p);
}

static void configure(void)
{
    sb_link_config_t c = {.ver = SB_LINK_VERSION, .channel = s_cfg.channel};
    memcpy(c.country, s_cfg.country, 2);
    memcpy(c.pmk, SB_PMK, 16);
    if (link_send(SB_LINK_H2C_CONFIG, &c, sizeof c) == ESP_OK) s_need_config = false;
}

static void self_test(void)
{
    static const uint8_t payload[] = "server-buddy spike";
    uint8_t lmk[16];
    memset(lmk, 0x5a, sizeof lmk); // test-only key
    ESP_LOGI(TAG, "self-test: broadcast, then unicast to absent peer (expect fail), "
                  "then encrypted peer add/del");
    sb_radio_send(BCAST, payload, sizeof payload, NULL);
    sb_radio_peer(ABSENT, true, NULL);
    sb_radio_send(ABSENT, payload, sizeof payload, NULL);
    sb_radio_peer(ABSENT, true, lmk);
    sb_radio_send(ABSENT, payload, sizeof payload, NULL);
    sb_radio_peer(ABSENT, false, NULL);
}

static bool stress_pending;
static uint32_t s_done; // SEND_DONE count; in flight = s_token - s_done
#define MAX_IN_FLIGHT 12 // below the C6's 16-token FIFO
static void handle(const msg_t *m);

// Spike: back-to-back max-size broadcasts; measures link rate and backpressure.
static void stress(int n)
{
    static uint8_t frame[SB_LINK_MAX_FRAME];
    for (size_t i = 0; i < sizeof frame; i++) frame[i] = (uint8_t)i;
    int64_t t0 = esp_timer_get_time();
    int ok = 0;
    static msg_t m;
    for (int i = 0; i < n; i++) {
        // Credit-based pacing: keep handling C6 events; never exceed the in-flight cap.
        while (xQueueReceive(s_q, &m, (s_token - s_done) >= MAX_IN_FLIGHT ? pdMS_TO_TICKS(100) : 0) == pdTRUE)
            handle(&m);
        ok += sb_radio_send(BCAST, frame, sizeof frame, NULL) == ESP_OK;
    }
    int64_t us = esp_timer_get_time() - t0;
    ESP_LOGI(TAG, "stress: %d/%d sends accepted in %lld ms (%.0f frames/s)", ok, n, us / 1000,
             n * 1e6 / (double)us);
}

static void handle(const msg_t *m)
{
    switch (m->id) {
    case SB_LINK_C2H_RESULT: {
        const sb_link_result_t *r = (const void *)m->data;
        if (m->len < sizeof *r) break;
        if (r->err == ESP_OK)
            ESP_LOGI(TAG, "C6 ok for 0x%08" PRIx32, r->req_id);
        else
            ESP_LOGW(TAG, "C6 error for 0x%08" PRIx32 ": %s", r->req_id,
                     esp_err_to_name(r->err));
        if (r->req_id == SB_LINK_H2C_CONFIG && r->err == ESP_OK) {
            self_test();
#ifdef SB_SPIKE_STRESS // build with -DSB_SPIKE_STRESS: 1000-frame burst on every boot
            stress_pending = true;
#endif
        }
        break;
    }
    case SB_LINK_C2H_STATUS: {
        const sb_link_status_t *s = (const void *)m->data;
        if (m->len < sizeof *s) break;
        ESP_LOGI(TAG,
                 "C6 status: radio=%u ch=%u country=%.2s mac=" MACSTR " up=%" PRIu32
                 "s rx=%" PRIu32 " rx_drop=%" PRIu32 " tx=%" PRIu32 " tx_fail=%" PRIu32
                 " tx_drop=%" PRIu32 " heap_min=%" PRIu32 " q_hw=%u peers=%u",
                 s->radio_up, s->channel, s->country, MAC2STR(s->mac), s->uptime_s, s->rx,
                 s->rx_drop, s->tx, s->tx_fail, s->tx_drop, s->heap_min, s->queue_high_water,
                 s->peers);
        break;
    }
    case SB_LINK_C2H_SEND_DONE: {
        const sb_link_send_done_t *d = (const void *)m->data;
        if (m->len < sizeof *d) break;
        s_done++;
        if (d->token <= 3 || !d->ok || d->token % 250 == 0)
            ESP_LOGI(TAG, "send #%" PRIu32 " to " MACSTR ": %s", d->token, MAC2STR(d->mac),
                     d->ok ? "delivered" : "NOT delivered");
        break;
    }
    case SB_LINK_C2H_RX: {
        const sb_link_rx_t *r = (const void *)m->data;
        if (m->len < sizeof *r || m->len != sizeof *r + r->len) break;
        ESP_LOGI(TAG, "rx %u bytes from " MACSTR " rssi=%d ch=%u", r->len, MAC2STR(r->mac),
                 r->rssi, r->channel);
        ESP_LOG_BUFFER_HEXDUMP(TAG, r->data, r->len < 32 ? r->len : 32, ESP_LOG_DEBUG);
        break;
    }
    }
}

static void task(void *arg)
{
    static msg_t m;
    TickType_t last_status = 0, last_beacon = 0;
    for (;;) {
        if (s_need_config) configure();
        if (stress_pending && xTaskGetTickCount() > pdMS_TO_TICKS(8000)) {
            stress_pending = false;
            stress(1000);
            uint8_t v = SB_LINK_VERSION;
            link_send(SB_LINK_H2C_GET_STATUS, &v, 1);
        }
        if (xQueueReceive(s_q, &m, pdMS_TO_TICKS(1000)) == pdTRUE) handle(&m);
        TickType_t now = xTaskGetTickCount();
        if (now - last_beacon >= pdMS_TO_TICKS(60000)) {
            static const uint8_t beacon[] = "server-buddy beacon";
            sb_radio_send(BCAST, beacon, sizeof beacon, NULL);
            last_beacon = now;
        }
        if (now - last_status >= pdMS_TO_TICKS(30000)) {
            uint8_t v = SB_LINK_VERSION;
            link_send(SB_LINK_H2C_GET_STATUS, &v, 1);
            last_status = now;
        }
    }
}

esp_err_t sb_radio_start(const sb_radio_cfg_t *cfg)
{
    s_cfg = *cfg;
    s_q = xQueueCreate(16, sizeof(msg_t));
    if (!s_q) return ESP_ERR_NO_MEM;
    const uint32_t ids[] = {SB_LINK_C2H_STATUS, SB_LINK_C2H_RX, SB_LINK_C2H_SEND_DONE,
                            SB_LINK_C2H_RESULT};
    for (size_t i = 0; i < sizeof ids / sizeof ids[0]; i++) {
        esp_err_t err = eh_host_peer_data_register(ids[i], on_c6, NULL);
        if (err != ESP_OK) return err;
    }
    esp_event_handler_register(ESP_HOSTED_EVENT, ESP_HOSTED_EVENT_CP_INIT, on_cp_init, NULL);
    return xTaskCreate(task, "sb_radio", 6144, NULL, 8, NULL) == pdPASS ? ESP_OK : ESP_FAIL;
}
