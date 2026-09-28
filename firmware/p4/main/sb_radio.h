#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

typedef struct {
    uint8_t channel; // fixed ESP-NOW channel
    char country[3]; // regulatory domain, e.g. "01" (world-safe) or "GB"
} sb_radio_cfg_t;

typedef struct {
    void *ctx;
    void (*ready)(void *ctx, const uint8_t mac[6], uint8_t channel);
    void (*reset)(void *ctx);
    void (*rx)(void *ctx, const uint8_t mac[6], int8_t rssi, const uint8_t *data, size_t len);
    void (*send_done)(void *ctx, uint32_t token, bool ok);
} sb_radio_events_t;

// Requires ESP-Hosted connected to the C6 and the default event loop.
esp_err_t sb_radio_start(const sb_radio_cfg_t *cfg, const sb_radio_events_t *events);
esp_err_t sb_radio_send(const uint8_t mac[6], const uint8_t *data, size_t len, uint32_t *token);
// lmk == NULL: unencrypted peer.
esp_err_t sb_radio_peer(const uint8_t mac[6], bool add, const uint8_t *lmk);
