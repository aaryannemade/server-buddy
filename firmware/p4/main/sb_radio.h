#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

typedef struct {
    uint8_t channel; // fixed ESP-NOW channel
    char country[3]; // regulatory domain, e.g. "01" (world-safe) or "GB"
} sb_radio_cfg_t;

// Requires ESP-Hosted connected to the C6 and the default event loop.
esp_err_t sb_radio_start(const sb_radio_cfg_t *cfg);
esp_err_t sb_radio_send(const uint8_t mac[6], const uint8_t *data, size_t len, uint32_t *token);
// lmk == NULL: unencrypted peer.
esp_err_t sb_radio_peer(const uint8_t mac[6], bool add, const uint8_t *lmk);
