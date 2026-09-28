#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

// Starts the onboard IP101 Ethernet with DHCP. Requires the default event loop.
esp_err_t sb_eth_start(const char *hostname);
bool sb_eth_has_ip(void);

typedef struct {
    bool link_up;
    uint32_t link_ups, link_downs, ip_acquired;
    uint32_t last_down_ms; // duration of the most recent outage
    uint32_t ip;           // lwIP byte order
} sb_eth_stats_t;

sb_eth_stats_t sb_eth_stats(void);
