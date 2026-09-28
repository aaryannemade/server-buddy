#pragma once

#include <stdbool.h>

#include "esp_err.h"

// Starts the onboard IP101 Ethernet with DHCP. Requires the default event loop.
esp_err_t sb_eth_start(const char *hostname);
bool sb_eth_has_ip(void);
