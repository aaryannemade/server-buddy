#pragma once

#include <stdint.h>

#include "esp_err.h"

// Initializes persistent API identity and follows Ethernet IP got/lost events.
// The HTTPS server itself is only present while the interface owns an IP address.
esp_err_t sb_api_start(const char *hub_id, uint32_t hub_boot);
