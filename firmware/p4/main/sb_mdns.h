#pragma once

#include "esp_err.h"

// Advertise the HTTPS API using the stable hub ID as its .local hostname.
esp_err_t sb_mdns_start(const char *hub_id);
