#include "sb_mdns.h"

#include "esp_check.h"
#include "esp_log.h"
#include "mdns.h"

static const char *TAG = "sb_mdns";

esp_err_t sb_mdns_start(const char *hub_id)
{
    if (!hub_id || !hub_id[0]) return ESP_ERR_INVALID_ARG;
    esp_err_t err = mdns_init();
    if (err != ESP_OK) return err;

    mdns_txt_item_t txt[] = {
        {.key = "id", .value = hub_id},
        {.key = "model", .value = "esp32-p4-wifi6-poe-eth"},
        {.key = "api", .value = "1"},
        {.key = "radio_protocol", .value = "1"},
    };
    err = mdns_hostname_set(hub_id);
    if (err == ESP_OK) err = mdns_instance_name_set("Server Buddy");
    if (err == ESP_OK)
        err = mdns_service_add(NULL, "_server-buddy", "_tcp", 443, txt,
                               sizeof txt / sizeof txt[0]);
    if (err != ESP_OK) {
        mdns_free();
        return err;
    }
    ESP_LOGI(TAG, "advertising %s.local _server-buddy._tcp port 443", hub_id);
    return ESP_OK;
}
