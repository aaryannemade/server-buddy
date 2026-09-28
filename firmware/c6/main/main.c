// ESP-Hosted co-processor. The hosted stack starts from its own constructors;
// the app only provides NVS and the default event loop (upstream pattern).
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"

void app_main(void)
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    ESP_LOGI("server_buddy_c6", "ESP-Hosted co-processor up");
}
