// Phase 0 toolchain smoke image. Hub firmware starts in Phase 2.
#include "esp_app_desc.h"
#include "esp_chip_info.h"
#include "esp_log.h"

static const char *TAG = "server_buddy";

void app_main(void)
{
    esp_chip_info_t chip;
    esp_chip_info(&chip);
    const esp_app_desc_t *app = esp_app_get_description();
    ESP_LOGI(TAG, "app=%s idf=%s chip_rev=v%d.%d", app->version, app->idf_ver,
             chip.revision / 100, chip.revision % 100);
}
