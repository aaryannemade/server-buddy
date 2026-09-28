// Toolchain smoke image. Hub firmware starts in Phase 2.
#include "esp_app_desc.h"
#include "esp_chip_info.h"
#include "esp_log.h"
#include "sb_crypto.h"
#include "sb_protocol.h"

static const char *TAG = "server_buddy";

void app_main(void)
{
    esp_chip_info_t chip;
    esp_chip_info(&chip);
    const esp_app_desc_t *app = esp_app_get_description();
    ESP_LOGI(TAG, "app=%s idf=%s chip_rev=v%d.%d protocol=v%d", app->version, app->idf_ver,
             chip.revision / 100, chip.revision % 100, SB_VERSION);

    // Self-test: key ID of the all-zero key must be stable across builds.
    uint8_t key[SB_KEY_LEN] = {0}, id[SB_KEY_ID_LEN];
    bool ok = sb_key_id(key, id);
    ESP_LOGI(TAG, "crypto self-test %s: %02x%02x%02x%02x", ok ? "ok" : "FAILED", id[0], id[1], id[2],
             id[3]);
}
