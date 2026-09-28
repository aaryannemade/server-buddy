// Phase 2 bring-up: report P4/C6 versions over ESP-Hosted. Read-only probe.
#include "esp_app_desc.h"
#include "esp_chip_info.h"
#include "esp_event.h"
#include "esp_hosted.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs_flash.h"
#include "sb_crypto.h"
#include "sb_protocol.h"

static const char *TAG = "server_buddy";

static void log_p4(void)
{
    esp_chip_info_t chip;
    esp_chip_info(&chip);
    const esp_app_desc_t *app = esp_app_get_description();
    ESP_LOGI(TAG, "p4 app=%s idf=%s chip_rev=v%d.%d protocol=v%d", app->version, app->idf_ver,
             chip.revision / 100, chip.revision % 100, SB_VERSION);
    uint8_t key[SB_KEY_LEN] = {0}, id[SB_KEY_ID_LEN];
    ESP_LOGI(TAG, "crypto self-test %s", sb_key_id(key, id) ? "ok" : "FAILED");
}

static void probe_c6(void)
{
    ESP_LOGI(TAG, "esp_hosted host v%d.%d.%d: init", ESP_HOSTED_VERSION_MAJOR_1,
             ESP_HOSTED_VERSION_MINOR_1, ESP_HOSTED_VERSION_PATCH_1);
    int rc = esp_hosted_init();
    if (rc) {
        ESP_LOGE(TAG, "esp_hosted_init failed: %d", rc);
        return;
    }
    rc = esp_hosted_connect_to_slave();
    if (rc) {
        ESP_LOGE(TAG, "C6 link FAILED (connect_to_slave=%d)", rc);
        return;
    }
    char name[32] = "";
    uint32_t chip_id = 0;
    if (esp_hosted_get_cp_info(&chip_id, name, sizeof name) == 0)
        ESP_LOGI(TAG, "C6 link up: target=%s chip_id=0x%" PRIx32, name, chip_id);
    esp_hosted_coprocessor_fwver_t fw = {0};
    rc = esp_hosted_get_coprocessor_fwversion(&fw);
    if (rc == 0)
        ESP_LOGI(TAG, "C6 firmware: %" PRIu32 ".%" PRIu32 ".%" PRIu32, (uint32_t)fw.major1,
                 (uint32_t)fw.minor1, (uint32_t)fw.patch1);
    else
        ESP_LOGW(TAG, "C6 firmware version query failed: %d (very old CP firmware?)", rc);
}

void app_main(void)
{
    log_p4();
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    probe_c6();
}
