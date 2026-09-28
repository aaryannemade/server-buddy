// Server Buddy P4: Ethernet, ESP-Hosted transport, and serialized hub core.
#include "esp_app_desc.h"
#include "esp_chip_info.h"
#include "esp_event.h"
#include "esp_hosted.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs_flash.h"
#include "sb_eth.h"
#include "sb_hub_app.h"
#include "sb_crypto.h"
#include "sb_protocol.h"

static const char *TAG = "server_buddy";

static const char *reset_reason(void)
{
    switch (esp_reset_reason()) {
    case ESP_RST_POWERON: return "power-on";
    case ESP_RST_SW: return "software";
    case ESP_RST_PANIC: return "PANIC";
    case ESP_RST_INT_WDT: case ESP_RST_TASK_WDT: case ESP_RST_WDT: return "WATCHDOG";
    case ESP_RST_BROWNOUT: return "BROWNOUT";
    case ESP_RST_EXT: return "external";
    default: return "other";
    }
}

// Periodic one-line health summary (grep "hub:" in soak logs).
static void health_task(void *arg)
{
    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(60000));
        sb_eth_stats_t e = sb_eth_stats();
        ESP_LOGI(TAG, "hub: up=%llds reset=%s eth=%s ups=%" PRIu32 " downs=%" PRIu32
                      " last_down=%" PRIu32 "ms ip_acq=%" PRIu32 " heap_min=%" PRIu32,
                 esp_timer_get_time() / 1000000, reset_reason(), e.link_up ? "up" : "DOWN",
                 e.link_ups, e.link_downs, e.last_down_ms, e.ip_acquired,
                 (uint32_t)esp_get_minimum_free_heap_size());
    }
}

static void log_p4(void)
{
    esp_chip_info_t chip;
    esp_chip_info(&chip);
    const esp_app_desc_t *app = esp_app_get_description();
    ESP_LOGI(TAG, "p4 app=%s idf=%s chip_rev=v%d.%d protocol=v%d", app->version, app->idf_ver,
             chip.revision / 100, chip.revision % 100, SB_VERSION);
    uint8_t key[SB_KEY_LEN] = {0}, id[SB_KEY_ID_LEN];
    ESP_LOGI(TAG, "crypto self-test %s", sb_key_id(key, id) ? "ok" : "FAILED");
    ESP_LOGI(TAG, "reset reason: %s", reset_reason());
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
        ESP_ERROR_CHECK(nvs_flash_erase()); // hub registry uses a separate partition
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    ESP_ERROR_CHECK(sb_eth_start("server-buddy"));
    probe_c6();
    // Initial production default: world-safe domain, fixed channel 1.
    const sb_radio_cfg_t radio = {.channel = 1, .country = "01"};
    err = sb_hub_app_start(&radio);
    if (err != ESP_OK)
        ESP_LOGE(TAG, "hub disabled (recovery mode): %s", esp_err_to_name(err));
    xTaskCreate(health_task, "sb_health", 3072, NULL, 3, NULL);
}
