// One-shot C6 updater (built with ESP-Hosted 2.x or 3.x host). Connects to the C6,
// validates the embedded image, and writes it ONLY if the confirmation token
// is present at the start of the `slave_fw` partition (written with esptool,
// see scripts/update-c6.sh). The token is erased before writing, so the update
// never repeats on reboot. Without the token this is a read-only probe.
#include <inttypes.h>
#include <string.h>

#include "esp_partition.h"
#include "esp_app_desc.h"
#include "esp_app_format.h"
#include "esp_event.h"
#include "esp_hosted.h"
#include "esp_hosted_ota.h"
#include "esp_log.h"
#include "esp_rom_crc.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs_flash.h"

static const char *TAG = "c6_updater";

extern const uint8_t img_start[] asm("_binary_c6_image_bin_start");
extern const uint8_t img_end[] asm("_binary_c6_image_bin_end");

#define CHUNK 1500
#define ESP_CHIP_ID_C6 0x000D

static bool image_ok(size_t len)
{
    const esp_image_header_t *h = (const esp_image_header_t *)img_start;
    if (len < sizeof(*h) + sizeof(esp_image_segment_header_t) + sizeof(esp_app_desc_t) ||
        h->magic != ESP_IMAGE_HEADER_MAGIC || h->chip_id != ESP_CHIP_ID_C6) {
        ESP_LOGE(TAG, "embedded image invalid (magic=0x%02x chip=0x%04x)", h->magic, h->chip_id);
        return false;
    }
    const esp_app_desc_t *d = (const esp_app_desc_t *)(img_start + sizeof(esp_image_header_t) +
                                                       sizeof(esp_image_segment_header_t));
    if (d->magic_word != ESP_APP_DESC_MAGIC_WORD) {
        ESP_LOGE(TAG, "embedded image has no app descriptor");
        return false;
    }
    ESP_LOGI(TAG, "embedded C6 image: %u bytes, project=%s version=%s idf=%s crc32=%08" PRIx32,
             (unsigned)len, d->project_name, d->version, d->idf_ver,
             esp_rom_crc32_le(0, img_start, len));
    return true;
}

#define TOKEN "SB-C6-UPDATE-CONFIRMED"

// True if the token is present; consumes (erases) it either way it is found.
static bool take_confirmation(void)
{
    const esp_partition_t *p =
        esp_partition_find_first(ESP_PARTITION_TYPE_DATA, 0x40, "slave_fw");
    if (!p) {
        ESP_LOGE(TAG, "no slave_fw partition");
        return false;
    }
    char buf[sizeof TOKEN] = {0};
    if (esp_partition_read(p, 0, buf, sizeof TOKEN - 1) != ESP_OK ||
        memcmp(buf, TOKEN, sizeof TOKEN - 1) != 0) {
        ESP_LOGI(TAG, "no confirmation token in slave_fw: dry run only");
        return false;
    }
    ESP_ERROR_CHECK(esp_partition_erase_range(p, 0, p->erase_size));
    ESP_LOGW(TAG, "confirmation token found and consumed");
    return true;
}

static void log_cp_version(void)
{
    esp_hosted_coprocessor_fwver_t v = {0};
    if (esp_hosted_get_coprocessor_fwversion(&v) == ESP_OK)
        ESP_LOGI(TAG, "C6 firmware: %" PRIu32 ".%" PRIu32 ".%" PRIu32, (uint32_t)v.major1,
                 (uint32_t)v.minor1, (uint32_t)v.patch1);
    else
        ESP_LOGW(TAG, "C6 firmware version unavailable (pre-1.0 firmware)");
}

void app_main(void)
{
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    ESP_LOGI(TAG, "ESP-Hosted host v%d.%d.%d connecting to C6", ESP_HOSTED_VERSION_MAJOR_1,
             ESP_HOSTED_VERSION_MINOR_1, ESP_HOSTED_VERSION_PATCH_1);
    ESP_ERROR_CHECK(esp_hosted_init());
    ESP_ERROR_CHECK(esp_hosted_connect_to_slave());
    log_cp_version();

    size_t len = (size_t)(img_end - img_start);
    if (!image_ok(len)) return;
    if (!take_confirmation()) {
        ESP_LOGI(TAG, "C6 untouched");
        return;
    }

    ESP_LOGW(TAG, "OTA begin");
    esp_err_t err = esp_hosted_slave_ota_begin();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "OTA begin failed: %s (C6 untouched)", esp_err_to_name(err));
        return;
    }
    for (size_t off = 0; off < len; off += CHUNK) {
        uint32_t n = (uint32_t)(len - off < CHUNK ? len - off : CHUNK);
        err = esp_hosted_slave_ota_write((uint8_t *)img_start + off, n);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "OTA write failed at %u: %s (C6 still boots old image)", (unsigned)off,
                     esp_err_to_name(err));
            return;
        }
        if ((off / CHUNK) % 100 == 0) ESP_LOGI(TAG, "written %u/%u", (unsigned)off, (unsigned)len);
    }
    err = esp_hosted_slave_ota_end();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "OTA end failed: %s (image rejected; C6 still boots old image)",
                 esp_err_to_name(err));
        return;
    }
    ESP_LOGW(TAG, "OTA end OK: C6 validated the image");
    // Pre-2.6 C6 firmware has no activate RPC; OTA end sets the boot slot.
    esp_hosted_coprocessor_fwver_t v = {0};
    if (esp_hosted_get_coprocessor_fwversion(&v) == ESP_OK &&
        (v.major1 > 2 || (v.major1 == 2 && v.minor1 > 5))) {
        err = esp_hosted_slave_ota_activate();
        ESP_LOGI(TAG, "activate: %s", esp_err_to_name(err));
    }
    ESP_LOGW(TAG, "DONE: power-cycle or reflash firmware/p4 to talk to the updated C6");
}
