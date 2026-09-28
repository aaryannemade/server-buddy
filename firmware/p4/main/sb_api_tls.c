#include "sb_api_tls.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "esp_random.h"
#include "mbedtls/ecp.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/x509_crt.h"

#define SB_TLS_NVS_KEY "api_tls"
#define SB_TLS_VERSION 1U
#define SB_TLS_HEADER_LEN 20U
#define SB_TLS_MAX_HUB_ID_LEN 63U
#define SB_TLS_MAX_KEY_LEN 1024U
#define SB_TLS_MAX_CERT_LEN 3072U
#define SB_TLS_MAX_RECORD_LEN \
    (SB_TLS_HEADER_LEN + SB_TLS_MAX_HUB_ID_LEN + 1U + SB_TLS_MAX_KEY_LEN + \
     SB_TLS_MAX_CERT_LEN)

enum {
    SB_TLS_MAGIC_OFFSET = 0,
    SB_TLS_VERSION_OFFSET = 4,
    SB_TLS_HEADER_LEN_OFFSET = 6,
    SB_TLS_ID_LEN_OFFSET = 8,
    SB_TLS_KEY_LEN_OFFSET = 12,
    SB_TLS_CERT_LEN_OFFSET = 16,
};

static const uint8_t SB_TLS_MAGIC[4] = {'S', 'B', 'T', 'L'};

static uint16_t get_u16(const uint8_t *p)
{
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t get_u32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static void put_u16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
}

static void put_u32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
    p[2] = (uint8_t)(value >> 16);
    p[3] = (uint8_t)(value >> 24);
}

static int tls_rng(void *ctx, unsigned char *out, size_t len)
{
    (void)ctx;
    esp_fill_random(out, len);
    return 0;
}

static bool valid_hub_id(const char *hub_id, size_t *len_out)
{
    if (!hub_id) return false;

    size_t len = strnlen(hub_id, SB_TLS_MAX_HUB_ID_LEN + 1U);
    if (len == 0 || len > SB_TLS_MAX_HUB_ID_LEN) return false;
    for (size_t i = 0; i < len; ++i) {
        unsigned char c = (unsigned char)hub_id[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_'))
            return false;
    }
    *len_out = len;
    return true;
}

static esp_err_t record_parts(const sb_api_tls_t *tls, const uint8_t **key,
                              size_t *key_len, const uint8_t **cert, size_t *cert_len)
{
    if (!tls || !tls->record || tls->record_len < SB_TLS_HEADER_LEN) return ESP_ERR_INVALID_STATE;

    const uint8_t *record = tls->record;
    uint32_t id_size = get_u32(record + SB_TLS_ID_LEN_OFFSET);
    uint32_t key_size = get_u32(record + SB_TLS_KEY_LEN_OFFSET);
    uint32_t cert_size = get_u32(record + SB_TLS_CERT_LEN_OFFSET);
    if (id_size > SB_TLS_MAX_HUB_ID_LEN + 1U || key_size > SB_TLS_MAX_KEY_LEN ||
        cert_size > SB_TLS_MAX_CERT_LEN)
        return ESP_ERR_INVALID_STATE;
    size_t expected = SB_TLS_HEADER_LEN + (size_t)id_size + (size_t)key_size + cert_size;
    if (expected != tls->record_len) return ESP_ERR_INVALID_STATE;

    if (key) *key = record + SB_TLS_HEADER_LEN + id_size;
    if (key_len) *key_len = key_size;
    if (cert) *cert = record + SB_TLS_HEADER_LEN + id_size + key_size;
    if (cert_len) *cert_len = cert_size;
    return ESP_OK;
}

static bool cert_has_hub_id(const mbedtls_x509_crt *cert, const char *hub_id,
                            size_t hub_id_len)
{
    for (const mbedtls_x509_sequence *item = &cert->subject_alt_names; item && item->buf.p;
         item = item->next) {
        mbedtls_x509_subject_alternative_name san = {0};
        int ret = mbedtls_x509_parse_subject_alt_name(&item->buf, &san);
        bool match = ret == 0 && san.type == MBEDTLS_X509_SAN_DNS_NAME &&
                     san.san.unstructured_name.len == hub_id_len &&
                     memcmp(san.san.unstructured_name.p, hub_id, hub_id_len) == 0;
        if (ret == 0) mbedtls_x509_free_subject_alt_name(&san);
        if (match) return true;
    }
    return false;
}

static esp_err_t validate_record(sb_api_tls_t *tls, const char *hub_id, size_t hub_id_len)
{
    if (tls->record_len < SB_TLS_HEADER_LEN || tls->record_len > SB_TLS_MAX_RECORD_LEN)
        return ESP_ERR_INVALID_SIZE;

    const uint8_t *record = tls->record;
    if (memcmp(record + SB_TLS_MAGIC_OFFSET, SB_TLS_MAGIC, sizeof SB_TLS_MAGIC) != 0 ||
        get_u16(record + SB_TLS_VERSION_OFFSET) != SB_TLS_VERSION ||
        get_u16(record + SB_TLS_HEADER_LEN_OFFSET) != SB_TLS_HEADER_LEN)
        return ESP_ERR_INVALID_VERSION;

    uint32_t id_len = get_u32(record + SB_TLS_ID_LEN_OFFSET);
    uint32_t key_len = get_u32(record + SB_TLS_KEY_LEN_OFFSET);
    uint32_t cert_len = get_u32(record + SB_TLS_CERT_LEN_OFFSET);
    if (id_len != hub_id_len + 1U || id_len > SB_TLS_MAX_HUB_ID_LEN + 1U ||
        key_len < 2U || key_len > SB_TLS_MAX_KEY_LEN || cert_len < 2U ||
        cert_len > SB_TLS_MAX_CERT_LEN ||
        (size_t)id_len + key_len + cert_len != tls->record_len - SB_TLS_HEADER_LEN)
        return ESP_ERR_INVALID_SIZE;

    const uint8_t *id = record + SB_TLS_HEADER_LEN;
    const uint8_t *key_pem = id + id_len;
    const uint8_t *cert_pem = key_pem + key_len;
    if (id[id_len - 1U] != '\0' || key_pem[key_len - 1U] != '\0' ||
        cert_pem[cert_len - 1U] != '\0' ||
        strnlen((const char *)id, id_len) != id_len - 1U ||
        strnlen((const char *)key_pem, key_len) != key_len - 1U ||
        strnlen((const char *)cert_pem, cert_len) != cert_len - 1U ||
        memcmp(id, hub_id, id_len) != 0)
        return ESP_ERR_INVALID_STATE;

    mbedtls_pk_context key;
    mbedtls_x509_crt cert;
    mbedtls_pk_init(&key);
    mbedtls_x509_crt_init(&cert);
    int ret = mbedtls_pk_parse_key(&key, key_pem, key_len, NULL, 0, tls_rng, NULL);
    if (ret == 0) ret = mbedtls_x509_crt_parse(&cert, cert_pem, cert_len);
    if (ret == 0 && (!mbedtls_pk_can_do(&key, MBEDTLS_PK_ECKEY) ||
                     mbedtls_pk_get_bitlen(&key) != 256U ||
                     !mbedtls_pk_can_do(&cert.pk, MBEDTLS_PK_ECKEY) ||
                     mbedtls_pk_get_bitlen(&cert.pk) != 256U || cert.next != NULL ||
                     cert.version != 3 || cert.MBEDTLS_PRIVATE(sig_md) != MBEDTLS_MD_SHA256 ||
                     cert.subject_raw.len != cert.issuer_raw.len ||
                     memcmp(cert.subject_raw.p, cert.issuer_raw.p, cert.subject_raw.len) != 0 ||
                     !cert_has_hub_id(&cert, hub_id, hub_id_len)))
        ret = -1;
    if (ret == 0) ret = mbedtls_pk_check_pair(&cert.pk, &key, tls_rng, NULL);
    mbedtls_x509_crt_free(&cert);
    mbedtls_pk_free(&key);
    return ret == 0 ? ESP_OK : ESP_ERR_INVALID_STATE;
}

static esp_err_t generate_record(sb_api_tls_t *tls, nvs_handle_t nvs, const char *hub_id,
                                  size_t hub_id_len)
{
    unsigned char *key_pem = calloc(1, SB_TLS_MAX_KEY_LEN);
    unsigned char *cert_pem = calloc(1, SB_TLS_MAX_CERT_LEN);
    unsigned char serial[16];
    char subject[SB_TLS_MAX_HUB_ID_LEN + 4U];
    mbedtls_pk_context key;
    mbedtls_x509write_cert cert;
    mbedtls_pk_init(&key);
    mbedtls_x509write_crt_init(&cert);

    esp_err_t err = ESP_ERR_NO_MEM;
    if (!key_pem || !cert_pem) goto cleanup;

    int ret = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    if (ret == 0)
        ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(key), tls_rng, NULL);
    if (ret == 0) ret = mbedtls_pk_write_key_pem(&key, key_pem, SB_TLS_MAX_KEY_LEN);

    memcpy(subject, "CN=", 3);
    memcpy(subject + 3, hub_id, hub_id_len + 1U);
    esp_fill_random(serial, sizeof serial);
    serial[0] &= 0x7f;
    serial[sizeof serial - 1U] |= 1U;

    mbedtls_x509write_crt_set_version(&cert, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_md_alg(&cert, MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_subject_key(&cert, &key);
    mbedtls_x509write_crt_set_issuer_key(&cert, &key);
    if (ret == 0) ret = mbedtls_x509write_crt_set_serial_raw(&cert, serial, sizeof serial);
    if (ret == 0) ret = mbedtls_x509write_crt_set_subject_name(&cert, subject);
    if (ret == 0) ret = mbedtls_x509write_crt_set_issuer_name(&cert, subject);
    if (ret == 0)
        ret = mbedtls_x509write_crt_set_validity(&cert, "20200101000000", "21200101000000");
    if (ret == 0) ret = mbedtls_x509write_crt_set_basic_constraints(&cert, 0, -1);
    if (ret == 0)
        ret = mbedtls_x509write_crt_set_key_usage(&cert, MBEDTLS_X509_KU_DIGITAL_SIGNATURE);

    mbedtls_x509_san_list san = {
        .node = {
            .type = MBEDTLS_X509_SAN_DNS_NAME,
            .san.unstructured_name = {
                .len = hub_id_len,
                .p = (unsigned char *)hub_id,
            },
        },
        .next = NULL,
    };
    if (ret == 0) ret = mbedtls_x509write_crt_set_subject_alternative_name(&cert, &san);
    if (ret == 0)
        ret = mbedtls_x509write_crt_pem(&cert, cert_pem, SB_TLS_MAX_CERT_LEN, tls_rng, NULL);

    err = ESP_FAIL;
    if (ret == 0) {
        size_t key_len = strnlen((const char *)key_pem, SB_TLS_MAX_KEY_LEN) + 1U;
        size_t cert_len = strnlen((const char *)cert_pem, SB_TLS_MAX_CERT_LEN) + 1U;
        size_t id_len = hub_id_len + 1U;
        size_t record_len = SB_TLS_HEADER_LEN + id_len + key_len + cert_len;
        if (key_len > SB_TLS_MAX_KEY_LEN || cert_len > SB_TLS_MAX_CERT_LEN ||
            record_len > SB_TLS_MAX_RECORD_LEN) {
            err = ESP_ERR_INVALID_SIZE;
        } else {
            uint8_t *record = calloc(1, record_len);
            if (!record) {
                err = ESP_ERR_NO_MEM;
            } else {
                memcpy(record + SB_TLS_MAGIC_OFFSET, SB_TLS_MAGIC, sizeof SB_TLS_MAGIC);
                put_u16(record + SB_TLS_VERSION_OFFSET, SB_TLS_VERSION);
                put_u16(record + SB_TLS_HEADER_LEN_OFFSET, SB_TLS_HEADER_LEN);
                put_u32(record + SB_TLS_ID_LEN_OFFSET, (uint32_t)id_len);
                put_u32(record + SB_TLS_KEY_LEN_OFFSET, (uint32_t)key_len);
                put_u32(record + SB_TLS_CERT_LEN_OFFSET, (uint32_t)cert_len);
                memcpy(record + SB_TLS_HEADER_LEN, hub_id, id_len);
                memcpy(record + SB_TLS_HEADER_LEN + id_len, key_pem, key_len);
                memcpy(record + SB_TLS_HEADER_LEN + id_len + key_len, cert_pem, cert_len);

                err = nvs_set_blob(nvs, SB_TLS_NVS_KEY, record, record_len);
                if (err == ESP_OK) err = nvs_commit(nvs);
                if (err == ESP_OK) {
                    tls->record = record;
                    tls->record_len = record_len;
                } else {
                    mbedtls_platform_zeroize(record, record_len);
                    free(record);
                }
            }
        }
    }

cleanup:
    mbedtls_platform_zeroize(serial, sizeof serial);
    mbedtls_platform_zeroize(subject, sizeof subject);
    if (key_pem) {
        mbedtls_platform_zeroize(key_pem, SB_TLS_MAX_KEY_LEN);
        free(key_pem);
    }
    if (cert_pem) {
        mbedtls_platform_zeroize(cert_pem, SB_TLS_MAX_CERT_LEN);
        free(cert_pem);
    }
    mbedtls_x509write_crt_free(&cert);
    mbedtls_pk_free(&key);
    return err;
}

esp_err_t sb_api_tls_init(sb_api_tls_t *tls, nvs_handle_t nvs, const char *hub_id)
{
    size_t hub_id_len;
    if (!tls || !valid_hub_id(hub_id, &hub_id_len)) return ESP_ERR_INVALID_ARG;
    tls->record = NULL;
    tls->record_len = 0;

    size_t record_len = 0;
    esp_err_t err = nvs_get_blob(nvs, SB_TLS_NVS_KEY, NULL, &record_len);
    if (err == ESP_ERR_NVS_NOT_FOUND) return generate_record(tls, nvs, hub_id, hub_id_len);
    if (err != ESP_OK) return err;
    if (record_len < SB_TLS_HEADER_LEN || record_len > SB_TLS_MAX_RECORD_LEN)
        return ESP_ERR_INVALID_SIZE;

    tls->record = malloc(record_len);
    if (!tls->record) return ESP_ERR_NO_MEM;
    tls->record_len = record_len;
    size_t loaded_len = record_len;
    err = nvs_get_blob(nvs, SB_TLS_NVS_KEY, tls->record, &loaded_len);
    if (err == ESP_OK && loaded_len != record_len) err = ESP_ERR_INVALID_SIZE;
    if (err == ESP_OK) err = validate_record(tls, hub_id, hub_id_len);
    if (err != ESP_OK) sb_api_tls_free(tls);
    return err;
}

void sb_api_tls_free(sb_api_tls_t *tls)
{
    if (!tls) return;
    if (tls->record) {
        mbedtls_platform_zeroize(tls->record, tls->record_len);
        free(tls->record);
    }
    tls->record = NULL;
    tls->record_len = 0;
}

const uint8_t *sb_api_tls_cert_pem(const sb_api_tls_t *tls)
{
    const uint8_t *cert = NULL;
    return record_parts(tls, NULL, NULL, &cert, NULL) == ESP_OK ? cert : NULL;
}

size_t sb_api_tls_cert_pem_len(const sb_api_tls_t *tls)
{
    size_t len = 0;
    return record_parts(tls, NULL, NULL, NULL, &len) == ESP_OK ? len : 0;
}

const uint8_t *sb_api_tls_private_key_pem(const sb_api_tls_t *tls)
{
    const uint8_t *key = NULL;
    return record_parts(tls, &key, NULL, NULL, NULL) == ESP_OK ? key : NULL;
}

size_t sb_api_tls_private_key_pem_len(const sb_api_tls_t *tls)
{
    size_t len = 0;
    return record_parts(tls, NULL, &len, NULL, NULL) == ESP_OK ? len : 0;
}
