#pragma once

#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "nvs.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t *record;
    size_t record_len;
} sb_api_tls_t;

// Loads the existing identity, or creates it only when the NVS key is absent.
// The caller retains ownership of the already-open read/write NVS handle.
esp_err_t sb_api_tls_init(sb_api_tls_t *tls, nvs_handle_t nvs, const char *hub_id);

// Call only after the HTTPS server has stopped using the returned PEM pointers.
void sb_api_tls_free(sb_api_tls_t *tls);

// Lengths include the PEM terminating NUL, as required by ESP-TLS.
const uint8_t *sb_api_tls_cert_pem(const sb_api_tls_t *tls);
size_t sb_api_tls_cert_pem_len(const sb_api_tls_t *tls);
const uint8_t *sb_api_tls_private_key_pem(const sb_api_tls_t *tls);
size_t sb_api_tls_private_key_pem_len(const sb_api_tls_t *tls);

// SHA-256 of the DER certificate, the value clients pin (public, safe to log).
esp_err_t sb_api_tls_fingerprint(const sb_api_tls_t *tls, uint8_t out[32]);

#ifdef __cplusplus
}
#endif
