// Pairing crypto for protocol v1 (docs/SECURITY.md). Backed by mbedTLS.
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SB_KEY_LEN 16
#define SB_NONCE_LEN 16
#define SB_TAG_LEN 16
#define SB_KEY_ID_LEN 4
#define SB_LMK_LEN 16
#define SB_KMIC_LEN 16
#define SB_MAC_LEN 6
#define SB_DIR_NODE_TO_HUB 0
#define SB_DIR_HUB_TO_NODE 1

// Non-secret by design; security rests on per-peer LMKs.
extern const uint8_t SB_PMK[16];

// RFC 5869 HKDF-SHA256. Returns false on mbedTLS failure or out_len > 255*32.
bool sb_hkdf_sha256(const uint8_t *ikm, size_t ikm_len, const uint8_t *salt, size_t salt_len,
                    const uint8_t *info, size_t info_len, uint8_t *out, size_t out_len);

bool sb_key_id(const uint8_t k_node[SB_KEY_LEN], uint8_t out[SB_KEY_ID_LEN]);

// Derives the ESP-NOW LMK and the application MIC key for a pairing.
bool sb_session_keys(const uint8_t k_node[SB_KEY_LEN], const uint8_t node_nonce[SB_NONCE_LEN],
                     const uint8_t hub_nonce[SB_NONCE_LEN], const uint8_t node_mac[SB_MAC_LEN],
                     const uint8_t hub_mac[SB_MAC_LEN], uint8_t epoch, uint8_t lmk[SB_LMK_LEN],
                     uint8_t k_mic[SB_KMIC_LEN]);

// MIC over `frame` (bytes before the MIC).
bool sb_mic(const uint8_t k_mic[SB_KMIC_LEN], uint8_t dir, const uint8_t *frame, size_t len,
            uint8_t out[8]);
// Fill the last 8 bytes of an encoded frame of length `len`.
bool sb_mic_seal(const uint8_t k_mic[SB_KMIC_LEN], uint8_t dir, uint8_t *frame, size_t len);
// Constant-time check of the trailing MIC. False if len < 8.
bool sb_mic_verify(const uint8_t k_mic[SB_KMIC_LEN], uint8_t dir, const uint8_t *frame,
                   size_t len);

// `frame` is the encoded frame up to (not including) the trailing tag.
bool sb_request_tag(const uint8_t k_node[SB_KEY_LEN], const uint8_t *frame, size_t len,
                    uint8_t out[SB_TAG_LEN]);
bool sb_response_tag(const uint8_t k_node[SB_KEY_LEN], const uint8_t node_nonce[SB_NONCE_LEN],
                     const uint8_t *frame, size_t len, uint8_t out[SB_TAG_LEN]);

// Constant-time comparison.
bool sb_tag_equal(const uint8_t *a, const uint8_t *b, size_t len);

// u32_le(SHA-256(blob)[0:4]).
bool sb_schema_hash(const uint8_t *blob, size_t len, uint32_t *out);

#ifdef __cplusplus
}
#endif
