#include "sb_crypto.h"

#include <string.h>

#include "mbedtls/md.h"
#include "mbedtls/platform_util.h"

const uint8_t SB_PMK[16] = {'S', 'e', 'r', 'v', 'e', 'r', 'B', 'u',
                            'd', 'd', 'y', 'P', 'M', 'K', 'v', '1'};

typedef struct {
    const uint8_t *p;
    size_t len;
} part_t;

#define LABEL(s) {(const uint8_t *)(s), sizeof(s) - 1}

static bool hmac_parts(const uint8_t *key, size_t key_len, const part_t *parts, size_t n,
                       uint8_t out[32])
{
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    bool ok = info && mbedtls_md_setup(&ctx, info, 1) == 0 &&
              mbedtls_md_hmac_starts(&ctx, key, key_len) == 0;
    for (size_t i = 0; ok && i < n; i++)
        ok = parts[i].len == 0 || mbedtls_md_hmac_update(&ctx, parts[i].p, parts[i].len) == 0;
    ok = ok && mbedtls_md_hmac_finish(&ctx, out) == 0;
    mbedtls_md_free(&ctx);
    return ok;
}

bool sb_hkdf_sha256(const uint8_t *ikm, size_t ikm_len, const uint8_t *salt, size_t salt_len,
                    const uint8_t *info, size_t info_len, uint8_t *out, size_t out_len)
{
    static const uint8_t zero_salt[32] = {0};
    if (out_len > 255 * 32) return false;
    if (!salt_len) salt = zero_salt, salt_len = sizeof zero_salt;
    uint8_t prk[32], t[32];
    part_t p1[] = {{ikm, ikm_len}};
    bool ok = hmac_parts(salt, salt_len, p1, 1, prk);
    size_t done = 0, t_len = 0;
    for (uint8_t i = 1; ok && done < out_len; i++) {
        part_t p[] = {{t, t_len}, {info, info_len}, {&i, 1}};
        ok = hmac_parts(prk, sizeof prk, p, 3, t);
        t_len = sizeof t;
        size_t n = out_len - done < t_len ? out_len - done : t_len;
        if (ok) memcpy(out + done, t, n);
        done += n;
    }
    mbedtls_platform_zeroize(prk, sizeof prk);
    mbedtls_platform_zeroize(t, sizeof t);
    return ok;
}

bool sb_key_id(const uint8_t k_node[SB_KEY_LEN], uint8_t out[SB_KEY_ID_LEN])
{
    uint8_t mac[32];
    part_t p[] = {LABEL("sb-v1 id")};
    bool ok = hmac_parts(k_node, SB_KEY_LEN, p, 1, mac);
    memcpy(out, mac, SB_KEY_ID_LEN);
    return ok;
}

bool sb_session_keys(const uint8_t k_node[SB_KEY_LEN], const uint8_t node_nonce[SB_NONCE_LEN],
                     const uint8_t hub_nonce[SB_NONCE_LEN], const uint8_t node_mac[SB_MAC_LEN],
                     const uint8_t hub_mac[SB_MAC_LEN], uint8_t epoch, uint8_t lmk[SB_LMK_LEN],
                     uint8_t k_mic[SB_KMIC_LEN])
{
    static const char label[] = "sb-v1 keys";
    uint8_t salt[2 * SB_NONCE_LEN];
    uint8_t info[sizeof label - 1 + 2 * SB_MAC_LEN + 1];
    memcpy(salt, node_nonce, SB_NONCE_LEN);
    memcpy(salt + SB_NONCE_LEN, hub_nonce, SB_NONCE_LEN);
    size_t n = sizeof label - 1;
    memcpy(info, label, n);
    memcpy(info + n, node_mac, SB_MAC_LEN);
    memcpy(info + n + SB_MAC_LEN, hub_mac, SB_MAC_LEN);
    info[sizeof info - 1] = epoch;
    uint8_t okm[SB_LMK_LEN + SB_KMIC_LEN];
    bool ok = sb_hkdf_sha256(k_node, SB_KEY_LEN, salt, sizeof salt, info, sizeof info, okm, sizeof okm);
    memcpy(lmk, okm, SB_LMK_LEN);
    memcpy(k_mic, okm + SB_LMK_LEN, SB_KMIC_LEN);
    mbedtls_platform_zeroize(okm, sizeof okm);
    return ok;
}

bool sb_mic(const uint8_t k_mic[SB_KMIC_LEN], uint8_t dir, const uint8_t *frame, size_t len,
            uint8_t out[8])
{
    uint8_t mac[32];
    part_t p[] = {LABEL("sb-v1 mic"), {&dir, 1}, {frame, len}};
    bool ok = hmac_parts(k_mic, SB_KMIC_LEN, p, 3, mac);
    memcpy(out, mac, 8);
    return ok;
}

bool sb_mic_seal(const uint8_t k_mic[SB_KMIC_LEN], uint8_t dir, uint8_t *frame, size_t len)
{
    return len >= 8 && sb_mic(k_mic, dir, frame, len - 8, frame + len - 8);
}

bool sb_mic_verify(const uint8_t k_mic[SB_KMIC_LEN], uint8_t dir, const uint8_t *frame,
                   size_t len)
{
    uint8_t want[8];
    return len >= 8 && sb_mic(k_mic, dir, frame, len - 8, want) &&
           sb_tag_equal(want, frame + len - 8, 8);
}

bool sb_request_tag(const uint8_t k_node[SB_KEY_LEN], const uint8_t *frame, size_t len,
                    uint8_t out[SB_TAG_LEN])
{
    uint8_t mac[32];
    part_t p[] = {LABEL("sb-v1 req"), {frame, len}};
    bool ok = hmac_parts(k_node, SB_KEY_LEN, p, 2, mac);
    memcpy(out, mac, SB_TAG_LEN);
    return ok;
}

bool sb_response_tag(const uint8_t k_node[SB_KEY_LEN], const uint8_t node_nonce[SB_NONCE_LEN],
                     const uint8_t *frame, size_t len, uint8_t out[SB_TAG_LEN])
{
    uint8_t mac[32];
    part_t p[] = {LABEL("sb-v1 resp"), {node_nonce, SB_NONCE_LEN}, {frame, len}};
    bool ok = hmac_parts(k_node, SB_KEY_LEN, p, 3, mac);
    memcpy(out, mac, SB_TAG_LEN);
    return ok;
}

bool sb_tag_equal(const uint8_t *a, const uint8_t *b, size_t len)
{
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) diff |= a[i] ^ b[i];
    return diff == 0;
}

bool sb_schema_hash(const uint8_t *blob, size_t len, uint32_t *out)
{
    uint8_t d[32];
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!info || mbedtls_md(info, blob, len, d) != 0) return false;
    *out = (uint32_t)d[0] | ((uint32_t)d[1] << 8) | ((uint32_t)d[2] << 16) | ((uint32_t)d[3] << 24);
    return true;
}
