#include "sb_api_logic.h"

#include <string.h>

#include "mbedtls/platform_util.h"
#include "mbedtls/sha256.h"

static const uint8_t MAGIC[4] = {'S', 'B', 'A', 'C'};

static uint32_t read_u32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static void write_u32(uint8_t *p, uint32_t value)
{
    for (unsigned i = 0; i < 4; i++) p[i] = (uint8_t)(value >> (8 * i));
}

bool sb_api_credential_decode(const uint8_t *record, size_t len, uint32_t *generation,
                              uint8_t hash[32])
{
    if (!record || !generation || !hash || len != SB_API_CRED_LEN ||
        memcmp(record, MAGIC, sizeof MAGIC) != 0 || read_u32(record + 4) != 1 ||
        read_u32(record + 8) == 0)
        return false;
    *generation = read_u32(record + 8);
    memcpy(hash, record + 12, 32);
    return true;
}

bool sb_api_credential_encode(uint32_t generation, const char *token,
                              uint8_t record[SB_API_CRED_LEN], uint8_t hash[32])
{
    if (!record || !hash || !token || !generation ||
        strnlen(token, SB_API_TOKEN_LEN + 1) != SB_API_TOKEN_LEN)
        return false;
    uint8_t digest[32];
    if (mbedtls_sha256((const unsigned char *)token, SB_API_TOKEN_LEN, digest, 0) != 0)
        return false;
    memcpy(record, MAGIC, sizeof MAGIC);
    write_u32(record + 4, 1);
    write_u32(record + 8, generation);
    memcpy(record + 12, digest, sizeof digest);
    memcpy(hash, digest, sizeof digest);
    mbedtls_platform_zeroize(digest, sizeof digest);
    return true;
}

bool sb_api_credential_verify(const char *token, const uint8_t hash[32])
{
    if (!token || !hash || strnlen(token, SB_API_TOKEN_LEN + 1) != SB_API_TOKEN_LEN)
        return false;
    uint8_t digest[32], diff = 0;
    if (mbedtls_sha256((const unsigned char *)token, SB_API_TOKEN_LEN, digest, 0) != 0)
        return false;
    for (size_t i = 0; i < sizeof digest; i++) diff |= digest[i] ^ hash[i];
    mbedtls_platform_zeroize(digest, sizeof digest);
    return diff == 0;
}

bool sb_api_can_resume(uint32_t epoch, uint32_t requested_epoch, uint64_t after,
                       uint64_t oldest, uint64_t latest)
{
    return epoch == requested_epoch && after <= latest &&
           (oldest == 0 || after >= oldest || oldest - after == 1);
}

cJSON *sb_api_parse_request(const uint8_t *payload, size_t len)
{
    if (!payload || !len || len > SB_API_MAX_INBOUND || memchr(payload, 0, len)) return NULL;
    const char *end = NULL;
    cJSON *root = cJSON_ParseWithLengthOpts((const char *)payload, len, &end, false);
    const char *limit = (const char *)payload + len;
    while (end && end < limit && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n'))
        end++;
    if (end == limit && cJSON_IsObject(root)) {
        const cJSON *op = cJSON_GetObjectItemCaseSensitive(root, "op");
        if (cJSON_IsString(op) && op->valuestring && op->valuestring[0]) return root;
    }
    cJSON_Delete(root);
    return NULL;
}
