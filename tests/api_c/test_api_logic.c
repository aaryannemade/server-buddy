#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "sb_api_logic.h"

static void credential_lifecycle(void)
{
    static const char *first = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    static const char *second = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    uint8_t committed[SB_API_CRED_LEN], candidate[SB_API_CRED_LEN], hash[32], loaded[32];
    uint32_t generation;

    assert(sb_api_credential_encode(1, first, committed, hash));
    assert(memcmp(committed, first, SB_API_CRED_LEN) != 0);
    assert(sb_api_credential_decode(committed, sizeof committed, &generation, loaded));
    assert(generation == 1 && sb_api_credential_verify(first, loaded));
    assert(!sb_api_credential_verify(second, loaded));
    assert(!sb_api_credential_verify("short", loaded));

    // A failed store/commit leaves the old record authoritative across restart.
    assert(sb_api_credential_encode(2, second, candidate, hash));
    assert(sb_api_credential_decode(committed, sizeof committed, &generation, loaded));
    assert(generation == 1 && sb_api_credential_verify(first, loaded));
    memcpy(committed, candidate, sizeof committed); // simulated successful commit
    assert(sb_api_credential_decode(committed, sizeof committed, &generation, loaded));
    assert(generation == 2 && !sb_api_credential_verify(first, loaded));
    assert(sb_api_credential_verify(second, loaded));

    assert(!sb_api_credential_decode(committed, sizeof committed - 1, &generation, loaded));
    candidate[0] ^= 1;
    assert(!sb_api_credential_decode(candidate, sizeof candidate, &generation, loaded));
    candidate[0] ^= 1;
    candidate[4] ^= 1;
    assert(!sb_api_credential_decode(candidate, sizeof candidate, &generation, loaded));
    assert(!sb_api_credential_encode(0, first, candidate, hash));
}

static void resume_boundaries(void)
{
    // After a snapshot watermark, all subsequent stream events must be replayed.
    assert(sb_api_can_resume(42, 42, 50, 51, 54));
    assert(sb_api_can_resume(42, 42, 54, 51, 54));
    assert(!sb_api_can_resume(42, 41, 50, 51, 54)); // hub restart
    assert(!sb_api_can_resume(42, 42, 55, 51, 54)); // future sequence
    assert(!sb_api_can_resume(42, 42, 49, 51, 54)); // ring eviction
    assert(sb_api_can_resume(42, 42, 0, 1, 0));   // empty stream
    assert(!sb_api_can_resume(43, 42, 0, 1, 0));
    // 64-event ring containing 65..128: resume 64 works, 63 requires snapshot.
    assert(sb_api_can_resume(42, 42, 64, 65, 128));
    assert(!sb_api_can_resume(42, 42, 63, 65, 128));
}

static void malformed_client(void)
{
    static const char *valid = "{\"op\":\"node.get\",\"slot\":0} \n";
    cJSON *request = sb_api_parse_request((const uint8_t *)valid, strlen(valid));
    assert(request);
    cJSON_Delete(request);

    const char *bad[] = {
        "{\"op\":\"pair.close\"}garbage",
        "{\"op\":true}",
        "{\"slot\":0}",
        "[\"pair.close\"]",
        "{\"op\":\"node.get\"",
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++)
        assert(!sb_api_parse_request((const uint8_t *)bad[i], strlen(bad[i])));
    uint8_t oversized[SB_API_MAX_INBOUND + 1];
    memset(oversized, ' ', sizeof oversized);
    assert(!sb_api_parse_request(oversized, sizeof oversized));
    static const uint8_t embedded_nul[] = {'{', '"', 'o', 'p', '"', ':', '"', 'x', '"', '}', 0};
    assert(!sb_api_parse_request(embedded_nul, sizeof embedded_nul));
}

int main(void)
{
    credential_lifecycle();
    resume_boundaries();
    malformed_client();
    puts("API logic tests passed");
    return 0;
}
