#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cJSON.h"

#define SB_API_CRED_LEN 44
#define SB_API_TOKEN_LEN 43
#define SB_API_MAX_INBOUND 2048

// Versioned credential record; no raw bearer token is persisted.
bool sb_api_credential_decode(const uint8_t *record, size_t len, uint32_t *generation,
                              uint8_t hash[32]);
bool sb_api_credential_encode(uint32_t generation, const char *token,
                              uint8_t record[SB_API_CRED_LEN], uint8_t hash[32]);
bool sb_api_credential_verify(const char *token, const uint8_t hash[32]);

// `oldest` is the earliest retained event, or latest+1 for an empty ring.
bool sb_api_can_resume(uint32_t epoch, uint32_t requested_epoch, uint64_t after,
                       uint64_t oldest, uint64_t latest);

// Accept one complete bounded JSON object with an operation name; caller owns it.
cJSON *sb_api_parse_request(const uint8_t *payload, size_t len);
