// Server Buddy radio protocol v1 codec. Spec: docs/PROTOCOL.md.
// Pure C11, no allocation. Decoded strings/data point into the input buffer,
// which must outlive the decoded struct.
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SB_VERSION 1
#define SB_HEADER_LEN 16
#define SB_MAX_FRAME 250
#define SB_MIC_LEN 8
#define SB_MAX_PAYLOAD (SB_MAX_FRAME - SB_HEADER_LEN - SB_MIC_LEN)
#define SB_MAX_STR 64
#define SB_MAX_STATE_ENTRIES 32
#define SB_MAX_DESCRIBE_CHUNKS 10
#define SB_DESCRIBE_HDR 9
#define SB_MAX_DESCRIBE_DATA (SB_MAX_PAYLOAD - SB_DESCRIBE_HDR)
#define SB_MAX_SCHEMA 2048
#define SB_MAX_ENTITIES 32
#define SB_MAX_OBJECT_ID 32

#define SB_FLAG_ACK_REQ 0x01
#define SB_FLAG_FULL_STATE 0x02

typedef enum {
    SB_OK = 0,
    SB_ERR_TOO_LARGE = 1,
    SB_ERR_TRUNCATED = 2,
    SB_ERR_BAD_MAGIC = 3,
    SB_ERR_BAD_VERSION = 4,
    SB_ERR_BAD_LENGTH = 5,
    SB_ERR_BAD_FLAGS = 6,
    SB_ERR_BAD_TYPE = 7,
    SB_ERR_UNSUPPORTED = 8,
    SB_ERR_BAD_VALUE = 9,
    SB_ERR_BAD_STRING = 10,
    SB_ERR_NO_SPACE = 11, // encoder output buffer too small (not a wire error)
} sb_err_t;

typedef enum {
    SB_MSG_HELLO = 0x01,
    SB_MSG_DESCRIBE = 0x02,
    SB_MSG_STATE = 0x03,
    SB_MSG_EVENT = 0x04,
    SB_MSG_ACK = 0x05,
    SB_MSG_COMMAND = 0x06, // reserved in v1
    SB_MSG_PAIR_REQUEST = 0x07,
    SB_MSG_PAIR_RESPONSE = 0x08,
    SB_MSG_HEARTBEAT = 0x09,
    SB_MSG_ERROR = 0x0A,
} sb_msg_type_t;

typedef enum {
    SB_V_NONE = 0,
    SB_V_BOOL = 1,
    SB_V_I32 = 2,
    SB_V_U32 = 3,
    SB_V_F32 = 4,
    SB_V_ENUM = 5,
    SB_V_STR = 6,
} sb_vtype_t;

typedef enum {
    SB_ACK_OK = 0,
    SB_ACK_DUPLICATE = 1,
    SB_ACK_NEED_DESCRIBE = 2,
    SB_ACK_NEW_BOOT = 3,
    SB_ACK_MALFORMED = 4,
    SB_ACK_BUSY = 5,
} sb_ack_status_t;

typedef enum { SB_PAIR_ACCEPTED = 0, SB_PAIR_HUB_FULL = 1 } sb_pair_status_t;

typedef struct {
    const uint8_t *p;
    uint8_t len;
} sb_str_t;

typedef struct {
    uint8_t type; // sb_vtype_t
    union {
        bool b;
        int32_t i;
        uint32_t u;
        float f;
        uint8_t e;
        sb_str_t s;
    };
} sb_value_t;

typedef struct {
    uint8_t entity;
    sb_value_t value;
} sb_state_entry_t;

// Payload structs are tagged and declared outside the union so the header is
// valid ISO C++ (ESPHome consumers).
typedef struct {
    uint32_t schema_hash;
    uint16_t interval;
    uint8_t reason;
    uint8_t hflags;
} sb_hello_t;

typedef struct {
    uint8_t xfer, index, count;
    uint16_t total;
    uint32_t hash;
    const uint8_t *data;
    uint8_t data_len;
} sb_describe_t;

typedef struct {
    uint8_t n;
    sb_state_entry_t e[SB_MAX_STATE_ENTRIES];
} sb_state_t;

typedef struct {
    uint8_t entity, etype;
    uint32_t oboot; // origin boot: fixed at event creation, kept across resends
    uint16_t evno;
    sb_value_t value;
} sb_event_t;

typedef struct {
    uint32_t aboot, aseq;
    uint8_t status, channel;
    uint32_t time;
} sb_ack_t;

typedef struct {
    uint8_t key_id[4], mac[6], nonce[16], tag[16];
} sb_pair_req_t;

typedef struct {
    uint8_t status, mac[6], nonce[16], channel, pepoch, tag[16];
} sb_pair_resp_t;

typedef struct {
    uint8_t code;
    sb_str_t detail;
} sb_error_t;

typedef struct {
    uint8_t type; // sb_msg_type_t
    uint8_t flags;
    uint8_t epoch;
    uint32_t boot;
    uint32_t seq;
    uint8_t mic[SB_MIC_LEN]; // trailing MIC as received/to send; unused for pairing
    union {
        sb_hello_t hello;
        sb_describe_t describe;
        sb_state_t state;
        sb_event_t event;
        sb_ack_t ack;
        sb_pair_req_t pair_req;
        sb_pair_resp_t pair_resp;
        sb_error_t error;
    } u;
} sb_frame_t;

typedef struct {
    uint8_t entity, platform, value_type, state_class;
    int8_t accuracy;
    uint8_t flags;
    sb_str_t object_id, name, unit, device_class, extra;
} sb_entity_t;

typedef struct {
    sb_str_t node_name, model, fw_version;
    uint8_t n;
    sb_entity_t e[SB_MAX_ENTITIES];
} sb_schema_t;

// True for types that carry a trailing MIC (everything except pairing).
bool sb_has_mic(uint8_t type);

// Structural decode only; verify the MIC with sb_mic_verify() first.
sb_err_t sb_decode(const uint8_t *buf, size_t len, sb_frame_t *out);
// Encodes (copying f->mic verbatim; seal afterwards with sb_mic_seal), then
// re-decodes the output so invalid frames are never emitted.
// Stack use ~0.5 KB: never call from the ESP-NOW/Wi-Fi callback.
sb_err_t sb_encode(const sb_frame_t *f, uint8_t *out, size_t cap, size_t *out_len);

sb_err_t sb_decode_schema(const uint8_t *buf, size_t len, sb_schema_t *out);
sb_err_t sb_encode_schema(const sb_schema_t *s, uint8_t *out, size_t cap, size_t *out_len);

const char *sb_err_name(sb_err_t err);
const char *sb_msg_name(uint8_t type);

// Canonical text form shared with the Python reference (tests, logs).
// Returns false if the buffer is too small.
bool sb_describe(const sb_frame_t *f, char *buf, size_t cap);
bool sb_describe_schema(const sb_schema_t *s, char *buf, size_t cap);

// Strict UTF-8 check (no overlongs, surrogates, > U+10FFFF, or NUL).
bool sb_utf8_valid(const uint8_t *p, size_t len);

#ifdef __cplusplus
}
#endif
