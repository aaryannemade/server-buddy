// P4 <-> C6 control/data link carried over ESP-Hosted "peer data" messages.
// Both ends are little-endian RISC-V built with the same toolchain, so packed
// structs are used directly. Bump SB_LINK_VERSION on any layout change.
#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SB_LINK_VERSION 2
#define SB_LINK_MAX_FRAME 250 // ESP-NOW v1 payload limit (see docs/PROTOCOL.md)

// Message IDs (ESP-Hosted peer-data msg_id space). H2C: P4 -> C6, C2H: C6 -> P4.
#define SB_LINK_ID(n) (0x53420000u | (n))
enum {
    SB_LINK_H2C_CONFIG = SB_LINK_ID(0x01),
    SB_LINK_H2C_SEND = SB_LINK_ID(0x02),
    SB_LINK_H2C_PEER_ADD = SB_LINK_ID(0x03),
    SB_LINK_H2C_PEER_DEL = SB_LINK_ID(0x04),
    SB_LINK_H2C_GET_STATUS = SB_LINK_ID(0x05),
    SB_LINK_H2C_RESTART = SB_LINK_ID(0x06), // C6 esp_restart(); P4 recovery path

    SB_LINK_C2H_STATUS = SB_LINK_ID(0x81),
    SB_LINK_C2H_RX = SB_LINK_ID(0x82),
    SB_LINK_C2H_SEND_DONE = SB_LINK_ID(0x83),
    SB_LINK_C2H_RESULT = SB_LINK_ID(0x84),
};

typedef struct __attribute__((packed)) {
    uint8_t ver;
    uint8_t channel;    // 1..14, must be legal for `country`
    char country[3];    // e.g. "GB\0"; "01" = world-safe (1..11)
    uint8_t pmk[16];    // ESP-NOW PMK (non-secret, see docs/SECURITY.md)
} sb_link_config_t;

typedef struct __attribute__((packed)) {
    uint8_t ver;
    uint8_t mac[6];
    uint32_t token; // echoed in SEND_DONE
    uint16_t len;
    uint8_t data[]; // len <= SB_LINK_MAX_FRAME
} sb_link_send_t;

typedef struct __attribute__((packed)) {
    uint8_t ver;
    uint8_t mac[6];
    uint8_t encrypt; // 1: use lmk
    uint8_t lmk[16];
    uint32_t token; // echoed in RESULT
} sb_link_peer_t;

typedef struct __attribute__((packed)) {
    uint8_t ver;
    uint8_t radio_up;
    uint8_t channel; // actual channel read back from the radio
    char country[3];
    uint8_t mac[6]; // C6 STA MAC (ESP-NOW source address)
    uint32_t uptime_s;
    uint32_t rx, rx_drop, tx, tx_fail, tx_drop;
    uint32_t heap_min;
    uint16_t queue_high_water;
    uint8_t peers;
} sb_link_status_t;

typedef struct __attribute__((packed)) {
    uint8_t ver;
    uint8_t mac[6];
    int8_t rssi;
    uint8_t channel;
    uint16_t len;
    uint8_t data[];
} sb_link_rx_t;

typedef struct __attribute__((packed)) {
    uint8_t ver;
    uint8_t mac[6];
    uint8_t ok; // MAC-level delivery (unicast: ACKed; broadcast: always 1)
    uint32_t token;
} sb_link_send_done_t;

typedef struct __attribute__((packed)) {
    uint8_t ver;
    uint32_t req_id; // the H2C message this answers
    uint32_t token;  // peer/send operation token; 0 for uncorrelated requests
    int32_t err;     // esp_err_t
} sb_link_result_t;

#ifdef __cplusplus
}
#endif
