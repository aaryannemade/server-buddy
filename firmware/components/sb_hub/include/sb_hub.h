// Server Buddy hub core: node registry, pairing, MIC + replay checks, schema
// (DESCRIBE) reassembly, retained state, events and availability.
// Pure C, platform-agnostic via sb_hub_ops_t, NOT thread-safe: callers must
// serialise every sb_hub_* call. Spec: docs/PROTOCOL.md, docs/SECURITY.md.
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "sb_protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SB_HUB_MAX_NODES 17 // native ESP-NOW encrypted-peer limit
#define SB_HUB_PAIR_WINDOW_MS 120000
#define SB_HUB_PAIR_CONFIRM_MS 10000
#define SB_HUB_DESCRIBE_TIMEOUT_MS 5000
#define SB_HUB_EVENT_DEDUPE 32
#define SB_HUB_EVENT_ID_LEN 80

enum { SB_HUB_ERR_FULL = -1, SB_HUB_ERR_INVALID = -2, SB_HUB_ERR_STORE = -3 };

typedef enum { SB_NODE_EMPTY = 0, SB_NODE_KEY_ONLY = 1, SB_NODE_ENROLLED = 2 } sb_node_state_t;

typedef enum {
    SB_EVT_NODE,       // registry/schema change for `slot` (incl. removal)
    SB_EVT_STATE,      // `entity` of `slot` has a new `value`
    SB_EVT_EVENT,      // transient event (`entity`, `etype`, `value`, `event_id`)
    SB_EVT_AVAIL,      // `available` changed
    SB_EVT_PAIR,       // `pair` (sb_pair_evt_t); slot 0xFF = window for any new node
    SB_EVT_NODE_ERROR, // node sent ERROR (`etype` = code)
} sb_hub_evt_kind_t;

typedef enum {
    SB_PAIR_OPENED,
    SB_PAIR_RESPONDED,
    SB_PAIR_DONE,
    SB_PAIR_FAILED,
    SB_PAIR_CLOSED,
} sb_pair_evt_t;

typedef struct sb_hub_evt {
    uint8_t kind, slot, entity, etype, pair;
    bool available;
    bool tombstone;         // node removal; identity remains valid
    uint64_t node_id;       // 0 for events not associated with a node
    uint32_t generation;
    const sb_value_t *value; // valid only during the callback
    const char *event_id;    // SB_EVT_EVENT only
} sb_hub_evt_t;

typedef struct {
    void *ctx;
    uint64_t (*now_ms)(void *ctx);
    uint32_t (*unix_time)(void *ctx); // 0 if unknown
    void (*random)(void *ctx, uint8_t *buf, size_t len);
    // Returns 0 on success and a token later reported via sb_hub_on_send_done.
    int (*radio_send)(void *ctx, const uint8_t mac[6], const uint8_t *data, size_t len,
                      uint32_t *token);
    // Add or replace (add=true) / delete a peer. lmk == NULL: unencrypted.
    int (*radio_peer)(void *ctx, const uint8_t mac[6], bool add, const uint8_t *lmk);
    // Persistence. put/del return 0 on success; get returns bytes read or -1.
    int (*store_put)(void *ctx, const char *key, const void *data, size_t len);
    int (*store_get)(void *ctx, const char *key, void *data, size_t cap);
    int (*store_del)(void *ctx, const char *key);
    void (*emit)(void *ctx, const sb_hub_evt_t *evt);
} sb_hub_ops_t;

typedef struct {
    uint8_t hub_mac[6]; // C6 radio MAC (ESP-NOW source address)
    uint8_t channel;
    uint32_t hub_boot; // persisted hub boot counter (ACK header only)
    char hub_id[24];   // stable hub identifier used in event IDs
} sb_hub_cfg_t;

typedef struct {
    uint32_t rx, rx_unknown, rx_bad_mic, rx_malformed, rx_bad_epoch, rx_replay, rx_duplicate,
        rx_new_boot, acks, pair_ignored, pair_done, pair_failed, store_fail, node_errors;
} sb_hub_stats_t;

typedef struct {
    uint8_t state; // sb_node_state_t
    uint8_t mac[6];
    uint8_t epoch;
    uint32_t generation;
    uint64_t node_id;
    bool available;
    uint64_t last_seen_ms;
    int8_t rssi;
    uint16_t report_interval_s;
    uint8_t boot_reason;
    bool has_schema;
    uint32_t schema_hash;
    const sb_schema_t *schema; // NULL without schema
    const sb_value_t *values;  // values[i] belongs to schema->e[i]
} sb_hub_node_view_t;

typedef struct sb_hub sb_hub_t;

// Loads persisted nodes. Call sb_hub_radio_ready() once the radio is up.
sb_hub_t *sb_hub_create(const sb_hub_cfg_t *cfg, const sb_hub_ops_t *ops);
void sb_hub_destroy(sb_hub_t *h);

// (Re)install all enrolled peers, e.g. after the C6 (re)starts.
void sb_hub_radio_ready(sb_hub_t *h);
void sb_hub_on_rx(sb_hub_t *h, const uint8_t mac[6], int8_t rssi, const uint8_t *data, size_t len);
void sb_hub_on_send_done(sb_hub_t *h, uint32_t token, bool ok);
// Timeouts (pairing, DESCRIBE, availability). Call about once per second.
void sb_hub_tick(sb_hub_t *h);

// Creates a key-only slot with a fresh node key and opens a targeted pairing
// window. Returns the slot or SB_HUB_ERR_*. `key_out` must be shown once.
int sb_hub_node_add(sb_hub_t *h, uint8_t key_out[16]);
int sb_hub_node_remove(sb_hub_t *h, int slot);
// slot >= 0: (re)pair that node only; slot < 0: any never-paired node.
int sb_hub_pair_open(sb_hub_t *h, int slot, uint32_t ms);
void sb_hub_pair_close(sb_hub_t *h);

bool sb_hub_node(const sb_hub_t *h, int slot, sb_hub_node_view_t *out);
sb_hub_stats_t sb_hub_stats(const sb_hub_t *h);

#ifdef __cplusplus
}
#endif
