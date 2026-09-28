#pragma once

#include "esp_err.h"
#include "sb_crypto.h"
#include "sb_hub.h"
#include "sb_radio.h"

#define SB_HUB_APP_API_QUEUE_LEN 8
#define SB_HUB_APP_STREAM_CAP 64

typedef struct {
    uint8_t len;
    char text[SB_MAX_STR + 1];
} sb_hub_app_str_t;

typedef struct {
    uint8_t type;
    union {
        bool b;
        int32_t i;
        uint32_t u;
        float f;
        uint8_t e;
        sb_hub_app_str_t s;
    };
} sb_hub_app_value_t;

typedef struct {
    uint8_t entity, platform, value_type, state_class;
    int8_t accuracy;
    uint8_t flags;
    sb_hub_app_str_t object_id, name, unit, device_class, extra;
    sb_hub_app_value_t value;
} sb_hub_app_entity_t;

typedef struct {
    uint8_t slot, state, mac[6], epoch;
    uint32_t generation;
    uint64_t node_id;
    bool available;
    uint64_t last_seen_ms;
    int8_t rssi;
    uint16_t report_interval_s;
    uint8_t boot_reason;
    bool has_schema;
    uint32_t schema_hash;
    sb_hub_app_str_t node_name, model, fw_version;
    uint8_t entity_count;
    sb_hub_app_entity_t entities[SB_MAX_ENTITIES];
} sb_hub_app_node_t;

typedef struct {
    uint64_t seq;
    uint8_t kind, slot, entity, etype, pair;
    bool available, tombstone;
    uint64_t node_id;
    uint32_t generation;
    bool has_value;
    sb_hub_app_value_t value;
    char event_id[SB_HUB_EVENT_ID_LEN];
} sb_hub_app_event_t;

typedef enum {
    SB_HUB_APP_INFO,
    SB_HUB_APP_STATS,
    SB_HUB_APP_NODE_GET,
    SB_HUB_APP_NODE_ADD,
    SB_HUB_APP_NODE_REMOVE,
    SB_HUB_APP_PAIR_OPEN,
    SB_HUB_APP_PAIR_CLOSE,
    SB_HUB_APP_STREAM_FETCH,
} sb_hub_app_api_op_t;

typedef struct {
    uint8_t op;
    int8_t slot;
    uint32_t duration_ms;
    uint32_t stream_epoch;
    uint64_t after_seq;
} sb_hub_app_api_request_t;

typedef struct {
    int result; // 0 or SB_HUB_ERR_*; transport errors are returned by sb_hub_app_api().
    union {
        struct {
            char hub_id[24];
            uint32_t hub_boot, stream_epoch;
            uint64_t stream_seq;
            uint8_t channel, node_count, max_nodes;
        } info;
        sb_hub_stats_t stats;
        struct {
            bool found;
            sb_hub_app_node_t node;
        } node;
        struct {
            uint8_t key[SB_KEY_LEN];
            sb_hub_app_node_t node;
        } added;
        struct {
            bool resync_required;
            uint32_t stream_epoch;
            uint64_t latest_seq;
            uint8_t count;
            sb_hub_app_event_t events[SB_HUB_APP_STREAM_CAP];
        } stream;
    };
} sb_hub_app_api_response_t;

// Starts the serialized hub owner, durable NVS adapter, and C6 radio bridge.
esp_err_t sb_hub_app_start(const sb_radio_cfg_t *radio_cfg);

// Thread-safe synchronous bridge. The request is copied before it is queued;
// the caller's buffers are never retained by the hub task.
esp_err_t sb_hub_app_api(const sb_hub_app_api_request_t *request,
                         sb_hub_app_api_response_t *response);
