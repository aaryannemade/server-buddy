// Server Buddy hub core. See include/sb_hub.h and docs/PROTOCOL.md,
// docs/SECURITY.md. Not thread-safe: serialise all sb_hub_* calls.
#include "sb_hub.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sb_crypto.h"

#define STORE_REC_VER 2
#define STORE_SCHEMA_VER 1
#define CHUNK SB_MAX_DESCRIBE_DATA // all DESCRIBE chunks but the last are this size

typedef struct {
    uint32_t origin_boot;
    uint16_t evno;
} ev_ring_t;

typedef struct {
    uint8_t state; // sb_node_state_t
    uint8_t mac[6];
    uint8_t key_id[SB_KEY_ID_LEN];
    uint8_t k_node[SB_KEY_LEN];
    uint8_t epoch;
    uint8_t lmk[SB_LMK_LEN], k_mic[SB_KMIC_LEN];
    uint32_t generation;
    uint64_t node_id;
    // replay
    uint32_t last_boot, last_seq;
    bool seq_valid;
    uint8_t ack_status; // status of the last accepted frame (re-ACK for dups)
    // session
    uint16_t report_interval_s;
    uint8_t boot_reason;
    uint64_t last_seen_ms;
    int8_t rssi;
    bool available;
    uint64_t peer_retry_ms;
    uint32_t errors;
    // schema + retained values
    uint8_t *schema_blob;
    size_t schema_len;
    bool has_schema;
    uint32_t schema_hash;
    sb_schema_t *schema; // entity strings point into schema_blob
    sb_value_t *values;
    char (*vstrs)[SB_MAX_STR + 1];
    // DESCRIBE transfer in progress
    uint8_t *stage;
    uint8_t xfer, count;
    uint16_t total;
    uint32_t hash;
    uint16_t got_mask;
    uint64_t progress_ms;
    // event dedupe
    ev_ring_t ring[SB_HUB_EVENT_DEDUPE];
    uint8_t ring_head, ring_len;
} node_t;

typedef struct __attribute__((packed)) {
    uint8_t ver, state;
    uint8_t mac[6];
    uint8_t k_node[SB_KEY_LEN];
    uint8_t epoch;
    uint8_t lmk[SB_LMK_LEN], k_mic[SB_KMIC_LEN];
    uint32_t generation;
    uint32_t last_boot;
    uint64_t node_id;
    uint16_t report_interval_s; // v2: availability must survive hub restarts
} node_rec_t;

typedef struct __attribute__((packed)) {
    uint8_t ver;
    uint64_t node_id;
    uint32_t generation;
    uint16_t blob_len;
    uint32_t hash;
} schema_rec_t;

struct sb_hub {
    sb_hub_cfg_t cfg;
    sb_hub_ops_t ops;
    node_t n[SB_HUB_MAX_NODES];
    struct {
        bool active, peer_installed, token_valid;
        uint8_t slot;
        uint8_t mac[6];
        uint8_t hub_nonce[SB_NONCE_LEN], node_nonce[SB_NONCE_LEN];
        uint8_t epoch, lmk[SB_LMK_LEN], k_mic[SB_KMIC_LEN];
        uint32_t token;
        uint64_t confirm_deadline_ms;
    } pair;
    uint64_t pair_window_deadline_ms;
    int8_t pair_window_slot; // -1: any never-paired node
    uint32_t hub_seq;
    uint8_t cleanup_len;
    uint8_t cleanup_mac[SB_HUB_MAX_NODES][6];
    char event_id[SB_HUB_EVENT_ID_LEN];
    sb_hub_stats_t stats;
};

// ------------------------------------------------------------------ helpers

static uint64_t now_ms(const sb_hub_t *h) { return h->ops.now_ms(h->ops.ctx); }

static void event_identity(const sb_hub_t *h, uint8_t slot, sb_hub_evt_t *e)
{
    if (slot >= SB_HUB_MAX_NODES || h->n[slot].state == SB_NODE_EMPTY) return;
    e->node_id = h->n[slot].node_id;
    e->generation = h->n[slot].generation;
}

static void emit(sb_hub_t *h, uint8_t kind, uint8_t slot)
{
    sb_hub_evt_t e = {.kind = kind, .slot = slot};
    event_identity(h, slot, &e);
    h->ops.emit(h->ops.ctx, &e);
}

static void emit_state(sb_hub_t *h, uint8_t slot, uint8_t entity, const sb_value_t *v)
{
    sb_hub_evt_t e = {.kind = SB_EVT_STATE, .slot = slot, .entity = entity, .value = v};
    event_identity(h, slot, &e);
    h->ops.emit(h->ops.ctx, &e);
}

static void emit_avail(sb_hub_t *h, uint8_t slot, bool available)
{
    sb_hub_evt_t e = {.kind = SB_EVT_AVAIL, .slot = slot, .available = available};
    event_identity(h, slot, &e);
    h->ops.emit(h->ops.ctx, &e);
}

static void set_available(sb_hub_t *h, uint8_t slot, node_t *n, bool available)
{
    if (n->available != available) {
        n->available = available;
        emit_avail(h, slot, available);
    }
}

static void ring_reset(node_t *n)
{
    memset(n->ring, 0, sizeof n->ring);
    n->ring_head = 0;
    n->ring_len = 0;
}

static void emit_pair(sb_hub_t *h, uint8_t pair, uint8_t slot)
{
    sb_hub_evt_t e = {.kind = SB_EVT_PAIR, .pair = pair, .slot = slot};
    event_identity(h, slot, &e);
    h->ops.emit(h->ops.ctx, &e);
}

static void emit_node_error(sb_hub_t *h, uint8_t slot, uint8_t code)
{
    sb_hub_evt_t e = {.kind = SB_EVT_NODE_ERROR, .slot = slot, .etype = code};
    event_identity(h, slot, &e);
    h->ops.emit(h->ops.ctx, &e);
}

static void store_key(char *buf, size_t cap, int slot, bool schema)
{
    snprintf(buf, cap, "sb/%c%d", schema ? 's' : 'n', (unsigned)slot);
}

static int save_node(sb_hub_t *h, node_t *n, int slot)
{
    node_rec_t r = {
        .ver = STORE_REC_VER,
        .state = n->state,
        .epoch = n->epoch,
        .generation = n->generation,
        .last_boot = n->last_boot,
        .node_id = n->node_id,
    };
    memcpy(r.mac, n->mac, 6);
    memcpy(r.k_node, n->k_node, SB_KEY_LEN);
    memcpy(r.lmk, n->lmk, SB_LMK_LEN);
    memcpy(r.k_mic, n->k_mic, SB_KMIC_LEN);
    r.report_interval_s = n->report_interval_s;
    char key[16];
    store_key(key, sizeof key, slot, false);
    int rc = h->ops.store_put(h->ops.ctx, key, &r, sizeof r);
    if (rc != 0) h->stats.store_fail++;
    return rc;
}

static void clear_schema(node_t *n)
{
    free(n->schema_blob);
    free(n->schema);
    free(n->values);
    free(n->vstrs);
    n->schema_blob = NULL;
    n->schema_len = 0;
    n->schema = NULL;
    n->values = NULL;
    n->vstrs = NULL;
    n->has_schema = false;
    n->schema_hash = 0;
}

// Consumes `blob`. A received schema is made visible only after its NVS write
// succeeds, so SB_ACK_OK always means the schema survives a hub restart.
static bool install_schema(sb_hub_t *h, node_t *n, uint8_t slot, uint8_t *blob, size_t len,
                           bool persist)
{
    sb_schema_t *schema = malloc(sizeof *schema);
    sb_value_t *values = NULL;
    char (*vstrs)[SB_MAX_STR + 1] = NULL;
    sb_schema_t tmp;
    bool ok = blob && len > 0 && len <= SB_MAX_SCHEMA && schema &&
              sb_decode_schema(blob, len, &tmp) == SB_OK;
    if (ok) {
        *schema = tmp;
        values = calloc(schema->n, sizeof *values);
        vstrs = calloc(schema->n, sizeof *vstrs);
        ok = values && vstrs;
        for (uint8_t i = 0; ok && i < schema->n; i++) values[i].type = SB_V_NONE;
    }
    uint32_t hh = 0;
    if (ok && !sb_schema_hash(blob, len, &hh)) ok = false;
    if (ok && persist) {
        size_t rec_len = sizeof(schema_rec_t) + len;
        uint8_t *record = malloc(rec_len);
        schema_rec_t header = {
            .ver = STORE_SCHEMA_VER,
            .node_id = n->node_id,
            .generation = n->generation,
            .blob_len = (uint16_t)len,
            .hash = hh,
        };
        if (record) {
            memcpy(record, &header, sizeof header);
            memcpy(record + sizeof header, blob, len);
        }
        char key[16];
        store_key(key, sizeof key, slot, true);
        if (!record || h->ops.store_put(h->ops.ctx, key, record, rec_len) != 0) {
            h->stats.store_fail++;
            ok = false;
        }
        free(record);
    }
    if (!ok) {
        free(blob);
        free(schema);
        free(values);
        free(vstrs);
        return false;
    }

    clear_schema(n);
    n->schema_blob = blob;
    n->schema_len = len;
    n->schema = schema;
    n->values = values;
    n->vstrs = vstrs;
    n->has_schema = true;
    n->schema_hash = hh;
    emit(h, SB_EVT_NODE, slot);
    return true;
}

static int ent_idx(const node_t *n, uint8_t entity)
{
    if (!n->schema) return -1;
    for (uint8_t i = 0; i < n->schema->n; i++)
        if (n->schema->e[i].entity == entity) return i;
    return -1;
}

static uint8_t event_type_count(const sb_entity_t *e)
{
    if (!e->extra.len) return 0;
    uint8_t c = 1;
    for (uint8_t i = 0; i < e->extra.len; i++)
        if (e->extra.p[i] == ',') c++;
    return c;
}

static bool ring_has(const node_t *n, uint32_t ob, uint16_t ev)
{
    for (uint8_t i = 0; i < n->ring_len; i++)
        if (n->ring[i].origin_boot == ob && n->ring[i].evno == ev) return true;
    return false;
}

// ------------------------------------------------------------------ ack/pair

static void send_ack(sb_hub_t *h, const uint8_t mac[6], uint8_t epoch,
                     const uint8_t k_mic[SB_KMIC_LEN], uint32_t aboot, uint32_t aseq,
                     uint8_t status)
{
    sb_frame_t f = {
        .type = SB_MSG_ACK,
        .epoch = epoch,
        .boot = h->cfg.hub_boot,
        .seq = ++h->hub_seq,
    };
    f.u.ack.aboot = aboot;
    f.u.ack.aseq = aseq;
    f.u.ack.status = status;
    f.u.ack.channel = h->cfg.channel;
    f.u.ack.time = h->ops.unix_time ? h->ops.unix_time(h->ops.ctx) : 0;
    uint8_t buf[SB_MAX_FRAME];
    size_t len = 0;
    if (sb_encode(&f, buf, sizeof buf, &len) != SB_OK) return;
    if (!sb_mic_seal(k_mic, SB_DIR_HUB_TO_NODE, buf, len)) return;
    h->ops.radio_send(h->ops.ctx, mac, buf, len, NULL);
    h->stats.acks++;
}

static void schedule_cleanup(sb_hub_t *h, const uint8_t mac[6])
{
    for (uint8_t i = 0; i < h->cleanup_len; i++)
        if (memcmp(h->cleanup_mac[i], mac, 6) == 0) return;
    if (h->cleanup_len < SB_HUB_MAX_NODES)
        memcpy(h->cleanup_mac[h->cleanup_len++], mac, 6);
}

static void restore_peer(sb_hub_t *h, node_t *n)
{
    if (n->state == SB_NODE_ENROLLED) {
        if (memcmp(n->mac, h->pair.mac, 6) != 0)
            if (h->ops.radio_peer(h->ops.ctx, h->pair.mac, false, NULL) != 0)
                schedule_cleanup(h, h->pair.mac);
        if (h->ops.radio_peer(h->ops.ctx, n->mac, true, n->lmk) != 0)
            n->peer_retry_ms = now_ms(h) + 1000;
    } else {
        if (h->ops.radio_peer(h->ops.ctx, h->pair.mac, false, NULL) != 0)
            schedule_cleanup(h, h->pair.mac);
    }
}

static void pair_roll_back(sb_hub_t *h)
{
    if (!h->pair.active) return;
    node_t *n = &h->n[h->pair.slot];
    restore_peer(h, n);
    emit_pair(h, SB_PAIR_FAILED, h->pair.slot);
    h->stats.pair_failed++;
    h->pair.active = false;
}

// Commit on a valid HELLO. Returns false (and rolls back) if the record
// cannot be persisted: an unpersisted commit would orphan the node after a
// hub restart (docs/SECURITY.md).
static bool pair_commit(sb_hub_t *h, node_t *n, const sb_frame_t *hello, uint8_t *status)
{
    node_t old = *n;

    if (n->state == SB_NODE_ENROLLED && memcmp(n->mac, h->pair.mac, 6) != 0 &&
        h->ops.radio_peer(h->ops.ctx, n->mac, false, NULL) != 0)
        schedule_cleanup(h, n->mac);
    n->state = SB_NODE_ENROLLED;
    memcpy(n->mac, h->pair.mac, 6);
    memcpy(n->lmk, h->pair.lmk, SB_LMK_LEN);
    memcpy(n->k_mic, h->pair.k_mic, SB_KMIC_LEN);
    n->epoch = h->pair.epoch;
    n->generation++;
    n->last_boot = n->last_seq = 0;
    n->seq_valid = false;
    n->ack_status = SB_ACK_OK;
    ring_reset(n);
    n->last_seen_ms = now_ms(h);
    n->report_interval_s = hello->u.hello.interval;
    n->boot_reason = hello->u.hello.reason;
    n->last_boot = hello->boot;
    n->last_seq = hello->seq;
    n->seq_valid = true;
    *status = SB_ACK_NEED_DESCRIBE;
    n->ack_status = *status;

    if (!h->pair.peer_installed) {
        if (h->ops.radio_peer(h->ops.ctx, n->mac, true, n->lmk) != 0) {
            *n = old;
            restore_peer(h, n);
            emit_pair(h, SB_PAIR_FAILED, h->pair.slot);
            h->stats.pair_failed++;
            h->pair.active = false;
            return false;
        }
        h->pair.peer_installed = true;
    }

    if (save_node(h, n, h->pair.slot) != 0) {
        *n = old;
        restore_peer(h, n);
        emit_pair(h, SB_PAIR_FAILED, h->pair.slot);
        h->stats.pair_failed++;
        h->pair.active = false;
        return false;
    }
    clear_schema(n);
    free(n->stage);
    n->stage = NULL;
    h->pair_window_deadline_ms = 0;
    h->pair_window_slot = -1;
    emit_pair(h, SB_PAIR_CLOSED, 0xFF);
    emit_pair(h, SB_PAIR_DONE, h->pair.slot);
    set_available(h, h->pair.slot, n, true);
    emit(h, SB_EVT_NODE, h->pair.slot);
    h->stats.pair_done++;
    h->pair.active = false;
    return true;
}

// Send PAIR_RESPONSE for `slot` (or resend the identical response on retry).
static void pair_respond(sb_hub_t *h, int slot, const sb_frame_t *f, const uint8_t *mac)
{
    node_t *n = &h->n[slot];
    // A retry of the same exchange (same slot + nonce) must rebuild the exact
    // same keys, or the node's HELLO under the first response fails silently.
    bool retry = h->pair.active && h->pair.slot == (uint8_t)slot &&
                 memcmp(h->pair.mac, mac, 6) == 0 &&
                 memcmp(h->pair.node_nonce, f->u.pair_req.nonce, SB_NONCE_LEN) == 0;
    if (!retry) {
        h->pair.epoch = (uint8_t)(n->epoch + 1);
        if (h->pair.epoch == 0) h->pair.epoch = 1;
        h->ops.random(h->ops.ctx, h->pair.hub_nonce, SB_NONCE_LEN);
        if (!sb_session_keys(n->k_node, f->u.pair_req.nonce, h->pair.hub_nonce, mac,
                             h->cfg.hub_mac, h->pair.epoch, h->pair.lmk, h->pair.k_mic)) {
            h->stats.pair_ignored++;
            return;
        }
        memcpy(h->pair.node_nonce, f->u.pair_req.nonce, SB_NONCE_LEN);
    }
    uint8_t epoch = h->pair.epoch;

    sb_frame_t r = {.type = SB_MSG_PAIR_RESPONSE, .boot = h->cfg.hub_boot, .seq = ++h->hub_seq};
    r.u.pair_resp.status = SB_PAIR_ACCEPTED;
    memcpy(r.u.pair_resp.mac, h->cfg.hub_mac, 6);
    memcpy(r.u.pair_resp.nonce, h->pair.hub_nonce, SB_NONCE_LEN);
    r.u.pair_resp.channel = h->cfg.channel;
    r.u.pair_resp.pepoch = epoch;
    uint8_t buf[SB_MAX_FRAME];
    size_t len = 0;
    if (sb_encode(&r, buf, sizeof buf, &len) != SB_OK) return;
    // Tag covers node_nonce || frame-before-tag (buf is exactly that).
    uint8_t tag[SB_TAG_LEN];
    if (!sb_response_tag(n->k_node, f->u.pair_req.nonce, buf, len - SB_TAG_LEN, tag)) return;
    memcpy(buf + len - SB_TAG_LEN, tag, SB_TAG_LEN);

    // The node cannot decrypt yet: the peer must be plaintext for this send.
    // Free the C6 peer slot first if this slot re-pairs under a new MAC.
    if (h->pair.active && memcmp(h->pair.mac, mac, 6) != 0 &&
        h->ops.radio_peer(h->ops.ctx, h->pair.mac, false, NULL) != 0)
        schedule_cleanup(h, h->pair.mac);
    if (n->state == SB_NODE_ENROLLED && memcmp(n->mac, mac, 6) != 0) {
        if (h->ops.radio_peer(h->ops.ctx, n->mac, false, NULL) != 0)
            schedule_cleanup(h, n->mac);
    }
    h->pair.active = true;
    h->pair.peer_installed = false;
    h->pair.token_valid = false;
    h->pair.slot = (uint8_t)slot;
    memcpy(h->pair.mac, mac, 6);
    h->pair.confirm_deadline_ms = now_ms(h) + SB_HUB_PAIR_CONFIRM_MS;
    if (h->ops.radio_peer(h->ops.ctx, mac, true, NULL) != 0) {
        pair_roll_back(h);
        return;
    }
    if (h->ops.radio_send(h->ops.ctx, mac, buf, len, &h->pair.token) != 0) {
        pair_roll_back(h);
        return;
    }
    h->pair.token_valid = true;
    emit_pair(h, SB_PAIR_RESPONDED, slot);
}

static void on_pair_request(sb_hub_t *h, const uint8_t *mac, const uint8_t *data, size_t len)
{
    sb_frame_t f;
    if (sb_decode(data, len, &f) != SB_OK || memcmp(f.u.pair_req.mac, mac, 6) != 0) {
        h->stats.pair_ignored++;
        return;
    }
    uint64_t now = now_ms(h);
    if (!h->pair.active && (h->pair_window_deadline_ms == 0 || now >= h->pair_window_deadline_ms)) {
        h->stats.pair_ignored++;
        return;
    }
    // Find the candidate slot and verify its tag.
    int cand = -1;
    uint8_t tag[SB_TAG_LEN];
    for (int s = 0; s < SB_HUB_MAX_NODES; s++) {
        if (h->pair_window_slot >= 0 && s != h->pair_window_slot) continue;
        node_t *n = &h->n[s];
        if (h->pair_window_slot < 0 && n->state != SB_NODE_KEY_ONLY) continue;
        if (n->state == SB_NODE_EMPTY) continue;
        if (memcmp(n->key_id, f.u.pair_req.key_id, SB_KEY_ID_LEN) != 0) continue;
        if (!sb_request_tag(n->k_node, data, len - SB_TAG_LEN, tag)) continue;
        if (!sb_tag_equal(tag, f.u.pair_req.tag, SB_TAG_LEN)) continue;
        cand = s;
        break;
    }
    if (cand < 0) {
        h->stats.pair_ignored++;
        return;
    }
    // A MAC already enrolled in another slot would shadow that node's frames.
    for (int s = 0; s < SB_HUB_MAX_NODES; s++) {
        node_t *x = &h->n[s];
        if (s != cand && x->state == SB_NODE_ENROLLED && memcmp(x->mac, mac, 6) == 0) {
            h->stats.pair_ignored++;
            return;
        }
    }
    // One pairing at a time; the same node retrying restarts its exchange.
    if (h->pair.active && h->pair.slot != (uint8_t)cand) {
        h->stats.pair_ignored++;
        return;
    }
    pair_respond(h, cand, &f, mac);
}

// ------------------------------------------------------------------ frames

static uint8_t on_hello(sb_hub_t *h, node_t *n, const sb_frame_t *f)
{
    n->report_interval_s = f->u.hello.interval;
    n->boot_reason = f->u.hello.reason;
    if (!n->has_schema || n->schema_hash != f->u.hello.schema_hash) return SB_ACK_NEED_DESCRIBE;
    return SB_ACK_OK;
}

static uint8_t on_describe(sb_hub_t *h, node_t *n, uint8_t slot, const sb_frame_t *f)
{
    const sb_describe_t *d = &f->u.describe;
    uint16_t last = (uint16_t)(d->total % CHUNK);
    uint8_t expect_count = (uint8_t)((d->total + CHUNK - 1) / CHUNK);
    uint16_t expect_len = (uint16_t)(d->index + 1 == d->count ? (last ? last : CHUNK) : CHUNK);
    // Chunking is fixed: all chunks but the last are CHUNK bytes (docs/PROTOCOL.md).
    if (d->total < 1 || d->total > SB_MAX_SCHEMA || expect_count != d->count ||
        d->data_len != (uint8_t)expect_len)
        return SB_ACK_MALFORMED;

    if (!n->stage || n->xfer != d->xfer || n->total != d->total || n->hash != d->hash) {
        free(n->stage);
        n->stage = malloc(d->total);
        if (!n->stage) return SB_ACK_BUSY;
        n->xfer = d->xfer;
        n->total = d->total;
        n->hash = d->hash;
        n->count = d->count;
        n->got_mask = 0;
    }
    if (d->index >= n->count) return SB_ACK_MALFORMED;
    if (n->got_mask & (1u << d->index)) return SB_ACK_OK; // duplicate chunk
    memcpy(n->stage + (size_t)d->index * CHUNK, d->data, d->data_len);
    n->got_mask |= (uint16_t)(1u << d->index);
    n->progress_ms = now_ms(h);
    if (n->got_mask != (uint16_t)((1u << n->count) - 1)) return SB_ACK_OK;

    uint32_t hash;
    if (!sb_schema_hash(n->stage, n->total, &hash) || hash != n->hash) {
        free(n->stage);
        n->stage = NULL;
        return SB_ACK_MALFORMED;
    }
    sb_schema_t check;
    if (sb_decode_schema(n->stage, n->total, &check) != SB_OK) {
        free(n->stage);
        n->stage = NULL;
        return SB_ACK_MALFORMED;
    }
    uint8_t *blob = n->stage;
    n->stage = NULL;
    return install_schema(h, n, slot, blob, n->total, true) ? SB_ACK_OK : SB_ACK_BUSY;
}

static uint8_t on_state(sb_hub_t *h, node_t *n, uint8_t slot, const sb_frame_t *f)
{
    if (!n->schema) return SB_ACK_NEED_DESCRIBE;
    // Validate fully before applying any entry.
    for (uint8_t i = 0; i < f->u.state.n; i++) {
        int idx = ent_idx(n, f->u.state.e[i].entity);
        const sb_value_t *v = &f->u.state.e[i].value;
        if (idx < 0 || (v->type != SB_V_NONE && v->type != n->schema->e[idx].value_type))
            return SB_ACK_MALFORMED;
    }
    for (uint8_t i = 0; i < f->u.state.n; i++) {
        uint8_t entity = f->u.state.e[i].entity;
        int idx = ent_idx(n, entity);
        const sb_value_t *v = &f->u.state.e[i].value;
        n->values[idx] = *v;
        if (v->type == SB_V_STR) {
            memcpy(n->vstrs[idx], v->s.p, v->s.len);
            n->vstrs[idx][v->s.len] = 0;
            n->values[idx].s.p = (const uint8_t *)n->vstrs[idx];
            n->values[idx].s.len = v->s.len;
        }
        emit_state(h, slot, entity, &n->values[idx]);
    }
    return SB_ACK_OK;
}

static uint8_t on_event(sb_hub_t *h, node_t *n, uint8_t slot, const sb_frame_t *f)
{
    if (!n->schema) return SB_ACK_NEED_DESCRIBE;
    int idx = ent_idx(n, f->u.event.entity);
    if (idx < 0 || n->schema->e[idx].platform != 4 ||
        f->u.event.etype >= event_type_count(&n->schema->e[idx]))
        return SB_ACK_MALFORMED;
    const sb_value_t *v = &f->u.event.value;
    if (v->type != SB_V_NONE && v->type != n->schema->e[idx].value_type) return SB_ACK_MALFORMED;
    if (ring_has(n, f->u.event.oboot, f->u.event.evno)) {
        h->stats.rx_duplicate++;
        return SB_ACK_DUPLICATE;
    }
    n->ring[n->ring_head].origin_boot = f->u.event.oboot;
    n->ring[n->ring_head].evno = f->u.event.evno;
    n->ring_head = (uint8_t)((n->ring_head + 1) % SB_HUB_EVENT_DEDUPE);
    if (n->ring_len < SB_HUB_EVENT_DEDUPE) n->ring_len++;
    sb_value_t val = *v;
    if (v->type == SB_V_STR) {
        memcpy(n->vstrs[idx], v->s.p, v->s.len);
        n->vstrs[idx][v->s.len] = 0;
        val.s.p = (const uint8_t *)n->vstrs[idx];
    }
    snprintf(h->event_id, sizeof h->event_id, "%s-%012" PRIx64 "-%" PRIu32 "-%" PRIu32 "-%" PRIu16,
             h->cfg.hub_id, n->node_id, n->generation, f->u.event.oboot, f->u.event.evno);
    sb_hub_evt_t e = {
        .kind = SB_EVT_EVENT,
        .slot = slot,
        .entity = f->u.event.entity,
        .etype = f->u.event.etype,
        .value = &val,
        .event_id = h->event_id,
    };
    event_identity(h, slot, &e);
    h->ops.emit(h->ops.ctx, &e);
    return SB_ACK_OK;
}

// ------------------------------------------------------------------ public

sb_hub_t *sb_hub_create(const sb_hub_cfg_t *cfg, const sb_hub_ops_t *ops)
{
    if (!cfg || !ops || !ops->now_ms || !ops->random || !ops->radio_send || !ops->radio_peer ||
        !ops->store_put || !ops->store_get || !ops->store_del || !ops->emit)
        return NULL;
    sb_hub_t *h = calloc(1, sizeof *h);
    if (!h) return NULL;
    h->cfg = *cfg;
    h->cfg.hub_id[sizeof h->cfg.hub_id - 1] = 0; // must be NUL-terminated
    h->ops = *ops;
    h->pair_window_slot = -1;
    for (int s = 0; s < SB_HUB_MAX_NODES; s++) ring_reset(&h->n[s]);
    for (int s = 0; s < SB_HUB_MAX_NODES; s++) {
        char key[16];
        store_key(key, sizeof key, s, false);
        node_rec_t r;
        if (ops->store_get(ops->ctx, key, &r, sizeof r) != (int)sizeof r || r.ver != STORE_REC_VER)
            continue;
        if (r.state != SB_NODE_KEY_ONLY && r.state != SB_NODE_ENROLLED) continue;
        node_t *n = &h->n[s];
        n->state = r.state;
        memcpy(n->mac, r.mac, 6);
        memcpy(n->k_node, r.k_node, SB_KEY_LEN);
        n->epoch = r.epoch;
        memcpy(n->lmk, r.lmk, SB_LMK_LEN);
        memcpy(n->k_mic, r.k_mic, SB_KMIC_LEN);
        n->generation = r.generation;
        n->last_boot = r.last_boot;
        n->node_id = r.node_id;
        n->report_interval_s = r.report_interval_s;
        sb_key_id(n->k_node, n->key_id);
        if (n->state != SB_NODE_ENROLLED) continue;
        size_t cap = sizeof(schema_rec_t) + SB_MAX_SCHEMA;
        uint8_t *record = malloc(cap);
        if (!record) continue;
        store_key(key, sizeof key, s, true);
        int rec_len = ops->store_get(ops->ctx, key, record, cap);
        schema_rec_t header;
        bool valid = rec_len >= (int)sizeof header;
        if (valid) memcpy(&header, record, sizeof header);
        valid = valid && header.ver == STORE_SCHEMA_VER && header.node_id == n->node_id &&
                header.generation == n->generation && header.blob_len > 0 &&
                header.blob_len <= SB_MAX_SCHEMA &&
                rec_len == (int)(sizeof header + header.blob_len);
        uint32_t hash = 0;
        valid = valid && sb_schema_hash(record + sizeof header, header.blob_len, &hash) &&
                hash == header.hash;
        if (valid) {
            memmove(record, record + sizeof header, header.blob_len);
            install_schema(h, n, (uint8_t)s, record, header.blob_len, false);
        } else {
            free(record);
        }
    }
    return h;
}

void sb_hub_destroy(sb_hub_t *h)
{
    if (!h) return;
    for (int s = 0; s < SB_HUB_MAX_NODES; s++) {
        node_t *n = &h->n[s];
        clear_schema(n);
        free(n->stage);
    }
    free(h);
}

void sb_hub_radio_ready(sb_hub_t *h)
{
    pair_roll_back(h);
    h->cleanup_len = 0; // a restarted C6 has an empty peer table
    for (int s = 0; s < SB_HUB_MAX_NODES; s++) {
        node_t *n = &h->n[s];
        if (n->state != SB_NODE_ENROLLED) continue;
        n->peer_retry_ms = h->ops.radio_peer(h->ops.ctx, n->mac, true, n->lmk) == 0
                               ? 0
                               : now_ms(h) + 1000;
    }
}

void sb_hub_on_send_done(sb_hub_t *h, uint32_t token, bool ok)
{
    if (!h->pair.active || h->pair.peer_installed || !h->pair.token_valid ||
        token != h->pair.token)
        return;
    h->pair.token_valid = false;
    if (!ok || h->ops.radio_peer(h->ops.ctx, h->pair.mac, true, h->pair.lmk) != 0) {
        pair_roll_back(h);
        return;
    }
    h->pair.peer_installed = true;
}

void sb_hub_on_rx(sb_hub_t *h, const uint8_t mac[6], int8_t rssi, const uint8_t *data,
                  size_t len)
{
    h->stats.rx++;
    if (len > SB_MAX_FRAME) {
        h->stats.rx_malformed++;
        return;
    }
    sb_frame_t f;
    if (sb_decode(data, len, &f) != SB_OK) {
        h->stats.rx_malformed++;
        return;
    }
    if (f.type == SB_MSG_PAIR_REQUEST) {
        on_pair_request(h, mac, data, len);
        return;
    }
    if (f.type == SB_MSG_ACK || f.type == SB_MSG_PAIR_RESPONSE) return; // hub-only types

    // Pending pairing: only a HELLO under the pending keys commits it.
    if (h->pair.active && memcmp(mac, h->pair.mac, 6) == 0) {
        if (f.type != SB_MSG_HELLO || f.epoch != h->pair.epoch ||
            !sb_mic_verify(h->pair.k_mic, SB_DIR_NODE_TO_HUB, data, len))
            return;
        node_t *n = &h->n[h->pair.slot];
        n->rssi = rssi;
        uint8_t status;
        if (!pair_commit(h, n, &f, &status)) return; // record not persisted: drop, no ACK
        send_ack(h, n->mac, n->epoch, n->k_mic, f.boot, f.seq, status);
        return;
    }

    node_t *n = NULL;
    for (int s = 0; s < SB_HUB_MAX_NODES; s++) {
        node_t *c = &h->n[s];
        if (c->state == SB_NODE_ENROLLED && memcmp(c->mac, mac, 6) == 0) {
            n = c;
            break;
        }
    }
    if (!n) {
        h->stats.rx_unknown++;
        return;
    }
    if (!sb_mic_verify(n->k_mic, SB_DIR_NODE_TO_HUB, data, len)) {
        h->stats.rx_bad_mic++;
        return;
    }
    if (f.epoch != n->epoch) {
        h->stats.rx_bad_epoch++;
        return;
    }

    uint64_t now = now_ms(h);
    uint8_t status = SB_ACK_OK;
    bool new_boot = false;
    uint32_t prev_boot = n->last_boot;
    uint32_t prev_seq = n->last_seq;
    bool prev_valid = n->seq_valid;
    uint8_t prev_status = n->ack_status;
    uint16_t prev_interval = n->report_interval_s;
    uint8_t prev_reason = n->boot_reason;
    if (f.boot > n->last_boot) {
        new_boot = true;
        n->last_boot = f.boot;
        n->last_seq = f.seq;
        n->seq_valid = true;
        n->ack_status = SB_ACK_OK;
    } else if (f.boot == n->last_boot) {
        if (!n->seq_valid) { // hub restarted: make the node bump its boot counter
            n->last_seen_ms = now;
            n->rssi = rssi;
            set_available(h, (uint8_t)(n - h->n), n, true);
            h->stats.rx_new_boot++;
            send_ack(h, n->mac, n->epoch, n->k_mic, f.boot, f.seq, SB_ACK_NEW_BOOT);
            return;
        }
        if (f.seq == n->last_seq) { // retry: re-ACK the original status
            n->last_seen_ms = now;
            n->rssi = rssi;
            set_available(h, (uint8_t)(n - h->n), n, true);
            h->stats.rx_duplicate++;
            if (f.flags & SB_FLAG_ACK_REQ)
                send_ack(h, n->mac, n->epoch, n->k_mic, f.boot, f.seq, n->ack_status);
            return;
        }
        if (f.seq < n->last_seq) {
            h->stats.rx_replay++;
            return;
        }
    } else {
        h->stats.rx_replay++;
        return;
    }

    // HELLO metadata affects availability, so include it in the durable
    // pre-ACK transition even when the node's boot counter did not change.
    bool hello = f.type == SB_MSG_HELLO;
    if (hello) {
        status = on_hello(h, n, &f);
        n->ack_status = status;
    }
    if (new_boot || hello) {
        if (save_node(h, n, (int)(n - h->n)) != 0) {
            n->last_boot = prev_boot;
            n->last_seq = prev_seq;
            n->seq_valid = prev_valid;
            n->ack_status = prev_status;
            n->report_interval_s = prev_interval;
            n->boot_reason = prev_reason;
            return;
        }
        if (new_boot) h->stats.rx_new_boot++;
    }

    set_available(h, (uint8_t)(n - h->n), n, true);
    n->last_seen_ms = now;
    n->rssi = rssi;

    uint8_t slot = (uint8_t)(n - h->n);
    bool no_reply = false;
    switch (f.type) {
    case SB_MSG_HELLO:
        break;
    case SB_MSG_DESCRIBE:
        status = on_describe(h, n, slot, &f);
        break;
    case SB_MSG_STATE:
        status = on_state(h, n, slot, &f);
        break;
    case SB_MSG_EVENT:
        status = on_event(h, n, slot, &f);
        break;
    case SB_MSG_HEARTBEAT:
        status = SB_ACK_OK;
        break;
    case SB_MSG_ERROR:
        n->errors++;
        h->stats.node_errors++;
        emit_node_error(h, slot, f.u.error.code);
        status = SB_ACK_OK;
        no_reply = true; // ERROR is never replied to (docs/PROTOCOL.md)
        break;
    default:
        return;
    }
    n->ack_status = status;
    n->last_seq = f.seq;
    if ((f.flags & SB_FLAG_ACK_REQ) && !no_reply)
        send_ack(h, n->mac, n->epoch, n->k_mic, f.boot, f.seq, status);
}

void sb_hub_tick(sb_hub_t *h)
{
    uint64_t now = now_ms(h);
    for (uint8_t i = 0; i < h->cleanup_len;) {
        if (h->ops.radio_peer(h->ops.ctx, h->cleanup_mac[i], false, NULL) == 0) {
            h->cleanup_len--;
            memcpy(h->cleanup_mac[i], h->cleanup_mac[h->cleanup_len], 6);
        } else {
            i++;
        }
    }
    if (h->pair_window_deadline_ms && now >= h->pair_window_deadline_ms) {
        h->pair_window_deadline_ms = 0;
        h->pair_window_slot = -1;
        emit_pair(h, SB_PAIR_CLOSED, 0xFF);
    }
    if (h->pair.active && now >= h->pair.confirm_deadline_ms) pair_roll_back(h);
    for (int s = 0; s < SB_HUB_MAX_NODES; s++) {
        node_t *n = &h->n[s];
        if (n->state == SB_NODE_ENROLLED && n->peer_retry_ms && now >= n->peer_retry_ms) {
            n->peer_retry_ms = h->ops.radio_peer(h->ops.ctx, n->mac, true, n->lmk) == 0
                                   ? 0
                                   : now + 1000;
        }
        if (n->stage && now - n->progress_ms > SB_HUB_DESCRIBE_TIMEOUT_MS) {
            free(n->stage);
            n->stage = NULL;
        }
        if (n->state == SB_NODE_ENROLLED && n->available && n->report_interval_s > 0 &&
            now - n->last_seen_ms > 3ull * n->report_interval_s * 1000ull) {
            n->available = false;
            emit_avail(h, (uint8_t)s, false);
        }
    }
}

int sb_hub_node_add(sb_hub_t *h, uint8_t key_out[SB_KEY_LEN])
{
    for (int s = 0; s < SB_HUB_MAX_NODES; s++) {
        node_t *n = &h->n[s];
        if (n->state != SB_NODE_EMPTY) continue;
        h->ops.random(h->ops.ctx, n->k_node, SB_KEY_LEN);
        uint8_t id[8];
        h->ops.random(h->ops.ctx, id, sizeof id);
        memcpy(&n->node_id, id, sizeof n->node_id);
        if (n->node_id == 0) n->node_id = 1; // zero means "not associated" in events
        n->state = SB_NODE_KEY_ONLY;
        n->epoch = 0;
        n->generation = 0;
        sb_key_id(n->k_node, n->key_id);
        if (save_node(h, n, s) != 0) {
            memset(n, 0, sizeof *n);
            return SB_HUB_ERR_STORE;
        }
        memcpy(key_out, n->k_node, SB_KEY_LEN);
        sb_hub_pair_open(h, s, SB_HUB_PAIR_WINDOW_MS);
        emit(h, SB_EVT_NODE, (uint8_t)s);
        return s;
    }
    return SB_HUB_ERR_FULL;
}

int sb_hub_node_remove(sb_hub_t *h, int slot)
{
    if (slot < 0 || slot >= SB_HUB_MAX_NODES || h->n[slot].state == SB_NODE_EMPTY)
        return SB_HUB_ERR_INVALID;
    if (h->pair.active && h->pair.slot == (uint8_t)slot) pair_roll_back(h);
    node_t *n = &h->n[slot];
    char key[16];
    store_key(key, sizeof key, slot, false);
    if (h->ops.store_del(h->ops.ctx, key) != 0) {
        h->stats.store_fail++;
        return SB_HUB_ERR_STORE;
    }
    store_key(key, sizeof key, slot, true);
    if (h->ops.store_del(h->ops.ctx, key) != 0) {
        h->stats.store_fail++;
    }
    if (n->state == SB_NODE_ENROLLED && h->ops.radio_peer(h->ops.ctx, n->mac, false, NULL) != 0)
        schedule_cleanup(h, n->mac);
    sb_hub_evt_t removed = {
        .kind = SB_EVT_NODE,
        .slot = (uint8_t)slot,
        .tombstone = true,
        .node_id = n->node_id,
        .generation = n->generation,
    };
    h->ops.emit(h->ops.ctx, &removed);
    clear_schema(n);
    free(n->stage);
    memset(n, 0, sizeof *n);
    return 0;
}

int sb_hub_pair_open(sb_hub_t *h, int slot, uint32_t ms)
{
    if (slot >= SB_HUB_MAX_NODES || (slot >= 0 && h->n[slot].state == SB_NODE_EMPTY))
        return SB_HUB_ERR_INVALID;
    h->pair_window_slot = (int8_t)slot;
    h->pair_window_deadline_ms = now_ms(h) + ms;
    emit_pair(h, SB_PAIR_OPENED, slot >= 0 ? (uint8_t)slot : 0xFF);
    return 0;
}

void sb_hub_pair_close(sb_hub_t *h)
{
    pair_roll_back(h);
    h->pair_window_deadline_ms = 0;
    h->pair_window_slot = -1;
    emit_pair(h, SB_PAIR_CLOSED, 0xFF);
}

bool sb_hub_node(const sb_hub_t *h, int slot, sb_hub_node_view_t *out)
{
    if (!h || slot < 0 || slot >= SB_HUB_MAX_NODES || !out) return false;
    const node_t *n = &h->n[slot];
    memset(out, 0, sizeof *out);
    out->state = n->state;
    memcpy(out->mac, n->mac, 6);
    out->epoch = n->epoch;
    out->generation = n->generation;
    out->node_id = n->node_id;
    out->available = n->available;
    out->last_seen_ms = n->last_seen_ms;
    out->rssi = n->rssi;
    out->report_interval_s = n->report_interval_s;
    out->boot_reason = n->boot_reason;
    out->has_schema = n->has_schema;
    out->schema_hash = n->schema_hash;
    out->schema = n->schema;
    out->values = n->values;
    return true;
}

sb_hub_stats_t sb_hub_stats(const sb_hub_t *h)
{
    return h ? h->stats : (sb_hub_stats_t){0};
}
