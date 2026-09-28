// Hub-core host tests: fake platform + simulated node exercise pairing,
// MIC/replay checks, DESCRIBE reassembly, state/events and availability.
// Build/run via the flake check `hub-c`. Exit code 0 = pass.
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sb_crypto.h"
#include "sb_hub.h"
#include "sb_protocol.h"

static int failures;
#define CHECK(cond, ...)                                                                           \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__);                                   \
            fprintf(stderr, __VA_ARGS__);                                                          \
            fputc('\n', stderr);                                                                   \
            failures++;                                                                            \
        }                                                                                          \
    } while (0)

// ------------------------------------------------------------ fake platform

static uint64_t g_now = 1000;

static uint64_t f_now(void *c) { (void)c; return g_now; }
static uint32_t f_unix(void *c) { (void)c; return 1790000000u; }

static uint32_t g_rng = 0x1234abcd;
static void f_random(void *c, uint8_t *buf, size_t len)
{
    (void)c;
    for (size_t i = 0; i < len; i++) {
        g_rng ^= g_rng << 13;
        g_rng ^= g_rng >> 17;
        g_rng ^= g_rng << 5;
        buf[i] = (uint8_t)g_rng;
    }
}

typedef struct {
    uint8_t mac[6];
    uint8_t buf[SB_MAX_FRAME];
    size_t len;
    uint32_t token;
} sent_t;
static sent_t g_sent[64];
static int g_nsent;

typedef struct {
    bool present, encrypted;
    uint8_t mac[6], lmk[16];
} fpeer_t;
static fpeer_t g_peers[24];

typedef struct {
    char key[12];
    size_t len;
    uint8_t data[SB_MAX_SCHEMA + 32];
} sentry_t;
static sentry_t g_store[40];
static int g_nstore;
static bool g_fail_next_put;
static bool g_fail_next_del;
static char g_fail_del_key[12];

static sent_t *last_to(const uint8_t mac[6])
{
    for (int i = g_nsent - 1; i >= 0; i--)
        if (memcmp(g_sent[i].mac, mac, 6) == 0) return &g_sent[i];
    return NULL;
}

static fpeer_t *find_peer(const uint8_t mac[6])
{
    for (size_t i = 0; i < sizeof g_peers / sizeof g_peers[0]; i++)
        if (g_peers[i].present && memcmp(g_peers[i].mac, mac, 6) == 0) return &g_peers[i];
    return NULL;
}

static int f_send(void *c, const uint8_t mac[6], const uint8_t *data, size_t len, uint32_t *tok)
{
    (void)c;
    if (g_nsent < (int)(sizeof g_sent / sizeof g_sent[0])) {
        memcpy(g_sent[g_nsent].mac, mac, 6);
        memcpy(g_sent[g_nsent].buf, data, len);
        g_sent[g_nsent].len = len;
        g_sent[g_nsent].token = (uint32_t)(g_nsent + 1);
        if (tok) *tok = g_sent[g_nsent].token;
        g_nsent++;
    }
    return 0;
}

static int f_peer(void *c, const uint8_t mac[6], bool add, const uint8_t *lmk)
{
    (void)c;
    fpeer_t *p = find_peer(mac);
    if (!add) {
        if (p) p->present = false;
        return 0;
    }
    if (!p) {
        p = &g_peers[0];
        for (size_t i = 0; i < sizeof g_peers / sizeof g_peers[0]; i++)
            if (!g_peers[i].present) {
                p = &g_peers[i];
                break;
            }
    }
    p->present = true;
    p->encrypted = lmk != NULL;
    memcpy(p->mac, mac, 6);
    if (lmk) memcpy(p->lmk, lmk, 16);
    return 0;
}

static sentry_t *find_entry(const char *key)
{
    for (int i = 0; i < g_nstore; i++)
        if (strcmp(g_store[i].key, key) == 0) return &g_store[i];
    return NULL;
}

static int f_put(void *c, const char *key, const void *data, size_t len)
{
    (void)c;
    if (g_fail_next_put) {
        g_fail_next_put = false;
        return -1;
    }
    sentry_t *e = find_entry(key);
    if (!e) {
        if (g_nstore >= (int)(sizeof g_store / sizeof g_store[0])) return -1;
        e = &g_store[g_nstore++];
        snprintf(e->key, sizeof e->key, "%s", key);
    }
    if (len > sizeof e->data) return -1;
    memcpy(e->data, data, len);
    e->len = len;
    return 0;
}

static int f_get(void *c, const char *key, void *data, size_t cap)
{
    sentry_t *e = find_entry(key);
    if (!e || cap < e->len) return -1;
    memcpy(data, e->data, e->len);
    return (int)e->len;
}

static int f_del(void *c, const char *key)
{
    if (g_fail_next_del || (g_fail_del_key[0] && strcmp(g_fail_del_key, key) == 0)) {
        g_fail_next_del = false;
        g_fail_del_key[0] = 0;
        return -1;
    }
    sentry_t *e = find_entry(key);
    if (e) e->len = 0, e->key[0] = 0;
    return 0;
}

typedef struct {
    uint8_t kind, slot, entity, etype, pair;
    bool available;
    bool tombstone;
    uint64_t node_id;
    uint32_t generation;
    sb_value_t value;
    char str[SB_MAX_STR + 1];
    char event_id[SB_HUB_EVENT_ID_LEN];
} rev_t;
static rev_t g_ev[512];
static int g_nev;

static int ev_count(uint8_t kind)
{
    int n = 0;
    for (int i = 0; i < g_nev; i++)
        if (g_ev[i].kind == kind) n++;
    return n;
}

static rev_t *ev_find(uint8_t kind, uint8_t slot, uint8_t entity)
{
    for (int i = g_nev - 1; i >= 0; i--)
        if (g_ev[i].kind == kind && g_ev[i].slot == slot && g_ev[i].entity == entity) return &g_ev[i];
    return NULL;
}

static void f_emit(void *c, const sb_hub_evt_t *e)
{
    (void)c;
    if (g_nev >= (int)(sizeof g_ev / sizeof g_ev[0])) return;
    rev_t *r = &g_ev[g_nev++];
    memset(r, 0, sizeof *r);
    r->kind = e->kind;
    r->slot = e->slot;
    r->entity = e->entity;
    r->etype = e->etype;
    r->pair = e->pair;
    r->available = e->available;
    r->tombstone = e->tombstone;
    r->node_id = e->node_id;
    r->generation = e->generation;
    if (e->value) {
        r->value = *e->value;
        if (e->value->type == SB_V_STR && e->value->s.p) {
            memcpy(r->str, e->value->s.p, e->value->s.len);
            r->value.s.p = (const uint8_t *)r->str;
        }
    }
    if (e->event_id) snprintf(r->event_id, sizeof r->event_id, "%s", e->event_id);
}

static sb_hub_ops_t g_ops = {
    .ctx = NULL,
    .now_ms = f_now,
    .unix_time = f_unix,
    .random = f_random,
    .radio_send = f_send,
    .radio_peer = f_peer,
    .store_put = f_put,
    .store_get = f_get,
    .store_del = f_del,
    .emit = f_emit,
};

static const sb_hub_cfg_t g_cfg = {
    .hub_mac = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
    .channel = 6,
    .hub_boot = 7,
    .hub_id = "12345678901234567890123",
};

// ------------------------------------------------------------ simulated node

typedef struct {
    uint8_t mac[6], k_node[16];
    uint8_t epoch, lmk[16], k_mic[16];
    uint8_t node_nonce[16];
    uint32_t boot, seq;
} sim_t;

static void sim_init(sim_t *s, uint8_t last)
{
    memset(s, 0, sizeof *s);
    for (int i = 0; i < 6; i++) s->mac[i] = (uint8_t)(0xa0 + i);
    s->mac[5] = last;
    s->boot = 1;
}

static void hub_rx(sb_hub_t *h, sim_t *s, const uint8_t *buf, size_t len)
{
    sb_hub_on_rx(h, s->mac, -55, buf, len);
}

static size_t sim_seal(sim_t *s, sb_frame_t *f, uint8_t *out)
{
    f->epoch = s->epoch;
    f->boot = s->boot;
    f->seq = ++s->seq;
    size_t n = 0;
    if (sb_encode(f, out, SB_MAX_FRAME, &n) != SB_OK) {
        CHECK(false, "sim encode failed");
        return 0;
    }
    sb_mic_seal(s->k_mic, SB_DIR_NODE_TO_HUB, out, n);
    return n;
}

// Deliver send-done for every pending token (the P4 hub task does this).
static void pump(sb_hub_t *h)
{
    int n = g_nsent;
    static uint32_t done[64];
    int nd = 0;
    for (int i = 0; i < n; i++) {
        bool seen = false;
        for (int j = 0; j < nd; j++) seen |= done[j] == g_sent[i].token;
        if (!seen) {
            sb_hub_on_send_done(h, g_sent[i].token, true);
            done[nd++] = g_sent[i].token;
        }
    }
}

static void sim_pair_request_nonce(sb_hub_t *h, sim_t *s, const uint8_t *nonce)
{
    sb_frame_t f = {.type = SB_MSG_PAIR_REQUEST, .boot = s->boot, .seq = ++s->seq};
    if (nonce) memcpy(s->node_nonce, nonce, 16);
    else f_random(NULL, s->node_nonce, 16);
    memcpy(f.u.pair_req.key_id, (uint8_t[4]){0}, 4); // filled by caller below
    uint8_t buf[SB_MAX_FRAME], id[4], tag[16];
    sb_key_id(s->k_node, id);
    memcpy(f.u.pair_req.key_id, id, 4);
    memcpy(f.u.pair_req.mac, s->mac, 6);
    memcpy(f.u.pair_req.nonce, s->node_nonce, 16);
    size_t n = 0;
    if (sb_encode(&f, buf, SB_MAX_FRAME, &n) != SB_OK) return;
    sb_request_tag(s->k_node, buf, n - SB_TAG_LEN, tag);
    memcpy(buf + n - SB_TAG_LEN, tag, SB_TAG_LEN);
    hub_rx(h, s, buf, n);
}

static void sim_pair_request(sb_hub_t *h, sim_t *s) { sim_pair_request_nonce(h, s, NULL); }

// True if the hub answered this node with a valid PAIR_RESPONSE (fills s keys).
static bool sim_pair_response(sim_t *s, int *status, uint8_t *epoch)
{
    sent_t *m = last_to(s->mac);
    if (!m) return false;
    sb_frame_t f;
    if (sb_decode(m->buf, m->len, &f) != SB_OK || f.type != SB_MSG_PAIR_RESPONSE) return false;
    uint8_t tag[16];
    sb_response_tag(s->k_node, s->node_nonce, m->buf, m->len - SB_TAG_LEN, tag);
    if (!sb_tag_equal(tag, f.u.pair_resp.tag, SB_TAG_LEN)) return false;
    sb_session_keys(s->k_node, s->node_nonce, f.u.pair_resp.nonce, s->mac, f.u.pair_resp.mac,
                    f.u.pair_resp.pepoch, s->lmk, s->k_mic);
    s->epoch = f.u.pair_resp.pepoch;
    *status = f.u.pair_resp.status;
    *epoch = f.u.pair_resp.pepoch;
    return true;
}

static size_t sim_hello(sb_hub_t *h, sim_t *s, uint32_t schema_hash, uint16_t interval)
{
    sb_frame_t f = {.type = SB_MSG_HELLO, .flags = SB_FLAG_ACK_REQ};
    f.u.hello.schema_hash = schema_hash;
    f.u.hello.interval = interval;
    f.u.hello.reason = 1;
    uint8_t buf[SB_MAX_FRAME];
    size_t n = sim_seal(s, &f, buf);
    hub_rx(h, s, buf, n);
    return n;
}

static size_t sim_describe(sb_hub_t *h, sim_t *s, uint8_t xfer, const uint8_t *blob, size_t blen)
{
    uint32_t hash;
    sb_schema_hash(blob, blen, &hash);
    uint8_t count = (uint8_t)((blen + SB_MAX_DESCRIBE_DATA - 1) / SB_MAX_DESCRIBE_DATA);
    size_t last = 0;
    for (uint8_t i = 0; i < count; i++) {
        size_t off = (size_t)i * SB_MAX_DESCRIBE_DATA;
        uint16_t len =
            (uint16_t)((i + 1 == count) ? blen - off : SB_MAX_DESCRIBE_DATA);
        sb_frame_t f = {.type = SB_MSG_DESCRIBE, .flags = SB_FLAG_ACK_REQ};
        f.u.describe.xfer = xfer;
        f.u.describe.index = i;
        f.u.describe.count = count;
        f.u.describe.total = (uint16_t)blen;
        f.u.describe.hash = hash;
        f.u.describe.data = blob + off;
        f.u.describe.data_len = (uint8_t)len;
        uint8_t buf[SB_MAX_FRAME];
        size_t n = sim_seal(s, &f, buf);
        hub_rx(h, s, buf, n);
        last = n;
    }
    return last;
}

static size_t sim_state(sb_hub_t *h, sim_t *s, int nent, const uint8_t *ents, const sb_value_t *vals)
{
    sb_frame_t f = {.type = SB_MSG_STATE, .flags = SB_FLAG_ACK_REQ | SB_FLAG_FULL_STATE};
    f.u.state.n = (uint8_t)nent;
    for (int i = 0; i < nent; i++) {
        f.u.state.e[i].entity = ents[i];
        f.u.state.e[i].value = vals[i];
    }
    uint8_t buf[SB_MAX_FRAME];
    size_t n = sim_seal(s, &f, buf);
    hub_rx(h, s, buf, n);
    return n;
}

static size_t sim_event(sb_hub_t *h, sim_t *s, uint8_t entity, uint8_t etype, uint32_t oboot,
                        uint16_t evno, const sb_value_t *v)
{
    sb_frame_t f = {.type = SB_MSG_EVENT, .flags = SB_FLAG_ACK_REQ};
    f.u.event.entity = entity;
    f.u.event.etype = etype;
    f.u.event.oboot = oboot;
    f.u.event.evno = evno;
    if (v) f.u.event.value = *v;
    uint8_t buf[SB_MAX_FRAME];
    size_t n = sim_seal(s, &f, buf);
    hub_rx(h, s, buf, n);
    return n;
}

// Hand-rolled frame for payloads the validating encoder refuses to build
// (e.g. a DESCRIBE chunk with an illegal length). Sealed like any node frame.
static size_t raw_frame(sim_t *s, uint8_t type, uint8_t flags, const uint8_t *payload,
                        uint16_t plen, uint8_t *out)
{
    memcpy(out, "SB", 2);
    out[2] = 1;
    out[3] = type;
    out[4] = flags;
    out[5] = s->epoch;
    out[6] = (uint8_t)s->boot;
    out[7] = (uint8_t)(s->boot >> 8);
    out[8] = (uint8_t)(s->boot >> 16);
    out[9] = (uint8_t)(s->boot >> 24);
    uint32_t seq = ++s->seq;
    out[10] = (uint8_t)seq;
    out[11] = (uint8_t)(seq >> 8);
    out[12] = (uint8_t)(seq >> 16);
    out[13] = (uint8_t)(seq >> 24);
    out[14] = (uint8_t)plen;
    out[15] = (uint8_t)(plen >> 8);
    memcpy(out + 16, payload, plen);
    size_t n = 16 + plen + SB_MIC_LEN;
    sb_mic_seal(s->k_mic, SB_DIR_NODE_TO_HUB, out, n);
    return n;
}

// Verify the newest hub frame to this node decodes as an ACK with `status`.
static bool check_ack(sim_t *s, uint32_t aboot, uint32_t aseq, uint8_t status)
{
    sent_t *m = last_to(s->mac);
    if (!m) return false;
    if (!sb_mic_verify(s->k_mic, SB_DIR_HUB_TO_NODE, m->buf, m->len)) return false;
    sb_frame_t f;
    if (sb_decode(m->buf, m->len, &f) != SB_OK || f.type != SB_MSG_ACK) return false;
    return f.epoch == s->epoch && f.u.ack.aboot == aboot && f.u.ack.aseq == aseq &&
           f.u.ack.status == status && f.u.ack.channel == g_cfg.channel &&
           f.u.ack.time == 1790000000u;
}

// ------------------------------------------------------------ demo schema

static sb_str_t S_(const char *s) { return (sb_str_t){(const uint8_t *)s, (uint8_t)strlen(s)}; }

static size_t demo_blob(uint8_t *blob)
{
    sb_schema_t sc = {
        .node_name = S_("Garage Sensor"),
        .model = S_("esp32c3"),
        .fw_version = S_("1.0.0"),
        .n = 7,
    };
    sb_entity_t *e = sc.e;
    e[0] = (sb_entity_t){1, 1, SB_V_F32, 1, 1, 0, S_("temperature"), S_("Temperature"),
                         S_("°C"), S_("temperature"), {0, 0}};
    e[1] = (sb_entity_t){2, 1, SB_V_U32, 1, 0, 1, S_("battery"), S_("Battery"), S_("%"),
                         S_("battery"), {0, 0}};
    e[2] = (sb_entity_t){3, 2, SB_V_BOOL, 0, 0, 0, S_("door"), S_("Door"), {0, 0}, S_("door"), {0, 0}};
    e[3] = (sb_entity_t){4, 4, SB_V_ENUM, 0, 0, 0, S_("button"), S_("Button"), {0, 0}, S_("button"),
                         S_("press,long_press")};
    e[4] = (sb_entity_t){5, 1, SB_V_F32, 1, 0, 0, S_("humidity"), S_("Humidity"), S_("%"),
                         S_("humidity"), {0, 0}};
    e[5] = (sb_entity_t){6, 3, SB_V_STR, 0, 0, 1, S_("reset_reason"), S_("Reset reason"), {0, 0},
                         {0, 0}, {0, 0}};
    e[6] = (sb_entity_t){7, 1, SB_V_I32, 1, 0, 1, S_("rssi"), S_("Signal"), S_("dBm"),
                         S_("signal_strength"), {0, 0}};
    size_t n = 0;
    CHECK(sb_encode_schema(&sc, blob, SB_MAX_SCHEMA, &n) == SB_OK, "encode schema");
    return n;
}

// ------------------------------------------------------------ tests

int main(void)
{
    uint8_t blob[SB_MAX_SCHEMA];
    size_t blen = demo_blob(blob);
    CHECK(blen > SB_MAX_DESCRIBE_DATA, "demo schema must need >= 2 chunks, got %zu", blen);

    sb_hub_t *h = sb_hub_create(&g_cfg, &g_ops);
    CHECK(h, "create");

    sim_t node;
    sim_init(&node, 0x01);
    uint8_t key[16];
    int slot = sb_hub_node_add(h, key);
    CHECK(slot == 0, "node_add -> %d", slot);
    CHECK(ev_count(SB_EVT_PAIR) == 1 && g_ev[0].pair == SB_PAIR_OPENED, "add opens window");
    memcpy(node.k_node, key, 16);

    // Pairing negatives.
    g_nsent = 0;
    sim_pair_request(h, &node); // valid, just to test response below... keep.
    CHECK(g_nsent == 1, "pair request gets one response");
    // Retry with the same nonce while pending: same slot, response resent.
    uint8_t first_nonce[16];
    memcpy(first_nonce, node.node_nonce, sizeof first_nonce);
    sim_pair_request_nonce(h, &node, first_nonce);
    CHECK(g_nsent == 2, "same-nonce retry gets another response");
    int st = 9;
    uint8_t ep = 0;
    CHECK(sim_pair_response(&node, &st, &ep) && st == SB_PAIR_ACCEPTED && ep == 1,
          "response verifies, epoch 1");
    fpeer_t *p = find_peer(node.mac);
    CHECK(p && !p->encrypted, "pair response uses plaintext peer");
    sb_hub_on_send_done(h, g_sent[g_nsent - 1].token + 100, true);
    CHECK(p && !p->encrypted, "unrelated send completion ignored");
    pump(h);
    p = find_peer(node.mac);
    CHECK(p && p->encrypted && memcmp(p->lmk, node.lmk, 16) == 0, "peer installed with LMK");

    // HELLO commits pairing; unknown schema -> NEED_DESCRIBE.
    g_nev = 0;
    uint32_t hash;
    sb_schema_hash(blob, blen, &hash);
    sim_hello(h, &node, hash + 1, 60);
    CHECK(check_ack(&node, 1, node.seq, SB_ACK_NEED_DESCRIBE), "HELLO -> NEED_DESCRIBE");
    {
        sb_hub_node_view_t v;
        CHECK(sb_hub_node(h, slot, &v) && v.state == SB_NODE_ENROLLED && v.epoch == 1 &&
                   v.generation == 1 && v.available && v.report_interval_s == 60,
               "node enrolled after HELLO");
        CHECK(ev_count(SB_EVT_AVAIL) == 1, "AVAIL(true) emitted");
        CHECK(ev_count(SB_EVT_NODE) == 1, "pair commit emits NODE refresh");
        rev_t *available = ev_find(SB_EVT_AVAIL, slot, 0);
        CHECK(available && available->node_id == v.node_id &&
                  available->generation == v.generation,
              "availability event carries stable identity");
    }

    // DESCRIBE: duplicate chunk ignored; completion installs schema.
    {
        g_nev = 0;
        // Manually send chunk 0 twice, then the rest, via a custom pass.
        uint32_t hh;
        sb_schema_hash(blob, blen, &hh);
        uint8_t count = (uint8_t)((blen + SB_MAX_DESCRIBE_DATA - 1) / SB_MAX_DESCRIBE_DATA);
        for (int pass = 0; pass < 2; pass++) {
            sb_frame_t f = {.type = SB_MSG_DESCRIBE, .flags = SB_FLAG_ACK_REQ};
            f.u.describe = (sb_describe_t){
                .xfer = 5, .index = 0, .count = count, .total = (uint16_t)blen, .hash = hh,
                .data = blob, .data_len = SB_MAX_DESCRIBE_DATA,
            };
            uint8_t buf[SB_MAX_FRAME];
            size_t n = sim_seal(&node, &f, buf);
            hub_rx(h, &node, buf, n);
        }
        for (uint8_t i = 1; i < count; i++) {
            size_t off = (size_t)i * SB_MAX_DESCRIBE_DATA;
            uint16_t len = (uint16_t)((i + 1 == count) ? blen - off : SB_MAX_DESCRIBE_DATA);
            sb_frame_t f = {.type = SB_MSG_DESCRIBE, .flags = SB_FLAG_ACK_REQ};
            f.u.describe = (sb_describe_t){
                .xfer = 5, .index = i, .count = count, .total = (uint16_t)blen, .hash = hh,
                .data = blob + off, .data_len = (uint8_t)len,
            };
            uint8_t buf[SB_MAX_FRAME];
            size_t n = sim_seal(&node, &f, buf);
            hub_rx(h, &node, buf, n);
        }
        CHECK(check_ack(&node, node.boot, node.seq, SB_ACK_OK), "last chunk -> OK");
        sb_hub_node_view_t v;
        CHECK(sb_hub_node(h, slot, &v) && v.has_schema && v.schema && v.schema->n == 7,
              "schema installed");
        CHECK(ev_count(SB_EVT_NODE) == 1, "NODE event once (dup chunk ignored)");
        char skey[12];
        snprintf(skey, sizeof skey, "sb/s%d", slot);
        sentry_t *se = find_entry(skey);
        CHECK(se && se->len > blen && se->len <= blen + 32 &&
                  memcmp(se->data + se->len - blen, blob, blen) == 0,
              "schema record persisted atomically");
    }

    // HELLO again with matching hash -> OK.
    sim_hello(h, &node, hash, 60);
    CHECK(check_ack(&node, node.boot, node.seq, SB_ACK_OK), "HELLO (known schema) -> OK");

    // STATE: valid, then type-mismatch, then unknown entity.
    {
        g_nev = 0;
        sb_value_t vals[3] = {{SB_V_F32, .f = 21.5f}, {SB_V_U32, .u = 87}, {SB_V_BOOL, .b = true}};
        const uint8_t ents[3] = {1, 2, 3};
        sim_state(h, &node, 3, ents, vals);
        CHECK(check_ack(&node, node.boot, node.seq, SB_ACK_OK), "STATE ok");
        CHECK(ev_count(SB_EVT_STATE) == 3, "3 state events");
        rev_t *t = ev_find(SB_EVT_STATE, slot, 1);
        CHECK(t && t->value.type == SB_V_F32 && t->value.f == 21.5f, "temperature event value");
        sb_hub_node_view_t identity;
        CHECK(sb_hub_node(h, slot, &identity) && t && t->node_id == identity.node_id &&
                  t->generation == identity.generation,
              "state event carries stable identity");
        g_nev = 0;
        sb_value_t bad[1] = {{SB_V_BOOL, .b = true}}; // bool for f32 entity
        const uint8_t e1[1] = {1};
        sim_state(h, &node, 1, e1, bad);
        CHECK(check_ack(&node, node.boot, node.seq, SB_ACK_MALFORMED), "type mismatch -> MALFORMED");
        CHECK(ev_count(SB_EVT_STATE) == 0, "no partial state");
        const uint8_t e9[1] = {99};
        sb_value_t v9[1] = {{SB_V_F32, .f = 1.0f}};
        sim_state(h, &node, 1, e9, v9);
        CHECK(check_ack(&node, node.boot, node.seq, SB_ACK_MALFORMED), "unknown entity");
    }

    // EVENT: new, then duplicate with a fresh seq, then bad etype.
    {
        g_nev = 0;
        sb_value_t press = {SB_V_ENUM, .e = 1};
        sim_event(h, &node, 4, 1, UINT32_MAX, UINT16_MAX, &press);
        CHECK(check_ack(&node, node.boot, node.seq, SB_ACK_OK), "max event identifiers accepted");
        CHECK(ev_count(SB_EVT_EVENT) == 1, "max event identifiers emitted");
        rev_t *max_id = ev_find(SB_EVT_EVENT, slot, 4);
        CHECK(max_id && strstr(max_id->event_id, "-1-4294967295-65535") != NULL,
              "maximum event ID is not truncated");
        g_nev = 0;
        sim_event(h, &node, 4, 1, node.boot, 1, &press);
        CHECK(check_ack(&node, node.boot, node.seq, SB_ACK_OK), "EVENT ok");
        rev_t *e = ev_find(SB_EVT_EVENT, slot, 4);
        CHECK(e && e->etype == 1 && e->value.type == SB_V_ENUM && e->value.e == 1, "event emitted");
        CHECK(e && strstr(e->event_id, "-1-1-1") != NULL, "event_id has gen/boot/evno");
        sb_hub_node_view_t identity;
        CHECK(sb_hub_node(h, slot, &identity) && e && e->node_id == identity.node_id &&
                  e->generation == identity.generation,
              "transient event carries stable identity");
        g_nev = 0;
        sim_event(h, &node, 4, 1, node.boot, 1, &press);
        CHECK(check_ack(&node, node.boot, node.seq, SB_ACK_DUPLICATE), "dup event -> DUPLICATE");
        CHECK(ev_count(SB_EVT_EVENT) == 0, "dup not re-emitted");
        sim_event(h, &node, 4, 9, node.boot, 2, &press);
        CHECK(check_ack(&node, node.boot, node.seq, SB_ACK_MALFORMED), "bad etype");
    }

    // ERROR: counted, emitted, never ACKed even with ACK_REQ.
    {
        g_nev = 0;
        g_nsent = 0;
        sb_frame_t f = {.type = SB_MSG_ERROR, .flags = SB_FLAG_ACK_REQ};
        f.u.error.code = 4;
        f.u.error.detail = S_("sensor");
        uint8_t buf[SB_MAX_FRAME];
        size_t n = sim_seal(&node, &f, buf);
        hub_rx(h, &node, buf, n);
        CHECK(ev_count(SB_EVT_NODE_ERROR) == 1, "node error emitted");
        sb_hub_node_view_t identity;
        rev_t *error = ev_find(SB_EVT_NODE_ERROR, slot, 0);
        CHECK(sb_hub_node(h, slot, &identity) && error &&
                  error->node_id == identity.node_id &&
                  error->generation == identity.generation,
              "node error carries stable identity");
        CHECK(g_nsent == 0, "ERROR never replied to");
    }

    // Replay/mic/epoch/unknown handling.
    {
        sb_hub_stats_t st0 = sb_hub_stats(h);
        size_t n;
        sb_value_t vals[1] = {{SB_V_F32, .f = 22.0f}};
        const uint8_t ents[1] = {1};
        n = sim_state(h, &node, 1, ents, vals);
        g_nev = 0;
        g_nsent = 0;
        // Exact resend: duplicate seq, re-ACK original status, no events.
        uint8_t dup[SB_MAX_FRAME];
        sb_frame_t f = {.type = SB_MSG_STATE, .flags = SB_FLAG_ACK_REQ | SB_FLAG_FULL_STATE};
        f.u.state.n = 1;
        f.u.state.e[0].entity = 1;
        f.u.state.e[0].value = vals[0];
        f.epoch = node.epoch;
        f.boot = node.boot;
        f.seq = node.seq; // same seq as the frame just sent
        size_t dn = 0;
        sb_encode(&f, dup, SB_MAX_FRAME, &dn);
        sb_mic_seal(node.k_mic, SB_DIR_NODE_TO_HUB, dup, dn);
        CHECK(dn == n, "dup frame encodes identically");
        hub_rx(h, &node, dup, dn);
        CHECK(ev_count(SB_EVT_STATE) == 0, "replayed seq not reprocessed");
        CHECK(g_nsent == 1 && check_ack(&node, node.boot, node.seq, SB_ACK_OK), "re-ACK on retry");
        g_nsent = 0;
        // Tampered payload (inside the f32 value; codec-valid): MIC fails.
        dup[SB_HEADER_LEN + 4] ^= 1;
        hub_rx(h, &node, dup, dn);
        CHECK(sb_hub_stats(h).rx_bad_mic == st0.rx_bad_mic + 1, "bad MIC counted");
        // Wrong epoch (rebuild from scratch; dup was tampered).
        f.seq = node.seq + 1;
        f.epoch = (uint8_t)(node.epoch + 1);
        memset(f.u.state.e, 0, sizeof f.u.state.e);
        f.u.state.n = 1;
        f.u.state.e[0].entity = 1;
        f.u.state.e[0].value = vals[0];
        sb_encode(&f, dup, SB_MAX_FRAME, &dn);
        sb_mic_seal(node.k_mic, SB_DIR_NODE_TO_HUB, dup, dn);
        hub_rx(h, &node, dup, dn);
        CHECK(sb_hub_stats(h).rx_bad_epoch == st0.rx_bad_epoch + 1, "bad epoch counted");
        // Unknown source MAC.
        sim_t ghost;
        sim_init(&ghost, 0xee);
        memcpy(ghost.k_node, key, 16);
        ghost.epoch = node.epoch;
        memcpy(ghost.k_mic, node.k_mic, 16);
        ghost.boot = node.boot;
        f.epoch = node.epoch;
        sb_encode(&f, dup, SB_MAX_FRAME, &dn);
        sb_mic_seal(ghost.k_mic, SB_DIR_NODE_TO_HUB, dup, dn);
        hub_rx(h, &ghost, dup, dn);
        CHECK(sb_hub_stats(h).rx_unknown == st0.rx_unknown + 1, "unknown mac counted");
    }

    // Availability timeout and recovery.
    {
        g_nev = 0;
        g_now += 3ull * 60 * 1000 + 1;
        sb_hub_tick(h);
        CHECK(ev_count(SB_EVT_AVAIL) == 1 && !g_ev[0].available, "node marked unavailable");
        sb_hub_node_view_t v;
        sb_hub_node(h, slot, &v);
        CHECK(!v.available, "view unavailable");
        g_nev = 0;
        sb_frame_t hb = {.type = SB_MSG_HEARTBEAT, .flags = SB_FLAG_ACK_REQ};
        uint8_t buf[SB_MAX_FRAME];
        size_t n = sim_seal(&node, &hb, buf);
        hub_rx(h, &node, buf, n);
        CHECK(ev_count(SB_EVT_AVAIL) == 1 && g_ev[0].available, "node back online");
        CHECK(check_ack(&node, node.boot, node.seq, SB_ACK_OK), "heartbeat acked");
    }

    // Hub restart: persisted node restored, seq unknown -> NEW_BOOT; then new boot.
    {
        sim_hello(h, &node, hash, 90);
        CHECK(check_ack(&node, node.boot, node.seq, SB_ACK_OK), "updated interval ACKed");
        sb_hub_destroy(h);
        h = sb_hub_create(&g_cfg, &g_ops);
        CHECK(h, "recreate");
        sb_hub_radio_ready(h);
        fpeer_t *p2 = find_peer(node.mac);
        CHECK(p2 && p2->encrypted && memcmp(p2->lmk, node.lmk, 16) == 0, "peer reinstalled");
        sb_hub_node_view_t v;
        CHECK(sb_hub_node(h, slot, &v) && v.state == SB_NODE_ENROLLED && v.has_schema &&
                  v.epoch == 1 && v.generation == 1, "node restored from store");
        g_nev = 0;
        sb_value_t vals[1] = {{SB_V_F32, .f = 23.5f}};
        const uint8_t ents[1] = {1};
        sim_state(h, &node, 1, ents, vals);
        CHECK(check_ack(&node, node.boot, node.seq, SB_ACK_NEW_BOOT), "unknown seq -> NEW_BOOT");
        CHECK(ev_count(SB_EVT_AVAIL) == 1 && g_ev[0].available, "AVAIL(true) via NEW_BOOT");
        CHECK(v.report_interval_s == 90, "interval persisted across restart");
        CHECK(ev_count(SB_EVT_STATE) == 0, "not processed before new boot");
        node.boot++;
        g_nev = 0;
        sim_state(h, &node, 1, ents, vals);
        CHECK(check_ack(&node, node.boot, node.seq, SB_ACK_OK), "new boot processed");
        CHECK(ev_count(SB_EVT_STATE) == 1, "state after new boot");
    }

    // Persist-before-ACK: a failing store write drops the frame.
    {
        sb_hub_stats_t st0 = sb_hub_stats(h);
        g_nev = 0;
        g_fail_next_put = true;
        node.boot++;
        sb_value_t vals[1] = {{SB_V_F32, .f = 24.5f}};
        const uint8_t ents[1] = {1};
        sim_state(h, &node, 1, ents, vals);
        CHECK(ev_count(SB_EVT_STATE) == 0, "frame dropped when store fails");
        CHECK(sb_hub_stats(h).store_fail == st0.store_fail + 1, "store failure counted");
        sim_state(h, &node, 1, ents, vals); // retry, store works now
        CHECK(ev_count(SB_EVT_STATE) == 1, "retry processed");
    }

    // Re-pair: new epoch + generation; old epoch frames rejected.
    {
        int rc = sb_hub_pair_open(h, slot, 30000);
        CHECK(rc == 0, "pair_open");
        sim_pair_request(h, &node);
        int st2 = 9;
        uint8_t ep2 = 0;
        CHECK(sim_pair_response(&node, &st2, &ep2) && st2 == SB_PAIR_ACCEPTED && ep2 == 2,
              "re-pair response epoch 2");
        pump(h);
        sim_hello(h, &node, hash, 60);
        sb_hub_node_view_t v;
        CHECK(check_ack(&node, node.boot, node.seq, SB_ACK_NEED_DESCRIBE),
              "re-pair invalidates prior-generation schema");
        CHECK(sb_hub_node(h, slot, &v) && v.epoch == 2 && v.generation == 2 && !v.has_schema,
              "re-pair committed without stale schema");
        sim_describe(h, &node, 7, blob, blen);
        CHECK(check_ack(&node, node.boot, node.seq, SB_ACK_OK), "schema rebound to new generation");
        sb_value_t vals[1] = {{SB_V_F32, .f = 25.0f}};
        const uint8_t ents[1] = {1};
        sim_state(h, &node, 1, ents, vals);
        CHECK(check_ack(&node, node.boot, node.seq, SB_ACK_OK), "state under new epoch");
    }

    // NONE/STR values; schema replacement; DESCRIBE timeout; rollback; idempotent retry.
    {
        // NONE for an f32 entity (unavailable/NaN per spec) is legal.
        g_nev = 0;
        sb_value_t none = {.type = SB_V_NONE};
        const uint8_t e1[1] = {1};
        sim_state(h, &node, 1, e1, &none);
        CHECK(check_ack(&node, node.boot, node.seq, SB_ACK_OK), "NONE value accepted");
        rev_t *t = ev_find(SB_EVT_STATE, slot, 1);
        CHECK(t && t->value.type == SB_V_NONE, "NONE state event");
        // STR round-trip (entity 6 is a text_sensor).
        sb_value_t sv = {.type = SB_V_STR, .s = {.p = (const uint8_t *)"deep sleep ok", .len = 13}};
        const uint8_t e6[1] = {6};
        sim_state(h, &node, 1, e6, &sv);
        CHECK(check_ack(&node, node.boot, node.seq, SB_ACK_OK), "STR state accepted");
        rev_t *r6 = ev_find(SB_EVT_STATE, slot, 6);
        CHECK(r6 && r6->value.type == SB_V_STR && r6->value.s.len == 13 &&
                  memcmp(r6->value.s.p, "deep sleep ok", 13) == 0, "STR state value");

        // Schema replacement: same entity ids, different bytes.
        uint8_t blob2[SB_MAX_SCHEMA];
        memcpy(blob2, blob, blen);
        blob2[3] ^= 0x20; // change node_name
        uint32_t hash2;
        sb_hub_node_view_t v;
        sb_schema_hash(blob2, blen, &hash2);
        CHECK(hash2 != hash, "second schema differs");
        sb_value_t tv = {.type = SB_V_F32, .f = 30.0f};
        sim_state(h, &node, 1, e1, &tv);
        g_nev = 0;
        sim_hello(h, &node, hash2, 90);
        CHECK(check_ack(&node, node.boot, node.seq, SB_ACK_NEED_DESCRIBE), "schema change detected");
        g_fail_next_put = true;
        sim_describe(h, &node, 8, blob2, blen);
        CHECK(check_ack(&node, node.boot, node.seq, SB_ACK_BUSY), "schema store failure is retryable");
        CHECK(sb_hub_node(h, slot, &v) && v.schema_hash == hash, "old schema kept on store failure");
        sim_describe(h, &node, 9, blob2, blen);
        CHECK(check_ack(&node, node.boot, node.seq, SB_ACK_OK), "replaced schema");
        CHECK(ev_count(SB_EVT_NODE) == 1, "NODE event on replacement");
        CHECK(sb_hub_node(h, slot, &v) && v.has_schema && v.schema_hash == hash2 &&
                  v.values[0].type == SB_V_NONE, "new schema active, values reset");

        // DESCRIBE timeout: a stalled transfer is discarded; a fresh one works.
        uint8_t cnt = (uint8_t)((blen + SB_MAX_DESCRIBE_DATA - 1) / SB_MAX_DESCRIBE_DATA);
        sb_frame_t f = {.type = SB_MSG_DESCRIBE, .flags = SB_FLAG_ACK_REQ};
        f.u.describe = (sb_describe_t){
            .xfer = 11, .index = 0, .count = cnt, .total = (uint16_t)blen, .hash = hash,
            .data = blob, .data_len = SB_MAX_DESCRIBE_DATA,
        };
        uint8_t buf[SB_MAX_FRAME];
        size_t n = sim_seal(&node, &f, buf);
        hub_rx(h, &node, buf, n);
        CHECK(check_ack(&node, node.boot, node.seq, SB_ACK_OK), "chunk 0 ok");
        g_now += SB_HUB_DESCRIBE_TIMEOUT_MS + 1;
        sb_hub_tick(h);
        sim_describe(h, &node, 11, blob, blen); // fresh transfer, same id
        CHECK(check_ack(&node, node.boot, node.seq, SB_ACK_OK), "transfer after timeout");
        CHECK(sb_hub_node(h, slot, &v) && v.schema_hash == hash, "original schema back");

        // Rollback of an enrolled re-pair: node keeps working under old keys.
        uint8_t old_epoch = node.epoch, old_mac[6], old_lmk[16], old_kmic[16];
        memcpy(old_mac, node.mac, 6);
        memcpy(old_lmk, node.lmk, 16);
        memcpy(old_kmic, node.k_mic, 16);
        CHECK(sb_hub_pair_open(h, slot, 30000) == 0, "open re-pair window");
        g_nev = 0;
        node.mac[5] ^= 0x40; // exercise rollback from a changed radio address
        sim_pair_request(h, &node);
        int stx;
        uint8_t epx;
        CHECK(sim_pair_response(&node, &stx, &epx), "re-pair response (rollback case)");
        pump(h);
        CHECK(!find_peer(old_mac) && find_peer(node.mac), "pending peer replaced old peer");
        g_now += SB_HUB_PAIR_CONFIRM_MS + 1;
        sb_hub_tick(h);
        CHECK(g_nev >= 1 && g_ev[g_nev - 1].kind == SB_EVT_PAIR &&
                  g_ev[g_nev - 1].pair == SB_PAIR_FAILED, "PAIR_FAILED emitted");
        CHECK(find_peer(old_mac) && find_peer(old_mac)->encrypted && !find_peer(node.mac),
              "rollback restores only old peer");
        memcpy(node.mac, old_mac, 6);
        node.epoch = old_epoch;
        memcpy(node.lmk, old_lmk, 16);
        memcpy(node.k_mic, old_kmic, 16);
        g_nev = 0;
        sim_state(h, &node, 1, e1, &tv);
        CHECK(check_ack(&node, node.boot, node.seq, SB_ACK_OK), "old keys work after rollback");
        CHECK(ev_count(SB_EVT_STATE) == 1, "state after rollback");

        // The exact PAIR_RESPONSE completion failing rolls back immediately.
        CHECK(sb_hub_pair_open(h, slot, 30000) == 0, "window for failed send");
        g_nev = 0;
        sim_pair_request(h, &node);
        CHECK(sim_pair_response(&node, &stx, &epx), "response before failed send");
        sent_t *pair_send = last_to(node.mac);
        CHECK(pair_send, "pair send captured");
        if (pair_send) sb_hub_on_send_done(h, pair_send->token, false);
        CHECK(g_nev >= 1 && g_ev[g_nev - 1].kind == SB_EVT_PAIR &&
                  g_ev[g_nev - 1].pair == SB_PAIR_FAILED,
              "failed pair send rolls back");
        node.epoch = old_epoch;
        memcpy(node.lmk, old_lmk, 16);
        memcpy(node.k_mic, old_kmic, 16);

        // A failed durable commit leaves the old enrollment intact and sends no ACK.
        CHECK(sb_hub_pair_open(h, slot, 30000) == 0, "window for failed commit");
        sim_pair_request(h, &node);
        CHECK(sim_pair_response(&node, &stx, &epx), "response before failed commit");
        pump(h);
        sb_hub_stats_t before_fail = sb_hub_stats(h);
        g_fail_next_put = true;
        sim_hello(h, &node, hash, 60);
        CHECK(sb_hub_stats(h).acks == before_fail.acks, "failed commit sends no ACK");
        CHECK(sb_hub_stats(h).store_fail == before_fail.store_fail + 1 &&
                  sb_hub_stats(h).pair_failed == before_fail.pair_failed + 1,
              "failed commit counted");
        CHECK(sb_hub_node(h, slot, &v) && v.epoch == old_epoch && v.generation == 2,
              "failed commit restores enrollment");
        node.epoch = old_epoch;
        memcpy(node.lmk, old_lmk, 16);
        memcpy(node.k_mic, old_kmic, 16);

        // Idempotent retry: same slot + nonce must derive identical keys.
        CHECK(sb_hub_pair_open(h, slot, 30000) == 0, "window for idempotent retry");
        sim_pair_request(h, &node);
        uint8_t lmk1[16], kmic1[16];
        CHECK(sim_pair_response(&node, &stx, &epx), "first response");
        memcpy(lmk1, node.lmk, 16);
        memcpy(kmic1, node.k_mic, 16);
        pump(h);
        uint8_t saved_nonce[16];
        memcpy(saved_nonce, node.node_nonce, 16);
        sim_pair_request_nonce(h, &node, saved_nonce);
        CHECK(sim_pair_response(&node, &stx, &epx), "retry response");
        CHECK(memcmp(lmk1, node.lmk, 16) == 0 && memcmp(kmic1, node.k_mic, 16) == 0,
              "same keys on same-nonce retry");
        sim_hello(h, &node, hash, 60);
        CHECK(sb_hub_node(h, slot, &v) && v.epoch == epx, "idempotent pairing commits");
    }

    // Window guards: closed window ignores requests; bad tag ignored;
    // wrong source MAC vs body ignored; second candidate blocked while pending.
    {
        sim_t other;
        sim_init(&other, 0x02);
        uint8_t k2[16];
        int s2 = sb_hub_node_add(h, k2);
        CHECK(s2 == 1, "second slot");
        // Window auto-opened for slot 1 by node_add; `other` is not that slot's key.
        sb_hub_pair_close(h);
        sb_hub_stats_t st0 = sb_hub_stats(h);
        sim_pair_request(h, &other);
        CHECK(sb_hub_stats(h).pair_ignored == st0.pair_ignored + 1, "closed window ignored");
        CHECK(sb_hub_pair_open(h, s2, 30000) == 0, "reopen for slot 1");
        // Wrong tag: flip one byte of the request after sealing.
        memcpy(other.k_node, k2, 16);
        g_nsent = 0;
        sb_frame_t f = {.type = SB_MSG_PAIR_REQUEST, .boot = 1, .seq = 1};
        sb_key_id(k2, f.u.pair_req.key_id);
        memcpy(f.u.pair_req.mac, other.mac, 6);
        f_random(NULL, other.node_nonce, 16);
        memcpy(f.u.pair_req.nonce, other.node_nonce, 16);
        uint8_t buf[SB_MAX_FRAME], tag[16];
        size_t n = 0;
        sb_encode(&f, buf, SB_MAX_FRAME, &n);
        sb_request_tag(k2, buf, n - SB_TAG_LEN, tag);
        memcpy(buf + n - SB_TAG_LEN, tag, SB_TAG_LEN);
        buf[SB_HEADER_LEN] ^= 0xff; // corrupt key_id -> wrong tag
        sb_hub_on_rx(h, other.mac, -40, buf, n);
        CHECK(g_nsent == 0, "bad tag ignored");
        // MAC mismatch: body says other.mac, source is node.mac.
        g_nsent = 0;
        sim_pair_request(h, &other); // correct, from other.mac
        CHECK(g_nsent == 1, "valid request answered");
        CHECK(sim_pair_response(&other, &st, &ep) && ep == 1, "other gets keys");
        pump(h);
        // While `other` is pending, a third request for slot 0 is ignored.
        sim_t third;
        sim_init(&third, 0x03);
        memcpy(third.k_node, key, 16);
        CHECK(sb_hub_pair_open(h, slot, 30000) == 0, "open slot 0 too");
        g_nsent = 0;
        sim_pair_request(h, &third);
        CHECK(g_nsent == 0, "one pairing at a time");
        // Timeout: pending rolls back, third can proceed.
        g_now += SB_HUB_PAIR_CONFIRM_MS + 1;
        sb_hub_tick(h);
        g_nsent = 0;
        sim_pair_request(h, &third);
        CHECK(g_nsent == 1, "after rollback, third served");
        // Leave no pending pairing behind for later blocks.
        g_now += SB_HUB_PAIR_CONFIRM_MS + 1;
        sb_hub_tick(h);
    }

    // DESCRIBE negatives: bad chunk size; completion with wrong content hash.
    {
        sim_t nd;
        sim_init(&nd, 0x09);
        uint8_t k9[16];
        int s9 = sb_hub_node_add(h, k9);
        memcpy(nd.k_node, k9, 16);
        sim_pair_request(h, &nd);
        int st9;
        uint8_t ep9;
        CHECK(sim_pair_response(&nd, &st9, &ep9) && st9 == SB_PAIR_ACCEPTED, "nd paired");
        pump(h);
        sim_hello(h, &nd, hash, 60);
        uint8_t b2[SB_MAX_SCHEMA];
        size_t l2 = demo_blob(b2);
        b2[10] ^= 0xff; // content differs from the announced (clean) hash
        uint8_t cnt = (uint8_t)((l2 + SB_MAX_DESCRIBE_DATA - 1) / SB_MAX_DESCRIBE_DATA);
        for (uint8_t i = 0; i < cnt; i++) {
            size_t off = (size_t)i * SB_MAX_DESCRIBE_DATA;
            uint16_t len = (uint16_t)((i + 1 == cnt) ? l2 - off : SB_MAX_DESCRIBE_DATA);
            sb_frame_t f = {.type = SB_MSG_DESCRIBE, .flags = SB_FLAG_ACK_REQ};
            f.u.describe = (sb_describe_t){
                .xfer = 1, .index = i, .count = cnt, .total = (uint16_t)l2, .hash = hash,
                .data = b2 + off, .data_len = (uint8_t)len,
            };
            uint8_t buf[SB_MAX_FRAME];
            size_t n = sim_seal(&nd, &f, buf);
            hub_rx(h, &nd, buf, n);
        }
        CHECK(check_ack(&nd, nd.boot, nd.seq, SB_ACK_MALFORMED), "hash mismatch -> MALFORMED");
        sb_hub_node_view_t v;
        CHECK(sb_hub_node(h, s9, &v) && !v.has_schema, "no schema installed");
        // Short middle chunk (fixed chunk size violated).
        CHECK(sb_hub_pair_open(h, s9, 30000) == 0, "reopen window for nd");
        sim_pair_request(h, &nd); // same slot: restarts exchange
        CHECK(sim_pair_response(&nd, &st9, &ep9), "nd re-pair response");
        pump(h);
        sim_hello(h, &nd, hash, 60);
        g_nsent = 0;
        uint8_t pl[9 + 100];
        pl[0] = 2; // xfer
        pl[1] = 0; // index
        pl[2] = 2; // count
        pl[3] = (uint8_t)l2;
        pl[4] = (uint8_t)(l2 >> 8);
        memcpy(pl + 5, &(uint32_t){hash}, 4);
        memcpy(pl + 9, blob, 100); // short middle chunk (should be CHUNK bytes)
        uint8_t buf[SB_MAX_FRAME];
        size_t n = raw_frame(&nd, SB_MSG_DESCRIBE, SB_FLAG_ACK_REQ, pl, sizeof pl, buf);
        hub_rx(h, &nd, buf, n);
        CHECK(check_ack(&nd, nd.boot, nd.seq, SB_ACK_MALFORMED), "bad chunk size");
        // Correct transfer then works.
        CHECK(sb_hub_pair_open(h, s9, 30000) == 0, "reopen window for nd again");
        sim_pair_request(h, &nd);
        CHECK(sim_pair_response(&nd, &st9, &ep9), "nd re-pair response 2");
        pump(h);
        sim_hello(h, &nd, hash, 60);
        sim_describe(h, &nd, 3, blob, blen);
        sb_hub_node_view_t v2;
        CHECK(sb_hub_node(h, s9, &v2) && v2.has_schema, "schema after good transfer");
    }

    // Capacity: fill to 17 nodes, 18th refused; remove works.
    {
        int pre = 0;
        for (int i = 0; i < SB_HUB_MAX_NODES; i++) {
            sb_hub_node_view_t pv;
            if (sb_hub_node(h, i, &pv) && pv.state != SB_NODE_EMPTY) pre++;
        }
        CHECK(pre == 3, "pre-occupied %d", pre); // node, other, nd
        int added = 0;
        for (int i = 0; i < SB_HUB_MAX_NODES + 2; i++) {
            uint8_t k[16];
            int s = sb_hub_node_add(h, k);
            if (s >= 0) added++;
            else break;
        }
        CHECK(added == SB_HUB_MAX_NODES - pre, "filled to %d", pre + added);
        uint8_t k[16];
        CHECK(sb_hub_node_add(h, k) == SB_HUB_ERR_FULL, "hub full");
        g_fail_next_del = true;
        CHECK(sb_hub_node_remove(h, 0) == SB_HUB_ERR_STORE, "failed durable removal reported");
        sb_hub_node_view_t kept;
        CHECK(sb_hub_node(h, 0, &kept) && kept.state == SB_NODE_ENROLLED,
              "failed removal keeps node active");
        uint64_t removed_id = kept.node_id;
        uint32_t removed_generation = kept.generation;
        g_nev = 0;
        snprintf(g_fail_del_key, sizeof g_fail_del_key, "sb/s%d", 0);
        CHECK(sb_hub_node_remove(h, 0) == 0, "remove slot 0");
        CHECK(find_entry("sb/n0") == NULL, "node record removed before schema cleanup");
        CHECK(find_entry("sb/s0") != NULL, "failed schema cleanup is best effort");
        CHECK(g_nev == 1 && g_ev[0].kind == SB_EVT_NODE && g_ev[0].tombstone &&
                  g_ev[0].node_id == removed_id && g_ev[0].generation == removed_generation,
              "removal event preserves tombstone identity");
        sim_t replacement;
        sim_init(&replacement, 0x0a);
        int reused = sb_hub_node_add(h, k);
        CHECK(reused == 0, "space freed and slot reused");
        memcpy(replacement.k_node, k, sizeof k);
        sim_pair_request(h, &replacement);
        int replacement_status;
        uint8_t replacement_epoch;
        CHECK(sim_pair_response(&replacement, &replacement_status, &replacement_epoch),
              "replacement pair response");
        pump(h);
        sim_hello(h, &replacement, hash, 60);
        CHECK(check_ack(&replacement, replacement.boot, replacement.seq, SB_ACK_NEED_DESCRIBE),
              "replacement does not inherit stale schema");
        sb_hub_destroy(h);
        h = sb_hub_create(&g_cfg, &g_ops);
        sb_hub_node_view_t replacement_view;
        CHECK(sb_hub_node(h, reused, &replacement_view) &&
                  replacement_view.state == SB_NODE_ENROLLED && !replacement_view.has_schema,
              "stale schema rejected after slot reuse and restart");
        sb_hub_stats_t st0 = sb_hub_stats(h);
        sb_frame_t hbf = {.type = SB_MSG_HEARTBEAT};
        uint8_t hb[SB_MAX_FRAME];
        size_t hbn = sim_seal(&node, &hbf, hb); // node.mac was slot 0's enrollee
        hub_rx(h, &node, hb, hbn);
        CHECK(sb_hub_stats(h).rx_unknown == st0.rx_unknown + 1, "removed node is unknown");
        CHECK(find_peer(node.mac) == NULL || !find_peer(node.mac)->present, "peer deleted");
    }


    // Key-only node survives a hub restart (record restored, window closed).
    {
        CHECK(sb_hub_node_remove(h, 3) == 0, "free a slot");
        uint8_t k4[16];
        int s4 = sb_hub_node_add(h, k4);
        sb_hub_destroy(h);
        h = sb_hub_create(&g_cfg, &g_ops);
        sb_hub_node_view_t v;
        CHECK(sb_hub_node(h, s4, &v) && v.state == SB_NODE_KEY_ONLY, "key-only restored");
        CHECK(sb_hub_pair_open(h, s4, 30000) == 0, "can open window for restored slot");
    }

    sb_hub_destroy(h);
    if (failures) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    puts("all hub tests passed");
    return 0;
}
