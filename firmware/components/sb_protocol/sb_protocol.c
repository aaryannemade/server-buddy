// Server Buddy protocol v1 codec. Validation order mirrors
// protocol/python/sb_protocol/codec.py exactly (golden vectors depend on it).
#include "sb_protocol.h"

#include <math.h>
#include <string.h>

// ------------------------------------------------------------------ reader

typedef struct {
    const uint8_t *p;
    size_t len, pos;
    sb_err_t err;
} rd_t;

static const uint8_t *rd_take(rd_t *r, size_t n)
{
    if (r->err) return NULL;
    if (n > r->len - r->pos) {
        r->err = SB_ERR_BAD_LENGTH;
        return NULL;
    }
    const uint8_t *out = r->p + r->pos;
    r->pos += n;
    return out;
}

static uint8_t rd_u8(rd_t *r)
{
    const uint8_t *p = rd_take(r, 1);
    return p ? p[0] : 0;
}

static uint16_t rd_u16(rd_t *r)
{
    const uint8_t *p = rd_take(r, 2);
    return p ? (uint16_t)(p[0] | (p[1] << 8)) : 0;
}

static uint32_t rd_u32(rd_t *r)
{
    const uint8_t *p = rd_take(r, 4);
    return p ? (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
                   ((uint32_t)p[3] << 24)
             : 0;
}

static void rd_copy(rd_t *r, uint8_t *dst, size_t n)
{
    const uint8_t *p = rd_take(r, n);
    if (p) memcpy(dst, p, n);
}

static void fail(rd_t *r, sb_err_t e)
{
    if (!r->err) r->err = e;
}

static sb_str_t rd_str(rd_t *r)
{
    sb_str_t s = {0};
    uint8_t n = rd_u8(r);
    if (r->err) return s;
    if (n > SB_MAX_STR) {
        fail(r, SB_ERR_BAD_STRING);
        return s;
    }
    const uint8_t *p = rd_take(r, n);
    if (!p) return s;
    if (!sb_utf8_valid(p, n)) {
        fail(r, SB_ERR_BAD_STRING);
        return s;
    }
    s.p = p;
    s.len = n;
    return s;
}

static void rd_end(rd_t *r)
{
    if (!r->err && r->pos != r->len) r->err = SB_ERR_BAD_LENGTH;
}

bool sb_utf8_valid(const uint8_t *p, size_t len)
{
    size_t i = 0;
    while (i < len) {
        uint8_t c = p[i];
        if (c == 0) return false;
        if (c < 0x80) {
            i++;
            continue;
        }
        size_t n;
        uint32_t cp, min;
        if ((c & 0xE0) == 0xC0) {
            n = 1, cp = c & 0x1F, min = 0x80;
        } else if ((c & 0xF0) == 0xE0) {
            n = 2, cp = c & 0x0F, min = 0x800;
        } else if ((c & 0xF8) == 0xF0) {
            n = 3, cp = c & 0x07, min = 0x10000;
        } else {
            return false;
        }
        if (n > len - i - 1) return false;
        for (size_t k = 1; k <= n; k++) {
            if ((p[i + k] & 0xC0) != 0x80) return false;
            cp = (cp << 6) | (p[i + k] & 0x3F);
        }
        if (cp < min || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return false;
        i += n + 1;
    }
    return true;
}

static sb_value_t rd_value(rd_t *r)
{
    sb_value_t v;
    memset(&v, 0, sizeof v);
    uint8_t t = rd_u8(r);
    if (r->err) return v;
    if (t > SB_V_STR) {
        fail(r, SB_ERR_BAD_VALUE);
        return v;
    }
    v.type = t;
    switch (t) {
    case SB_V_NONE:
        break;
    case SB_V_BOOL: {
        uint8_t b = rd_u8(r);
        if (!r->err && b > 1) fail(r, SB_ERR_BAD_VALUE);
        v.b = b == 1;
        break;
    }
    case SB_V_I32:
        v.i = (int32_t)rd_u32(r);
        break;
    case SB_V_U32:
        v.u = rd_u32(r);
        break;
    case SB_V_F32: {
        uint32_t bits = rd_u32(r);
        memcpy(&v.f, &bits, 4);
        if (!r->err && !isfinite(v.f)) fail(r, SB_ERR_BAD_VALUE);
        break;
    }
    case SB_V_ENUM:
        v.e = rd_u8(r);
        break;
    case SB_V_STR:
        v.s = rd_str(r);
        break;
    }
    return v;
}

// ------------------------------------------------------------------ decode

bool sb_has_mic(uint8_t type)
{
    return type != SB_MSG_PAIR_REQUEST && type != SB_MSG_PAIR_RESPONSE;
}

static bool ack_req_allowed(uint8_t type)
{
    switch (type) {
    case SB_MSG_HELLO:
    case SB_MSG_DESCRIBE:
    case SB_MSG_STATE:
    case SB_MSG_EVENT:
    case SB_MSG_HEARTBEAT:
    case SB_MSG_ERROR:
        return true;
    default:
        return false;
    }
}

sb_err_t sb_decode(const uint8_t *buf, size_t len, sb_frame_t *f)
{
    memset(f, 0, sizeof *f);
    if (len > SB_MAX_FRAME) return SB_ERR_TOO_LARGE;
    if (len < SB_HEADER_LEN) return SB_ERR_TRUNCATED;
    if (buf[0] != 'S' || buf[1] != 'B') return SB_ERR_BAD_MAGIC;
    if (buf[2] != SB_VERSION) return SB_ERR_BAD_VERSION;
    rd_t h = {buf, len, 3, SB_OK};
    f->type = rd_u8(&h);
    f->flags = rd_u8(&h);
    f->epoch = rd_u8(&h);
    f->boot = rd_u32(&h);
    f->seq = rd_u32(&h);
    uint16_t plen = rd_u16(&h);
    if (f->type < SB_MSG_HELLO || f->type > SB_MSG_ERROR) return SB_ERR_BAD_TYPE;
    if (f->type == SB_MSG_COMMAND) return SB_ERR_UNSUPPORTED;
    size_t mic = sb_has_mic(f->type) ? SB_MIC_LEN : 0;
    if ((size_t)SB_HEADER_LEN + plen + mic != len) return SB_ERR_BAD_LENGTH;
    if ((f->flags & ~(SB_FLAG_ACK_REQ | SB_FLAG_FULL_STATE)) ||
        ((f->flags & SB_FLAG_ACK_REQ) && !ack_req_allowed(f->type)) ||
        ((f->flags & SB_FLAG_FULL_STATE) && f->type != SB_MSG_STATE))
        return SB_ERR_BAD_FLAGS;
    if (mic) memcpy(f->mic, buf + SB_HEADER_LEN + plen, SB_MIC_LEN);

    rd_t r = {buf + SB_HEADER_LEN, plen, 0, SB_OK};
    switch (f->type) {
    case SB_MSG_HELLO:
        f->u.hello.schema_hash = rd_u32(&r);
        f->u.hello.interval = rd_u16(&r);
        f->u.hello.reason = rd_u8(&r);
        f->u.hello.hflags = rd_u8(&r);
        if (!r.err && (f->u.hello.reason > 5 || (f->u.hello.hflags & ~0x01))) fail(&r, SB_ERR_BAD_VALUE);
        break;
    case SB_MSG_DESCRIBE:
        f->u.describe.xfer = rd_u8(&r);
        f->u.describe.index = rd_u8(&r);
        f->u.describe.count = rd_u8(&r);
        f->u.describe.total = rd_u16(&r);
        f->u.describe.hash = rd_u32(&r);
        if (r.err) break;
        f->u.describe.data_len = (uint8_t)(r.len - r.pos);
        f->u.describe.data = rd_take(&r, f->u.describe.data_len);
        if (f->u.describe.count < 1 || f->u.describe.count > SB_MAX_DESCRIBE_CHUNKS ||
            f->u.describe.index >= f->u.describe.count || f->u.describe.total < 1 ||
            f->u.describe.total > SB_MAX_SCHEMA || f->u.describe.data_len == 0)
            fail(&r, SB_ERR_BAD_VALUE);
        break;
    case SB_MSG_STATE: {
        uint8_t n = rd_u8(&r);
        if (r.err) break;
        if (n < 1 || n > SB_MAX_STATE_ENTRIES) {
            fail(&r, SB_ERR_BAD_VALUE);
            break;
        }
        f->u.state.n = n;
        for (uint8_t i = 0; i < n && !r.err; i++) {
            f->u.state.e[i].entity = rd_u8(&r);
            f->u.state.e[i].value = rd_value(&r);
        }
        for (uint8_t i = 0; i < n && !r.err; i++)
            for (uint8_t j = i + 1; j < n; j++)
                if (f->u.state.e[i].entity == f->u.state.e[j].entity) fail(&r, SB_ERR_BAD_VALUE);
        break;
    }
    case SB_MSG_EVENT:
        f->u.event.entity = rd_u8(&r);
        f->u.event.etype = rd_u8(&r);
        f->u.event.oboot = rd_u32(&r);
        f->u.event.evno = rd_u16(&r);
        f->u.event.value = rd_value(&r);
        break;
    case SB_MSG_ACK:
        f->u.ack.aboot = rd_u32(&r);
        f->u.ack.aseq = rd_u32(&r);
        f->u.ack.status = rd_u8(&r);
        f->u.ack.channel = rd_u8(&r);
        f->u.ack.time = rd_u32(&r);
        if (!r.err && f->u.ack.status > SB_ACK_BUSY) fail(&r, SB_ERR_BAD_VALUE);
        break;
    case SB_MSG_PAIR_REQUEST:
        rd_copy(&r, f->u.pair_req.key_id, 4);
        rd_copy(&r, f->u.pair_req.mac, 6);
        rd_copy(&r, f->u.pair_req.nonce, 16);
        rd_copy(&r, f->u.pair_req.tag, 16);
        if (!r.err && f->epoch != 0) fail(&r, SB_ERR_BAD_VALUE);
        break;
    case SB_MSG_PAIR_RESPONSE:
        f->u.pair_resp.status = rd_u8(&r);
        rd_copy(&r, f->u.pair_resp.mac, 6);
        rd_copy(&r, f->u.pair_resp.nonce, 16);
        f->u.pair_resp.channel = rd_u8(&r);
        f->u.pair_resp.pepoch = rd_u8(&r);
        rd_copy(&r, f->u.pair_resp.tag, 16);
        if (!r.err && (f->epoch != 0 || f->u.pair_resp.status > SB_PAIR_HUB_FULL ||
                       (f->u.pair_resp.status == SB_PAIR_ACCEPTED && f->u.pair_resp.pepoch == 0)))
            fail(&r, SB_ERR_BAD_VALUE);
        break;
    case SB_MSG_HEARTBEAT:
        break;
    case SB_MSG_ERROR:
        f->u.error.code = rd_u8(&r);
        f->u.error.detail = rd_str(&r);
        break;
    }
    rd_end(&r);
    return r.err;
}

// ------------------------------------------------------------------ writer

typedef struct {
    uint8_t *p;
    size_t cap, pos;
    sb_err_t err;
} wr_t;

static void wr_bytes(wr_t *w, const void *src, size_t n)
{
    if (w->err) return;
    if (n > w->cap - w->pos) {
        w->err = SB_ERR_NO_SPACE;
        return;
    }
    if (n) memcpy(w->p + w->pos, src, n);
    w->pos += n;
}

static void wr_u8(wr_t *w, uint8_t v) { wr_bytes(w, &v, 1); }

static void wr_u16(wr_t *w, uint16_t v)
{
    uint8_t b[2] = {(uint8_t)v, (uint8_t)(v >> 8)};
    wr_bytes(w, b, 2);
}

static void wr_u32(wr_t *w, uint32_t v)
{
    uint8_t b[4] = {(uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16), (uint8_t)(v >> 24)};
    wr_bytes(w, b, 4);
}

static void wr_str(wr_t *w, sb_str_t s)
{
    if (!w->err && (s.len > SB_MAX_STR || (s.len && !s.p))) w->err = SB_ERR_BAD_STRING;
    wr_u8(w, s.len);
    wr_bytes(w, s.p, s.len);
}

static void wr_value(wr_t *w, const sb_value_t *v)
{
    wr_u8(w, v->type);
    switch (v->type) {
    case SB_V_NONE:
        break;
    case SB_V_BOOL:
        wr_u8(w, v->b ? 1 : 0);
        break;
    case SB_V_I32:
        wr_u32(w, (uint32_t)v->i);
        break;
    case SB_V_U32:
        wr_u32(w, v->u);
        break;
    case SB_V_F32: {
        uint32_t bits;
        memcpy(&bits, &v->f, 4);
        wr_u32(w, bits);
        break;
    }
    case SB_V_ENUM:
        wr_u8(w, v->e);
        break;
    case SB_V_STR:
        wr_str(w, v->s);
        break;
    default:
        if (!w->err) w->err = SB_ERR_BAD_VALUE;
    }
}

sb_err_t sb_encode(const sb_frame_t *f, uint8_t *out, size_t cap, size_t *out_len)
{
    wr_t w = {out, cap, 0, SB_OK};
    wr_bytes(&w, "SB", 2);
    wr_u8(&w, SB_VERSION);
    wr_u8(&w, f->type);
    wr_u8(&w, f->flags);
    wr_u8(&w, f->epoch);
    wr_u32(&w, f->boot);
    wr_u32(&w, f->seq);
    wr_u16(&w, 0); // patched below
    switch (f->type) {
    case SB_MSG_HELLO:
        wr_u32(&w, f->u.hello.schema_hash);
        wr_u16(&w, f->u.hello.interval);
        wr_u8(&w, f->u.hello.reason);
        wr_u8(&w, f->u.hello.hflags);
        break;
    case SB_MSG_DESCRIBE:
        wr_u8(&w, f->u.describe.xfer);
        wr_u8(&w, f->u.describe.index);
        wr_u8(&w, f->u.describe.count);
        wr_u16(&w, f->u.describe.total);
        wr_u32(&w, f->u.describe.hash);
        wr_bytes(&w, f->u.describe.data, f->u.describe.data_len);
        break;
    case SB_MSG_STATE:
        if (f->u.state.n > SB_MAX_STATE_ENTRIES) return SB_ERR_BAD_VALUE;
        wr_u8(&w, f->u.state.n);
        for (uint8_t i = 0; i < f->u.state.n; i++) {
            wr_u8(&w, f->u.state.e[i].entity);
            wr_value(&w, &f->u.state.e[i].value);
        }
        break;
    case SB_MSG_EVENT:
        wr_u8(&w, f->u.event.entity);
        wr_u8(&w, f->u.event.etype);
        wr_u32(&w, f->u.event.oboot);
        wr_u16(&w, f->u.event.evno);
        wr_value(&w, &f->u.event.value);
        break;
    case SB_MSG_ACK:
        wr_u32(&w, f->u.ack.aboot);
        wr_u32(&w, f->u.ack.aseq);
        wr_u8(&w, f->u.ack.status);
        wr_u8(&w, f->u.ack.channel);
        wr_u32(&w, f->u.ack.time);
        break;
    case SB_MSG_PAIR_REQUEST:
        wr_bytes(&w, f->u.pair_req.key_id, 4);
        wr_bytes(&w, f->u.pair_req.mac, 6);
        wr_bytes(&w, f->u.pair_req.nonce, 16);
        wr_bytes(&w, f->u.pair_req.tag, 16);
        break;
    case SB_MSG_PAIR_RESPONSE:
        wr_u8(&w, f->u.pair_resp.status);
        wr_bytes(&w, f->u.pair_resp.mac, 6);
        wr_bytes(&w, f->u.pair_resp.nonce, 16);
        wr_u8(&w, f->u.pair_resp.channel);
        wr_u8(&w, f->u.pair_resp.pepoch);
        wr_bytes(&w, f->u.pair_resp.tag, 16);
        break;
    case SB_MSG_HEARTBEAT:
        break;
    case SB_MSG_ERROR:
        wr_u8(&w, f->u.error.code);
        wr_str(&w, f->u.error.detail);
        break;
    default:
        return SB_ERR_UNSUPPORTED;
    }
    if (w.err) return w.err;
    size_t plen = w.pos - SB_HEADER_LEN;
    if (sb_has_mic(f->type)) wr_bytes(&w, f->mic, SB_MIC_LEN);
    if (w.err) return w.err;
    if (w.pos > SB_MAX_FRAME) return SB_ERR_TOO_LARGE;
    out[14] = (uint8_t)plen;
    out[15] = (uint8_t)(plen >> 8);

    sb_frame_t check;
    sb_err_t err = sb_decode(out, w.pos, &check);
    if (err) return err;
    *out_len = w.pos;
    return SB_OK;
}

// ------------------------------------------------------------------ schema

static bool object_id_valid(sb_str_t s)
{
    if (s.len < 1 || s.len > SB_MAX_OBJECT_ID) return false;
    for (uint8_t i = 0; i < s.len; i++) {
        uint8_t c = s.p[i];
        if (!(c == '_' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z'))) return false;
    }
    return true;
}

sb_err_t sb_decode_schema(const uint8_t *buf, size_t len, sb_schema_t *s)
{
    memset(s, 0, sizeof *s);
    if (len > SB_MAX_SCHEMA) return SB_ERR_TOO_LARGE;
    rd_t r = {buf, len, 0, SB_OK};
    s->node_name = rd_str(&r);
    s->model = rd_str(&r);
    s->fw_version = rd_str(&r);
    uint8_t n = rd_u8(&r);
    if (r.err) return r.err;
    if (n < 1 || n > SB_MAX_ENTITIES) return SB_ERR_BAD_VALUE;
    s->n = n;
    for (uint8_t i = 0; i < n; i++) {
        sb_entity_t *e = &s->e[i];
        e->entity = rd_u8(&r);
        e->platform = rd_u8(&r);
        e->value_type = rd_u8(&r);
        e->state_class = rd_u8(&r);
        e->accuracy = (int8_t)rd_u8(&r);
        e->flags = rd_u8(&r);
        e->object_id = rd_str(&r);
        e->name = rd_str(&r);
        e->unit = rd_str(&r);
        e->device_class = rd_str(&r);
        e->extra = rd_str(&r);
        if (r.err) return r.err;
        if (e->platform < 1 || e->platform > 4 || e->value_type < SB_V_BOOL ||
            e->value_type > SB_V_STR || e->state_class > 3 || (e->flags & ~0x01))
            return SB_ERR_BAD_VALUE;
        if (!object_id_valid(e->object_id)) return SB_ERR_BAD_STRING;
    }
    for (uint8_t i = 0; i < n; i++)
        for (uint8_t j = i + 1; j < n; j++)
            if (s->e[i].entity == s->e[j].entity) return SB_ERR_BAD_VALUE;
    rd_end(&r);
    return r.err;
}

sb_err_t sb_encode_schema(const sb_schema_t *s, uint8_t *out, size_t cap, size_t *out_len)
{
    if (s->n > SB_MAX_ENTITIES) return SB_ERR_BAD_VALUE;
    wr_t w = {out, cap, 0, SB_OK};
    wr_str(&w, s->node_name);
    wr_str(&w, s->model);
    wr_str(&w, s->fw_version);
    wr_u8(&w, s->n);
    for (uint8_t i = 0; i < s->n; i++) {
        const sb_entity_t *e = &s->e[i];
        wr_u8(&w, e->entity);
        wr_u8(&w, e->platform);
        wr_u8(&w, e->value_type);
        wr_u8(&w, e->state_class);
        wr_u8(&w, (uint8_t)e->accuracy);
        wr_u8(&w, e->flags);
        wr_str(&w, e->object_id);
        wr_str(&w, e->name);
        wr_str(&w, e->unit);
        wr_str(&w, e->device_class);
        wr_str(&w, e->extra);
    }
    if (w.err) return w.err;
    sb_schema_t check;
    sb_err_t err = sb_decode_schema(out, w.pos, &check);
    if (err) return err;
    *out_len = w.pos;
    return SB_OK;
}

// ------------------------------------------------------------------ names

const char *sb_err_name(sb_err_t err)
{
    static const char *const names[] = {
        "OK",         "TOO_LARGE",   "TRUNCATED", "BAD_MAGIC",  "BAD_VERSION", "BAD_LENGTH",
        "BAD_FLAGS",  "BAD_TYPE",    "UNSUPPORTED", "BAD_VALUE", "BAD_STRING", "NO_SPACE",
    };
    return (unsigned)err < sizeof names / sizeof names[0] ? names[err] : "UNKNOWN";
}

const char *sb_msg_name(uint8_t type)
{
    static const char *const names[] = {
        "?",    "HELLO",        "DESCRIBE",      "STATE",     "EVENT", "ACK",
        "COMMAND", "PAIR_REQUEST", "PAIR_RESPONSE", "HEARTBEAT", "ERROR",
    };
    return type < sizeof names / sizeof names[0] ? names[type] : "?";
}
