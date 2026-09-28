// Canonical text form; must match sb_protocol.codec.describe*() byte-for-byte.
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "sb_protocol.h"

typedef struct {
    char *p;
    size_t cap, pos;
    bool ok;
} out_t;

static void put(out_t *o, const char *fmt, ...)
{
    if (!o->ok) return;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(o->p + o->pos, o->cap - o->pos, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= o->cap - o->pos) {
        o->ok = false;
        return;
    }
    o->pos += (size_t)n;
}

static void hex(out_t *o, const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++) put(o, "%02x", p[i]);
}

static void value(out_t *o, const sb_value_t *v)
{
    switch (v->type) {
    case SB_V_NONE:
        put(o, "N");
        break;
    case SB_V_BOOL:
        put(o, "B:%d", v->b ? 1 : 0);
        break;
    case SB_V_I32:
        put(o, "I:%" PRId32, v->i);
        break;
    case SB_V_U32:
        put(o, "U:%" PRIu32, v->u);
        break;
    case SB_V_F32: {
        uint32_t bits;
        memcpy(&bits, &v->f, 4);
        put(o, "F:%08" PRIx32, bits);
        break;
    }
    case SB_V_ENUM:
        put(o, "E:%u", v->e);
        break;
    case SB_V_STR:
        put(o, "S:");
        hex(o, v->s.p, v->s.len);
        break;
    default:
        o->ok = false;
    }
}

bool sb_describe(const sb_frame_t *f, char *buf, size_t cap)
{
    if (!cap) return false;
    out_t o = {buf, cap, 0, true};
    buf[0] = 0;
    put(&o, "%s f=%02x e=%u b=%" PRIu32 " s=%" PRIu32 " ", sb_msg_name(f->type), f->flags, f->epoch,
        f->boot, f->seq);
    switch (f->type) {
    case SB_MSG_HELLO:
        put(&o, "hash=%08" PRIx32 " int=%u reason=%u hf=%u", f->u.hello.schema_hash, f->u.hello.interval,
            f->u.hello.reason, f->u.hello.hflags);
        break;
    case SB_MSG_DESCRIBE:
        put(&o, "xfer=%u idx=%u cnt=%u total=%u hash=%08" PRIx32 " data=", f->u.describe.xfer,
            f->u.describe.index, f->u.describe.count, f->u.describe.total, f->u.describe.hash);
        hex(&o, f->u.describe.data, f->u.describe.data_len);
        break;
    case SB_MSG_STATE:
        if (f->u.state.n > SB_MAX_STATE_ENTRIES) return false;
        put(&o, "[");
        for (uint8_t i = 0; i < f->u.state.n; i++) {
            put(&o, "%s%u:", i ? "," : "", f->u.state.e[i].entity);
            value(&o, &f->u.state.e[i].value);
        }
        put(&o, "]");
        break;
    case SB_MSG_EVENT:
        put(&o, "ent=%u type=%u oboot=%" PRIu32 " evno=%u val=", f->u.event.entity, f->u.event.etype,
            f->u.event.oboot, f->u.event.evno);
        value(&o, &f->u.event.value);
        break;
    case SB_MSG_ACK:
        put(&o, "aboot=%" PRIu32 " aseq=%" PRIu32 " st=%u ch=%u t=%" PRIu32, f->u.ack.aboot, f->u.ack.aseq,
            f->u.ack.status, f->u.ack.channel, f->u.ack.time);
        break;
    case SB_MSG_PAIR_REQUEST:
        put(&o, "kid=");
        hex(&o, f->u.pair_req.key_id, 4);
        put(&o, " mac=");
        hex(&o, f->u.pair_req.mac, 6);
        put(&o, " nn=");
        hex(&o, f->u.pair_req.nonce, 16);
        put(&o, " tag=");
        hex(&o, f->u.pair_req.tag, 16);
        break;
    case SB_MSG_PAIR_RESPONSE:
        put(&o, "st=%u mac=", f->u.pair_resp.status);
        hex(&o, f->u.pair_resp.mac, 6);
        put(&o, " hn=");
        hex(&o, f->u.pair_resp.nonce, 16);
        put(&o, " ch=%u ep=%u tag=", f->u.pair_resp.channel, f->u.pair_resp.pepoch);
        hex(&o, f->u.pair_resp.tag, 16);
        break;
    case SB_MSG_HEARTBEAT:
        put(&o, "-");
        break;
    case SB_MSG_ERROR:
        put(&o, "code=%u detail=", f->u.error.code);
        hex(&o, f->u.error.detail.p, f->u.error.detail.len);
        break;
    default:
        return false;
    }
    if (sb_has_mic(f->type)) {
        put(&o, " mic=");
        hex(&o, f->mic, SB_MIC_LEN);
    }
    return o.ok;
}

bool sb_describe_schema(const sb_schema_t *s, char *buf, size_t cap)
{
    if (!cap) return false;
    out_t o = {buf, cap, 0, true};
    buf[0] = 0;
    put(&o, "name=");
    hex(&o, s->node_name.p, s->node_name.len);
    put(&o, " model=");
    hex(&o, s->model.p, s->model.len);
    put(&o, " fw=");
    hex(&o, s->fw_version.p, s->fw_version.len);
    if (s->n > SB_MAX_ENTITIES) return false;
    put(&o, " n=%u", s->n);
    for (uint8_t i = 0; i < s->n; i++) {
        const sb_entity_t *e = &s->e[i];
        put(&o, " {%u,%u,%u,%u,%d,%u,", e->entity, e->platform, e->value_type, e->state_class,
            e->accuracy, e->flags);
        const sb_str_t *strs[] = {&e->object_id, &e->name, &e->unit, &e->device_class, &e->extra};
        for (int k = 0; k < 5; k++) {
            if (k) put(&o, ",");
            hex(&o, strs[k]->p, strs[k]->len);
        }
        put(&o, "}");
    }
    return o.ok;
}
