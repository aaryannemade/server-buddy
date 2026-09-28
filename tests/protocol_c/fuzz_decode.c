// libFuzzer target: decoders must never crash, and anything accepted must
// re-encode to the identical bytes.
#include <stdlib.h>
#include <string.h>

#include "sb_protocol.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t len)
{
    sb_frame_t f;
    if (sb_decode(data, len, &f) == SB_OK) {
        uint8_t enc[SB_MAX_FRAME];
        size_t n = 0;
        char desc[2048];
        if (sb_encode(&f, enc, sizeof enc, &n) != SB_OK || n != len || memcmp(enc, data, len))
            abort();
        if (!sb_describe(&f, desc, sizeof desc)) abort();
    }
    static sb_schema_t s;
    if (sb_decode_schema(data, len, &s) == SB_OK) {
        static uint8_t enc[SB_MAX_SCHEMA];
        size_t n = 0;
        if (sb_encode_schema(&s, enc, sizeof enc, &n) != SB_OK || n != len || memcmp(enc, data, len))
            abort();
    }
    return 0;
}
