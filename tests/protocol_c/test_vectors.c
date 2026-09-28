// Cross-checks the C codec against the Python-generated golden vectors, then
// runs a deterministic mutation fuzz. Usage: test_vectors <vector-dir>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sb_crypto.h"
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

static size_t unhex(const char *s, uint8_t *out, size_t cap)
{
    size_t n = strlen(s) / 2;
    if (n > cap) {
        fprintf(stderr, "hex too long\n");
        exit(2);
    }
    for (size_t i = 0; i < n; i++) sscanf(s + 2 * i, "%2hhx", &out[i]);
    return n;
}

static void tohex(const uint8_t *p, size_t n, char *out)
{
    for (size_t i = 0; i < n; i++) sprintf(out + 2 * i, "%02x", p[i]);
    out[2 * n] = 0;
}

// Splits `line` on '|' in place. Returns field count.
static int split(char *line, char **f, int max)
{
    int n = 0;
    line[strcspn(line, "\r\n")] = 0;
    for (char *p = line; n < max;) {
        f[n++] = p;
        char *bar = strchr(p, '|');
        if (!bar) break;
        *bar = 0;
        p = bar + 1;
    }
    return n;
}

static FILE *open_vec(const char *dir, const char *name)
{
    char path[1024];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    FILE *fp = fopen(path, "r");
    if (!fp) {
        perror(path);
        exit(2);
    }
    return fp;
}

static uint8_t demo_kmic[SB_KMIC_LEN];
static bool have_kmic;

static uint8_t seeds[128][SB_MAX_FRAME];
static size_t seed_len[128];
static int n_seeds;

// `golden`: also checks MICs and that no-space is reported (not for mutations).
static void test_frames(const char *dir, const char *file, bool golden)
{
    FILE *fp = open_vec(dir, file);
    char line[4096], *f[4], desc[4096];
    int count = 0;
    while (fgets(line, sizeof line, fp)) {
        CHECK(split(line, f, 4) == 4, "bad line");
        static uint8_t buf[1024];
        size_t len = unhex(f[2], buf, sizeof buf);
        if (golden && n_seeds < 128 && len <= SB_MAX_FRAME) {
            memcpy(seeds[n_seeds], buf, len);
            seed_len[n_seeds++] = len;
        }
        sb_frame_t fr;
        sb_err_t err = sb_decode(buf, len, &fr);
        CHECK(!strcmp(sb_err_name(err), f[1]), "%s: got %s want %s", f[0], sb_err_name(err), f[1]);
        if (err == SB_OK) {
            CHECK(sb_describe(&fr, desc, sizeof desc), "%s: describe", f[0]);
            CHECK(!strcmp(desc, f[3]), "%s:\n  got  %s\n  want %s", f[0], desc, f[3]);
            uint8_t enc[SB_MAX_FRAME];
            size_t enc_len = 0;
            CHECK(sb_encode(&fr, enc, sizeof enc, &enc_len) == SB_OK, "%s: encode", f[0]);
            CHECK(enc_len == len && !memcmp(enc, buf, len), "%s: re-encode differs", f[0]);
            if (!golden) goto next;
            CHECK(sb_encode(&fr, enc, len - 1, &enc_len) == SB_ERR_NO_SPACE, "%s: no-space", f[0]);
            if (sb_has_mic(fr.type)) {
                uint8_t dir = fr.type == SB_MSG_ACK ? SB_DIR_HUB_TO_NODE : SB_DIR_NODE_TO_HUB;
                CHECK(have_kmic && sb_mic_verify(demo_kmic, dir, buf, len), "%s: mic", f[0]);
                CHECK(!sb_mic_verify(demo_kmic, (uint8_t)(dir ^ 1), buf, len), "%s: mic dir", f[0]);
                uint8_t resealed[SB_MAX_FRAME];
                memcpy(resealed, buf, len);
                memset(resealed + len - SB_MIC_LEN, 0, SB_MIC_LEN);
                CHECK(sb_mic_seal(demo_kmic, dir, resealed, len) && !memcmp(resealed, buf, len),
                      "%s: seal", f[0]);
            }
        }
    next:
        count++;
    }
    fclose(fp);
    printf("%s: %d vectors\n", file, count);
}

static void test_schema(const char *dir)
{
    FILE *fp = open_vec(dir, "schema.txt");
    static char line[16384], desc[16384];
    static uint8_t buf[4096], enc[4096];
    char *f[4];
    int count = 0;
    while (fgets(line, sizeof line, fp)) {
        CHECK(split(line, f, 4) == 4, "bad line");
        size_t len = unhex(f[2], buf, sizeof buf);
        sb_schema_t s;
        sb_err_t err = sb_decode_schema(buf, len, &s);
        CHECK(!strcmp(sb_err_name(err), f[1]), "%s: got %s want %s", f[0], sb_err_name(err), f[1]);
        if (err == SB_OK) {
            CHECK(sb_describe_schema(&s, desc, sizeof desc), "%s: describe", f[0]);
            CHECK(!strcmp(desc, f[3]), "%s:\n  got  %s\n  want %s", f[0], desc, f[3]);
            size_t enc_len = 0;
            CHECK(sb_encode_schema(&s, enc, sizeof enc, &enc_len) == SB_OK, "%s: encode", f[0]);
            CHECK(enc_len == len && !memcmp(enc, buf, len), "%s: re-encode differs", f[0]);
        }
        count++;
    }
    fclose(fp);
    printf("schema: %d vectors\n", count);
}

static void test_crypto(const char *dir)
{
    FILE *fp = open_vec(dir, "crypto.txt");
    char line[4096], *f[12], got[1024];
    uint8_t a[256], b[256], c[256], d[256], e[256], out[256];
    int count = 0;
    while (fgets(line, sizeof line, fp)) {
        int n = split(line, f, 12);
        const char *want = f[n - 1];
        if (!strcmp(f[0], "hkdf")) {
            size_t la = unhex(f[1], a, sizeof a), lb = unhex(f[2], b, sizeof b),
                   lc = unhex(f[3], c, sizeof c), L = (size_t)atoi(f[4]);
            CHECK(sb_hkdf_sha256(a, la, b, lb, c, lc, out, L), "hkdf");
            tohex(out, L, got);
        } else if (!strcmp(f[0], "keyid")) {
            unhex(f[1], a, sizeof a);
            CHECK(sb_key_id(a, out), "keyid");
            tohex(out, SB_KEY_ID_LEN, got);
        } else if (!strcmp(f[0], "keys")) {
            unhex(f[1], a, sizeof a), unhex(f[2], b, sizeof b), unhex(f[3], c, sizeof c);
            unhex(f[4], d, sizeof d), unhex(f[5], e, sizeof e);
            CHECK(sb_session_keys(a, b, c, d, e, (uint8_t)atoi(f[6]), out, demo_kmic), "keys");
            have_kmic = true;
            char lmk_hex[64];
            tohex(out, SB_LMK_LEN, lmk_hex);
            CHECK(!strcmp(lmk_hex, f[7]), "lmk: got %s want %s", lmk_hex, f[7]);
            tohex(demo_kmic, SB_KMIC_LEN, got);
        } else if (!strcmp(f[0], "mic")) {
            unhex(f[1], a, sizeof a);
            size_t lc = unhex(f[3], c, sizeof c);
            CHECK(sb_mic(a, (uint8_t)atoi(f[2]), c, lc, out), "mic");
            tohex(out, 8, got);
        } else if (!strcmp(f[0], "reqtag")) {
            unhex(f[1], a, sizeof a);
            size_t lb = unhex(f[2], b, sizeof b);
            CHECK(sb_request_tag(a, b, lb, out), "reqtag");
            tohex(out, SB_TAG_LEN, got);
        } else if (!strcmp(f[0], "resptag")) {
            unhex(f[1], a, sizeof a), unhex(f[2], b, sizeof b);
            size_t lc = unhex(f[3], c, sizeof c);
            CHECK(sb_response_tag(a, b, c, lc, out), "resptag");
            tohex(out, SB_TAG_LEN, got);
        } else {
            CHECK(0, "unknown crypto kind %s", f[0]);
            continue;
        }
        CHECK(!strcmp(got, want), "%s: got %s want %s", f[0], got, want);
        count++;
    }
    fclose(fp);
    uint8_t x[4] = {1, 2, 3, 4}, y[4] = {1, 2, 3, 5};
    CHECK(sb_tag_equal(x, x, 4) && !sb_tag_equal(x, y, 4), "tag_equal");
    printf("crypto: %d vectors\n", count);
}

static uint32_t rng_state = 0x9E3779B9;

static uint32_t RND(void)
{
    uint32_t s = rng_state;
    s ^= s << 13;
    s ^= s >> 17;
    s ^= s << 5;
    return rng_state = s;
}

static void test_mutation_fuzz(void)
{
    long accepted = 0;
    for (long it = 0; it < 500000; it++) {
        uint8_t buf[SB_MAX_FRAME + 8];
        int k = (int)(RND() % (uint32_t)n_seeds);
        size_t len = seed_len[k];
        memcpy(buf, seeds[k], len);
        int muts = 1 + (int)(RND() % 4);
        for (int m = 0; m < muts; m++) {
            uint32_t op = RND() % 3;
            if (op == 0 && len) {
                {
                size_t at = RND() % len;
                buf[at] = (uint8_t)RND();
            }
            } else if (op == 1 && len) {
                size_t at = RND() % len;
                memmove(buf + at, buf + at + 1, len - at - 1);
                len--;
            } else if (len < sizeof buf) {
                size_t at = RND() % (len + 1);
                memmove(buf + at + 1, buf + at, len - at);
                buf[at] = (uint8_t)RND();
                len++;
            }
        }
        // Exact-size heap copy so ASan catches any overread.
        uint8_t *heap = malloc(len ? len : 1);
        memcpy(heap, buf, len);
        sb_frame_t f;
        if (sb_decode(heap, len, &f) == SB_OK) {
            uint8_t enc[SB_MAX_FRAME];
            size_t enc_len = 0;
            char desc[2048];
            CHECK(sb_encode(&f, enc, sizeof enc, &enc_len) == SB_OK && enc_len == len &&
                      !memcmp(enc, heap, len),
                  "fuzz roundtrip");
            CHECK(sb_describe(&f, desc, sizeof desc), "fuzz describe");
            accepted++;
        }
        free(heap);
    }
    printf("fuzz: 500000 mutations, %ld accepted\n", accepted);
}

int main(int argc, char **argv)
{
    if (argc != 2 && argc != 3) {
        fprintf(stderr, "usage: %s <vector-dir> [<dir-with-mutations.txt>]\n", argv[0]);
        return 2;
    }
    test_crypto(argv[1]); // first: provides the demo MIC key
    test_frames(argv[1], "frames.txt", true);
    if (argc == 3) test_frames(argv[2], "mutations.txt", false);
    test_schema(argv[1]);
    test_mutation_fuzz();
    if (failures) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    puts("all protocol tests passed");
    return 0;
}
