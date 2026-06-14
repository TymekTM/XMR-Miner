/*
 * Unit tests for blob/target/nonce helpers extracted into blob.c.
 * These cover the previously-untestable static helpers in worker.c,
 * including build_hashing_blob (the standard-stratum share-validity path).
 * Returns non-zero on any failure.
 */
#include "miner/blob.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int checks = 0;
static int failures = 0;

#define CHECK(cond) do { \
    checks++; \
    if (!(cond)) { \
        printf("  [FAIL] %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        failures++; \
    } \
} while (0)

static void test_hex_codec(void) {
    uint8_t in[4] = { 0x01, 0x23, 0x45, 0x67 };
    char enc[16];
    hex_encode(in, 4, enc);
    CHECK(strcmp(enc, "01234567") == 0);

    uint8_t out[4];
    hex_decode("89abcdef", out, 4);
    CHECK(out[0] == 0x89 && out[1] == 0xab && out[2] == 0xcd && out[3] == 0xef);

    /* round-trip */
    uint8_t rt[8] = { 0xff, 0x00, 0x1a, 0x7f, 0x80, 0xfe, 0x55, 0xaa };
    char rt_enc[32];
    hex_encode(rt, 8, rt_enc);
    uint8_t rt_out[8];
    hex_decode(rt_enc, rt_out, 8);
    CHECK(memcmp(rt, rt_out, 8) == 0);
}

static void test_hex_decode_seed(void) {
    uint8_t out[32];
    /* valid 64-char hex */
    CHECK(hex_decode_seed("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", out) == 0);
    CHECK(out[0] == 0x00 && out[31] == 0xff);
    /* wrong length */
    CHECK(hex_decode_seed("0011", out) == -1);
    CHECK(hex_decode_seed("", out) == -1);
}

static void test_varint(void) {
    uint8_t buf[8];
    int len;

    len = encode_varint(0, buf);
    CHECK(len == 1 && buf[0] == 0x00);

    len = encode_varint(127, buf);
    CHECK(len == 1 && buf[0] == 0x7f);

    len = encode_varint(128, buf);
    CHECK(len == 2 && buf[0] == 0x80 && buf[1] == 0x01);

    len = encode_varint(300, buf);
    CHECK(len == 2 && buf[0] == 0xac && buf[1] == 0x02);

    /* round-trip a range of values */
    for (uint64_t v = 0; v < 100000; v += 257) {
        uint8_t b[10];
        int w = encode_varint(v, b);
        CHECK(w >= 1 && w <= 9);
        int d = decode_varint(b, w);
        CHECK(d == w);
    }
}

static void test_decode_varint_malformed(void) {
    uint8_t b[9];
    memset(b, 0x80, 9);  /* all continuation, never terminates */
    CHECK(decode_varint(b, 9) == -1);
}

static void test_get_monero_nonce_offset(void) {
    /* blob: version(2) + timestamp_varint + prev_hash(32) + nonce(4) */
    /* timestamp = 100 -> varint 1 byte -> offset = 2+1+32 = 35 */
    uint8_t blob1[76] = {0};
    blob1[0] = 0x06; blob1[1] = 0x00;
    blob1[2] = 0x64;  /* ts varint = 100 */
    CHECK(get_monero_nonce_offset(blob1, 76) == 35);

    /* timestamp = 1000 (0x3E8) -> varint 2 bytes -> offset = 2+2+32 = 36 */
    blob1[2] = 0xe8; blob1[3] = 0x07;
    CHECK(get_monero_nonce_offset(blob1, 76) == 36);

    /* too short */
    CHECK(get_monero_nonce_offset(blob1, 10) == -1);
}

static void test_format_nonce_hex(void) {
    char out[16];
    /* monero: little-endian byte order */
    format_nonce_hex(0x12345678, 1, out, sizeof(out));
    CHECK(strcmp(out, "78563412") == 0);

    /* standard: big-endian */
    format_nonce_hex(0x12345678, 0, out, sizeof(out));
    CHECK(strcmp(out, "12345678") == 0);

    format_nonce_hex(0x00000000, 1, out, sizeof(out));
    CHECK(strcmp(out, "00000000") == 0);
}

static void test_share_meets_target_standard(void) {
    /* standard: compare u32_le at hash[0..3] against (uint32_t)target */
    uint8_t hash[32] = {0};
    /* hash head = 0x00000100 (LE) = 256; target 1000 -> meets; target 100 -> no */
    hash[0] = 0x00; hash[1] = 0x01;  /* u32_le = 256 */
    CHECK(share_meets_target(hash, 1000, 0) == 1);
    CHECK(share_meets_target(hash, 256, 0) == 1);   /* boundary == */
    CHECK(share_meets_target(hash, 255, 0) == 0);
    CHECK(share_meets_target(hash, 0, 0) == 0);     /* target 0 rejects all */
}

static void test_share_meets_target_monero(void) {
    /* monero: compare u64_le at hash[24..31] against target */
    uint8_t hash[32] = {0};
    /* set tail-64 to a known value: 0x0000000000001234 */
    hash[24] = 0x34; hash[25] = 0x12;
    uint64_t val = read_u64_le(hash + 24);
    CHECK(val == 0x1234);
    CHECK(share_meets_target(hash, 0x1234, 1) == 1);   /* boundary == */
    CHECK(share_meets_target(hash, 0x1233, 1) == 0);
    CHECK(share_meets_target(hash, 0x2000, 1) == 1);
}

static void test_algo_to_rx_flags(void) {
    CHECK(algo_to_rx_flags(NULL) == RX_FLAG_DEFAULT);
    CHECK(algo_to_rx_flags("rx/0") == RX_FLAG_DEFAULT);
    CHECK(algo_to_rx_flags("rx/1") == RX_FLAG_V2);
    CHECK(algo_to_rx_flags("rx/v2") == RX_FLAG_V2);
}

static stratum_job_t make_minimal_job(void) {
    stratum_job_t job;
    memset(&job, 0, sizeof(job));
    job.version_hex = "0a";
    /* ntime as big-endian hex -> 1700000000 (needs a 5-byte varint, as real
       Monero block timestamps do, so the resulting blob is the full 76 bytes) */
    job.ntime_hex = "6553f100";
    job.prev_hash = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    job.coinb1 = "ff";
    job.coinb2 = "ff";
    job.extranonce1 = "";
    job.extranonce2_size = 4;
    return job;
}

static void test_build_hashing_blob_structure(void) {
    stratum_job_t job = make_minimal_job();
    uint8_t blob[76];
    CHECK(build_hashing_blob(&job, blob, 0x12345678) == 0);

    /* version bytes preserved at [0..1] */
    CHECK(blob[0] == 0x0a);
    CHECK(blob[1] == 0x00);

    /* nonce at offset 2 + tslen + 32; ts=1700000000 -> 5-byte varint -> offset 39 */
    int noff = get_monero_nonce_offset(blob, 76);
    CHECK(noff == 39);
    /* nonce stored little-endian */
    CHECK(blob[noff] == 0x78 && blob[noff+1] == 0x56 &&
          blob[noff+2] == 0x34 && blob[noff+3] == 0x12);

    /* last byte is the 0x01 merge marker */
    CHECK(blob[75] == 0x01);
}

static void test_build_hashing_blob_nonce_independence(void) {
    /* changing the nonce must only change the nonce bytes; the rest of the
       blob (which depends on coinbase/prevhash/treehash) stays identical. */
    stratum_job_t job = make_minimal_job();
    uint8_t b0[76], b1[76];
    CHECK(build_hashing_blob(&job, b0, 0x11111111) == 0);
    CHECK(build_hashing_blob(&job, b1, 0x22222222) == 0);

    int noff = get_monero_nonce_offset(b0, 76);
    int diffs = 0;
    for (int i = 0; i < 76; i++) {
        if (b0[i] != b1[i]) {
            CHECK(i >= noff && i < noff + 4);  /* only nonce bytes differ */
            diffs++;
        }
    }
    CHECK(diffs == 4);
}

static void test_build_hashing_blob_reproducible(void) {
    stratum_job_t job = make_minimal_job();
    uint8_t b0[76], b1[76];
    CHECK(build_hashing_blob(&job, b0, 0xabcdef01) == 0);
    CHECK(build_hashing_blob(&job, b1, 0xabcdef01) == 0);
    CHECK(memcmp(b0, b1, 76) == 0);
}

int main(void) {
    printf("[TEST] blob/target/nonce helpers\n");
    test_hex_codec();
    test_hex_decode_seed();
    test_varint();
    test_decode_varint_malformed();
    test_get_monero_nonce_offset();
    test_format_nonce_hex();
    test_share_meets_target_standard();
    test_share_meets_target_monero();
    test_algo_to_rx_flags();
    test_build_hashing_blob_structure();
    test_build_hashing_blob_nonce_independence();
    test_build_hashing_blob_reproducible();

    printf("[TEST] %d checks, %d failures\n", checks, failures);
    printf("[TEST] %s\n", failures == 0 ? "PASS" : "FAIL");
    return failures == 0 ? 0 : 1;
}
