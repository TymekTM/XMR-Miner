#include "crypto/argon2/argon2.h"
#include "crypto/blake2/blake2b.h"
#include "common/log.h"
#include <stdio.h>
#include <string.h>

static int test_argon2d_h0(void) {
    u8 pwd[32]; memset(pwd, 1, 32);
    u8 salt[16]; memset(salt, 2, 16);
    u8 secret[8]; memset(secret, 3, 8);
    u8 ad[12]; memset(ad, 4, 12);

    u8 H0[64];
    blake2b_state st;
    blake2b_init(&st, 64);
    u32 le;
    write_u32_le(&le, 4);   blake2b_update(&st, &le, 4);
    write_u32_le(&le, 32);  blake2b_update(&st, &le, 4);
    write_u32_le(&le, 32);  blake2b_update(&st, &le, 4);
    write_u32_le(&le, 3);   blake2b_update(&st, &le, 4);
    write_u32_le(&le, 0x13); blake2b_update(&st, &le, 4);
    write_u32_le(&le, 0);   blake2b_update(&st, &le, 4);
    write_u32_le(&le, 32);  blake2b_update(&st, &le, 4);
    blake2b_update(&st, pwd, 32);
    write_u32_le(&le, 16);  blake2b_update(&st, &le, 4);
    blake2b_update(&st, salt, 16);
    write_u32_le(&le, 8);   blake2b_update(&st, &le, 4);
    blake2b_update(&st, secret, 8);
    write_u32_le(&le, 12);  blake2b_update(&st, &le, 4);
    blake2b_update(&st, ad, 12);
    blake2b_final(&st, H0, 64);

    u8 expected[64] = {
        0xb8,0x81,0x97,0x91,0xa0,0x35,0x96,0x60,
        0xbb,0x77,0x09,0xc8,0x5f,0xa4,0x8f,0x04,
        0xd5,0xd8,0x2c,0x05,0xc5,0xf2,0x15,0xcc,
        0xdb,0x88,0x54,0x91,0x71,0x7c,0xf7,0x57,
        0x08,0x2c,0x28,0xb9,0x51,0xbe,0x38,0x14,
        0x10,0xb5,0xfc,0x2e,0xb7,0x27,0x40,0x33,
        0xb9,0xfd,0xc7,0xae,0x67,0x2b,0xca,0xac,
        0x5d,0x17,0x90,0x97,0xa4,0xaf,0x31,0x09,
    };

    if (memcmp(H0, expected, 64) != 0) {
        LOG_ERR("FAIL: H0 mismatch");
        LOG_ERR("  Expected: %02x%02x%02x%02x...", expected[0], expected[1], expected[2], expected[3]);
        LOG_ERR("  Got:      %02x%02x%02x%02x...", H0[0], H0[1], H0[2], H0[3]);
        return 1;
    }
    LOG_INFO("PASS: H0 matches RFC pre-hashing digest");
    return 0;
}

static int test_argon2d_rfc_vector(void) {
    u8 pwd[32];
    memset(pwd, 1, 32);
    u8 salt[16];
    memset(salt, 2, 16);
    u8 secret[8];
    memset(secret, 3, 8);
    u8 ad[12];
    memset(ad, 4, 12);

    u8 hash[32];
    int rc = argon2_hash(ARGON2_D, 3, 32, 4,
                          pwd, 32, salt, 16,
                          secret, 8, ad, 12,
                          hash, 32, NULL);

    if (rc != 0) {
        LOG_ERR("FAIL: argon2d RFC vector returned error");
        return 1;
    }

    u8 expected[32] = {
        0x51,0x2b,0x39,0x1b,0x6f,0x11,0x62,0x97,
        0x53,0x71,0xd3,0x09,0x19,0x73,0x42,0x94,
        0xf8,0x68,0xe3,0xbe,0x39,0x84,0xf3,0xc1,
        0xa1,0x3a,0x4d,0xb9,0xfa,0xbe,0x4a,0xcb,
    };

    if (memcmp(hash, expected, 32) != 0) {
        LOG_ERR("FAIL: argon2d RFC vector mismatch");
        LOG_ERR("  Expected: %02x%02x%02x%02x...",
            expected[0], expected[1], expected[2], expected[3]);
        LOG_ERR("  Got:      %02x%02x%02x%02x...",
            hash[0], hash[1], hash[2], hash[3]);
        return 1;
    }

    LOG_INFO("PASS: argon2d RFC 9106 test vector");
    return 0;
}

static int test_gb(void) {
    u64 a=1, b=2, c=3, d=4;
    argon2_test_gb(&a, &b, &c, &d);
    u64 ea=0x0000010000002d07ULL, eb=0x5a0e02060e2a0606ULL, ec=0x2d07000307150003ULL, ed=0x2d07000001030000ULL;
    if (a!=ea||b!=eb||c!=ec||d!=ed) {
        LOG_ERR("FAIL: gb(1,2,3,4) mismatch");
        LOG_ERR("  expected: %016llx %016llx %016llx %016llx", ea, eb, ec, ed);
        LOG_ERR("  got:      %016llx %016llx %016llx %016llx", a, b, c, d);
        return 1;
    }
    LOG_INFO("PASS: gb(1,2,3,4)");
    return 0;
}

static int test_argon2d_hprime(void) {
    u8 H0[64] = {
        0xb8,0x81,0x97,0x91,0xa0,0x35,0x96,0x60,
        0xbb,0x77,0x09,0xc8,0x5f,0xa4,0x8f,0x04,
        0xd5,0xd8,0x2c,0x05,0xc5,0xf2,0x15,0xcc,
        0xdb,0x88,0x54,0x91,0x71,0x7c,0xf7,0x57,
        0x08,0x2c,0x28,0xb9,0x51,0xbe,0x38,0x14,
        0x10,0xb5,0xfc,0x2e,0xb7,0x27,0x40,0x33,
        0xb9,0xfd,0xc7,0xae,0x67,0x2b,0xca,0xac,
        0x5d,0x17,0x90,0x97,0xa4,0xaf,0x31,0x09,
    };
    u8 block_input[72];
    memcpy(block_input, H0, 64);
    write_u32_le(block_input + 64, 0);
    write_u32_le(block_input + 68, 0);

    u8 block[1024];
    u32 outlen = 1024;
    u32 r = (outlen + 31) / 32 - 2;
    u8 buf[4];
    write_u32_le(buf, outlen);
    u8 V[64];
    blake2b_state st;
    blake2b_init(&st, 64);
    blake2b_update(&st, buf, 4);
    blake2b_update(&st, block_input, 72);
    blake2b_final(&st, V, 64);
    memcpy(block, V, 32);
    for (u32 i = 2; i <= r; i++) {
        blake2b_init(&st, 64);
        blake2b_update(&st, V, 64);
        blake2b_final(&st, V, 64);
        memcpy(block + (i - 1) * 32, V, 32);
    }
    u32 last_len = outlen - 32 * r;
    blake2b_init(&st, last_len);
    blake2b_update(&st, V, 64);
    blake2b_final(&st, V, last_len);
    memcpy(block + r * 32, V, last_len);

    u64 expected_qwords[8] = {
        0xdb2fea6b2c6f5c8aULL,
        0x719413be00f82634ULL,
        0xa1e3f6dd42aa25ccULL,
        0x3ea8efd4d55ac0d1ULL,
        0x1278849d789aa327ULL,
        0x54ec500e01cb4887ULL,
        0x96c5956594a99199ULL,
        0x54ef81c17e9b4b85ULL,
    };

    int ok = 1;
    for (int i = 0; i < 8; i++) {
        u64 got;
        memcpy(&got, block + i * 8, 8);
        if (got != expected_qwords[i]) {
            LOG_ERR("  Block[0][%d]: expected %016llx got %016llx",
                i, (unsigned long long)expected_qwords[i], (unsigned long long)got);
            ok = 0;
        }
    }
    if (ok) {
        LOG_INFO("PASS: H_prime (blake2b_long) first block matches reference");
    } else {
        LOG_ERR("FAIL: H_prime first block mismatch");
    }
    return ok ? 0 : 1;
}

static int test_argon2d_p1(void) {
    u8 hash[32];
    int rc = argon2_hash(ARGON2_D, 2, 16, 1,
                          "", 0, "somesalt", 8,
                          NULL, 0, NULL, 0,
                          hash, 32, NULL);
    if (rc != 0) {
        LOG_ERR("FAIL: argon2d p=1 returned error");
        return 1;
    }

    u8 expected[32] = {
        0x57,0x86,0xdf,0xae,0x5c,0xc0,0xd2,0xef,
        0xf0,0x6a,0x12,0x3f,0xca,0xd8,0x83,0x50,
        0x66,0xca,0x09,0x0d,0x1f,0x60,0x04,0x26,
        0xa0,0xd7,0x4e,0x07,0x96,0x82,0xc2,0xde,
    };

    if (memcmp(hash, expected, 32) != 0) {
        LOG_ERR("FAIL: argon2d p=1 mismatch");
        LOG_ERR("  Expected: %02x%02x%02x%02x...",
            expected[0], expected[1], expected[2], expected[3]);
        LOG_ERR("  Got:      %02x%02x%02x%02x...",
            hash[0], hash[1], hash[2], hash[3]);
        return 1;
    }
    LOG_INFO("PASS: argon2d p=1 (t=2, m=16)");
    return 0;
}

static int test_argon2d_deterministic(void) {
    u8 hash1[32], hash2[32];
    argon2_hash(ARGON2_D, 1, 8, 1, "test", 4, "salt", 4, NULL, 0, NULL, 0, hash1, 32, NULL);
    argon2_hash(ARGON2_D, 1, 8, 1, "test", 4, "salt", 4, NULL, 0, NULL, 0, hash2, 32, NULL);
    if (memcmp(hash1, hash2, 32) != 0) {
        LOG_ERR("FAIL: argon2d not deterministic");
        return 1;
    }
    LOG_INFO("PASS: argon2d deterministic");
    return 0;
}

int main(void) {
    log_init(LOG_DEBUG);
    LOG_INFO("=== Argon2 Tests ===");
    int fails = 0;
    fails += test_argon2d_h0();
    fails += test_gb();
    fails += test_argon2d_hprime();
    fails += test_argon2d_p1();
    fails += test_argon2d_rfc_vector();
    fails += test_argon2d_deterministic();
    LOG_INFO("=== Results: %d failures ===", fails);
    return fails;
}
