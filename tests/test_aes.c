#include "crypto/aes/aes_ni.h"
#include "common/log.h"
#include <stdio.h>
#include <string.h>

static int test_aes256_nist_vector(void) {
    u8 key[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
    };
    u8 plaintext[16] = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,
    };
    u8 expected[16] = {
        0x8e,0xa2,0xb7,0xca,0x51,0x67,0x45,0xbf,0xea,0xfc,0x49,0x90,0x4b,0x49,0x60,0x89,
    };
    u8 ciphertext[16];
    u8 decrypted[16];

    aes_ctx ctx;
    aes256_init(&ctx, key);
    aes256_encrypt_block(&ctx, plaintext, ciphertext);

    if (memcmp(ciphertext, expected, 16) != 0) {
        LOG_ERR("FAIL: AES-256 NIST vector mismatch");
        LOG_ERR("  Expected: %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x",
            expected[0],expected[1],expected[2],expected[3],expected[4],expected[5],expected[6],expected[7],
            expected[8],expected[9],expected[10],expected[11],expected[12],expected[13],expected[14],expected[15]);
        LOG_ERR("  Got:      %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x",
            ciphertext[0],ciphertext[1],ciphertext[2],ciphertext[3],ciphertext[4],ciphertext[5],ciphertext[6],ciphertext[7],
            ciphertext[8],ciphertext[9],ciphertext[10],ciphertext[11],ciphertext[12],ciphertext[13],ciphertext[14],ciphertext[15]);
        return 1;
    }

    aes256_decrypt_block(&ctx, ciphertext, decrypted);
    if (memcmp(plaintext, decrypted, 16) != 0) {
        LOG_ERR("FAIL: AES-256 decrypt roundtrip failed");
        return 1;
    }

    LOG_INFO("PASS: AES-256 NIST test vector");
    return 0;
}

static int test_aes256_zero_roundtrip(void) {
    u8 key[32] = {0};
    u8 plaintext[16] = {0};
    u8 ciphertext[16];
    u8 decrypted[16];

    aes_ctx ctx;
    aes256_init(&ctx, key);
    aes256_encrypt_block(&ctx, plaintext, ciphertext);
    aes256_decrypt_block(&ctx, ciphertext, decrypted);

    if (memcmp(plaintext, decrypted, 16) != 0) {
        LOG_ERR("FAIL: AES-256 zero key roundtrip");
        return 1;
    }

    LOG_INFO("PASS: AES-256 zero key roundtrip");
    return 0;
}

static int test_aes_ni_available(void) {
    int ni = aes_ni_available();
    LOG_INFO("PASS: AES-NI %s", ni ? "available" : "NOT available");
    return 0;
}

int main(void) {
    log_init(LOG_DEBUG);
    LOG_INFO("=== AES-256 Tests ===");

    int fails = 0;
    fails += test_aes_ni_available();
    fails += test_aes256_nist_vector();
    fails += test_aes256_zero_roundtrip();

    LOG_INFO("=== Results: %d failures ===", fails);
    return fails;
}
