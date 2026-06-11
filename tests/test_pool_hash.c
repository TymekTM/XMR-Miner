#include "crypto/randomx/randomx.h"
#include "crypto/randomx/randomx_internal.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>

static void hex_decode(const char *hex, uint8_t *out, int max_bytes) {
    int hex_len = (int)strlen(hex);
    int byte_len = hex_len / 2;
    if (byte_len > max_bytes) byte_len = max_bytes;
    for (int i = 0; i < byte_len; i++) {
        char h[3] = { hex[i * 2], hex[i * 2 + 1], 0 };
        out[i] = (uint8_t)strtoul(h, NULL, 16);
    }
}

static void hex_encode(const uint8_t *data, int len, char *out) {
    for (int i = 0; i < len; i++)
        snprintf(out + i * 2, 3, "%02x", data[i]);
    out[len * 2] = '\0';
}

static int decode_varint(const uint8_t *p, int max_bytes) {
    int val = 0, shift = 0, i;
    for (i = 0; i < max_bytes && i < 9; i++) {
        val |= (p[i] & 0x7F) << shift;
        if (!(p[i] & 0x80)) return i + 1;
        shift += 7;
    }
    return -1;
}

int main(void) {
    const char *seed_hex = "c5972b1ca01152f802748d99f9ebab63e60244718fec36b1d09210fa11d3dafe";
    const char *blob_hex = "1010dd8e8ed00617fabc1371037f5c8bea1e3df2491f35fa8b7b5785642fc5d306ddea6c11a7ee000000000a892be4aac02f0fdc987f243511807dbb60ce6ed3acdead0c21c79097af94e26c";
    int pass = 1;

    uint8_t seed[32];
    hex_decode(seed_hex, seed, 32);

    printf("[TEST] Seed: ");
    for (int i = 0; i < 32; i++) printf("%02x", seed[i]);
    printf("\n");

    printf("[TEST] Allocating cache...\n"); fflush(stdout);
    rx_cache *cache = rx_alloc_cache(0);
    rx_init_cache(cache, seed, 32);
    printf("[TEST] Cache initialized\n"); fflush(stdout);

    printf("[TEST] Allocating dataset...\n"); fflush(stdout);
    rx_dataset *dataset = rx_alloc_dataset(0);
    printf("[TEST] Initializing dataset (8 threads)...\n"); fflush(stdout);
    rx_init_dataset(dataset, cache, 0, RX_DATASET_ITEMS + RX_DATASET_EXTRA_ITEMS, 8, 8);

    printf("[TEST] Verifying blake2b of test input...\n"); fflush(stdout);
    {
        const char *tv_input = "This is a test";
        uint8_t tmp[64];
        blake2b(tmp, 64, tv_input, strlen(tv_input), NULL, 0);
        printf("  blake2b-512(\"This is a test\"): ");
        for(int i=0;i<64;i++) printf("%02x", tmp[i]);
        printf("\n");
        uint8_t tmp32[32];
        blake2b(tmp32, 32, tv_input, strlen(tv_input), NULL, 0);
        printf("  blake2b-256(\"This is a test\"): ");
        for(int i=0;i<32;i++) printf("%02x", tmp32[i]);
        printf("\n  Expected blake2b-256: fe9bee7df50a35fda7d9175add85b1feaf615607bfb15d629ff2103218c63e62\n");
    }

    printf("\n[TEST] Verifying against official RandomX test vector (key=\"test key 000\")...\n"); fflush(stdout);
    {
        rx_cache *cache_tv = rx_alloc_cache(0);
        const char *tv_key = "test key 000";
        rx_init_cache(cache_tv, tv_key, strlen(tv_key));
        rx_dataset *ds_tv = rx_alloc_dataset(0);
        printf("[TEST] Init TV dataset (1 thread)...\n"); fflush(stdout);
        rx_init_dataset(ds_tv, cache_tv, 0,
                        RX_DATASET_ITEMS + RX_DATASET_EXTRA_ITEMS, 1, 1);
        rx_vm *vm_tv = rx_create_vm(RX_FLAG_JIT | RX_FLAG_DEFAULT, cache_tv, ds_tv);
        const char *tv_input = "This is a test";
        uint8_t tv_hash[32];
        rx_calculate_hash(vm_tv, tv_input, strlen(tv_input), tv_hash);
        uint8_t tv_expected[] = {0x63,0x91,0x83,0xaa,0xe1,0xbf,0x4c,0x9a,0x35,0x88,0x4c,0xb4,0x6b,0x09,0xca,0xd9,0x17,0x5f,0x04,0xef,0xd7,0x68,0x4e,0x72,0x62,0xa0,0xac,0x1c,0x2f,0x0b,0x4e,0x3f};
        int tv_match = memcmp(tv_hash, tv_expected, 32) == 0;
        printf("  test vector: %s\n", tv_match ? "PASS" : "FAIL");
        if (!tv_match) {
            printf("  got:      "); for(int i=0;i<32;i++) printf("%02x", tv_hash[i]); printf("\n");
            printf("  expected: "); for(int i=0;i<32;i++) printf("%02x", tv_expected[i]); printf("\n");
            pass = 0;
        }
        rx_destroy_vm(vm_tv);
        rx_free_dataset(ds_tv);
        rx_free_cache(cache_tv);
    }
    printf("[TEST] Dataset initialized\n"); fflush(stdout);

    uint8_t blob[256];
    int blob_len = (int)strlen(blob_hex) / 2;
    hex_decode(blob_hex, blob, blob_len);

    printf("[TEST] Blob (%d bytes): ", blob_len);
    for (int i = 0; i < blob_len; i++) printf("%02x", blob[i]);
    printf("\n");

    int ts_len = decode_varint(blob + 2, blob_len - 2);
    int nonce_off = 2 + ts_len + 32;
    printf("[TEST] ts_len=%d nonce_off=%d\n", ts_len, nonce_off);

    rx_vm *vm_interp = rx_create_vm(RX_FLAG_DEFAULT, cache, dataset);
    if (!vm_interp) {
        printf("[FAIL] Interpreter VM creation failed\n");
        return 1;
    }
    rx_vm *vm_jit = rx_create_vm(RX_FLAG_JIT | RX_FLAG_DEFAULT, cache, dataset);
    if (!vm_jit) {
        printf("[FAIL] JIT VM creation failed\n");
        return 1;
    }
    printf("[TEST] VMs created (interp + JIT)\n"); fflush(stdout);

    printf("\n[TEST] Comparing interpreter vs JIT for first 10 nonces:\n");
    for (uint32_t nonce = 0; nonce < 10; nonce++) {
        memcpy(blob + nonce_off, &nonce, 4);
        uint8_t hash_interp[32], hash_jit[32];
        rx_calculate_hash(vm_interp, blob, blob_len, hash_interp);
        rx_calculate_hash(vm_jit, blob, blob_len, hash_jit);

        char hi[65], hj[65];
        hex_encode(hash_interp, 32, hi);
        hex_encode(hash_jit, 32, hj);

        int match = memcmp(hash_interp, hash_jit, 32) == 0;
        if (!match) pass = 0;
        printf("  nonce=%u interp=%s\n         jit=%s  %s\n",
               nonce, hi, hj, match ? "MATCH" : "MISMATCH");
    }

    printf("\n[TEST] Locating the historical submitted hash around nonce 0x0E3E:\n");
    {
        const char *submitted_hex =
            "45bf550c8cd81312a6474507989f0b3af5d9c756ea8d79daab91a20ff3520000";
        uint8_t submitted[32];
        int matched_nonce = -1;
        hex_decode(submitted_hex, submitted, 32);
        for (uint32_t nonce = 0x0E38; nonce <= 0x0E3E; ++nonce) {
            uint8_t hash[32];
            char hash_hex[65];
            memcpy(blob + nonce_off, &nonce, sizeof(nonce));
            rx_calculate_hash(vm_jit, blob, blob_len, hash);
            hex_encode(hash, 32, hash_hex);
            printf("  nonce=%u hash=%s%s\n", nonce, hash_hex,
                   memcmp(hash, submitted, sizeof(hash)) == 0 ? "  SUBMITTED" : "");
            if (memcmp(hash, submitted, sizeof(hash)) == 0)
                matched_nonce = (int)nonce;
        }
        printf("  submitted nonce field: %u\n", 0x0E3E);
        printf("  submitted hash belongs to nonce: %d\n", matched_nonce);
        if (matched_nonce == 0x0E3E) {
            printf("[FAIL] historical rejection was not caused by nonce/hash mismatch\n");
            pass = 0;
        } else if (matched_nonce < 0) {
            printf("[WARN] submitted hash was generated outside the inspected nonce window\n");
        } else {
            printf("[PASS] historical rejection reproduced as nonce/hash mismatch\n");
        }
    }

    rx_destroy_vm(vm_interp);
    rx_destroy_vm(vm_jit);
    rx_free_dataset(dataset);
    rx_free_cache(cache);

    printf("\n[%s]\n", pass ? "PASS" : "FAIL");
    return pass ? 0 : 1;
}
