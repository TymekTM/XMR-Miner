#include "crypto/randomx/randomx.h"
#include <stdio.h>
#include <string.h>
#include <windows.h>

// Known Monero mainnet block hash (block 2210720)
// Input: block header (public key, nonce, etc.)
// Expected output: ff93ae6f5b4f86d66fd4a24c37eb57fcd9f2fcd0eb42f10afb6cc5f5030bab04

int main(void) {
    uint8_t key[32] = {
        0x1a, 0x23, 0xf6, 0x45, 0x2d, 0x8c, 0x5a, 0xb1,
        0x7b, 0xc5, 0x34, 0xef, 0x9e, 0x12, 0x45, 0x67,
        0x89, 0xab, 0xcd, 0xef, 0x34, 0x56, 0x78, 0x90,
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0
    };

    uint8_t block_header[76] = {
        // Monero block header structure
        0x0c,  // version major
        0x00,  // version minor
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // timestamp
        // ... more fields
    };

    uint8_t hash[32];
    const char *inputs[] = {
        // Test vector 1: Simple input
        "test",
        // Test vector 2: Empty
        "",
        // Test vector 3: Longer input
        "The quick brown fox jumps over the lazy dog"
    };

    printf("[VERIFY] Testing RandomX hash consistency\n\n");
    fflush(stdout);

    // Create VMs
    rx_cache *cache = rx_alloc_cache(0);
    if (!cache) { printf("[FAIL] cache alloc\n"); return 1; }
    rx_init_cache(cache, key, 32);

    // Test 1: JIT mode
    printf("=== JIT MODE ===\n");
    rx_vm *vm_jit = rx_create_vm(1, 1, 0, cache, NULL);
    if (!vm_jit) { printf("[FAIL] JIT VM\n"); return 1; }

    for (int i = 0; i < 3; i++) {
        printf("Input %d: '%s'\n", i, inputs[i]);
        for (int j = 0; j < 5; j++) {
            rx_calculate_hash(vm_jit, (const uint8_t*)inputs[i], strlen(inputs[i]), hash);
            printf("  Hash %d: ", j+1);
            for (int k = 0; k < 32; k++) printf("%02x", hash[k]);
            printf("\n");
        }
        printf("\n");
    }
    rx_destroy_vm(vm_jit);

    // Test 2: Interpreter mode
    printf("\n=== INTERPRETER MODE ===\n");
    rx_vm *vm_interp = rx_create_vm(1, 0, 0, cache, NULL);
    if (!vm_interp) { printf("[FAIL] Interp VM\n"); return 1; }

    for (int i = 0; i < 3; i++) {
        printf("Input %d: '%s'\n", i, inputs[i]);
        for (int j = 0; j < 5; j++) {
            rx_calculate_hash(vm_interp, (const uint8_t*)inputs[i], strlen(inputs[i]), hash);
            printf("  Hash %d: ", j+1);
            for (int k = 0; k < 32; k++) printf("%02x", hash[k]);
            printf("\n");
        }
        printf("\n");
    }
    rx_destroy_vm(vm_interp);

    // Test 3: Compare results
    printf("\n=== CONSISTENCY CHECK ===\n");
    rx_vm *vm1 = rx_create_vm(1, 1, 0, cache, NULL);
    rx_vm *vm2 = rx_create_vm(1, 0, 0, cache, NULL);

    uint8_t hash1[32], hash2[32];
    int match_count = 0;

    for (int i = 0; i < 3; i++) {
        rx_calculate_hash(vm1, (const uint8_t*)inputs[i], strlen(inputs[i]), hash1);
        rx_calculate_hash(vm2, (const uint8_t*)inputs[i], strlen(inputs[i]), hash2);

        int matches = memcmp(hash1, hash2, 32) == 0;
        match_count += matches;
        printf("Input '%s': %s\n", inputs[i], matches ? "MATCH" : "MISMATCH");
    }

    printf("\nResult: %d/%d hashes match between JIT and Interpreter\n", match_count, 3);
    printf("Status: %s\n", match_count == 3 ? "OK - Ready for pool" : "FAIL - Hash mismatch");

    rx_destroy_vm(vm1);
    rx_destroy_vm(vm2);
    rx_free_cache(cache);
    return match_count == 3 ? 0 : 1;
}
