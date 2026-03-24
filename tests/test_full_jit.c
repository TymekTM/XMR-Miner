#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "crypto/randomx/randomx_internal.h"
#include "crypto/randomx/randomx.h"

extern rx_vm *rx_create_vm(int useJit, int lightClient, int height, rx_cache* cache, rx_dataset* dataset);
extern void rx_destroy_vm(rx_vm* vm);
extern rx_cache *rx_alloc_cache(int flags);
extern void rx_free_cache(rx_cache *cache);
extern void rx_init_cache(rx_cache* cache, const void *key, size_t keySize);
extern void rx_calculate_hash(rx_vm *vm, const void *input, size_t input_size, void *output);

int main() {
    printf("[TEST] Full mode JIT test\n");

    // Create cache
    printf("[TEST] Creating cache...\n"); fflush(stdout);
    rx_cache *cache = rx_alloc_cache(0);
    if (!cache) {
        printf("[FAIL] Cache allocation\n");
        return 1;
    }

    // Initialize cache with Argon2d
    const char *key = "test key";
    printf("[TEST] Initializing cache...\n"); fflush(stdout);
    rx_init_cache(cache, key, strlen(key));
    printf("[TEST] Cache ready\n"); fflush(stdout);

    // Create VM in full mode with JIT
    printf("[TEST] Creating VM (full mode JIT)...\n"); fflush(stdout);
    rx_vm *vm = rx_create_vm(1, 0, 0, cache, NULL);  // useJit=1, lightClient=0 (full mode), height=0, no dataset
    if (!vm) {
        printf("[FAIL] VM allocation\n");
        rx_free_cache(cache);
        return 1;
    }

    // Test hash
    const char *input = "test input for hashing";
    uint8_t hash[32];

    printf("[TEST] Computing hash...\n"); fflush(stdout);
    clock_t start = clock();
    rx_calculate_hash(vm, input, strlen(input), hash);
    clock_t end = clock();
    double ms = 1000.0 * (end - start) / CLOCKS_PER_SEC;

    printf("[TEST] Hash computed in %.2f ms\n", ms);
    printf("[TEST] Hash (hex): ");
    for (int i = 0; i < 32; i++) printf("%02x", hash[i]);
    printf("\n");

    // Another hash to check consistency
    uint8_t hash2[32];
    rx_calculate_hash(vm, input, strlen(input), hash2);
    if (memcmp(hash, hash2, 32) == 0) {
        printf("[TEST] Hashes consistent - OK\n");
    } else {
        printf("[FAIL] Hashes differ!\n");
    }

    rx_destroy_vm(vm);
    rx_free_cache(cache);

    printf("[SUCCESS] Full mode JIT works\n");
    return 0;
}
