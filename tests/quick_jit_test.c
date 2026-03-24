#include "crypto/randomx/randomx.h"
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <time.h>

int main(void) {
    uint8_t key[32] = {0x01};
    uint8_t hash[32];
    const char *input = "test input for quick jit benchmark";

    printf("[QUICK] Allocating cache...\n"); fflush(stdout);
    rx_cache *cache = rx_alloc_cache(0);
    if (!cache) { printf("[FAIL] cache alloc\n"); return 1; }

    printf("[QUICK] Initializing cache...\n"); fflush(stdout);
    rx_init_cache(cache, key, 32);

    printf("[QUICK] Creating JIT VM (light mode - cache only)...\n"); fflush(stdout);
    rx_vm *vm = rx_create_vm(1, 1, 0, cache, NULL);
    if (!vm) { printf("[FAIL] VM alloc\n"); return 1; }

    printf("[QUICK] Testing JIT execution...\n"); fflush(stdout);
    LARGE_INTEGER t0, t1, freq;
    QueryPerformanceFrequency(&freq);

    // Warm up
    rx_calculate_hash(vm, (const uint8_t*)input, strlen(input), hash);
    printf("[QUICK] Warm-up done. Hash: ");
    for (int i = 0; i < 8; i++) printf("%02x", hash[i]);
    printf("\n");

    // Benchmark
    int num_hashes = 5;
    QueryPerformanceCounter(&t0);
    for (int i = 0; i < num_hashes; i++) {
        rx_calculate_hash(vm, (const uint8_t*)input, strlen(input), hash);
    }
    QueryPerformanceCounter(&t1);

    double elapsed = (double)(t1.QuadPart - t0.QuadPart) / freq.QuadPart;
    double hps = num_hashes / elapsed;

    printf("\n=== QUICK JIT TEST RESULTS ===\n");
    printf("Hashes:      %d\n", num_hashes);
    printf("Time:        %.3f s\n", elapsed);
    printf("Hashrate:    %.2f H/s\n", hps);
    printf("Status:      OK - JIT working\n");

    // Now test interpreter mode
    printf("\n[QUICK] Testing INTERPRETER  mode...\n"); fflush(stdout);
    rx_destroy_vm(vm);
    vm = rx_create_vm(0, 0, 0, cache, NULL);
    if (!vm) { printf("[FAIL] VM alloc (interp)\n"); return 1; }

    rx_calculate_hash(vm, (const uint8_t*)input, strlen(input), hash);
    printf("[QUICK] Warm-up done (interp). Hash: ");
    for (int i = 0; i < 8; i++) printf("%02x", hash[i]);
    printf("\n");

    QueryPerformanceCounter(&t0);
    for (int i = 0; i < num_hashes; i++) {
        rx_calculate_hash(vm, (const uint8_t*)input, strlen(input), hash);
    }
    QueryPerformanceCounter(&t1);

    elapsed = (double)(t1.QuadPart - t0.QuadPart) / freq.QuadPart;
    double hps_interp = num_hashes / elapsed;

    printf("\n=== INTERPRETER TEST RESULTS ===\n");
    printf("Hashes:      %d\n", num_hashes);
    printf("Time:        %.3f s\n", elapsed);
    printf("Hashrate:    %.2f H/s\n", hps_interp);
    printf("Status:      OK - Interpreter working\n");

    printf("\n=== COMPARISON ===\n");
    printf("JIT speedup: %.2fx\n", hps / hps_interp);

    rx_destroy_vm(vm);
    rx_free_cache(cache);
    return 0;
}
