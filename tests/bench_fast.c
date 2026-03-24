#include "crypto/randomx/randomx.h"
#include "crypto/randomx/randomx_internal.h"
#include <stdio.h>
#include <string.h>
#include <windows.h>

int main(void) {
    uint8_t key[32] = {0x01};

    printf("[BENCH] Allocating cache...\n"); fflush(stdout);
    rx_cache *cache = rx_alloc_cache(0);
    if (!cache) { printf("[FAIL] cache alloc\n"); return 1; }

    printf("[BENCH] Initializing cache (~30s)...\n"); fflush(stdout);
    rx_init_cache(cache, key, 32);
    printf("[BENCH] Cache ready\n"); fflush(stdout);

    printf("[BENCH] Initializing dataset (multi-threaded)...\n"); fflush(stdout);
    rx_dataset *dataset = rx_alloc_dataset(0);
    if (!dataset) { printf("[FAIL] dataset alloc\n"); return 1; }
    rx_init_dataset_cached(dataset, cache, 0, RX_DATASET_ITEMS, 8, 8);
    printf("[BENCH] Dataset ready\n"); fflush(stdout);

    rx_vm *vm = rx_create_vm(1, 0, 0, cache, dataset);
    if (!vm) { printf("[FAIL] VM alloc\n"); return 1; }

    uint8_t blob[76] = {0};
    memset(blob, 0x41, 76);
    uint8_t hash[32];

    printf("[BENCH] Warming up...\n"); fflush(stdout);
    rx_calculate_hash_first(vm, blob, 76);
    rx_calculate_hash_next(vm, blob, 76, hash);
    printf("[BENCH] Warm-up done. Starting benchmark...\n"); fflush(stdout);

    int num_hashes = 1000;
    LARGE_INTEGER t0, t1, freq;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t0);
    for (int i = 0; i < num_hashes; i++) {
        rx_calculate_hash_next(vm, blob, 76, hash);
    }
    QueryPerformanceCounter(&t1);
    double elapsed = (double)(t1.QuadPart - t0.QuadPart) / freq.QuadPart;
    double hps = num_hashes / elapsed;

    printf("\n=== RESULTS ===\n");
    printf("Hashes:       %d\n", num_hashes);
    printf("Time:         %.3f s\n", elapsed);
    printf("Hashrate:     %.2f H/s\n", hps);
    printf("Time/hash:    %.1f ms\n", (elapsed / num_hashes) * 1000.0);
    printf("Hash sample:  ");
    for (int i = 0; i < 8; i++) printf("%02x", hash[i]);
    printf("...\n"); fflush(stdout);

    rx_destroy_vm(vm);
    rx_free_dataset(dataset);
    rx_free_cache(cache);
    return 0;
}
