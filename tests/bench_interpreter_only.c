#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "crypto/randomx/randomx.h"
#include "crypto/randomx/randomx_internal.h"

int main(void) {
    uint8_t key[32] = {0x01};

    printf("[BENCH] Allocating cache\n");
    rx_cache *cache = rx_alloc_cache(0);
    if (!cache) return 1;

    printf("[BENCH] Initializing cache\n"); fflush(stdout);
    rx_init_cache(cache, key, 32);

    printf("[BENCH] Allocating dataset\n"); fflush(stdout);
    rx_dataset *dataset = rx_alloc_dataset(0);
    if (!dataset) return 1;

    printf("[BENCH] Initializing dataset (14 threads)\n"); fflush(stdout);
    LARGE_INTEGER t0, t1, freq;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t0);
    rx_init_dataset(dataset, cache, 0, RX_DATASET_ITEMS, 14, 14);
    QueryPerformanceCounter(&t1);
    double init_time = (double)(t1.QuadPart - t0.QuadPart) / freq.QuadPart;
    printf("[BENCH] Dataset ready in %.1f seconds\n", init_time);

    // Create interpreter-only VM (use_jit=0)
    printf("[BENCH] Creating interpreter VM\n"); fflush(stdout);
    rx_vm *vm = rx_create_vm(1, 0, 0, cache, dataset);  // use_jit=0 for interpreter
    if (!vm) return 1;

    // Benchmark
    const char *input = "benchmark test";
    uint8_t hash[32];

    printf("[BENCH] Warming up (1 hash)...\n"); fflush(stdout);
    rx_calculate_hash(vm, input, strlen(input), hash);

    printf("[BENCH] Measuring 10 hashes...\n"); fflush(stdout);
    QueryPerformanceCounter(&t0);
    for (int i = 0; i < 10; i++) {
        rx_calculate_hash(vm, input, strlen(input), hash);
    }
    QueryPerformanceCounter(&t1);

    double hash_time = (double)(t1.QuadPart - t0.QuadPart) / freq.QuadPart;
    double hashrate = 10.0 / hash_time;

    printf("[BENCH] 10 hashes in %.3f seconds\n", hash_time);
    printf("[BENCH] Hashrate: %.2f H/s\n", hashrate);
    printf("[BENCH] Time per hash: %.2f ms\n", hash_time * 100);

    rx_destroy_vm(vm);
    rx_free_dataset(dataset);
    rx_free_cache(cache);

    return 0;
}
