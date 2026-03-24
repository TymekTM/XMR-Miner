#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "crypto/randomx/randomx.h"
#include "crypto/randomx/randomx_internal.h"

int main(void) {
    uint8_t key[32] = {0x01};

    printf("[TEST] Creating cache\n"); fflush(stdout);
    rx_cache *cache = rx_alloc_cache(0);
    if (!cache) return 1;

    printf("[TEST] Initializing cache\n"); fflush(stdout);
    rx_init_cache(cache, key, 32);

    printf("[TEST] Allocating small dataset (64MB)\n"); fflush(stdout);
    rx_dataset *dataset = rx_alloc_dataset(0);
    if (!dataset) return 1;

    printf("[TEST] Initializing 2M items (quick test)\n"); fflush(stdout);
    LARGE_INTEGER t0, t1, freq;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t0);
    rx_init_dataset(dataset, cache, 0, 2097152, 4, 4);  // 2M items, 4 threads
    QueryPerformanceCounter(&t1);
    printf("[TEST] Dataset init time: %.1f sec\n", (double)(t1.QuadPart - t0.QuadPart) / freq.QuadPart);

    // Test with JIT (vm.c has JIT enabled now)
    printf("[TEST] Creating VM WITH JIT\n"); fflush(stdout);
    rx_vm *vm_jit = rx_create_vm(1, 1, 0, cache, dataset);
    if (!vm_jit) return 1;

    const char *input = "test";
    uint8_t hash[32];

    printf("[TEST] Testing 1 hash with JIT...\n"); fflush(stdout);
    QueryPerformanceCounter(&t0);
    rx_calculate_hash(vm_jit, input, strlen(input), hash);
    QueryPerformanceCounter(&t1);
    double time_ms = (double)(t1.QuadPart - t0.QuadPart) / freq.QuadPart * 1000;
    printf("[RESULT] JIT: 1 hash in %.0f ms (%.2f H/s)\n", time_ms, 1000.0 / time_ms);

    rx_destroy_vm(vm_jit);
    rx_free_dataset(dataset);
    rx_free_cache(cache);

    printf("[TEST] Done\n");
    return 0;
}
