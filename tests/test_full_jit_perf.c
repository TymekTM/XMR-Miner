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

// For debug - first two fields of rx_vm struct
typedef struct {
    void *jit;
    int useJit;
} rx_vm_debug;

int main() {
    printf("[PERF] Full mode JIT performance test\n");

    // Create cache
    rx_cache *cache = rx_alloc_cache(0);
    if (!cache) {
        printf("[FAIL] Cache allocation\n");
        return 1;
    }

    // Initialize cache
    const char *key = "test key";
    rx_init_cache(cache, key, strlen(key));
    printf("[PERF] Cache ready\n"); fflush(stdout);

    // Create VM in full mode with JIT
    // rx_create_vm(full_mem, use_jit, large_pages, cache, dataset)
    rx_vm *vm = rx_create_vm(1, 1, 0, cache, NULL);  // full_mem=1, use_jit=1, large_pages=0
    if (!vm) {
        printf("[FAIL] VM allocation\n");
        rx_free_cache(cache);
        return 1;
    }
    printf("[PERF] VM created (useJit=%d, jit=%p)\n", ((rx_vm_debug*)vm)->useJit, ((rx_vm_debug*)vm)->jit); fflush(stdout);

    // Warm up
    const char *input = "benchmark input";
    uint8_t hash[32];
    rx_calculate_hash(vm, input, strlen(input), hash);
    printf("[PERF] Warm-up done\n"); fflush(stdout);

    // Measure 10 hashes
    clock_t start = clock();
    for (int i = 0; i < 10; i++) {
        rx_calculate_hash(vm, input, strlen(input), hash);
    }
    clock_t end = clock();

    double seconds = (double)(end - start) / CLOCKS_PER_SEC;
    double hashrate = 10.0 / seconds;

    printf("[PERF] 10 hashes in %.3f seconds\n", seconds);
    printf("[PERF] Hashrate: %.2f H/s\n", hashrate);

    rx_destroy_vm(vm);
    rx_free_cache(cache);

    return 0;
}
