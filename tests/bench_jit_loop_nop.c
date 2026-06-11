#include "crypto/randomx/randomx.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

extern int g_jit_loop_nop;

#define ROUNDS 11
#define HASHES 1000

static double now_seconds(void) {
    LARGE_INTEGER counter, frequency;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&counter);
    return (double)counter.QuadPart / (double)frequency.QuadPart;
}

static int compare_double(const void *a, const void *b) {
    double da = *(const double *)a;
    double db = *(const double *)b;
    return (da > db) - (da < db);
}

static double run_once(rx_vm *vm, uint8_t blob[76], int loop_nop,
                       uint8_t hash[32]) {
    g_jit_loop_nop = loop_nop;
    rx_calculate_hash_first(vm, blob, 76);
    for (int i = 0; i < 32; ++i) {
        memcpy(blob + 39, &i, sizeof(i));
        rx_calculate_hash_next(vm, blob, 76, hash);
    }

    double start = now_seconds();
    for (int i = 0; i < HASHES; ++i) {
        uint32_t nonce = (uint32_t)(i * 0x9e3779b9u);
        memcpy(blob + 39, &nonce, sizeof(nonce));
        rx_calculate_hash_next(vm, blob, 76, hash);
    }
    return HASHES / (now_seconds() - start);
}

int main(void) {
    static const uint8_t key[] = "test key 000";
    double base[ROUNDS], optimized[ROUNDS];
    uint8_t base_hash[32], optimized_hash[32];
    uint8_t base_blob[76], optimized_blob[76];

    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
    SetThreadAffinityMask(GetCurrentThread(), 1);
    memset(base_blob, 0x42, sizeof(base_blob));
    memcpy(optimized_blob, base_blob, sizeof(base_blob));

    rx_cache *cache = rx_alloc_cache(1);
    rx_dataset *dataset = rx_alloc_dataset(1);
    if (!cache || !dataset) return 1;
    rx_init_cache(cache, key, sizeof(key) - 1);
    rx_init_dataset_cached(dataset, cache, 0,
                           RX_DATASET_ITEMS + RX_DATASET_EXTRA_ITEMS, 8, 8);
    rx_vm *base_vm = rx_create_vm(RX_FLAG_JIT, cache, dataset);
    rx_vm *optimized_vm = rx_create_vm(RX_FLAG_JIT, cache, dataset);
    if (!base_vm || !optimized_vm) return 1;

    for (int round = 0; round < ROUNDS; ++round) {
        if (round & 1) {
            optimized[round] = run_once(optimized_vm, optimized_blob, 0, optimized_hash);
            base[round] = run_once(base_vm, base_blob, 1, base_hash);
        } else {
            base[round] = run_once(base_vm, base_blob, 1, base_hash);
            optimized[round] = run_once(optimized_vm, optimized_blob, 0, optimized_hash);
        }
        if (memcmp(base_hash, optimized_hash, sizeof(base_hash)) != 0) {
            printf("[FAIL] hash mismatch\n");
            return 1;
        }
        printf("round %2d: base %.1f H/s, no-nop %.1f H/s, delta %+.2f%%\n",
               round + 1, base[round], optimized[round],
               100.0 * (optimized[round] / base[round] - 1.0));
    }

    qsort(base, ROUNDS, sizeof(double), compare_double);
    qsort(optimized, ROUNDS, sizeof(double), compare_double);
    printf("median: base %.1f H/s, no-nop %.1f H/s, delta %+.2f%%\n",
           base[ROUNDS / 2], optimized[ROUNDS / 2],
           100.0 * (optimized[ROUNDS / 2] / base[ROUNDS / 2] - 1.0));

    g_jit_loop_nop = 1;
    rx_destroy_vm(base_vm);
    rx_destroy_vm(optimized_vm);
    rx_free_dataset(dataset);
    rx_free_cache(cache);
    return 0;
}
