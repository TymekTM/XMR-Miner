#include "crypto/randomx/randomx.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

extern int g_jit_short_branches;
extern int g_jit_involution_pairs;
extern int g_jit_branch_align;
extern int g_jit_loop_nop;

#define ROUNDS 7
#define HASHES 400

static double now_seconds(void) {
    LARGE_INTEGER counter;
    LARGE_INTEGER frequency;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&counter);
    return (double)counter.QuadPart / (double)frequency.QuadPart;
}

static int compare_double(const void *a, const void *b) {
    double da = *(const double *)a;
    double db = *(const double *)b;
    return (da > db) - (da < db);
}

static double run_once(rx_vm *vm, uint8_t blob[76], int short_branches,
                       int involution_pairs, int branch_align,
                       int loop_nop,
                       uint8_t last_hash[32]) {
    g_jit_short_branches = short_branches;
    g_jit_involution_pairs = involution_pairs;
    g_jit_branch_align = branch_align;
    g_jit_loop_nop = loop_nop;
    rx_calculate_hash_first(vm, blob, 76);
    for (int i = 0; i < 16; ++i) {
        memcpy(blob + 39, &i, sizeof(i));
        rx_calculate_hash_next(vm, blob, 76, last_hash);
    }

    double start = now_seconds();
    for (int i = 0; i < HASHES; ++i) {
        uint32_t nonce = (uint32_t)(i * 0x9e3779b9u);
        memcpy(blob + 39, &nonce, sizeof(nonce));
        rx_calculate_hash_next(vm, blob, 76, last_hash);
    }
    return HASHES / (now_seconds() - start);
}

int main(void) {
    static const uint8_t key[] = "test key 000";
    double near_results[ROUNDS];
    double short_results[ROUNDS];
    uint8_t near_hash[32], short_hash[32];
    uint8_t blob_near[76], blob_short[76];

    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
    SetThreadAffinityMask(GetCurrentThread(), 1);
    memset(blob_near, 0x42, sizeof(blob_near));
    memcpy(blob_short, blob_near, sizeof(blob_near));

    rx_cache *cache = rx_alloc_cache(1);
    rx_dataset *dataset = rx_alloc_dataset(1);
    if (!cache || !dataset) {
        printf("[FAIL] allocation\n");
        return 1;
    }
    rx_init_cache(cache, key, sizeof(key) - 1);
    rx_init_dataset_cached(dataset, cache, 0,
                           RX_DATASET_ITEMS + RX_DATASET_EXTRA_ITEMS, 8, 8);

    rx_vm *near_vm = rx_create_vm(RX_FLAG_JIT, cache, dataset);
    rx_vm *short_vm = rx_create_vm(RX_FLAG_JIT, cache, dataset);
    if (!near_vm || !short_vm) {
        printf("[FAIL] VM allocation\n");
        return 1;
    }

    for (int round = 0; round < ROUNDS; ++round) {
        if ((round & 1) == 0) {
            near_results[round] = run_once(near_vm, blob_near, 0, 0, 0, 1, near_hash);
            short_results[round] = run_once(short_vm, blob_short, 1, 0, 0, 1, short_hash);
        } else {
            short_results[round] = run_once(short_vm, blob_short, 1, 0, 0, 1, short_hash);
            near_results[round] = run_once(near_vm, blob_near, 0, 0, 0, 1, near_hash);
        }
        if (memcmp(near_hash, short_hash, sizeof(near_hash)) != 0) {
            printf("[FAIL] hash mismatch in round %d\n", round);
            return 1;
        }
        printf("round %d: near %.1f H/s, short %.1f H/s, delta %+.2f%%\n",
               round + 1, near_results[round], short_results[round],
               100.0 * (short_results[round] / near_results[round] - 1.0));
    }

    qsort(near_results, ROUNDS, sizeof(double), compare_double);
    qsort(short_results, ROUNDS, sizeof(double), compare_double);
    double near_median = near_results[ROUNDS / 2];
    double short_median = short_results[ROUNDS / 2];
    printf("median: near %.1f H/s, short %.1f H/s, delta %+.2f%%\n",
           near_median, short_median,
           100.0 * (short_median / near_median - 1.0));

    memcpy(blob_short, blob_near, sizeof(blob_near));
    for (int round = 0; round < ROUNDS; ++round) {
        if ((round & 1) == 0) {
            near_results[round] = run_once(near_vm, blob_near, 0, 0, 0, 1, near_hash);
            short_results[round] = run_once(short_vm, blob_short, 0, 1, 0, 1, short_hash);
        } else {
            short_results[round] = run_once(short_vm, blob_short, 0, 1, 0, 1, short_hash);
            near_results[round] = run_once(near_vm, blob_near, 0, 0, 0, 1, near_hash);
        }
        if (memcmp(near_hash, short_hash, sizeof(near_hash)) != 0) {
            printf("[FAIL] involution hash mismatch in round %d\n", round);
            return 1;
        }
        printf("pairs %d: base %.1f H/s, optimized %.1f H/s, delta %+.2f%%\n",
               round + 1, near_results[round], short_results[round],
               100.0 * (short_results[round] / near_results[round] - 1.0));
    }
    qsort(near_results, ROUNDS, sizeof(double), compare_double);
    qsort(short_results, ROUNDS, sizeof(double), compare_double);
    near_median = near_results[ROUNDS / 2];
    short_median = short_results[ROUNDS / 2];
    printf("pairs median: base %.1f H/s, optimized %.1f H/s, delta %+.2f%%\n",
           near_median, short_median,
           100.0 * (short_median / near_median - 1.0));

    memcpy(blob_short, blob_near, sizeof(blob_near));
    for (int align = 16; align <= 32; align *= 2) {
        for (int round = 0; round < ROUNDS; ++round) {
            if ((round & 1) == 0) {
                near_results[round] = run_once(near_vm, blob_near, 0, 0, 0, 1, near_hash);
                short_results[round] = run_once(short_vm, blob_short, 0, 0, align, 1, short_hash);
            } else {
                short_results[round] = run_once(short_vm, blob_short, 0, 0, align, 1, short_hash);
                near_results[round] = run_once(near_vm, blob_near, 0, 0, 0, 1, near_hash);
            }
            if (memcmp(near_hash, short_hash, sizeof(near_hash)) != 0) {
                printf("[FAIL] branch alignment hash mismatch in round %d\n", round);
                return 1;
            }
            printf("align%d %d: base %.1f H/s, aligned %.1f H/s, delta %+.2f%%\n",
                   align, round + 1, near_results[round], short_results[round],
                   100.0 * (short_results[round] / near_results[round] - 1.0));
        }
        qsort(near_results, ROUNDS, sizeof(double), compare_double);
        qsort(short_results, ROUNDS, sizeof(double), compare_double);
        near_median = near_results[ROUNDS / 2];
        short_median = short_results[ROUNDS / 2];
        printf("align%d median: base %.1f H/s, aligned %.1f H/s, delta %+.2f%%\n",
               align, near_median, short_median,
               100.0 * (short_median / near_median - 1.0));
    }

    memcpy(blob_short, blob_near, sizeof(blob_near));
    for (int round = 0; round < ROUNDS; ++round) {
        if ((round & 1) == 0) {
            near_results[round] = run_once(near_vm, blob_near, 0, 0, 0, 1, near_hash);
            short_results[round] = run_once(short_vm, blob_short, 0, 0, 0, 0, short_hash);
        } else {
            short_results[round] = run_once(short_vm, blob_short, 0, 0, 0, 0, short_hash);
            near_results[round] = run_once(near_vm, blob_near, 0, 0, 0, 1, near_hash);
        }
        if (memcmp(near_hash, short_hash, sizeof(near_hash)) != 0) {
            printf("[FAIL] loop NOP hash mismatch in round %d\n", round);
            return 1;
        }
        printf("loop-nop %d: base %.1f H/s, removed %.1f H/s, delta %+.2f%%\n",
               round + 1, near_results[round], short_results[round],
               100.0 * (short_results[round] / near_results[round] - 1.0));
    }
    qsort(near_results, ROUNDS, sizeof(double), compare_double);
    qsort(short_results, ROUNDS, sizeof(double), compare_double);
    near_median = near_results[ROUNDS / 2];
    short_median = short_results[ROUNDS / 2];
    printf("loop-nop median: base %.1f H/s, removed %.1f H/s, delta %+.2f%%\n",
           near_median, short_median,
           100.0 * (short_median / near_median - 1.0));

    g_jit_short_branches = 0;
    g_jit_involution_pairs = 0;
    g_jit_branch_align = 0;
    g_jit_loop_nop = 1;
    rx_destroy_vm(near_vm);
    rx_destroy_vm(short_vm);
    rx_free_dataset(dataset);
    rx_free_cache(cache);
    return 0;
}
