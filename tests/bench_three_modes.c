#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <windows.h>

#include "crypto/randomx/randomx_internal.h"

#define HASH_SIZE 32

static void enable_huge_pages(void) {
    TOKEN_PRIVILEGES tp = {0};
    LUID luid;
    HANDLE token;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        if (LookupPrivilegeValueA(NULL, "SeLockMemoryPrivilege", &luid)) {
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL);
        }
        CloseHandle(token);
    }
}

static uint64_t splitmix64_next(uint64_t *state) {
    uint64_t z;
    *state += 0x9e3779b97f4a7c15ULL;
    z = *state;
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

static void build_input(int vector_index, uint8_t *buf1, size_t *len1, uint8_t *buf2, size_t *len2) {
    uint64_t s1 = 0x123456789abcdef0ULL ^ (uint64_t)vector_index;
    uint64_t s2 = 0x0fedcba987654321ULL ^ ((uint64_t)vector_index << 1);
    *len1 = 32 + (size_t)(vector_index % 96);
    *len2 = 32 + (size_t)((vector_index * 7) % 96);

    for (size_t i = 0; i < *len1; i += 8) {
        uint64_t x = splitmix64_next(&s1);
        size_t n = (*len1 - i < 8) ? (*len1 - i) : 8;
        memcpy(buf1 + i, &x, n);
    }
    for (size_t i = 0; i < *len2; i += 8) {
        uint64_t x = splitmix64_next(&s2);
        size_t n = (*len2 - i < 8) ? (*len2 - i) : 8;
        memcpy(buf2 + i, &x, n);
    }
}

static void print_hash(const uint8_t *hash) {
    for (int i = 0; i < HASH_SIZE; i++) {
        printf("%02x", hash[i]);
    }
}

static double now_seconds(LARGE_INTEGER freq) {
    LARGE_INTEGER t;
    QueryPerformanceCounter(&t);
    return (double)t.QuadPart / (double)freq.QuadPart;
}

int main(void) {
    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
    enable_huge_pages();

    printf("=== RandomX 3-Mode Validation + Benchmark ===\n");

    uint8_t key[] = "test_key_123456";
    rx_cache *cache = rx_alloc_cache(1);
    if (!cache) {
        printf("[FAIL] Cache allocation failed\n");
        return 1;
    }
    rx_init_cache(cache, key, sizeof(key));

    rx_dataset *dataset = rx_alloc_dataset(1);
    if (!dataset) {
        printf("[FAIL] Dataset allocation failed\n");
        rx_free_cache(cache);
        return 1;
    }
    rx_init_dataset_cached(dataset, cache, 0, RX_DATASET_ITEMS, 8, 8);

    rx_vm *vm_interp1 = rx_create_vm(RX_FLAG_DEFAULT, cache, dataset);
    rx_vm *vm_interp2 = rx_create_vm(RX_FLAG_DEFAULT, cache, dataset);
    rx_vm *vm_single1 = rx_create_vm(RX_FLAG_JIT | RX_FLAG_DEFAULT, cache, dataset);
    rx_vm *vm_single2 = rx_create_vm(RX_FLAG_JIT | RX_FLAG_DEFAULT, cache, dataset);
    rx_vm *vm_dual1 = rx_create_vm(RX_FLAG_JIT | RX_FLAG_DEFAULT, cache, dataset);
    rx_vm *vm_dual2 = rx_create_vm(RX_FLAG_JIT | RX_FLAG_DEFAULT, cache, dataset);

    if (!vm_interp1 || !vm_interp2 || !vm_single1 || !vm_single2 || !vm_dual1 || !vm_dual2) {
        printf("[FAIL] VM allocation failed\n");
        rx_destroy_vm(vm_interp1);
        rx_destroy_vm(vm_interp2);
        rx_destroy_vm(vm_single1);
        rx_destroy_vm(vm_single2);
        rx_destroy_vm(vm_dual1);
        rx_destroy_vm(vm_dual2);
        rx_free_dataset(dataset);
        rx_free_cache(cache);
        return 1;
    }

    printf("\n=== Correctness: dual JIT == single JIT == interpreter ===\n");

    const int vectors = 64;
    int ok = 1;

    for (int i = 0; i < vectors; i++) {
        uint8_t in1[160] = {0};
        uint8_t in2[160] = {0};
        size_t len1 = 0;
        size_t len2 = 0;

        uint8_t h_interp1[HASH_SIZE] = {0};
        uint8_t h_interp2[HASH_SIZE] = {0};
        uint8_t h_single1[HASH_SIZE] = {0};
        uint8_t h_single2[HASH_SIZE] = {0};
        uint8_t h_dual1[HASH_SIZE] = {0};
        uint8_t h_dual2[HASH_SIZE] = {0};

        build_input(i, in1, &len1, in2, &len2);

        rx_calculate_hash(vm_interp1, in1, len1, h_interp1);
        rx_calculate_hash(vm_interp2, in2, len2, h_interp2);

        rx_calculate_hash(vm_single1, in1, len1, h_single1);
        rx_calculate_hash(vm_single2, in2, len2, h_single2);

        rx_calculate_hash_dual(vm_dual1, vm_dual2, in1, len1, in2, len2, h_dual1, h_dual2);

        if (memcmp(h_interp1, h_single1, HASH_SIZE) != 0 ||
            memcmp(h_interp1, h_dual1, HASH_SIZE) != 0 ||
            memcmp(h_interp2, h_single2, HASH_SIZE) != 0 ||
            memcmp(h_interp2, h_dual2, HASH_SIZE) != 0) {
            ok = 0;
            printf("[FAIL] Vector %d mismatch\n", i);
            printf("  VM1 interp: "); print_hash(h_interp1); printf("\n");
            printf("  VM1 single: "); print_hash(h_single1); printf("\n");
            printf("  VM1 dual  : "); print_hash(h_dual1); printf("\n");
            printf("  VM2 interp: "); print_hash(h_interp2); printf("\n");
            printf("  VM2 single: "); print_hash(h_single2); printf("\n");
            printf("  VM2 dual  : "); print_hash(h_dual2); printf("\n");
            break;
        }
    }

    if (!ok) {
        printf("[FAIL] Correctness check failed\n");
        rx_destroy_vm(vm_interp1);
        rx_destroy_vm(vm_interp2);
        rx_destroy_vm(vm_single1);
        rx_destroy_vm(vm_single2);
        rx_destroy_vm(vm_dual1);
        rx_destroy_vm(vm_dual2);
        rx_free_dataset(dataset);
        rx_free_cache(cache);
        return 1;
    }

    printf("[PASS] All %d vectors matched for both lanes\n", vectors);

    printf("\n=== Hashrate Benchmark ===\n");
    const int bench_iters = 300;
    LARGE_INTEGER freq;
    QueryPerformanceFrequency(&freq);

    uint8_t input1[76] = {0};
    uint8_t input2[76] = {0};
    uint8_t out1[HASH_SIZE] = {0};
    uint8_t out2[HASH_SIZE] = {0};

    for (int i = 0; i < 16; i++) {
        input1[0] = (uint8_t)i;
        input2[0] = (uint8_t)(i + 1);
        rx_calculate_hash(vm_interp1, input1, sizeof(input1), out1);
        rx_calculate_hash(vm_single1, input1, sizeof(input1), out1);
        rx_calculate_hash_dual(vm_dual1, vm_dual2, input1, sizeof(input1), input2, sizeof(input2), out1, out2);
    }

    double t0, t1;

    t0 = now_seconds(freq);
    for (int i = 0; i < bench_iters; i++) {
        input1[0] = (uint8_t)i;
        input1[1] = (uint8_t)(i >> 8);
        rx_calculate_hash(vm_interp1, input1, sizeof(input1), out1);
    }
    t1 = now_seconds(freq);
    double interp_time = t1 - t0;
    double interp_hs = (double)bench_iters / interp_time;

    t0 = now_seconds(freq);
    for (int i = 0; i < bench_iters; i++) {
        input1[0] = (uint8_t)i;
        input1[1] = (uint8_t)(i >> 8);
        rx_calculate_hash(vm_single1, input1, sizeof(input1), out1);
    }
    t1 = now_seconds(freq);
    double single_time = t1 - t0;
    double single_hs = (double)bench_iters / single_time;

    t0 = now_seconds(freq);
    for (int i = 0; i < bench_iters; i++) {
        input1[0] = (uint8_t)i;
        input1[1] = (uint8_t)(i >> 8);
        input2[0] = (uint8_t)(i + 17);
        input2[1] = (uint8_t)((i + 17) >> 8);
        rx_calculate_hash_dual(vm_dual1, vm_dual2, input1, sizeof(input1), input2, sizeof(input2), out1, out2);
    }
    t1 = now_seconds(freq);
    double dual_time = t1 - t0;
    double dual_hs = (double)(2 * bench_iters) / dual_time;

    printf("Interpreter : %.2f H/s  (%.3f s for %d hashes)\n", interp_hs, interp_time, bench_iters);
    printf("Single JIT  : %.2f H/s  (%.3f s for %d hashes)\n", single_hs, single_time, bench_iters);
    printf("Dual JIT    : %.2f H/s  (%.3f s for %d pairs = %d hashes)\n", dual_hs, dual_time, bench_iters, 2 * bench_iters);

    printf("\n=== Ratios ===\n");
    printf("Single JIT / Interpreter: %.3fx\n", single_hs / interp_hs);
    printf("Dual JIT   / Interpreter: %.3fx\n", dual_hs / interp_hs);
    printf("Dual JIT   / Single JIT : %.3fx\n", dual_hs / single_hs);

    rx_destroy_vm(vm_interp1);
    rx_destroy_vm(vm_interp2);
    rx_destroy_vm(vm_single1);
    rx_destroy_vm(vm_single2);
    rx_destroy_vm(vm_dual1);
    rx_destroy_vm(vm_dual2);
    rx_free_dataset(dataset);
    rx_free_cache(cache);
    return 0;
}
