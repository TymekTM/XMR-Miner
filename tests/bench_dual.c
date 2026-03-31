#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <windows.h>
#include "crypto/randomx/randomx_internal.h"
#include "common/cpu.h"
#include "common/log.h"

#define ITERATIONS 200

rx_cache* cache = NULL;
rx_dataset* dataset = NULL;

static void enable_huge_pages() {
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

static void print_hash(const char* label, const uint8_t* hash) {
    printf("%s: ", label);
    for (int i = 0; i < 32; i++) printf("%02x", hash[i]);
    printf("\n");
}

static int verify_correctness() {
    printf("\n=== CORRECTNESS VERIFICATION ===\n");
    fflush(stdout);

    rx_vm* vm1_dual = rx_create_vm(1, 1, 1, cache, dataset);
    rx_vm* vm2_dual = rx_create_vm(1, 1, 1, cache, dataset);
    rx_vm* vm1_single = rx_create_vm(1, 1, 1, cache, dataset);
    rx_vm* vm2_single = rx_create_vm(1, 1, 1, cache, dataset);

    printf("VMs created\n"); fflush(stdout);

    uint8_t seed1[32] = {0xAA, 0xBB, 0xCC, 0xDD};
    uint8_t seed2[32] = {0x11, 0x22, 0x33, 0x44};

    uint8_t dual_hash1[64] = {0}, dual_hash2[64] = {0};
    uint8_t single_hash1[64] = {0}, single_hash2[64] = {0};

    printf("Computing single hashes...\n"); fflush(stdout);
    rx_calculate_hash(vm1_single, seed1, sizeof(seed1), single_hash1);
    printf("  VM1 single done\n"); fflush(stdout);
    rx_calculate_hash(vm2_single, seed2, sizeof(seed2), single_hash2);
    printf("  VM2 single done\n"); fflush(stdout);

    printf("Computing dual hashes...\n"); fflush(stdout);
    rx_calculate_hash_dual(vm1_dual, vm2_dual, seed1, sizeof(seed1), seed2, sizeof(seed2), dual_hash1, dual_hash2);
    printf("  Dual done\n"); fflush(stdout);

    int ok = 1;
    if (memcmp(dual_hash1, single_hash1, 32) != 0) {
        printf("[FAIL] VM1 hash mismatch!\n");
        print_hash("  Dual ", dual_hash1);
        print_hash("  Single", single_hash1);
        ok = 0;
    } else {
        printf("[PASS] VM1 hash matches\n");
        print_hash("  Hash ", dual_hash1);
    }

    if (memcmp(dual_hash2, single_hash2, 32) != 0) {
        printf("[FAIL] VM2 hash mismatch!\n");
        print_hash("  Dual ", dual_hash2);
        print_hash("  Single", single_hash2);
        ok = 0;
    } else {
        printf("[PASS] VM2 hash matches\n");
        print_hash("  Hash ", dual_hash2);
    }

    rx_destroy_vm(vm1_dual);
    rx_destroy_vm(vm2_dual);
    rx_destroy_vm(vm1_single);
    rx_destroy_vm(vm2_single);

    return ok;
}

DWORD WINAPI dual_miner_thread(LPVOID arg) {
    int thread_id = *(int*)arg;

    int core_ids[] = {0, 2, 4, 6, 8, 10, 12, 14, 16, 17, 18, 19, 20, 21, 22, 23};
    DWORD_PTR mask = (DWORD_PTR)1 << core_ids[thread_id % 16];
    SetThreadAffinityMask(GetCurrentThread(), mask);

    rx_vm* vm1 = rx_create_vm(1, 1, 1, cache, dataset);
    rx_vm* vm2 = rx_create_vm(1, 1, 1, cache, dataset);

    uint8_t seed1[32] = {0};
    uint8_t seed2[32] = {0};
    seed1[0] = thread_id * 2;
    seed2[0] = thread_id * 2 + 1;

    uint8_t hash1[64] = {0};
    uint8_t hash2[64] = {0};

    for (int i = 0; i < 2; i++) {
        rx_calculate_hash_dual(vm1, vm2, seed1, sizeof(seed1), seed2, sizeof(seed2), hash1, hash2);
    }

    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);

    for (int i = 0; i < ITERATIONS; i++) {
        rx_calculate_hash_dual(vm1, vm2, seed1, sizeof(seed1), seed2, sizeof(seed2), hash1, hash2);
    }

    QueryPerformanceCounter(&end);
    double time_taken = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;
    double hashrate = (2.0 * ITERATIONS) / time_taken;

    if (thread_id == 0) {
        printf("[Dual] Thread %d: %.2f H/s (2x%d hashes in %.3fs)\n",
               thread_id, hashrate, ITERATIONS, time_taken);
    }

    rx_destroy_vm(vm1);
    rx_destroy_vm(vm2);

    double* result = (double*)malloc(sizeof(double));
    *result = hashrate;
    return (DWORD_PTR)result;
}

DWORD WINAPI single_miner_thread(LPVOID arg) {
    int thread_id = *(int*)arg;

    int core_ids[] = {0, 2, 4, 6, 8, 10, 12, 14, 16, 17, 18, 19, 20, 21, 22, 23};
    DWORD_PTR mask = (DWORD_PTR)1 << core_ids[thread_id % 16];
    SetThreadAffinityMask(GetCurrentThread(), mask);

    rx_vm* vm = rx_create_vm(1, 1, 1, cache, dataset);

    uint8_t seed[32] = {0};
    seed[0] = thread_id;

    uint8_t hash[64] = {0};

    for (int i = 0; i < 2; i++) {
        rx_calculate_hash(vm, seed, sizeof(seed), hash);
    }

    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);

    for (int i = 0; i < ITERATIONS; i++) {
        rx_calculate_hash(vm, seed, sizeof(seed), hash);
    }

    QueryPerformanceCounter(&end);
    double time_taken = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;
    double hashrate = ITERATIONS / time_taken;

    if (thread_id == 0) {
        printf("[Single] Thread %d: %.2f H/s (%d hashes in %.3fs)\n",
               thread_id, hashrate, ITERATIONS, time_taken);
    }

    rx_destroy_vm(vm);

    double* result = (double*)malloc(sizeof(double));
    *result = hashrate;
    return (DWORD_PTR)result;
}

int main(int argc, char** argv) {
    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
    enable_huge_pages();

    int num_threads = 8;
    if (argc > 1) num_threads = atoi(argv[1]);

    printf("=== DUAL-HASH JIT BENCHMARK ===\n");
    printf("Initializing RandomX...\n");
    cache = rx_alloc_cache(1);
    if (cache->large_pages) {
        printf("[I] Cache allocated with large pages.\n");
    }
    uint8_t key[] = "test_key_123456";
    rx_init_cache(cache, key, sizeof(key));

    dataset = rx_alloc_dataset(1);
    if (dataset->large_pages) {
        printf("[I] Dataset allocated with large pages.\n");
    }
    rx_init_dataset_cached(dataset, cache, 0, RX_DATASET_ITEMS, 8, 8);

    if (!verify_correctness()) {
        printf("\n[CORRECTNESS FAILED] Aborting benchmark.\n");
        rx_free_dataset(dataset);
        rx_free_cache(cache);
        return 1;
    }

    printf("\n--- SINGLE-HASH MODE (%d threads) ---\n", num_threads);
    HANDLE* threads = (HANDLE*)malloc(num_threads * sizeof(HANDLE));
    int* tids = (int*)malloc(num_threads * sizeof(int));

    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);

    for (int i = 0; i < num_threads; i++) {
        tids[i] = i;
        threads[i] = CreateThread(NULL, 0, single_miner_thread, &tids[i], 0, NULL);
    }
    WaitForMultipleObjects(num_threads, threads, TRUE, INFINITE);
    QueryPerformanceCounter(&end);
    double single_time = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;
    double single_total = (double)(num_threads * ITERATIONS) / single_time;
    printf("[Single] Total: %.2f H/s (%d threads)\n\n", single_total, num_threads);

    printf("--- DUAL-HASH MODE (%d threads, 2x interleaved) ---\n", num_threads);
    QueryPerformanceCounter(&start);

    for (int i = 0; i < num_threads; i++) {
        tids[i] = i;
        threads[i] = CreateThread(NULL, 0, dual_miner_thread, &tids[i], 0, NULL);
    }
    WaitForMultipleObjects(num_threads, threads, TRUE, INFINITE);
    QueryPerformanceCounter(&end);
    double dual_time = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;
    double dual_total = (double)(2 * num_threads * ITERATIONS) / dual_time;
    printf("[Dual] Total: %.2f H/s (%d threads, 2x interleaved)\n\n", dual_total, num_threads);

    printf("=== SUMMARY ===\n");
    printf("Single-hash: %.2f H/s\n", single_total);
    printf("Dual-hash  : %.2f H/s\n", dual_total);
    printf("Improvement: %.2fx\n", dual_total / single_total);

    free(threads);
    free(tids);
    rx_free_dataset(dataset);
    rx_free_cache(cache);
    return 0;
}
