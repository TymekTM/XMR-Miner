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

typedef struct {
    int thread_id;
    double hashrate;
} thread_data_t;

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

DWORD WINAPI miner_thread(LPVOID arg) {
    thread_data_t* data = (thread_data_t*)arg;

    rx_vm* vm1 = rx_create_vm(1, 1, 1, cache, dataset);
    rx_vm* vm2 = rx_create_vm(1, 1, 1, cache, dataset);

    uint8_t seed1[32] = {0};
    uint8_t seed2[32] = {0};
    seed1[0] = (uint8_t)data->thread_id;
    seed2[0] = (uint8_t)(data->thread_id + 100);

    uint8_t hash1[32], hash2[32];

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
    data->hashrate = (ITERATIONS * 2) / time_taken;

    if (data->thread_id == 0) {
        printf("  T0 hash1: ");
        for (int i = 0; i < 32; i++) printf("%02x", hash1[i]);
        printf("\n  T0 hash2: ");
        for (int i = 0; i < 32; i++) printf("%02x", hash2[i]);
        printf("\n  T0 large_pages=%d jit=%d\n", vm1->large_pages, vm1->useJit);
    }

    rx_destroy_vm(vm1);
    rx_destroy_vm(vm2);

    return 0;
}

int main(int argc, char** argv) {
    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
    enable_huge_pages();

    int num_threads = 16;
    if (argc > 1) num_threads = atoi(argv[1]);

    printf("Initializing RandomX (dual mode)...\n");
    cache = rx_alloc_cache(1);
    if (!cache->large_pages) printf("WARNING: Cache NOT large pages\n");
    uint8_t key[] = "test_key_123456";
    rx_init_cache(cache, key, sizeof(key));

    dataset = rx_alloc_dataset(1);
    if (!dataset->large_pages) printf("WARNING: Dataset NOT large pages\n");
    rx_init_dataset_cached(dataset, cache, 0, RX_DATASET_ITEMS, 8, 8);

    printf("Starting %d dual miner threads (2 hashes each)...\n", num_threads);

    HANDLE* threads = (HANDLE*)malloc(num_threads * sizeof(HANDLE));
    thread_data_t* tdata = (thread_data_t*)malloc(num_threads * sizeof(thread_data_t));

    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);

    for (int i = 0; i < num_threads; i++) {
        tdata[i].thread_id = i;
        tdata[i].hashrate = 0.0;
        threads[i] = CreateThread(NULL, 0, miner_thread, &tdata[i], 0, NULL);
    }

    WaitForMultipleObjects(num_threads, threads, TRUE, INFINITE);

    QueryPerformanceCounter(&end);
    double total_time = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;

    printf("\n==== PERFORMANCE (DUAL JIT) ====\n");
    printf("Threads       : %d (x2 hashes each)\n", num_threads);
    printf("Time Taken    : %.3f s\n", total_time);
    printf("Total Hashrate: %.2f H/s\n", (double)(num_threads * ITERATIONS * 2) / total_time);

    free(threads);
    free(tdata);
    rx_free_dataset(dataset);
    rx_free_cache(cache);
    return 0;
}
