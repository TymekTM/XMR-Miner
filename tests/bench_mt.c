#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
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
    
    // Set thread affinity to a specific core to prevent L3 cache thrashing
    int core_ids[] = {0, 2, 4, 6, 8, 10, 12, 14, 16, 17, 18, 19, 20, 21, 22, 23};
    DWORD_PTR mask = (DWORD_PTR)1 << core_ids[data->thread_id % 16];
    SetThreadAffinityMask(GetCurrentThread(), mask);

    rx_vm* vm = rx_create_vm(1, 1, 1, cache, dataset);
    
    if (data->thread_id == 0) {
        printf("Large pages: %d\n", vm->large_pages);
    }

    uint8_t seed[32] = {0};
    seed[0] = data->thread_id;
    
    // Warmup
    for (int i = 0; i < 2; i++) {
        rx_calculate_hash(vm, seed, sizeof(seed), seed);
    }
    
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    
    for (int i = 0; i < ITERATIONS; i++) {
        rx_calculate_hash(vm, seed, sizeof(seed), seed);
    }
    
    QueryPerformanceCounter(&end);
    double time_taken = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;
    data->hashrate = ITERATIONS / time_taken;
    
    rx_destroy_vm(vm);
    
    return 0;
}

int main(int argc, char** argv) {
    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
    enable_huge_pages();
    // log_init();
    
    int num_threads = 16;
    if (argc > 1) num_threads = atoi(argv[1]);
    
    printf("Initializing RandomX...\n");
    cache = rx_alloc_cache(1);
    if (cache->large_pages) {
        printf("Cache allocated with large pages.\n");
    } else {
        printf("Cache NOT allocated with large pages.\n");
    }
    uint8_t key[] = "test_key_123456";
    rx_init_cache(cache, key, sizeof(key));
    
    dataset = rx_alloc_dataset(1);
    if (dataset->large_pages) {
        printf("Dataset allocated with large pages.\n");
    } else {
        printf("Dataset NOT allocated with large pages.\n");
    }
    rx_init_dataset_cached(dataset, cache, 0, RX_DATASET_ITEMS, 8, 8);
    
    printf("Starting %d miner threads...\n", num_threads);
    
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
    
    printf("\n==== PERFORMANCE ====\n");
    printf("Threads       : %d\n", num_threads);
    printf("Time Taken    : %.3f s\n", total_time);
    printf("Total Hashrate: %.2f H/s\n", (double)(num_threads * ITERATIONS) / total_time);
    
    free(threads);
    free(tdata);
    rx_free_dataset(dataset);
    rx_free_cache(cache);
    return 0;
}
