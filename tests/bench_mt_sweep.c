#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <windows.h>
#include "crypto/randomx/randomx_internal.h"

#define ITERATIONS 120
#define MAX_BENCH_CORES 128

static rx_cache* cache = NULL;
static rx_dataset* dataset = NULL;
static int g_affinity_policy = 0;
static int g_thread_prio = THREAD_PRIORITY_HIGHEST;

typedef struct {
    int thread_id;
    int os_cpu;
    double hashrate;
} thread_data_t;

typedef struct {
    int count;
    int os_index[MAX_BENCH_CORES];
    int is_pcore[MAX_BENCH_CORES];
    int sibling[MAX_BENCH_CORES];
} core_list_t;

static core_list_t g_cores;
static int g_affinity_ready = 0;

static int detect_cores(core_list_t *cores) {
    cores->count = 0;
    DWORD len = 0;
    GetLogicalProcessorInformationEx(RelationProcessorCore, NULL, &len);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) return 0;

    SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *buf = (SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *)malloc(len);
    if (!buf) return 0;
    if (!GetLogicalProcessorInformationEx(RelationProcessorCore, buf, &len)) {
        free(buf);
        return 0;
    }

    BYTE *ptr = (BYTE *)buf;
    DWORD remaining = len;
    while (remaining > 0) {
        SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *item = (SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *)ptr;
        if (item->Relationship == RelationProcessorCore && item->Processor.GroupCount > 0) {
            GROUP_AFFINITY mask = item->Processor.GroupMask[0];
            int first = -1;
            int second = -1;
            int bits = 0;
            for (int b = 0; b < 64; b++) {
                if (mask.Mask & (1ULL << b)) {
                    int os_idx = b + mask.Group * 64;
                    if (first < 0) first = os_idx;
                    else if (second < 0) second = os_idx;
                    bits++;
                }
            }
            if (first >= 0 && cores->count < MAX_BENCH_CORES) {
                int i = cores->count++;
                cores->os_index[i] = first;
                cores->sibling[i] = second;
                cores->is_pcore[i] = (bits >= 2) ? 1 : 0;
            }
        }
        ptr += item->Size;
        remaining -= item->Size;
    }

    free(buf);
    return cores->count;
}

static int build_affinity_order(int *order, int max_order) {
    if (!g_affinity_ready || g_cores.count <= 0) return 0;
    int n = 0;

    if (g_affinity_policy == 1) {
        for (int i = 0; i < g_cores.count && n < max_order; i++) if (g_cores.is_pcore[i]) order[n++] = g_cores.os_index[i];
        for (int i = 0; i < g_cores.count && n < max_order; i++) if (g_cores.is_pcore[i] && g_cores.sibling[i] >= 0) order[n++] = g_cores.sibling[i];
        for (int i = 0; i < g_cores.count && n < max_order; i++) if (!g_cores.is_pcore[i]) order[n++] = g_cores.os_index[i];
    } else if (g_affinity_policy == 2) {
        for (int i = 0; i < g_cores.count && n < max_order; i++) if (g_cores.is_pcore[i]) order[n++] = g_cores.os_index[i];
        for (int i = 0; i < g_cores.count && n < max_order; i++) if (!g_cores.is_pcore[i]) order[n++] = g_cores.os_index[i];
        for (int i = 0; i < g_cores.count && n < max_order; i++) if (g_cores.is_pcore[i] && g_cores.sibling[i] >= 0) order[n++] = g_cores.sibling[i];
    } else if (g_affinity_policy == 3) {
        int tmp[MAX_BENCH_CORES * 2];
        int m = 0;
        for (int i = 0; i < g_cores.count && m < max_order; i++) tmp[m++] = g_cores.os_index[i];
        for (int i = 0; i < g_cores.count && m < max_order; i++) if (g_cores.sibling[i] >= 0) tmp[m++] = g_cores.sibling[i];
        for (int i = 0; i < m && n < max_order; i++) {
            for (int j = i + 1; j < m; j++) {
                if (tmp[j] < tmp[i]) {
                    int t = tmp[i];
                    tmp[i] = tmp[j];
                    tmp[j] = t;
                }
            }
        }
        for (int i = 0; i < m && n < max_order; i++) order[n++] = tmp[i];
    } else {
        for (int i = 0; i < g_cores.count && n < max_order; i++) if (g_cores.is_pcore[i]) order[n++] = g_cores.os_index[i];
        for (int i = 0; i < g_cores.count && n < max_order; i++) if (!g_cores.is_pcore[i]) order[n++] = g_cores.os_index[i];
    }

    return n;
}

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

static DWORD WINAPI miner_thread(LPVOID arg) {
    thread_data_t* data = (thread_data_t*)arg;

    SetThreadPriority(GetCurrentThread(), g_thread_prio);

    if (data->os_cpu >= 0) {
        GROUP_AFFINITY ga = {0};
        ga.Group = (WORD)(data->os_cpu / 64);
        ga.Mask = (KAFFINITY)(1ULL << (data->os_cpu % 64));
        SetThreadGroupAffinity(GetCurrentThread(), &ga, NULL);
    }

    rx_vm* vm = rx_create_vm(1, 1, 1, cache, dataset);
    uint8_t seed[32] = {0};
    seed[0] = (uint8_t)data->thread_id;
    for (int i = 0; i < 2; i++) rx_calculate_hash(vm, seed, sizeof(seed), seed);

    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    for (int i = 0; i < ITERATIONS; i++) rx_calculate_hash(vm, seed, sizeof(seed), seed);
    QueryPerformanceCounter(&end);

    double elapsed = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;
    data->hashrate = ITERATIONS / elapsed;
    rx_destroy_vm(vm);
    return 0;
}

static double run_threads(int num_threads) {
    HANDLE* threads = (HANDLE*)malloc(num_threads * sizeof(HANDLE));
    thread_data_t* tdata = (thread_data_t*)calloc(num_threads, sizeof(thread_data_t));
    int order[MAX_BENCH_CORES * 2];
    int order_count = build_affinity_order(order, (int)(sizeof(order) / sizeof(order[0])));

    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);

    for (int i = 0; i < num_threads; i++) {
        tdata[i].thread_id = i;
        tdata[i].os_cpu = (order_count > 0) ? order[i % order_count] : -1;
        threads[i] = CreateThread(NULL, 0, miner_thread, &tdata[i], 0, NULL);
    }
    WaitForMultipleObjects(num_threads, threads, TRUE, INFINITE);
    QueryPerformanceCounter(&end);

    double wall = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;
    double total = (double)(num_threads * ITERATIONS) / wall;

    for (int i = 0; i < num_threads; i++) CloseHandle(threads[i]);
    free(threads);
    free(tdata);
    return total;
}

int main(int argc, char** argv) {
    int max_threads = 20;
    int proc_prio_mode = 1;
    if (argc > 1) max_threads = atoi(argv[1]);
    if (argc > 2) g_affinity_policy = atoi(argv[2]);
    if (argc > 3) {
        int p = atoi(argv[3]);
        g_thread_prio = (p == 0) ? THREAD_PRIORITY_NORMAL : THREAD_PRIORITY_TIME_CRITICAL;
    }
    if (argc > 4) proc_prio_mode = atoi(argv[4]);
    if (max_threads < 1) max_threads = 1;

    if (proc_prio_mode == 2) SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS);
    else if (proc_prio_mode == 1) SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
    else SetPriorityClass(GetCurrentProcess(), NORMAL_PRIORITY_CLASS);
    enable_huge_pages();

    g_affinity_ready = detect_cores(&g_cores) > 0;

    cache = rx_alloc_cache(1);
    uint8_t key[] = "test_key_123456";
    rx_init_cache(cache, key, sizeof(key));
    dataset = rx_alloc_dataset(1);
    rx_init_dataset_cached(dataset, cache, 0, RX_DATASET_ITEMS, 8, 8);

    printf("meta,policy=%d,thread_prio=%d,proc_prio=%d\n", g_affinity_policy, g_thread_prio, proc_prio_mode);
    printf("threads,total_hs\n");
    for (int t = 1; t <= max_threads; t++) {
        double hs = run_threads(t);
        printf("%d,%.2f\n", t, hs);
        fflush(stdout);
    }

    rx_free_dataset(dataset);
    rx_free_cache(cache);
    return 0;
}
