#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <windows.h>
#include "crypto/randomx/randomx_internal.h"
#include "common/cpu.h"
#include "common/log.h"

#define ITERATIONS 2000

rx_cache* cache = NULL;
rx_dataset* dataset = NULL;

typedef struct {
    int thread_id;
    int mode; // 0=interp, 1=single jit, 2=dual jit
    double hashrate;
    uint8_t hash1[32];
    uint8_t hash2[32];
    double per_thread_time;
} thread_data_t;

#define MAX_BENCH_CORES 128

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
    int has_ecores = 0;
    for (int i = 0; i < g_cores.count; i++) if (!g_cores.is_pcore[i]) has_ecores = 1;

    for (int i = 0; i < g_cores.count && n < max_order; i++) {
        if (g_cores.is_pcore[i]) order[n++] = g_cores.os_index[i];
    }
    if (!has_ecores) {
        for (int i = 0; i < g_cores.count && n < max_order; i++) {
            if (g_cores.is_pcore[i] && g_cores.sibling[i] >= 0) order[n++] = g_cores.sibling[i];
        }
    }
    for (int i = 0; i < g_cores.count && n < max_order; i++) {
        if (!g_cores.is_pcore[i]) order[n++] = g_cores.os_index[i];
    }

    return n;
}

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

DWORD WINAPI bench_thread(LPVOID arg) {
    thread_data_t* d = (thread_data_t*)arg;
    int tid = d->thread_id;

    int order[MAX_BENCH_CORES * 2];
    int order_count = build_affinity_order(order, (int)(sizeof(order) / sizeof(order[0])));
    if (order_count > 0) {
        int os_idx = order[tid % order_count];
        GROUP_AFFINITY ga = {0};
        ga.Group = (WORD)(os_idx / 64);
        ga.Mask = (KAFFINITY)(1ULL << (os_idx % 64));
        SetThreadGroupAffinity(GetCurrentThread(), &ga, NULL);
    }

    uint8_t seed[32] = {0};
    seed[0] = (uint8_t)tid;

    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);

    if (d->mode == 0) {
        rx_vm* vm = rx_create_vm(RX_FLAG_DEFAULT, cache, dataset);
        uint8_t hash[32];
        for (int i = 0; i < 2; i++) rx_calculate_hash(vm, seed, sizeof(seed), hash);
        QueryPerformanceCounter(&start);
        for (int i = 0; i < ITERATIONS; i++) rx_calculate_hash(vm, seed, sizeof(seed), hash);
        QueryPerformanceCounter(&end);
        memcpy(d->hash1, hash, 32);
        rx_destroy_vm(vm);
    } else if (d->mode == 1) {
        rx_vm* vm = rx_create_vm(RX_FLAG_JIT, cache, dataset);
        uint8_t hash[32];
        for (int i = 0; i < 2; i++) rx_calculate_hash(vm, seed, sizeof(seed), hash);
        QueryPerformanceCounter(&start);
        for (int i = 0; i < ITERATIONS; i++) rx_calculate_hash(vm, seed, sizeof(seed), hash);
        QueryPerformanceCounter(&end);
        memcpy(d->hash1, hash, 32);
        rx_destroy_vm(vm);
    } else {
        rx_vm* vm1 = rx_create_vm(RX_FLAG_JIT, cache, dataset);
        rx_vm* vm2 = rx_create_vm(RX_FLAG_JIT, cache, dataset);
        uint8_t seed2[32] = {0};
        seed2[0] = (uint8_t)(tid + 200);
        uint8_t h1[32], h2[32];
        for (int i = 0; i < 2; i++) rx_calculate_hash_dual(vm1, vm2, seed, sizeof(seed), seed2, sizeof(seed2), h1, h2);
        QueryPerformanceCounter(&start);
        for (int i = 0; i < ITERATIONS; i++) rx_calculate_hash_dual(vm1, vm2, seed, sizeof(seed), seed2, sizeof(seed2), h1, h2);
        QueryPerformanceCounter(&end);
        memcpy(d->hash1, h1, 32);
        memcpy(d->hash2, h2, 32);
        rx_destroy_vm(vm1);
        rx_destroy_vm(vm2);
    }

    double elapsed = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;
    int hashes_per_thread = (d->mode == 2) ? ITERATIONS * 2 : ITERATIONS;
    d->hashrate = hashes_per_thread / elapsed;
    d->per_thread_time = elapsed;
    return 0;
}

static double run_mode(int num_threads, int mode, const char* label, uint8_t* ref_hash, uint8_t* ref_hash2) {
    thread_data_t* tdata = (thread_data_t*)calloc(num_threads, sizeof(thread_data_t));
    HANDLE* threads = (HANDLE*)calloc(num_threads, sizeof(HANDLE));

    for (int i = 0; i < num_threads; i++) {
        tdata[i].thread_id = i;
        tdata[i].mode = mode;
    }

    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);

    for (int i = 0; i < num_threads; i++)
        threads[i] = CreateThread(NULL, 0, bench_thread, &tdata[i], 0, NULL);
    WaitForMultipleObjects(num_threads, threads, TRUE, INFINITE);
    QueryPerformanceCounter(&end);

    double wall = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;
    int hashes_per_thread = (mode == 2) ? ITERATIONS * 2 : ITERATIONS;
    double total_hr = (double)(num_threads * hashes_per_thread) / wall;

    double avg_per_thread = 0;
    double min_per_thread = 1e18, max_per_thread = 0;
    for (int i = 0; i < num_threads; i++) {
        avg_per_thread += tdata[i].per_thread_time;
        if (tdata[i].per_thread_time < min_per_thread) min_per_thread = tdata[i].per_thread_time;
        if (tdata[i].per_thread_time > max_per_thread) max_per_thread = tdata[i].per_thread_time;
    }
    avg_per_thread /= num_threads;

    printf("  %-16s %8.1f H/s  wall=%.3fs  avg_t=%.3fs  min_t=%.3fs  max_t=%.3fs  imbalance=%.1f%%\n",
           label, total_hr, wall, avg_per_thread, min_per_thread, max_per_thread,
           (max_per_thread - min_per_thread) / avg_per_thread * 100.0);

    int hash_ok = 1;
    if (ref_hash && num_threads > 0) {
        if (memcmp(tdata[0].hash1, ref_hash, 32) != 0) {
            printf("    [FAIL] hash1 mismatch!\n");
            print_hash("    expected", ref_hash);
            print_hash("    got     ", tdata[0].hash1);
            hash_ok = 0;
        } else {
            printf("    [OK] hash1 matches\n");
        }
    }
    if (ref_hash2 && mode == 2 && num_threads > 0) {
        if (memcmp(tdata[0].hash2, ref_hash2, 32) != 0) {
            printf("    [FAIL] hash2 mismatch!\n");
            hash_ok = 0;
        } else {
            printf("    [OK] hash2 matches\n");
        }
    }

    for (int i = 0; i < num_threads; i++) CloseHandle(threads[i]);
    free(threads);
    free(tdata);
    return total_hr;
}

int main(int argc, char** argv) {
    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
    enable_huge_pages();

    int max_threads = 8;
    if (argc > 1) max_threads = atoi(argv[1]);

    g_affinity_ready = detect_cores(&g_cores) > 0;
    if (g_affinity_ready) {
        int p = 0;
        for (int i = 0; i < g_cores.count; i++) if (g_cores.is_pcore[i]) p++;
        printf("[AFFINITY] detected %d cores (%d P, %d E)\n", g_cores.count, p, g_cores.count - p);
    }

    cache = rx_alloc_cache(1);
    uint8_t key[] = "test_key_123456";
    rx_init_cache(cache, key, sizeof(key));
    dataset = rx_alloc_dataset(1);
    rx_init_dataset_cached(dataset, cache, 0, RX_DATASET_ITEMS, 8, 8);

    uint8_t ref_hash1[32] = {0};
    uint8_t ref_hash2[32] = {0};

    printf("[REF] Computing reference hashes (single interp)...\n");
    {
        rx_vm* vm_ref = rx_create_vm(RX_FLAG_DEFAULT, cache, dataset);
        uint8_t seed[32] = {0};
        rx_calculate_hash(vm_ref, seed, sizeof(seed), ref_hash1);
        print_hash("  ref hash1", ref_hash1);
        rx_destroy_vm(vm_ref);
    }
    {
        rx_vm* vm_ref = rx_create_vm(RX_FLAG_DEFAULT, cache, dataset);
        uint8_t seed[32] = {0};
        seed[0] = 200;
        rx_calculate_hash(vm_ref, seed, sizeof(seed), ref_hash2);
        print_hash("  ref hash2", ref_hash2);
        rx_destroy_vm(vm_ref);
    }

    printf("\n======================================================================\n");
    printf("  BENCH 1-%d THREADS  (dataset allocated once, large pages)\n", max_threads);
    printf("======================================================================\n\n");

    double res_interp[16], res_single[16], res_dual[16];
    memset(res_interp, 0, sizeof(res_interp));
    memset(res_single, 0, sizeof(res_single));
    memset(res_dual, 0, sizeof(res_dual));

    for (int t = 1; t <= max_threads; t++) {
        printf("--- %d thread%s ---\n", t, t > 1 ? "s" : "");
        res_interp[t] = run_mode(t, 0, "Interp", ref_hash1, NULL);
        res_single[t] = run_mode(t, 1, "Single JIT", ref_hash1, NULL);
        res_dual[t]   = run_mode(t, 2, "Dual JIT", ref_hash1, ref_hash2);
        printf("\n");
    }

    printf("======================================================================\n");
    printf("  SUMMARY TABLE\n");
    printf("======================================================================\n");
    printf("%-6s  %-12s  %-12s  %-12s  %-8s  %-8s\n",
           "Thr", "Interp", "Single JIT", "Dual JIT", "S/I", "D/I");
    printf("------  ------------  ------------  ------------  --------  --------\n");
    for (int t = 1; t <= max_threads; t++) {
        printf("%-6d  %8.1f H/s  %8.1f H/s  %8.1f H/s  %6.2fx  %6.2fx\n",
               t, res_interp[t], res_single[t], res_dual[t],
               res_interp[t] > 0 ? res_single[t] / res_interp[t] : 0,
               res_interp[t] > 0 ? res_dual[t] / res_interp[t] : 0);
    }

    rx_free_dataset(dataset);
    rx_free_cache(cache);
    return 0;
}
