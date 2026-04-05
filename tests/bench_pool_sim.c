#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <windows.h>
#include <mmsystem.h>
#pragma comment(lib, "winmm.lib")
#include "crypto/randomx/randomx_internal.h"
#include "common/cpu.h"
#include "common/log.h"

#define HASHES_PER_RUN 5000

typedef struct {
    int thread_id;
    int mode;
    double hashrate;
    double wall_time;
} thread_data_t;

rx_cache *cache = NULL;
rx_dataset *dataset = NULL;

#define MAX_CORES 128

typedef struct {
    int count;
    int os_index[MAX_CORES];
    int is_pcore[MAX_CORES];
    int sibling[MAX_CORES];
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
    if (!GetLogicalProcessorInformationEx(RelationProcessorCore, buf, &len)) { free(buf); return 0; }
    BYTE *ptr = (BYTE *)buf;
    DWORD remaining = len;
    while (remaining > 0) {
        SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *item = (SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *)ptr;
        if (item->Relationship == RelationProcessorCore && item->Processor.GroupCount > 0) {
            GROUP_AFFINITY mask = item->Processor.GroupMask[0];
            int first = -1, second = -1, bits = 0;
            for (int b = 0; b < 64; b++) {
                if (mask.Mask & (1ULL << b)) {
                    int os_idx = b + mask.Group * 64;
                    if (first < 0) first = os_idx;
                    else if (second < 0) second = os_idx;
                    bits++;
                }
            }
            if (first >= 0 && cores->count < MAX_CORES) {
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
    for (int i = 0; i < g_cores.count && n < max_order; i++)
        if (g_cores.is_pcore[i]) order[n++] = g_cores.os_index[i];
    for (int i = 0; i < g_cores.count && n < max_order; i++)
        if (g_cores.is_pcore[i] && g_cores.sibling[i] >= 0) order[n++] = g_cores.sibling[i];
    for (int i = 0; i < g_cores.count && n < max_order; i++)
        if (!g_cores.is_pcore[i]) order[n++] = g_cores.os_index[i];
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

DWORD WINAPI bench_thread(LPVOID arg) {
    thread_data_t *d = (thread_data_t *)arg;
    int tid = d->thread_id;

    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);

    int order[MAX_CORES * 2];
    int order_count = build_affinity_order(order, sizeof(order) / sizeof(order[0]));
    if (order_count > 0) {
        int os_idx = order[tid % order_count];
        GROUP_AFFINITY ga = {0};
        ga.Group = (WORD)(os_idx / 64);
        ga.Mask = (KAFFINITY)(1ULL << (os_idx % 64));
        SetThreadGroupAffinity(GetCurrentThread(), &ga, NULL);
    }

    uint8_t blob[76];
    memset(blob, 0, sizeof(blob));
    blob[0] = 0x10;
    blob[1] = 0x03;
    blob[2] = 0xe3;
    for (int i = 3; i < 7; i++) blob[i] = (uint8_t)(tid * 17 + i);
    for (int i = 39; i < 43; i++) blob[i] = 0xAA;

    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);

    if (d->mode == 0) {
        rx_vm *vm = rx_create_vm(RX_FLAG_DEFAULT, cache, dataset);
        uint8_t hash[32];
        for (int i = 0; i < 2; i++) rx_calculate_hash(vm, blob, sizeof(blob), hash);
        QueryPerformanceCounter(&start);
        for (int i = 0; i < HASHES_PER_RUN; i++) {
            *(uint32_t *)(blob + 39) = (uint32_t)i;
            rx_calculate_hash(vm, blob, sizeof(blob), hash);
        }
        QueryPerformanceCounter(&(end));
        rx_destroy_vm(vm);
    } else if (d->mode == 1) {
        rx_vm *vm = rx_create_vm(RX_FLAG_JIT, cache, dataset);
        uint8_t hash[32];
        uint8_t commitment[32];
        for (int i = 0; i < 2; i++) {
            *(uint32_t *)(blob + 39) = (uint32_t)i;
            rx_calculate_hash(vm, blob, sizeof(blob), hash);
            rx_calculate_commitment(blob, sizeof(blob), hash, commitment);
        }
        QueryPerformanceCounter(&start);
        for (int i = 0; i < HASHES_PER_RUN; i++) {
            *(uint32_t *)(blob + 39) = (uint32_t)i;
            rx_calculate_hash(vm, blob, sizeof(blob), hash);
            rx_calculate_commitment(blob, sizeof(blob), hash, commitment);
        }
        QueryPerformanceCounter(&end);
        rx_destroy_vm(vm);
    } else if (d->mode == 3) {
        rx_vm *vm = rx_create_vm(RX_FLAG_JIT, cache, dataset);
        uint8_t hash[32];
        uint8_t commitment[32];

        *(uint32_t *)(blob + 39) = 0;
        rx_calculate_hash_first(vm, blob, sizeof(blob));

        for (int i = 0; i < 2; i++) {
            *(uint32_t *)(blob + 39) = (uint32_t)(i + 1);
            rx_calculate_hash_next(vm, blob, sizeof(blob), hash);
            rx_calculate_commitment(blob, sizeof(blob), hash, commitment);
        }

        QueryPerformanceCounter(&start);
        for (int i = 0; i < HASHES_PER_RUN; i++) {
            *(uint32_t *)(blob + 39) = (uint32_t)(i + 1);
            rx_calculate_hash_next(vm, blob, sizeof(blob), hash);
            rx_calculate_commitment(blob, sizeof(blob), hash, commitment);
        }
        QueryPerformanceCounter(&end);
        rx_destroy_vm(vm);
    } else if (d->mode == 4) {
        rx_vm *vm = rx_create_vm(RX_FLAG_JIT, cache, dataset);
        uint8_t hash[32];

        *(uint32_t *)(blob + 39) = 0;
        rx_calculate_hash_first(vm, blob, sizeof(blob));

        for (int i = 0; i < 2; i++) {
            *(uint32_t *)(blob + 39) = (uint32_t)(i + 1);
            rx_calculate_hash_next(vm, blob, sizeof(blob), hash);
        }

        QueryPerformanceCounter(&start);
        for (int i = 0; i < HASHES_PER_RUN; i++) {
            *(uint32_t *)(blob + 39) = (uint32_t)(i + 1);
            rx_calculate_hash_next(vm, blob, sizeof(blob), hash);
        }
        QueryPerformanceCounter(&end);
        rx_destroy_vm(vm);
    } else {
        rx_vm *vm1 = rx_create_vm(RX_FLAG_JIT, cache, dataset);
        rx_vm *vm2 = rx_create_vm(RX_FLAG_JIT, cache, dataset);
        uint8_t blob2[76];
        memcpy(blob2, blob, sizeof(blob));
        uint8_t h1[32], h2[32], c1[32], c2[32];
        for (int i = 0; i < 2; i++) {
            *(uint32_t *)(blob + 39) = (uint32_t)(i * 2);
            *(uint32_t *)(blob2 + 39) = (uint32_t)(i * 2 + 1);
            rx_calculate_hash_dual(vm1, vm2, blob, sizeof(blob), blob2, sizeof(blob2), h1, h2);
            rx_calculate_commitment(blob, sizeof(blob), h1, c1);
            rx_calculate_commitment(blob2, sizeof(blob2), h2, c2);
        }
        QueryPerformanceCounter(&start);
        for (int i = 0; i < HASHES_PER_RUN; i++) {
            *(uint32_t *)(blob + 39) = (uint32_t)(i * 2);
            *(uint32_t *)(blob2 + 39) = (uint32_t)(i * 2 + 1);
            rx_calculate_hash_dual(vm1, vm2, blob, sizeof(blob), blob2, sizeof(blob2), h1, h2);
            rx_calculate_commitment(blob, sizeof(blob), h1, c1);
            rx_calculate_commitment(blob2, sizeof(blob2), h2, c2);
        }
        QueryPerformanceCounter(&end);
        rx_destroy_vm(vm1);
        rx_destroy_vm(vm2);
    }

    d->wall_time = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;
    int hashes_per_thread = (d->mode == 2) ? HASHES_PER_RUN * 2 : HASHES_PER_RUN;
    d->hashrate = hashes_per_thread / d->wall_time;
    return 0;
}

static double run_mode(int num_threads, int mode, const char *label) {
    thread_data_t *tdata = (thread_data_t *)calloc(num_threads, sizeof(thread_data_t));
    HANDLE *threads = (HANDLE *)calloc(num_threads, sizeof(HANDLE));
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
    int hashes_per_thread = (mode == 2) ? HASHES_PER_RUN * 2 : HASHES_PER_RUN;
    double total_hr = (double)(num_threads * hashes_per_thread) / wall;

    double min_t = 1e18, max_t = 0;
    for (int i = 0; i < num_threads; i++) {
        if (tdata[i].wall_time < min_t) min_t = tdata[i].wall_time;
        if (tdata[i].wall_time > max_t) max_t = tdata[i].wall_time;
    }
    double per_thread_avg = total_hr / num_threads;

    printf("  %-20s %8.1f H/s total  %8.1f H/s/thread  wall=%.2fs  spread=%.1f%%\n",
           label, total_hr, per_thread_avg, wall,
           num_threads > 1 ? (max_t - min_t) / ((min_t + max_t) / 2) * 100.0 : 0.0);

    for (int i = 0; i < num_threads; i++) CloseHandle(threads[i]);
    free(threads);
    free(tdata);
    return total_hr;
}

int main(int argc, char **argv) {
    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
    timeBeginPeriod(1);
    enable_huge_pages();

    int max_threads = 8;
    int specific_mode = -1;
    if (argc > 1) max_threads = atoi(argv[1]);
    if (argc > 2) specific_mode = atoi(argv[2]);

    g_affinity_ready = detect_cores(&g_cores) > 0;
    if (g_affinity_ready) {
        int p = 0;
        for (int i = 0; i < g_cores.count; i++) if (g_cores.is_pcore[i]) p++;
        printf("[AFFINITY] %d cores (%d P, %d E)\n", g_cores.count, p, g_cores.count - p);
    }

    cache = rx_alloc_cache(1);
    uint8_t key[] = "pool_sim_seed_123";
    rx_init_cache(cache, key, sizeof(key));
    dataset = rx_alloc_dataset(1);
    rx_init_dataset_cached(dataset, cache, 0, RX_DATASET_ITEMS, 8, 8);

    printf("\n======================================================================\n");
    printf("  POOL SIMULATION BENCH  (%d hashes/thread, 76-byte blob + commitment)\n", HASHES_PER_RUN);
    printf("======================================================================\n\n");

    printf("[VERIFY] Checking batch API (hash_first/hash_next) correctness...\n");
    {
        rx_vm *vm_std = rx_create_vm(RX_FLAG_JIT, cache, dataset);
        rx_vm *vm_batch = rx_create_vm(RX_FLAG_JIT, cache, dataset);
        uint8_t blob_v[76];
        memset(blob_v, 0, sizeof(blob_v));
        blob_v[0] = 0x10; blob_v[1] = 0x03; blob_v[2] = 0xe3;
        uint8_t hash_std[32], hash_batch[32];
        int pass = 1;
        *(uint32_t *)(blob_v + 39) = 0;
        rx_calculate_hash_first(vm_batch, blob_v, sizeof(blob_v));
        for (int i = 0; i < 100; i++) {
            *(uint32_t *)(blob_v + 39) = (uint32_t)(i + 1);
            rx_calculate_hash_next(vm_batch, blob_v, sizeof(blob_v), hash_batch);
            *(uint32_t *)(blob_v + 39) = (uint32_t)i;
            rx_calculate_hash(vm_std, blob_v, sizeof(blob_v), hash_std);
            if (memcmp(hash_std, hash_batch, 32) != 0) {
                printf("[VERIFY] MISMATCH at nonce %d\n", i);
                pass = 0; break;
            }
        }
        rx_destroy_vm(vm_std);
        rx_destroy_vm(vm_batch);
        printf("[VERIFY] Batch API vs standard: %s\n", pass ? "PASS" : "FAIL");
    }
    printf("\n");

    double res_i[16], res_s[16], res_d[16], res_b[16], res_bn[16];
    memset(res_i, 0, sizeof(res_i));
    memset(res_s, 0, sizeof(res_s));
    memset(res_d, 0, sizeof(res_d));
    memset(res_b, 0, sizeof(res_b));
    memset(res_bn, 0, sizeof(res_bn));

    for (int t = 1; t <= max_threads; t++) {
        printf("--- %d thread%s ---\n", t, t > 1 ? "s" : "");
        if (specific_mode < 0 || specific_mode == 0) res_i[t] = run_mode(t, 0, "Interpreter");
        if (specific_mode < 0 || specific_mode == 1) res_s[t] = run_mode(t, 1, "JIT + commitment");
        if (specific_mode < 0 || specific_mode == 3) res_b[t] = run_mode(t, 3, "JIT batch (hash_next)");
        if (specific_mode < 0 || specific_mode == 4) res_bn[t] = run_mode(t, 4, "JIT batch (no commit)");
        if (specific_mode < 0 || specific_mode == 2) res_d[t] = run_mode(t, 2, "Dual JIT + commitment");
        printf("\n");
    }

    printf("======================================================================\n");
    printf("  SUMMARY (pool-simulated: 76-byte blob + commitment per hash)\n");
    printf("======================================================================\n");
    printf("%-6s  %-12s  %-12s  %-12s  %-12s  %-12s  %-6s  %-6s\n",
           "Thr", "Interp", "JIT", "Batch", "BatchNC", "Dual JIT", "B/J", "D/I");
    printf("------  ------------  ------------  ------------  ------------  ------------  ------  ------\n");
    for (int t = 1; t <= max_threads; t++) {
        printf("%-6d  %8.1f H/s  %8.1f H/s  %8.1f H/s  %8.1f H/s  %8.1f H/s  %5.1fx  %6.2fx\n",
               t, res_i[t], res_s[t], res_b[t], res_bn[t], res_d[t],
               res_s[t] > 0 ? res_b[t] / res_s[t] : 0,
               res_i[t] > 0 ? res_d[t] / res_i[t] : 0);
    }

    rx_free_dataset(dataset);
    rx_free_cache(cache);
    timeEndPeriod(1);
    return 0;
}
