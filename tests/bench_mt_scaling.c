#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <windows.h>
#include <mmsystem.h>
#include "crypto/randomx/randomx_internal.h"
#include "crypto/randomx/msr.h"

#pragma comment(lib, "winmm.lib")

#define MAX_THREADS 16
#define ITERS_PER_THREAD 400

extern int g_jit_sp_prefetch_hint;
extern int g_jit_bmi2_mulx;
extern int g_jit_cfround_elim;
extern int g_jit_large_pages;
extern int g_jit_jcc_align;
extern int g_jit_near_rcp_pool;
extern int g_aes_hash_fill_prefetch;
extern int g_jit_double_buffer;
extern int g_jit_inline_rcp_pool;
extern int g_jit_rorx;
extern int g_jit_stack_rcp_pool;
extern int g_jit_cfround_rorx;
extern int g_aes_hash_fill_upstream;
static int g_iters_per_thread = ITERS_PER_THREAD;

typedef struct {
    int count;
    int p_count;
    int e_count;
    int p[MAX_THREADS];
    int ht[MAX_THREADS];
    int e[MAX_THREADS];
    int cpu[MAX_THREADS];
} affinity_list;

typedef struct {
    int id;
    int dual;
    int cpu;
    rx_cache *cache;
    rx_dataset *dataset;
    volatile LONG *ready;
    HANDLE start_event;
    double elapsed;
} thread_arg;

static int detect_affinity(affinity_list *out, int policy) {
    DWORD len = 0;
    out->count = 0;
    GetLogicalProcessorInformationEx(RelationProcessorCore, NULL, &len);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) return 0;
    SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *buf = malloc(len);
    if (!buf || !GetLogicalProcessorInformationEx(RelationProcessorCore, buf, &len)) {
        free(buf);
        return 0;
    }

    BYTE *ptr = (BYTE *)buf;
    BYTE *end = ptr + len;
    while (ptr < end) {
        SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *item =
            (SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *)ptr;
        if (item->Relationship == RelationProcessorCore && item->Processor.GroupCount > 0) {
            GROUP_AFFINITY mask = item->Processor.GroupMask[0];
            int first = -1, sibling = -1, bits = 0;
            for (int b = 0; b < 64; b++) {
                if (mask.Mask & (1ULL << b)) {
                    if (first < 0) first = b + mask.Group * 64;
                    else if (sibling < 0) sibling = b + mask.Group * 64;
                    bits++;
                }
            }
            if (first >= 0) {
                if (bits >= 2 && out->p_count < MAX_THREADS) {
                    int i = out->p_count++;
                    out->p[i] = first;
                    out->ht[i] = sibling;
                } else if (out->e_count < MAX_THREADS) {
                    out->e[out->e_count++] = first;
                }
            }
        }
        ptr += item->Size;
    }
    free(buf);

    for (int i = 0; i < out->p_count && out->count < MAX_THREADS; i++)
        out->cpu[out->count++] = out->p[i];
    if (policy == 1) {
        for (int i = 0; i < out->p_count && out->count < MAX_THREADS; i++)
            if (out->ht[i] >= 0) out->cpu[out->count++] = out->ht[i];
    } else if (policy >= 2 && policy <= 4) {
        static const int ht_limit[] = {0, 0, 7, 6, 4};
        int limit = ht_limit[policy];
        for (int i = 0; i < out->p_count && i < limit &&
                        out->count < MAX_THREADS; i++)
            if (out->ht[i] >= 0) out->cpu[out->count++] = out->ht[i];
    }
    for (int i = 0; i < out->e_count && out->count < MAX_THREADS; i++)
        out->cpu[out->count++] = out->e[i];
    if (policy == 0) {
        for (int i = 0; i < out->p_count && out->count < MAX_THREADS; i++)
            if (out->ht[i] >= 0) out->cpu[out->count++] = out->ht[i];
    } else if (policy >= 2 && policy <= 4) {
        static const int ht_limit[] = {0, 0, 7, 6, 4};
        int start = ht_limit[policy];
        for (int i = start; i < out->p_count && out->count < MAX_THREADS; i++)
            if (out->ht[i] >= 0) out->cpu[out->count++] = out->ht[i];
    }
    return out->count;
}

static DWORD WINAPI bench_thread(LPVOID opaque) {
    thread_arg *a = (thread_arg *)opaque;
    GROUP_AFFINITY ga = {0};
    ga.Group = (WORD)(a->cpu / 64);
    ga.Mask = (KAFFINITY)(1ULL << (a->cpu % 64));
    SetThreadGroupAffinity(GetCurrentThread(), &ga, NULL);
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);

    rx_vm *vm1 = rx_create_vm(RX_FLAG_JIT, a->cache, a->dataset);
    rx_vm *vm2 = a->dual ? rx_create_vm(RX_FLAG_JIT, a->cache, a->dataset) : NULL;
    uint8_t in1[32] = {0}, in2[32] = {0}, h1[32], h2[32];
    in1[0] = (uint8_t)a->id;
    in2[0] = (uint8_t)(a->id + 97);

    if (a->dual) {
        for (int i = 0; i < 4; i++)
            rx_calculate_hash_dual(vm1, vm2, in1, sizeof(in1), in2, sizeof(in2), h1, h2);
    } else {
        rx_calculate_hash_first(vm1, in1, sizeof(in1));
        for (int i = 0; i < 4; i++)
            rx_calculate_hash_next(vm1, in1, sizeof(in1), h1);
    }

    InterlockedIncrement(a->ready);
    WaitForSingleObject(a->start_event, INFINITE);

    LARGE_INTEGER freq, begin, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&begin);
    for (int i = 0; i < g_iters_per_thread; i++) {
        in1[1] = (uint8_t)i;
        in2[1] = (uint8_t)(i + 31);
        if (a->dual) rx_calculate_hash_dual(vm1, vm2, in1, sizeof(in1), in2, sizeof(in2), h1, h2);
        else rx_calculate_hash_next(vm1, in1, sizeof(in1), h1);
    }
    QueryPerformanceCounter(&end);
    a->elapsed = (double)(end.QuadPart - begin.QuadPart) / (double)freq.QuadPart;

    rx_destroy_vm(vm1);
    if (vm2) rx_destroy_vm(vm2);
    return 0;
}

static double run_case(int threads, int dual_threads, const affinity_list *affinity) {
    static rx_cache *cache;
    static rx_dataset *dataset;
    if (!cache) {
        uint8_t key[] = "mt_scaling_shared_dataset";
        cache = rx_alloc_cache(1);
        rx_init_cache(cache, key, sizeof(key));
        dataset = rx_alloc_dataset(1);
        rx_init_dataset_cached(dataset, cache, 0, RX_DATASET_ITEMS, 8, 8);
    }

    thread_arg args[MAX_THREADS] = {0};
    HANDLE handles[MAX_THREADS] = {0};
    volatile LONG ready = 0;
    HANDLE start_event = CreateEventA(NULL, TRUE, FALSE, NULL);
    double e0 = 0.0, e1 = 0.0;
    LARGE_INTEGER freq, begin, end;
    QueryPerformanceFrequency(&freq);

    for (int i = 0; i < threads; i++) {
        args[i].id = i;
        args[i].dual = i < dual_threads;
        args[i].cpu = affinity->cpu[i % affinity->count];
        args[i].cache = cache;
        args[i].dataset = dataset;
        args[i].ready = &ready;
        args[i].start_event = start_event;
        handles[i] = CreateThread(NULL, 0, bench_thread, &args[i], 0, NULL);
    }
    while (InterlockedCompareExchange(&ready, 0, 0) < threads) Sleep(1);

    int power_ok = msr_read_package_energy(&e0);
    QueryPerformanceCounter(&begin);
    SetEvent(start_event);
    WaitForMultipleObjects((DWORD)threads, handles, TRUE, INFINITE);
    QueryPerformanceCounter(&end);
    if (power_ok) power_ok = msr_read_package_energy(&e1);

    double max_elapsed = 0.0;
    for (int i = 0; i < threads; i++) {
        if (args[i].elapsed > max_elapsed) max_elapsed = args[i].elapsed;
        CloseHandle(handles[i]);
    }
    CloseHandle(start_event);
    double hashes = (double)(threads + dual_threads) * g_iters_per_thread;
    double hashrate = hashes / max_elapsed;
    double wall = (double)(end.QuadPart - begin.QuadPart) / (double)freq.QuadPart;
    double watts = 0.0;
    if (power_ok) {
        double joules = e1 - e0;
        if (joules < 0.0) joules += 4294967296.0 / 16384.0;
        watts = joules / wall;
    }
    char mode[24];
    if (dual_threads == 0) snprintf(mode, sizeof(mode), "single");
    else if (dual_threads == threads) snprintf(mode, sizeof(mode), "dual");
    else snprintf(mode, sizeof(mode), "hybrid-%dD", dual_threads);
    printf("%2dT %-10s %9.1f H/s", threads, mode, hashrate);
    if (watts > 0.1) printf("  %6.1f W  %6.2f H/W", watts, hashrate / watts);
    else printf("  power unavailable");
    printf("\n");
    return hashrate;
}

int main(int argc, char **argv) {
    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
    timeBeginPeriod(1);
    msr_init();

    int policy = argc > 2 ? atoi(argv[2]) : 0;
    affinity_list affinity = {0};
    if (!detect_affinity(&affinity, policy)) return 1;
    int max_threads = argc > 1 ? atoi(argv[1]) : 16;
    if (max_threads > MAX_THREADS) max_threads = MAX_THREADS;
    if (max_threads < 1) max_threads = 1;
    int only_threads = argc > 3 ? atoi(argv[3]) : 0;
    g_jit_sp_prefetch_hint = argc > 4 ? atoi(argv[4]) : 1;
    g_iters_per_thread = argc > 5 ? atoi(argv[5]) : ITERS_PER_THREAD;
    if (g_iters_per_thread < 1) g_iters_per_thread = 1;
    int only_single = argc > 6 ? atoi(argv[6]) : 0;
    double power_limit = argc > 7 ? atof(argv[7]) : 0.0;
    int prefetch_control = argc > 8 ? atoi(argv[8]) : -1;
    g_jit_bmi2_mulx = argc > 9 ? atoi(argv[9]) : 0;
    g_jit_cfround_elim = argc > 10 ? atoi(argv[10]) : 0;
    g_jit_large_pages = argc > 11 ? atoi(argv[11]) : 0;
    g_jit_jcc_align = argc > 12 ? atoi(argv[12]) : 0;
    g_jit_near_rcp_pool = argc > 13 ? atoi(argv[13]) : 0;
    g_aes_hash_fill_prefetch = argc > 14 ? atoi(argv[14]) : 0;
    g_jit_double_buffer = argc > 15 ? atoi(argv[15]) : 0;
    g_jit_inline_rcp_pool = argc > 16 ? atoi(argv[16]) : 0;
    g_jit_rorx = argc > 17 ? atoi(argv[17]) : 0;
    g_jit_stack_rcp_pool = argc > 18 ? atoi(argv[18]) : 0;
    g_jit_cfround_rorx = argc > 19 ? atoi(argv[19]) : 0;
    g_aes_hash_fill_upstream = argc > 20 ? atoi(argv[20]) : 0;
    uint64_t original_power_limit = 0;
    uint64_t original_prefetch_control = 0;
    int power_limit_set = power_limit > 0.0 &&
        msr_set_package_power_limit(power_limit, &original_power_limit);
    int prefetch_control_set = prefetch_control >= 0 &&
        msr_set_prefetch_control((uint64_t)prefetch_control,
                                 &original_prefetch_control);
    if (prefetch_control >= 0)
        printf("[MSR] Hardware prefetch disable mask: 0x%X%s\n",
               prefetch_control, prefetch_control_set ? "" : " (not applied)");

    int points[] = {1, 2, 4, 8, 12, 14, 15, 16};
    double base[2] = {0.0, 0.0};
    printf("Shared-dataset RandomX MT scaling, max %dT, affinity policy=%d, "
           "sp-prefetch=%d, bmi2-mulx=%d, cfround-elim=%d, "
           "jit-large-pages=%d, jcc-align=%d, near-rcp=%d, aes-prefetch=%d, "
           "double-buffer=%d, inline-rcp=%d, rorx=%d, stack-rcp=%d, "
           "cfround-rorx=%d, aes-upstream=%d, iterations=%d%s\n",
           max_threads, policy, g_jit_sp_prefetch_hint, g_jit_bmi2_mulx,
           g_jit_cfround_elim, g_jit_large_pages, g_jit_jcc_align,
           g_jit_near_rcp_pool, g_aes_hash_fill_prefetch, g_jit_double_buffer,
           g_jit_inline_rcp_pool, g_jit_rorx, g_jit_stack_rcp_pool,
           g_jit_cfround_rorx, g_aes_hash_fill_upstream, g_iters_per_thread,
           only_single ? ", single-only" : "");
    for (int p = 0; p < (int)(sizeof(points) / sizeof(points[0])); p++) {
        int t = points[p];
        if (t > max_threads) continue;
        if (only_threads > 0 && t != only_threads) continue;
        for (int mode = 0; mode < 2; mode++) {
            if (only_single && mode != 0) continue;
            double hr = run_case(t, mode ? t : 0, &affinity);
            if (t == 1) base[mode] = hr;
            else if (base[mode] > 0.0) {
                double scale = hr / base[mode];
                double eff = scale / t * 100.0;
                printf("    -> corrected: scale=%5.2fx efficiency=%5.1f%%\n", scale, eff);
            }
        }
        if (t >= 12 && !only_single) {
            run_case(t, 2, &affinity);
            run_case(t, 4, &affinity);
        }
    }
    if (power_limit_set && !msr_restore_package_power_limit(original_power_limit))
        fprintf(stderr, "[MSR] Failed to restore package power limit\n");
    if (prefetch_control_set &&
        !msr_restore_prefetch_control(original_prefetch_control))
        fprintf(stderr, "[MSR] Failed to restore prefetch control\n");
    timeEndPeriod(1);
    msr_destroy();
    return 0;
}
