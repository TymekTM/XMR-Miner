#include "miner.h"
#include "worker.h"
#include "stratum/stratum.h"
#include "crypto/randomx/randomx.h"
#include "common/config.h"
#include "common/log.h"
#include "common/cpu.h"
#include <windows.h>
#include <mmsystem.h>
#include <intrin.h>
#pragma comment(lib, "winmm.lib")
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_CORES 64
#define MODE_SINGLE 0
#define MODE_DUAL 1
#define MODE_CACHE_MAX_THREADS 128
#define MODE_CACHE_FILE "mode_cache.csv"

static int g_best_mode = MODE_SINGLE;
static int g_mode_cache_loaded = 0;
static int g_mode_cache[MODE_CACHE_MAX_THREADS + 1];

static void mode_cache_load(void) {
    if (g_mode_cache_loaded) return;
    for (int i = 0; i <= MODE_CACHE_MAX_THREADS; i++) g_mode_cache[i] = -1;

    FILE *f = fopen(MODE_CACHE_FILE, "r");
    if (!f) {
        g_mode_cache_loaded = 1;
        return;
    }

    int threads = 0;
    int mode = 0;
    while (fscanf(f, "%d,%d", &threads, &mode) == 2) {
        if (threads >= 1 && threads <= MODE_CACHE_MAX_THREADS && (mode == MODE_SINGLE || mode == MODE_DUAL)) {
            g_mode_cache[threads] = mode;
        }
    }
    fclose(f);
    g_mode_cache_loaded = 1;
}

static void mode_cache_save(void) {
    FILE *f = fopen(MODE_CACHE_FILE, "w");
    if (!f) return;

    for (int t = 1; t <= MODE_CACHE_MAX_THREADS; t++) {
        if (g_mode_cache[t] == MODE_SINGLE || g_mode_cache[t] == MODE_DUAL) {
            fprintf(f, "%d,%d\n", t, g_mode_cache[t]);
        }
    }
    fclose(f);
}

typedef struct {
    int count;
    int os_index[MAX_CORES];    // OS processor index for each physical core
    int is_pcore[MAX_CORES];    // 1 = P-core, 0 = E-core
    int sibling[MAX_CORES];     // second logical processor for HT cores (-1 if none)
} core_list_t;

static int detect_physical_cores(core_list_t *cores) {
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
        if (item->Relationship == RelationProcessorCore) {
            GROUP_AFFINITY mask = item->Processor.GroupMask[0];
            int os_idx = -1;
            int sibling = -1;
            int bits = 0;
            for (int b = 0; b < 64 && b < (int)sizeof(mask.Mask) * 8; b++) {
                if (mask.Mask & (1ULL << b)) {
                    int cpu = b + mask.Group * 64;
                    if (os_idx < 0) os_idx = cpu;
                    else if (sibling < 0) sibling = cpu;
                    bits++;
                }
            }
            if (os_idx >= 0 && cores->count < MAX_CORES) {
                cores->os_index[cores->count] = os_idx;
                cores->is_pcore[cores->count] = (bits == 2) ? 1 : 0;
                cores->sibling[cores->count] = sibling;
                cores->count++;
            }
        }
        ptr += item->Size;
        remaining -= item->Size;
    }

    free(buf);
    return cores->count;
}

static void sort_cores_pcore_first(core_list_t *cores) {
    // Bubble sort: P-cores first, preserving relative order
    for (int i = 0; i < cores->count - 1; i++) {
        for (int j = 0; j < cores->count - 1 - i; j++) {
            if (cores->is_pcore[j] < cores->is_pcore[j + 1]) {
                int tmp;
                tmp = cores->os_index[j]; cores->os_index[j] = cores->os_index[j + 1]; cores->os_index[j + 1] = tmp;
                tmp = cores->is_pcore[j]; cores->is_pcore[j] = cores->is_pcore[j + 1]; cores->is_pcore[j + 1] = tmp;
                tmp = cores->sibling[j]; cores->sibling[j] = cores->sibling[j + 1]; cores->sibling[j + 1] = tmp;
            }
        }
    }
}

static int build_affinity_order(const core_list_t *cores, int *order, int max_count) {
    int n = 0;
    for (int i = 0; i < cores->count && n < max_count; i++) {
        if (cores->is_pcore[i]) order[n++] = cores->os_index[i];
    }
    for (int i = 0; i < cores->count && n < max_count; i++) {
        if (cores->is_pcore[i] && cores->sibling[i] >= 0) order[n++] = cores->sibling[i];
    }
    for (int i = 0; i < cores->count && n < max_count; i++) {
        if (!cores->is_pcore[i]) order[n++] = cores->os_index[i];
    }
    return n;
}

struct miner_ctx {
    int num_threads;
    int huge_pages;
    int physical_cores;
    stratum_ctx_t *stratum;
    worker_t *workers;
    HANDLE *thread_handles;
    int running;
    rx_cache *cache;
    rx_dataset *dataset;
    CRITICAL_SECTION cache_lock;
    char current_seed_hex[65];
    int cache_initialized;
    int mode;
};

miner_ctx_t *miner_create(int num_threads, int huge_pages, int physical_cores, int mode, stratum_ctx_t *stratum) {
    miner_ctx_t *ctx = (miner_ctx_t *)calloc(1, sizeof(miner_ctx_t));
    if (!ctx) return NULL;
    ctx->num_threads = num_threads;
    ctx->huge_pages = huge_pages;
    ctx->physical_cores = physical_cores;
    ctx->stratum = stratum;
    ctx->mode = mode;
    ctx->running = 0;
    ctx->cache_initialized = 0;
    InitializeCriticalSection(&ctx->cache_lock);
    return ctx;
}

void miner_destroy(miner_ctx_t *ctx) {
    if (!ctx) return;
    miner_stop(ctx);
    DeleteCriticalSection(&ctx->cache_lock);
    if (ctx->dataset) {
        rx_free_dataset(ctx->dataset);
        ctx->dataset = NULL;
    }
    if (ctx->cache) {
        rx_free_cache(ctx->cache);
        ctx->cache = NULL;
    }
    free(ctx->workers);
    free(ctx->thread_handles);
    free(ctx);
}

static DWORD WINAPI thread_entry(LPVOID arg) {
    worker_run((worker_t *)arg);
    return 0;
}

static void seed_to_hex(const uint8_t *seed, int seed_len, char *out) {
    for (int i = 0; i < seed_len; i++)
        snprintf(out + i * 2, 3, "%02x", seed[i]);
    out[seed_len * 2] = '\0';
}

typedef struct {
    rx_vm *vm1;
    rx_vm *vm2;
    int dual;
    uint32_t seed0;
} bench_thread_arg;

static DWORD WINAPI bench_thread_entry(LPVOID arg) {
    bench_thread_arg *a = (bench_thread_arg *)arg;
    uint8_t in1[32] = {0};
    uint8_t in2[32] = {0};
    uint8_t out1[32], out2[32];
    const int warmup = 2;
    const int iters = 24;

    memcpy(in1, &a->seed0, sizeof(a->seed0));
    uint32_t seed2 = a->seed0 ^ 0x9E3779B9u;
    memcpy(in2, &seed2, sizeof(seed2));

    if (a->dual) {
        for (int i = 0; i < warmup; i++) {
            rx_calculate_hash_dual(a->vm1, a->vm2, in1, sizeof(in1), in2, sizeof(in2), out1, out2);
        }
        for (int i = 0; i < iters; i++) {
            rx_calculate_hash_dual(a->vm1, a->vm2, in1, sizeof(in1), in2, sizeof(in2), out1, out2);
        }
    } else {
        for (int i = 0; i < warmup; i++) rx_calculate_hash(a->vm1, in1, sizeof(in1), out1);
        for (int i = 0; i < iters; i++) rx_calculate_hash(a->vm1, in1, sizeof(in1), out1);
    }

    return 0;
}

static double run_mode_bench(int num_threads, int dual, rx_cache *cache, rx_dataset *dataset) {
    const int iters = 24;
    int bench_threads = num_threads;
    if (bench_threads < 1) bench_threads = 1;
    if (bench_threads > 16) bench_threads = 16;

    bench_thread_arg *args = (bench_thread_arg *)calloc((size_t)bench_threads, sizeof(bench_thread_arg));
    HANDLE *threads = (HANDLE *)calloc((size_t)bench_threads, sizeof(HANDLE));
    if (!args || !threads) {
        free(args);
        free(threads);
        return 0.0;
    }

    for (int i = 0; i < bench_threads; i++) {
        args[i].dual = dual;
        args[i].seed0 = 0xA5A50000u + (uint32_t)i;
        args[i].vm1 = rx_create_vm(RX_FLAG_V2, cache, dataset);
        if (!args[i].vm1) {
            for (int j = 0; j <= i; j++) {
                if (args[j].vm1) rx_destroy_vm(args[j].vm1);
                if (args[j].vm2) rx_destroy_vm(args[j].vm2);
            }
            free(args);
            free(threads);
            return 0.0;
        }
        if (dual) {
            args[i].vm2 = rx_create_vm(RX_FLAG_V2, cache, dataset);
            if (!args[i].vm2) {
                for (int j = 0; j <= i; j++) {
                    if (args[j].vm1) rx_destroy_vm(args[j].vm1);
                    if (args[j].vm2) rx_destroy_vm(args[j].vm2);
                }
                free(args);
                free(threads);
                return 0.0;
            }
        }
    }

    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);

    for (int i = 0; i < bench_threads; i++) {
        threads[i] = CreateThread(NULL, 0, bench_thread_entry, &args[i], 0, NULL);
    }
    WaitForMultipleObjects((DWORD)bench_threads, threads, TRUE, 30000);
    QueryPerformanceCounter(&end);

    for (int i = 0; i < bench_threads; i++) {
        if (threads[i]) CloseHandle(threads[i]);
        if (args[i].vm1) rx_destroy_vm(args[i].vm1);
        if (args[i].vm2) rx_destroy_vm(args[i].vm2);
    }
    free(args);
    free(threads);

    double dt = (double)(end.QuadPart - start.QuadPart) / (double)freq.QuadPart;
    if (dt <= 0.0) return 0.0;
    double hashes = (double)bench_threads * (double)iters * (dual ? 2.0 : 1.0);
    return hashes / dt;
}

static int select_best_mode(int num_threads, rx_cache *cache, rx_dataset *dataset) {
    mode_cache_load();
    if (num_threads >= 1 && num_threads <= MODE_CACHE_MAX_THREADS) {
        int cached = g_mode_cache[num_threads];
        if (cached == MODE_SINGLE || cached == MODE_DUAL) {
            LOG_INFO("[BENCH] Using cached mode for %d threads: %s",
                num_threads, cached == MODE_DUAL ? "dual" : "single");
            return cached;
        }
    }

    double single = run_mode_bench(num_threads, 0, cache, dataset);
    double dual = run_mode_bench(num_threads, 1, cache, dataset);

    LOG_INFO("[BENCH] Single %.0f H/s | Dual %.0f H/s (threads=%d)", single, dual, num_threads);
    if (dual > single * 1.02) {
        LOG_INFO("[BENCH] Selected DUAL mode");
        if (num_threads >= 1 && num_threads <= MODE_CACHE_MAX_THREADS) {
            g_mode_cache[num_threads] = MODE_DUAL;
            mode_cache_save();
        }
        return MODE_DUAL;
    }
    LOG_INFO("[BENCH] Selected SINGLE mode");
    if (num_threads >= 1 && num_threads <= MODE_CACHE_MAX_THREADS) {
        g_mode_cache[num_threads] = MODE_SINGLE;
        mode_cache_save();
    }
    return MODE_SINGLE;
}

void miner_reinit_cache(miner_ctx_t *ctx, const uint8_t *seed, int seed_len) {
    char new_hex[65] = {0};
    seed_to_hex(seed, seed_len, new_hex);

    int need_reinit = 0;
    EnterCriticalSection(&ctx->cache_lock);
    if (strcmp(new_hex, ctx->current_seed_hex) != 0) {
        need_reinit = 1;
        strncpy(ctx->current_seed_hex, new_hex, sizeof(ctx->current_seed_hex) - 1);
    }
    LeaveCriticalSection(&ctx->cache_lock);

    if (!need_reinit) return;

    LOG_INFO("[MINER] Initializing cache with new seed: %.16s...", new_hex);

    if (!ctx->cache) {
        ctx->cache = rx_alloc_cache(ctx->huge_pages);
        if (!ctx->cache) {
            LOG_ERR("[MINER] Failed to allocate cache");
            return;
        }
    }

    rx_init_cache(ctx->cache, seed, (size_t)seed_len);
    ctx->cache_initialized = 1;

    if (ctx->dataset) {
        LOG_INFO("[MINER] Reinitializing dataset with new seed...");
        rx_init_dataset_cached(ctx->dataset, ctx->cache, 0, RX_DATASET_ITEMS + RX_DATASET_EXTRA_ITEMS, ctx->num_threads, ctx->physical_cores);
        LOG_INFO("[MINER] Dataset reinitialized");
    }

    EnterCriticalSection(&ctx->cache_lock);
    for (int i = 0; i < ctx->num_threads; i++) {
        if (ctx->workers[i].vm) {
            rx_destroy_vm((rx_vm *)ctx->workers[i].vm);
            ctx->workers[i].vm = NULL;
        }
        if (ctx->workers[i].vm2) {
            rx_destroy_vm((rx_vm *)ctx->workers[i].vm2);
            ctx->workers[i].vm2 = NULL;
        }
        int flags = ctx->workers[i].current_rx_flags ? ctx->workers[i].current_rx_flags : RX_FLAG_DEFAULT;
        flags |= RX_FLAG_JIT;
        ctx->workers[i].vm = rx_create_vm(flags, ctx->cache, ctx->dataset);
        if (ctx->mode == MODE_DUAL) {
            ctx->workers[i].vm2 = rx_create_vm(flags, ctx->cache, ctx->dataset);
        }
    }
    LeaveCriticalSection(&ctx->cache_lock);

    LOG_INFO("[MINER] Cache reinitialized with seed: %.16s...", new_hex);
}

void *miner_get_vm(miner_ctx_t *ctx, int worker_id) {
    if (worker_id < 0 || worker_id >= ctx->num_threads) return NULL;
    return (void *)ctx->workers[worker_id].vm;
}

void miner_recreate_vms(miner_ctx_t *ctx, int rx_flags) {
    EnterCriticalSection(&ctx->cache_lock);
    for (int i = 0; i < ctx->num_threads; i++) {
        ctx->workers[i].current_rx_flags = rx_flags;
        if (ctx->workers[i].vm) {
            rx_destroy_vm((rx_vm *)ctx->workers[i].vm);
            ctx->workers[i].vm = NULL;
        }
        if (ctx->workers[i].vm2) {
            rx_destroy_vm((rx_vm *)ctx->workers[i].vm2);
            ctx->workers[i].vm2 = NULL;
        }
        ctx->workers[i].vm = rx_create_vm(RX_FLAG_JIT | rx_flags, ctx->cache, ctx->dataset);
        if (ctx->workers[i].use_dual) {
            ctx->workers[i].vm2 = rx_create_vm(RX_FLAG_JIT | rx_flags, ctx->cache, ctx->dataset);
        }
    }
    LeaveCriticalSection(&ctx->cache_lock);
    LOG_INFO("[MINER] VMs recreated with flags=0x%x", rx_flags);
}

int miner_start(miner_ctx_t *ctx, const uint8_t *initial_seed, int initial_seed_len) {
    ctx->running = 1;
    stratum_set_running(ctx->stratum, 1);

    ctx->workers = (worker_t *)calloc(ctx->num_threads, sizeof(worker_t));
    ctx->thread_handles = (HANDLE *)calloc(ctx->num_threads, sizeof(HANDLE));
    if (!ctx->workers || !ctx->thread_handles) {
        LOG_ERR("[MINER] Failed to allocate worker structures");
        return -1;
    }

    const uint8_t *cache_seed = initial_seed;
    int cache_seed_len = initial_seed_len;
    uint8_t zero_seed[32] = {0};
    if (!cache_seed || cache_seed_len == 0) {
        cache_seed = zero_seed;
        cache_seed_len = 32;
    }

    LOG_INFO("[MINER] Initializing RandomX cache (this takes ~30 seconds)...");

    ctx->cache = rx_alloc_cache(ctx->huge_pages);
    if (!ctx->cache) {
        LOG_ERR("[MINER] Failed to allocate cache");
        return -1;
    }

    rx_init_cache(ctx->cache, cache_seed, (size_t)cache_seed_len);
    seed_to_hex(cache_seed, cache_seed_len, ctx->current_seed_hex);
    ctx->cache_initialized = 1;

    LOG_INFO("[MINER] Cache initialized with seed: %.16s...", ctx->current_seed_hex);

    extern rx_dataset *rx_alloc_dataset(int large_pages);
    extern void rx_init_dataset(rx_dataset *, rx_cache *, uint32_t, uint32_t, int, int);
    extern void rx_init_dataset_cached(rx_dataset *, rx_cache *, uint32_t, uint32_t, int, int);
    LOG_INFO("[MINER] Initializing dataset (2 GB, this takes ~60 seconds)...");
    ctx->dataset = rx_alloc_dataset(ctx->huge_pages);
    if (!ctx->dataset) {
        LOG_ERR("[MINER] Failed to allocate dataset");
        return -1;
    }
    LOG_INFO("[MINER] Dataset allocated, initializing items...");
    rx_init_dataset_cached(ctx->dataset, ctx->cache, 0, RX_DATASET_ITEMS + RX_DATASET_EXTRA_ITEMS, ctx->num_threads, ctx->physical_cores);
    LOG_INFO("[MINER] Dataset initialized");

    if (ctx->mode == MINER_MODE_SINGLE) g_best_mode = MODE_SINGLE;
    else if (ctx->mode == MINER_MODE_DUAL) g_best_mode = MODE_DUAL;
    else g_best_mode = select_best_mode(ctx->num_threads, ctx->cache, ctx->dataset);

    for (int i = 0; i < ctx->num_threads; i++) {
        ctx->workers[i].id = i;
        ctx->workers[i].vm = rx_create_vm(RX_FLAG_JIT | RX_FLAG_DEFAULT, ctx->cache, ctx->dataset);
        ctx->workers[i].vm2 = NULL;
        ctx->workers[i].use_dual = (g_best_mode == MODE_DUAL) ? 1 : 0;
        if (ctx->workers[i].use_dual) {
            ctx->workers[i].vm2 = rx_create_vm(RX_FLAG_JIT | RX_FLAG_DEFAULT, ctx->cache, ctx->dataset);
        }
        ctx->workers[i].stratum = ctx->stratum;
        ctx->workers[i].miner = ctx;
        ctx->workers[i].hashes = 0;
        ctx->workers[i].start_time = 0;
        ctx->workers[i].should_stop = 0;
        ctx->workers[i].nonce_offset = (uint32_t)i;
        ctx->workers[i].nonce_stride = (uint32_t)ctx->num_threads;
        ctx->workers[i].loop_count = 0;
        ctx->workers[i].extranonce2_counter = 0;
        ctx->workers[i].current_rx_flags = RX_FLAG_DEFAULT;
        strncpy(ctx->workers[i].initial_seed, ctx->current_seed_hex, sizeof(ctx->workers[i].initial_seed) - 1);
    }

    LOG_INFO("[MINER] Starting %d threads...", ctx->num_threads);
    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
    timeBeginPeriod(1);

    {
        int msr_ok = 0;
        typedef long (*NtSystemDebugControl_fn)(int, void*, void*, unsigned long, void*, unsigned long, unsigned long*);
        static NtSystemDebugControl_fn pNtDbg = NULL;
        struct { uint32_t msr; uint64_t value; } msr_in;
        uint64_t msr_out = 0;
        unsigned long ret_len = 0;
        uint64_t val = 0, perf_ctl = 0, platform = 0, ratio = 0;
        long status = 0;

        if (!pNtDbg) pNtDbg = (NtSystemDebugControl_fn)GetProcAddress(GetModuleHandleW(L"ntdll"), "NtSystemDebugControl");
        if (pNtDbg) {
            __try {
                val = __readmsr(0xCE);
                if (val & 1) {
                    perf_ctl = __readmsr(0x199);
                    ratio = (perf_ctl >> 8) & 0xFF;
                    if (ratio == 0) { platform = __readmsr(0x003); ratio = (platform >> 8) & 0xFF; }
                    if (ratio > 0) { msr_in.msr = 0x199; msr_in.value = (ratio << 8) | (ratio & 0xFF); status = pNtDbg(0x13, &msr_in, sizeof(msr_in), &msr_out, sizeof(msr_out), &ret_len, 0); if (status >= 0) msr_ok = 1; }
                }
            } __except(EXCEPTION_EXECUTE_HANDLER) { msr_ok = 0; }
        }
        if (!msr_ok) {
            __try {
                val = __readmsr(0xCE);
                if (val & 1) { perf_ctl = __readmsr(0x199); ratio = (perf_ctl >> 8) & 0xFF; if (ratio == 0) { platform = __readmsr(0x003); ratio = (platform >> 8) & 0xFF; } if (ratio > 0) { __writemsr(0x199, (ratio << 8) | (ratio & 0xFF)); msr_ok = 1; } }
            } __except(EXCEPTION_EXECUTE_HANDLER) { msr_ok = 0; }
        }
        if (msr_ok) LOG_INFO("[MSR] IA32_PERF_CTL set to max performance");
        else LOG_INFO("[MSR] MSR tuning not available (need admin/driver)");
    }

    core_list_t cores;
    int num_physical = detect_physical_cores(&cores);
    sort_cores_pcore_first(&cores);
    int affinity_order[MAX_CORES * 2];
    int affinity_count = build_affinity_order(&cores, affinity_order, MAX_CORES * 2);

    if (num_physical > 0) {
        int pcores = 0;
        for (int c = 0; c < cores.count; c++) if (cores.is_pcore[c]) pcores++;
        LOG_INFO("[AFFINITY] Detected %d physical cores (%d P-core, %d E-core)",
                 num_physical, pcores, num_physical - pcores);
    }

    for (int i = 0; i < ctx->num_threads; i++) {
        ctx->thread_handles[i] = CreateThread(NULL, 0, thread_entry, &ctx->workers[i], 0, NULL);
        if (!ctx->thread_handles[i]) {
            LOG_ERR("[MINER] Failed to create thread %d", i);
            continue;
        }
        SetThreadPriority(ctx->thread_handles[i], THREAD_PRIORITY_HIGHEST);
        {
            static void *pFn = NULL;
            if (!pFn) pFn = (void*)GetProcAddress(GetModuleHandleW(L"ntdll"), "NtSetInformationThread");
            if (pFn) {
                long (*fn)(HANDLE, long, void*, unsigned long) = (long (*)(HANDLE, long, void*, unsigned long))pFn;
                LONG pt[3] = { 1, 2, 1 };
                fn(ctx->thread_handles[i], 0x5C, pt, sizeof(pt));
            }
        }
        if (num_physical > 0 && affinity_count > 0) {
            GROUP_AFFINITY ga = {0};
            int os_idx = affinity_order[i % affinity_count];
            ga.Group = (WORD)(os_idx / 64);
            ga.Mask = (KAFFINITY)(1ULL << (os_idx % 64));
            SetThreadGroupAffinity(ctx->thread_handles[i], &ga, NULL);
            LOG_DEBUG("[AFFINITY] W%d -> CPU%d", i, os_idx);
        }
    }

    LOG_INFO("[MINER] Mining started - press Ctrl+C to stop");
    return 0;
}

void miner_stop(miner_ctx_t *ctx) {
    if (!ctx || !ctx->running) return;
    ctx->running = 0;
    stratum_set_running(ctx->stratum, 0);

    for (int i = 0; i < ctx->num_threads; i++) {
        ctx->workers[i].should_stop = 1;
    }

    WaitForMultipleObjects(ctx->num_threads, ctx->thread_handles, TRUE, 10000);
    for (int i = 0; i < ctx->num_threads; i++) {
        if (ctx->thread_handles[i]) CloseHandle(ctx->thread_handles[i]);
    }

    u64 total = 0;
    for (int i = 0; i < ctx->num_threads; i++) {
        total += ctx->workers[i].hashes;
        if (ctx->workers[i].vm) {
            rx_destroy_vm((rx_vm *)ctx->workers[i].vm);
            ctx->workers[i].vm = NULL;
        }
        if (ctx->workers[i].vm2) {
            rx_destroy_vm((rx_vm *)ctx->workers[i].vm2);
            ctx->workers[i].vm2 = NULL;
        }
    }
    if (total > 0) {
        LOG_INFO("[MINER] Total: %llu hashes", total);
    }

    LOG_INFO("[MINER] Stopped");
}
