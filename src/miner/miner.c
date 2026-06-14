#include "miner.h"
#include "worker.h"
#include "affinity.h"
#include "stratum/stratum.h"
#include "crypto/randomx/randomx.h"
#include "common/config.h"
#include "common/log.h"
#include "common/cpu.h"
#include "crypto/randomx/msr.h"
#include <windows.h>
#include <mmsystem.h>
#include <intrin.h>
#pragma comment(lib, "winmm.lib")
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MODE_SINGLE 0
#define MODE_DUAL 1
#define MODE_CACHE_MAX_THREADS 128
#define MODE_CACHE_FILE "mode_cache_v3.csv"
#define MODE_BENCH_WARMUP 4
#define MODE_BENCH_ITERS 96

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
    CRITICAL_SECTION perf_lock;
    uint64_t perf_last_time;
    uint64_t perf_last_hashes;
    double perf_last_energy;
    int perf_power_ready;
    double power_limit;
    uint64_t original_power_limit;
    int power_limit_set;
};

miner_ctx_t *miner_create(int num_threads, int huge_pages, int physical_cores,
                          int mode, double power_limit, stratum_ctx_t *stratum) {
    miner_ctx_t *ctx = (miner_ctx_t *)calloc(1, sizeof(miner_ctx_t));
    if (!ctx) return NULL;
    ctx->num_threads = num_threads;
    ctx->huge_pages = huge_pages;
    ctx->physical_cores = physical_cores;
    ctx->stratum = stratum;
    ctx->mode = mode;
    ctx->power_limit = power_limit;
    ctx->running = 0;
    ctx->cache_initialized = 0;
    InitializeCriticalSection(&ctx->cache_lock);
    InitializeCriticalSection(&ctx->perf_lock);
    return ctx;
}

void miner_destroy(miner_ctx_t *ctx) {
    if (!ctx) return;
    miner_stop(ctx);
    DeleteCriticalSection(&ctx->perf_lock);
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

void miner_report_performance(miner_ctx_t *ctx) {
    if (!ctx || !TryEnterCriticalSection(&ctx->perf_lock)) return;

    uint64_t now = GetTickCount64();
    if (ctx->perf_last_time != 0 && now - ctx->perf_last_time < 9000) {
        LeaveCriticalSection(&ctx->perf_lock);
        return;
    }

    uint64_t total_hashes = 0;
    for (int i = 0; i < ctx->num_threads; i++) {
        total_hashes += ctx->workers[i].hashes;
    }

    double energy = 0.0;
    int power_ok = msr_read_package_energy(&energy);
    if (ctx->perf_last_time != 0) {
        double seconds = (double)(now - ctx->perf_last_time) / 1000.0;
        double hashrate = (double)(total_hashes - ctx->perf_last_hashes) / seconds;
        if (power_ok && ctx->perf_power_ready) {
            double delta_energy = energy - ctx->perf_last_energy;
            if (delta_energy < 0.0) delta_energy += 4294967296.0 / 16384.0;
            double watts = delta_energy / seconds;
            if (watts > 0.1) {
                LOG_INFO("[PERF] %.1f H/s | %.1f W package | %.2f H/W | %d threads | %s",
                         hashrate, watts, hashrate / watts, ctx->num_threads,
                         g_best_mode == MODE_DUAL ? "dual" : "single");
            } else {
                LOG_INFO("[PERF] %.1f H/s | power unavailable", hashrate);
            }
        } else {
            LOG_INFO("[PERF] %.1f H/s | power unavailable (RAPL/MSR)", hashrate);
        }
    }

    ctx->perf_last_time = now;
    ctx->perf_last_hashes = total_hashes;
    if (power_ok) {
        ctx->perf_last_energy = energy;
        ctx->perf_power_ready = 1;
    }
    LeaveCriticalSection(&ctx->perf_lock);
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
    int cpu;
    uint32_t seed0;
} bench_thread_arg;

static DWORD WINAPI bench_thread_entry(LPVOID arg) {
    bench_thread_arg *a = (bench_thread_arg *)arg;
    uint8_t in1[76] = {0};
    uint8_t in2[76] = {0};
    uint8_t out1[32], out2[32];

    if (a->cpu >= 0) {
        GROUP_AFFINITY ga = {0};
        ga.Group = (WORD)(a->cpu / 64);
        ga.Mask = (KAFFINITY)(1ULL << (a->cpu % 64));
        SetThreadGroupAffinity(GetCurrentThread(), &ga, NULL);
    }

    memcpy(in1, &a->seed0, sizeof(a->seed0));
    uint32_t seed2 = a->seed0 ^ 0x9E3779B9u;
    memcpy(in2, &seed2, sizeof(seed2));

    if (a->dual) {
        for (int i = 0; i < MODE_BENCH_WARMUP + MODE_BENCH_ITERS; i++) {
            uint32_t nonce1 = a->seed0 + (uint32_t)(i * 2);
            uint32_t nonce2 = nonce1 + 1;
            memcpy(in1 + 39, &nonce1, sizeof(nonce1));
            memcpy(in2 + 39, &nonce2, sizeof(nonce2));
            rx_calculate_hash_dual(a->vm1, a->vm2, in1, sizeof(in1), in2, sizeof(in2), out1, out2);
        }
    } else {
        uint32_t nonce = a->seed0;
        memcpy(in1 + 39, &nonce, sizeof(nonce));
        rx_calculate_hash_first(a->vm1, in1, sizeof(in1));
        for (int i = 0; i < MODE_BENCH_WARMUP + MODE_BENCH_ITERS; i++) {
            nonce++;
            memcpy(in1 + 39, &nonce, sizeof(nonce));
            rx_calculate_hash_next(a->vm1, in1, sizeof(in1), out1);
        }
    }

    return 0;
}

static double run_mode_bench(int num_threads, int dual, rx_cache *cache, rx_dataset *dataset) {
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

    core_list_t cores = {0};
    int affinity_order[AFFINITY_MAX_CORES * 2];
    int affinity_count = 0;
    if (affinity_detect_cores(&cores) > 0) {
        affinity_sort_pcore_first(&cores);
        affinity_count = affinity_build_order(&cores, affinity_order, AFFINITY_MAX_CORES * 2);
    }

    for (int i = 0; i < bench_threads; i++) {
        args[i].dual = dual;
        args[i].cpu = affinity_count > 0 ? affinity_order[i % affinity_count] : -1;
        args[i].seed0 = 0xA5A50000u + (uint32_t)i;
        args[i].vm1 = rx_create_vm(RX_FLAG_JIT | RX_FLAG_DEFAULT, cache, dataset);
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
            args[i].vm2 = rx_create_vm(RX_FLAG_JIT | RX_FLAG_DEFAULT, cache, dataset);
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
    DWORD wait_result = WaitForMultipleObjects((DWORD)bench_threads, threads, TRUE, 30000);
    if (wait_result == WAIT_TIMEOUT) {
        /* Threads do bounded, lock-free work and should finish quickly. If the
           30s probe timed out (e.g. heavy system load), wait it out to
           completion before destroying the VMs they still reference. */
        WaitForMultipleObjects((DWORD)bench_threads, threads, TRUE, INFINITE);
    }
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
    double hashes = (double)bench_threads * (double)(MODE_BENCH_WARMUP + MODE_BENCH_ITERS) *
                    (dual ? 2.0 : 1.0);
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
    if (dual > single * 1.005) {
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

void *miner_get_vm2(miner_ctx_t *ctx, int worker_id) {
    if (worker_id < 0 || worker_id >= ctx->num_threads) return NULL;
    return (void *)ctx->workers[worker_id].vm2;
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
    msr_init();
    if (ctx->power_limit > 0.0) {
        ctx->power_limit_set = msr_set_package_power_limit(
            ctx->power_limit, &ctx->original_power_limit);
        if (!ctx->power_limit_set)
            LOG_WARN("[MSR] Requested %.1f W package limit was not applied",
                     ctx->power_limit);
    }

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
    int num_physical = affinity_detect_cores(&cores);
    affinity_sort_pcore_first(&cores);
    int affinity_order[AFFINITY_MAX_CORES * 2];
    int affinity_count = affinity_build_order(&cores, affinity_order, AFFINITY_MAX_CORES * 2);

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
    if (ctx->power_limit_set) {
        if (msr_restore_package_power_limit(ctx->original_power_limit))
            LOG_INFO("[MSR] Original package power limit restored");
        else
            LOG_WARN("[MSR] Failed to restore original package power limit");
        ctx->power_limit_set = 0;
    }
    msr_destroy();

    LOG_INFO("[MINER] Stopped");
}
