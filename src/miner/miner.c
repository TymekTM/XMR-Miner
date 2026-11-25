#include "miner.h"
#include "worker.h"
#include "affinity.h"
#include "watchdog.h"
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
    double baseline_watts;
    double power_limit;
    uint64_t original_power_limit;
    int power_limit_set;
    int lanes;
    int efficiency;
    int eco_qos;
    volatile LONG pause_req;
    volatile LONG paused_count;
    volatile LONG yield_pause_p;
    volatile LONG yield_pause_e;
    volatile LONG yield_state;
    HANDLE resume_p_event;
    HANDLE resume_e_event;
    int has_ecores;
    double last_hashrate;
    double last_watts;
    char yield_reason[64];
    char plan_desc[64];
};

void miner_set_lanes(miner_ctx_t *ctx, int lanes) { if (ctx) ctx->lanes = lanes; }
void miner_set_efficiency(miner_ctx_t *ctx, int efficiency, int eco_qos) {
    if (!ctx) return;
    ctx->efficiency = efficiency ? 1 : 0;
    ctx->eco_qos = eco_qos ? 1 : 0;
}
void *miner_get_cache(miner_ctx_t *ctx) { return ctx->cache; }
void *miner_get_dataset(miner_ctx_t *ctx) { return ctx->dataset; }

void miner_set_yield_state(miner_ctx_t *ctx, int yield_state, const char *reason) {
    if (!ctx) return;
    LONG pause_p = 0, pause_e = 0;
    if (yield_state == YIELD_STATE_PAUSED) {
        pause_p = 1;
        pause_e = 1;
    } else if (yield_state == YIELD_STATE_ECO) {
        pause_p = 1;
        pause_e = 0;
    }
    InterlockedExchange(&ctx->yield_state, (LONG)yield_state);
    InterlockedExchange(&ctx->yield_pause_p, pause_p);
    InterlockedExchange(&ctx->yield_pause_e, pause_e);
    if (ctx->resume_p_event) {
        if (pause_p) ResetEvent(ctx->resume_p_event);
        else SetEvent(ctx->resume_p_event);
    }
    if (ctx->resume_e_event) {
        if (pause_e) ResetEvent(ctx->resume_e_event);
        else SetEvent(ctx->resume_e_event);
    }
    if (reason) {
        EnterCriticalSection(&ctx->perf_lock);
        snprintf(ctx->yield_reason, sizeof(ctx->yield_reason), "%s", reason);
        LeaveCriticalSection(&ctx->perf_lock);
    }
}

void miner_update_yield_reason(miner_ctx_t *ctx, const char *reason) {
    if (!ctx || !reason) return;
    if (TryEnterCriticalSection(&ctx->perf_lock)) {
        snprintf(ctx->yield_reason, sizeof(ctx->yield_reason), "%s", reason);
        LeaveCriticalSection(&ctx->perf_lock);
    }
}

int miner_get_yield_state(miner_ctx_t *ctx) {
    if (!ctx) return YIELD_STATE_FULL;
    return (int)InterlockedCompareExchange(&ctx->yield_state, 0, 0);
}

void miner_get_live_stats(miner_ctx_t *ctx, double *hashrate_out, double *watts_out) {
    if (!ctx) {
        if (hashrate_out) *hashrate_out = 0.0;
        if (watts_out) *watts_out = 0.0;
        return;
    }
    EnterCriticalSection(&ctx->perf_lock);
    if (hashrate_out) *hashrate_out = ctx->last_hashrate;
    if (watts_out) *watts_out = ctx->last_watts;
    LeaveCriticalSection(&ctx->perf_lock);
}

void miner_check_worker_pause(miner_ctx_t *ctx, void *worker_ptr) {
    if (!ctx) return;
    worker_t *w = (worker_t *)worker_ptr;
    /* On hybrid CPUs, ECO parks P-cores and leaves E-cores running.
       On homogeneous CPUs without E-cores, ECO parks the first half of workers. */
    int use_p_gate = 1;
    if (w) {
        if (ctx->has_ecores) use_p_gate = w->is_pcore ? 1 : 0;
        else use_p_gate = (w->id < (ctx->num_threads + 1) / 2) ? 1 : 0;
    }
    LONG sys_pause = InterlockedCompareExchange(&ctx->pause_req, 0, 0);
    LONG yld_pause = use_p_gate
        ? InterlockedCompareExchange(&ctx->yield_pause_p, 0, 0)
        : InterlockedCompareExchange(&ctx->yield_pause_e, 0, 0);
    if (!sys_pause && !yld_pause) return;

    InterlockedIncrement(&ctx->paused_count);
    if (w) w->batch_active = 0; /* force fresh job on resume to prevent stale shares */
    HANDLE ev = use_p_gate ? ctx->resume_p_event : ctx->resume_e_event;
    while (ctx->running) {
        sys_pause = InterlockedCompareExchange(&ctx->pause_req, 0, 0);
        yld_pause = use_p_gate
            ? InterlockedCompareExchange(&ctx->yield_pause_p, 0, 0)
            : InterlockedCompareExchange(&ctx->yield_pause_e, 0, 0);
        if (!sys_pause && !yld_pause) break;
        if (sys_pause) {
            Sleep(5);
        } else if (ev) {
            WaitForSingleObject(ev, 250);
        } else {
            Sleep(50);
        }
    }
    InterlockedDecrement(&ctx->paused_count);
}

void miner_check_pause(miner_ctx_t *ctx) {
    miner_check_worker_pause(ctx, NULL);
}

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
    ctx->resume_p_event = CreateEventA(NULL, TRUE, TRUE, NULL);
    ctx->resume_e_event = CreateEventA(NULL, TRUE, TRUE, NULL);
    return ctx;
}

void miner_destroy(miner_ctx_t *ctx) {
    if (!ctx) return;
    miner_stop(ctx);
    if (ctx->resume_p_event) CloseHandle(ctx->resume_p_event);
    if (ctx->resume_e_event) CloseHandle(ctx->resume_e_event);
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
        int ystate = (int)InterlockedCompareExchange(&ctx->yield_state, 0, 0);
        const char *ystr = (ystate == YIELD_STATE_ECO) ? " [ECO]" :
                           (ystate == YIELD_STATE_PAUSED) ? " [PAUSED]" : "";
        double watts = 0.0;
        if (power_ok && ctx->perf_power_ready) {
            double delta_energy = energy - ctx->perf_last_energy;
            if (delta_energy < 0.0) delta_energy += msr_get_energy_wrap_joules();
            watts = delta_energy / seconds;
        }
        ctx->last_hashrate = hashrate;
        ctx->last_watts = watts;
        if (ystate == YIELD_STATE_PAUSED) {
            LOG_INFO("[PERF] PAUSED (%s) | %.1f W pkg",
                     ctx->yield_reason[0] ? ctx->yield_reason : "yielding", watts);
        } else if (power_ok && ctx->perf_power_ready && watts > 0.1) {
            const char *plan = ctx->plan_desc[0] ? ctx->plan_desc : (g_best_mode == MODE_DUAL ? "dual" : "single");
            double dw = (ctx->baseline_watts > 0.5) ? (watts - ctx->baseline_watts) : 0.0;
            if (dw > 2.0) {
                LOG_INFO("[PERF] %.1f H/s | %.1f W pkg (+%.1f W) | %.2f H/W (%.1f H/dW) | %dT%s | %s",
                         hashrate, watts, dw, hashrate / watts, hashrate / dw, ctx->num_threads, ystr, plan);
            } else {
                LOG_INFO("[PERF] %.1f H/s | %.1f W package | %.2f H/W | %dT%s | %s",
                         hashrate, watts, hashrate / watts, ctx->num_threads, ystr, plan);
            }
        } else {
            LOG_INFO("[PERF] %.1f H/s | power unavailable | %dT%s | %s",
                     hashrate, ctx->num_threads, ystr, ctx->plan_desc[0] ? ctx->plan_desc : "single");
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
        /* Raise pause gate under cache_lock so any second worker observing !need_reinit
           immediately parks at miner_check_pause until the rebuild completes. */
        InterlockedExchange(&ctx->pause_req, 1);
    }
    LeaveCriticalSection(&ctx->cache_lock);

    if (!need_reinit) {
        miner_check_pause(ctx);
        return;
    }

    LOG_INFO("[MINER] Seed changed (%.16s...) - pausing workers for safe dataset reinit...", new_hex);
    while (ctx->num_threads > 1 &&
           InterlockedCompareExchange(&ctx->paused_count, 0, 0) < (LONG)(ctx->num_threads - 1) &&
           ctx->running) {
        Sleep(5);
    }
    if (!ctx->running) {
        InterlockedExchange(&ctx->pause_req, 0);
        return;
    }

    if (!ctx->cache) {
        ctx->cache = rx_alloc_cache(ctx->huge_pages);
        if (!ctx->cache) {
            LOG_ERR("[MINER] Failed to allocate cache");
            InterlockedExchange(&ctx->pause_req, 0);
            return;
        }
    }

    rx_init_cache(ctx->cache, seed, (size_t)seed_len);
    ctx->cache_initialized = 1;

    if (ctx->dataset) {
        int init_threads = cpu_count_logical();
        if (init_threads > 2) init_threads -= 2;
        if (init_threads < 1) init_threads = 1;
        LOG_INFO("[MINER] Reinitializing dataset with %d threads...", init_threads);
        rx_init_dataset_cached(ctx->dataset, ctx->cache, 0, RX_DATASET_ITEMS + RX_DATASET_EXTRA_ITEMS,
                               init_threads, ctx->physical_cores);
        LOG_INFO("[MINER] Dataset reinitialized");
    }

    for (int i = 0; i < ctx->num_threads; i++) {
        ctx->workers[i].batch_active = 0;
    }
    InterlockedExchange(&ctx->pause_req, 0);
    LOG_INFO("[MINER] Cache/dataset reinitialized with seed: %.16s..., workers resumed", new_hex);
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
    InterlockedExchange(&ctx->pause_req, 1);
    while (ctx->num_threads > 1 &&
           InterlockedCompareExchange(&ctx->paused_count, 0, 0) < (LONG)(ctx->num_threads - 1) &&
           ctx->running) {
        Sleep(5);
    }
    for (int i = 0; i < ctx->num_threads; i++) {
        ctx->workers[i].current_rx_flags = rx_flags;
        ctx->workers[i].batch_active = 0;
        if (ctx->workers[i].vm) {
            rx_destroy_vm((rx_vm *)ctx->workers[i].vm);
            ctx->workers[i].vm = NULL;
        }
        if (ctx->workers[i].vm2) {
            rx_destroy_vm((rx_vm *)ctx->workers[i].vm2);
            ctx->workers[i].vm2 = NULL;
        }
        int need_single_vm = (ctx->workers[i].lanes <= 1) || ((rx_flags & RX_FLAG_V2) != 0);
        if (need_single_vm) {
            int f = RX_FLAG_JIT | rx_flags | (!ctx->workers[i].is_pcore ? RX_FLAG_CFROUND_GUARD : 0);
            ctx->workers[i].vm = rx_create_vm(f, ctx->cache, ctx->dataset);
            if (ctx->workers[i].use_dual) {
                ctx->workers[i].vm2 = rx_create_vm(f, ctx->cache, ctx->dataset);
            }
        }
    }
    InterlockedExchange(&ctx->pause_req, 0);
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
    ctx->dataset = rx_alloc_dataset(ctx->huge_pages ? 2 : 0);
    if (!ctx->dataset) {
        LOG_ERR("[MINER] Failed to allocate dataset");
        return -1;
    }
    int init_threads = cpu_count_logical();
    if (init_threads > 2) init_threads -= 2;
    if (init_threads < 1) init_threads = 1;
    LOG_INFO("[MINER] Dataset allocated, initializing items with %d threads...", init_threads);
    rx_init_dataset_cached(ctx->dataset, ctx->cache, 0, RX_DATASET_ITEMS + RX_DATASET_EXTRA_ITEMS, init_threads, ctx->physical_cores);
    LOG_INFO("[MINER] Dataset initialized");

    core_list_t cores;
    memset(&cores, 0, sizeof(cores));
    int num_physical = affinity_detect_cores(&cores);
    affinity_sort_pcore_first(&cores);
    core_slot_t slots[AFFINITY_MAX_CORES * 2];
    int slot_count = 0;
    if (num_physical > 0) {
        slot_count = ctx->efficiency
            ? affinity_build_slots_e_first(&cores, slots, AFFINITY_MAX_CORES * 2)
            : affinity_build_slots(&cores, slots, AFFINITY_MAX_CORES * 2);
    }

    /* Track which physical P-cores have an active HT sibling assigned */
    uint8_t core_has_ht[AFFINITY_MAX_CORES];
    memset(core_has_ht, 0, sizeof(core_has_ht));
    for (int i = 0; i < ctx->num_threads && slot_count > 0; i++) {
        const core_slot_t *sl = &slots[i % slot_count];
        if (sl->is_ht_sibling && sl->core_idx >= 0 && sl->core_idx < AFFINITY_MAX_CORES)
            core_has_ht[sl->core_idx] = 1;
    }

    int has_avx512 = rx_cpu_has_avx512_lanes();
    int p_workers = 0, e_workers = 0, ht_workers = 0, p_lanes_sum = 0, total_scratchpads = 0;
    int any_multilane = 0;

    /* Count how many E-cores are active in this thread plan so we can respect
       the chip-wide L2+L3 scratchpad budget:
       - P-cores only (<= 4T): 3 lanes per P-core (up to 24 MB, +28-35% vs 1L)
       - P-cores only (5..8T): 2 lanes per P-core (up to 32 MB, fits P-L2 + L3, +28% vs 1L)
       - Hybrid P+E (> 8T, e_active > 0): 1 lane per P-core keeps all P-core
         scratchpads inside private 2 MB P-L2, leaving the full shared L3 + E-L2
         for E-cores (with RX_FLAG_CFROUND_GUARD on E-cores = +7.7% per E-core).
         No scratchpad evictions to DDR4! */
    int active_ecores = 0;
    for (int i = 0; i < ctx->num_threads && slot_count > 0; i++) {
        if (!slots[i % slot_count].is_pcore) active_ecores++;
    }
    ctx->has_ecores = (active_ecores > 0) ? 1 : 0;

    for (int i = 0; i < ctx->num_threads; i++) {
        int is_pcore = 1, is_ht = 0, os_cpu = -1, core_idx = -1;
        if (slot_count > 0) {
            const core_slot_t *sl = &slots[i % slot_count];
            is_pcore = sl->is_pcore;
            is_ht = sl->is_ht_sibling;
            os_cpu = sl->os_cpu;
            core_idx = sl->core_idx;
        }
        int w_lanes;
        if (ctx->lanes > 0) {
            w_lanes = ctx->lanes > 4 ? 4 : ctx->lanes;
        } else {
            if (!is_pcore) {
                w_lanes = 1;
            } else if (is_ht || (core_idx >= 0 && core_has_ht[core_idx])) {
                w_lanes = 1;
            } else if (active_ecores > 0) {
                /* Hybrid P+E mode: keep P-cores 1L inside private L2 so L3 stays clean for E-cores */
                w_lanes = 1;
            } else if (has_avx512) {
                w_lanes = 3;
            } else {
                w_lanes = (ctx->num_threads <= 4) ? 3 : 2;
            }
        }
        ctx->workers[i].lanes = w_lanes;
        ctx->workers[i].is_pcore = is_pcore;
        ctx->workers[i].is_ht_sibling = is_ht;
        ctx->workers[i].os_cpu = os_cpu;
        if (w_lanes > 1) any_multilane = 1;
        total_scratchpads += w_lanes;
        if (is_ht) ht_workers++;
        else if (is_pcore) { p_workers++; p_lanes_sum += w_lanes; }
        else e_workers++;
    }

    if (any_multilane) {
        g_best_mode = MODE_SINGLE;
        /* AVX-512 register banks prefer gran=64; AVX2 (Raptor Lake) prefers gran=256 */
        extern int g_mjit_granularity;
        if (has_avx512 && g_mjit_granularity == 256) g_mjit_granularity = 64;
    } else if (ctx->mode == MINER_MODE_SINGLE) {
        g_best_mode = MODE_SINGLE;
    } else if (ctx->mode == MINER_MODE_DUAL) {
        g_best_mode = MODE_DUAL;
    } else {
        g_best_mode = select_best_mode(ctx->num_threads, ctx->cache, ctx->dataset);
    }

    for (int i = 0; i < ctx->num_threads; i++) {
        ctx->workers[i].id = i;
        int base_flags = RX_FLAG_JIT | RX_FLAG_DEFAULT | (!ctx->workers[i].is_pcore ? RX_FLAG_CFROUND_GUARD : 0);
        ctx->workers[i].vm = (ctx->workers[i].lanes <= 1) ? rx_create_vm(base_flags, ctx->cache, ctx->dataset) : NULL;
        ctx->workers[i].vm2 = NULL;
        ctx->workers[i].use_dual = (ctx->workers[i].lanes <= 1 && g_best_mode == MODE_DUAL) ? 1 : 0;
        if (ctx->workers[i].use_dual) {
            ctx->workers[i].vm2 = rx_create_vm(base_flags, ctx->cache, ctx->dataset);
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

    if (p_workers > 0 && e_workers > 0) {
        snprintf(ctx->plan_desc, sizeof(ctx->plan_desc), "%s %dP(%dL)+%dE(1L+cfg)%s%s",
                 ctx->efficiency ? "eco-hybrid" : "hybrid",
                 p_workers, p_lanes_sum / p_workers, e_workers,
                 ht_workers ? "+HT" : "", ctx->eco_qos ? " [EcoQoS]" : "");
    } else if (e_workers > 0 && p_workers == 0) {
        snprintf(ctx->plan_desc, sizeof(ctx->plan_desc), "eco-only %dE(1L+cfg)%s",
                 e_workers, ctx->eco_qos ? " [EcoQoS]" : "");
    } else if (any_multilane && p_workers > 0) {
        snprintf(ctx->plan_desc, sizeof(ctx->plan_desc), "multi-lane %dL (%s)%s",
                 p_lanes_sum / p_workers, has_avx512 ? "AVX512" : "AVX2-bank2",
                 ctx->eco_qos ? " [EcoQoS]" : "");
    } else {
        snprintf(ctx->plan_desc, sizeof(ctx->plan_desc), "%s%s",
                 g_best_mode == MODE_DUAL ? "dual" : "single",
                 ctx->eco_qos ? " [EcoQoS]" : "");
    }

    LOG_INFO("[MINER] Plan: %s | scratchpads=%d (%d MB) | VAES=%s",
             ctx->plan_desc, total_scratchpads, total_scratchpads * 2,
             cpu_has_vaes() ? "yes" : "no");
    LOG_INFO("[MINER] Starting %d threads...", ctx->num_threads);
    /* Use BELOW_NORMAL_PRIORITY_CLASS + THREAD_PRIORITY_LOWEST (priority 4) for workers
       so Discord/audio/desktop apps (priority >= 8) preempt workers instantly while
       avoiding Windows 11 Thread Director's aggressive P-core throttling on priority 1 (IDLE). */
    SetPriorityClass(GetCurrentProcess(), BELOW_NORMAL_PRIORITY_CLASS);
    msr_init();
    if (ctx->power_limit > 0.0) {
        ctx->power_limit_set = msr_set_package_power_limit(
            ctx->power_limit, &ctx->original_power_limit);
        if (!ctx->power_limit_set)
            LOG_WARN("[MSR] Requested %.1f W package limit was not applied",
                     ctx->power_limit);
    }

    if (num_physical > 0) {
        int pcores = 0;
        for (int c = 0; c < cores.count; c++) if (cores.is_pcore[c]) pcores++;
        LOG_INFO("[AFFINITY] Detected %d physical cores (%d P-core, %d E-core) [order: %s]",
                 num_physical, pcores, num_physical - pcores,
                 ctx->efficiency ? "E -> P -> P-HT" : "P -> E -> P-HT");
    }

    /* Sample 1.0s baseline package power (WinRing0 RAPL or user-space Windows EMI v2)
       before starting workers so [PERF] reports both Total H/W and incremental H/dW. */
    {
        double e0 = 0.0, e1 = 0.0;
        if (msr_read_package_energy(&e0)) {
            uint64_t t0 = GetTickCount64();
            Sleep(1000);
            uint64_t t1 = GetTickCount64();
            if (msr_read_package_energy(&e1) && t1 > t0) {
                double de = e1 - e0;
                if (de < 0.0) de += msr_get_energy_wrap_joules();
                ctx->baseline_watts = de / ((double)(t1 - t0) / 1000.0);
                if (ctx->baseline_watts > 0.5) {
                    LOG_INFO("[POWER] Baseline package power: %.1f W (RAPL/EMI)", ctx->baseline_watts);
                }
            }
        }
    }

    for (int i = 0; i < ctx->num_threads; i++) {
        ctx->thread_handles[i] = CreateThread(NULL, 0, thread_entry, &ctx->workers[i], 0, NULL);
        if (!ctx->thread_handles[i]) {
            LOG_ERR("[MINER] Failed to create thread %d", i);
            continue;
        }
        SetThreadPriority(ctx->thread_handles[i], THREAD_PRIORITY_LOWEST);
        if (ctx->eco_qos) {
            THREAD_POWER_THROTTLING_STATE pts;
            memset(&pts, 0, sizeof(pts));
            pts.Version = THREAD_POWER_THROTTLING_CURRENT_VERSION;
            pts.ControlMask = THREAD_POWER_THROTTLING_EXECUTION_SPEED;
            pts.StateMask = THREAD_POWER_THROTTLING_EXECUTION_SPEED;
            SetThreadInformation(ctx->thread_handles[i], ThreadPowerThrottling, &pts, sizeof(pts));
        }
        if (ctx->workers[i].os_cpu >= 0) {
            GROUP_AFFINITY ga = {0};
            int os_idx = ctx->workers[i].os_cpu;
            ga.Group = (WORD)(os_idx / 64);
            ga.Mask = (KAFFINITY)(1ULL << (os_idx % 64));
            SetThreadGroupAffinity(ctx->thread_handles[i], &ga, NULL);
            LOG_DEBUG("[AFFINITY] W%d -> CPU%d (%s, %dL)", i, os_idx,
                      ctx->workers[i].is_pcore ? (ctx->workers[i].is_ht_sibling ? "P-HT" : "P") : "E",
                      ctx->workers[i].lanes);
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
    /* Wake any workers parked by Auto-Yield so shutdown finishes immediately */
    InterlockedExchange(&ctx->yield_pause_p, 0);
    InterlockedExchange(&ctx->yield_pause_e, 0);
    if (ctx->resume_p_event) SetEvent(ctx->resume_p_event);
    if (ctx->resume_e_event) SetEvent(ctx->resume_e_event);

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
