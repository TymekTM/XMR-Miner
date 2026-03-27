#include "miner.h"
#include "worker.h"
#include "stratum/stratum.h"
#include "crypto/randomx/randomx.h"
#include "common/log.h"
#include "common/cpu.h"
#include <windows.h>
#include <string.h>
#include <stdlib.h>

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
};

miner_ctx_t *miner_create(int num_threads, int huge_pages, int physical_cores, stratum_ctx_t *stratum) {
    miner_ctx_t *ctx = (miner_ctx_t *)calloc(1, sizeof(miner_ctx_t));
    if (!ctx) return NULL;
    ctx->num_threads = num_threads;
    ctx->huge_pages = huge_pages;
    ctx->physical_cores = physical_cores;
    ctx->stratum = stratum;
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
        rx_init_dataset_cached(ctx->dataset, ctx->cache, 0, 33554432, ctx->num_threads, ctx->physical_cores);
        LOG_INFO("[MINER] Dataset reinitialized");
    }

    EnterCriticalSection(&ctx->cache_lock);
    for (int i = 0; i < ctx->num_threads; i++) {
        if (ctx->workers[i].vm) {
            rx_destroy_vm((rx_vm *)ctx->workers[i].vm);
            ctx->workers[i].vm = NULL;
        }
        ctx->workers[i].vm = rx_create_vm(1, 1, ctx->huge_pages, ctx->cache, ctx->dataset);
    }
    LeaveCriticalSection(&ctx->cache_lock);

    LOG_INFO("[MINER] Cache reinitialized with seed: %.16s...", new_hex);
}

void *miner_get_vm(miner_ctx_t *ctx, int worker_id) {
    if (worker_id < 0 || worker_id >= ctx->num_threads) return NULL;
    return ctx->workers[worker_id].vm;
}

int miner_start(miner_ctx_t *ctx, const uint8_t *initial_seed, int initial_seed_len) {
    ctx->running = 1;
    stratum_set_running(ctx->stratum, 1);

    ctx->workers = (worker_t *)calloc(ctx->num_threads, sizeof(worker_t));
    ctx->thread_handles = (HANDLE *)calloc(ctx->num_threads, sizeof(HANDLE));

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
    rx_init_dataset_cached(ctx->dataset, ctx->cache, 0, 33554432, ctx->num_threads, ctx->physical_cores);
    LOG_INFO("[MINER] Dataset initialized");

    for (int i = 0; i < ctx->num_threads; i++) {
        ctx->workers[i].id = i;
        ctx->workers[i].vm = rx_create_vm(1, 1, ctx->huge_pages, ctx->cache, ctx->dataset);
        ctx->workers[i].stratum = ctx->stratum;
        ctx->workers[i].miner = ctx;
        ctx->workers[i].hashes = 0;
        ctx->workers[i].start_time = 0;
        ctx->workers[i].should_stop = 0;
        ctx->workers[i].nonce_offset = (uint32_t)i;
        ctx->workers[i].loop_count = 0;
        ctx->workers[i].extranonce2_counter = 0;
        strncpy(ctx->workers[i].initial_seed, ctx->current_seed_hex, sizeof(ctx->workers[i].initial_seed) - 1);
    }

    LOG_INFO("[MINER] Starting %d threads...", ctx->num_threads);

    for (int i = 0; i < ctx->num_threads; i++) {
        ctx->thread_handles[i] = CreateThread(NULL, 0, thread_entry, &ctx->workers[i], 0, NULL);
        if (!ctx->thread_handles[i]) {
            LOG_ERR("[MINER] Failed to create thread %d", i);
            continue;
        }
        SetThreadPriority(ctx->thread_handles[i], THREAD_PRIORITY_TIME_CRITICAL);
        if (ctx->num_threads == 1 && ctx->physical_cores > 0) {
            GROUP_AFFINITY ga = {0};
            ga.Group = 0;
            ga.Mask = (KAFFINITY)1;
            ga.Reserved[0] = ga.Reserved[1] = ga.Reserved[2] = 0;
            SetThreadGroupAffinity(ctx->thread_handles[i], &ga, NULL);
        } else if (i < ctx->physical_cores) {
            DWORD_PTR mask = 1ULL << i;
            SetThreadAffinityMask(ctx->thread_handles[i], mask);
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
    }
    if (total > 0) {
        LOG_INFO("[MINER] Total: %llu hashes", total);
    }

    LOG_INFO("[MINER] Stopped");
}
