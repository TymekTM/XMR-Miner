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
    stratum_ctx_t *stratum;
    worker_t *workers;
    HANDLE *thread_handles;
    int running;
    rx_cache *cache;
    CRITICAL_SECTION cache_lock;
    char current_seed_hex[65];
    int cache_initialized;
};

miner_ctx_t *miner_create(int num_threads, stratum_ctx_t *stratum) {
    miner_ctx_t *ctx = (miner_ctx_t *)calloc(1, sizeof(miner_ctx_t));
    if (!ctx) return NULL;
    ctx->num_threads = num_threads;
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
    EnterCriticalSection(&ctx->cache_lock);

    char new_hex[65] = {0};
    seed_to_hex(seed, seed_len, new_hex);

    if (strcmp(new_hex, ctx->current_seed_hex) == 0) {
        LeaveCriticalSection(&ctx->cache_lock);
        return;
    }

    LOG_INFO("[MINER] Initializing cache with new seed: %.16s...", new_hex);

    if (!ctx->cache) {
        ctx->cache = rx_alloc_cache(0);
        if (!ctx->cache) {
            LOG_ERR("[MINER] Failed to allocate cache");
            LeaveCriticalSection(&ctx->cache_lock);
            return;
        }
    }

    rx_init_cache(ctx->cache, seed, (size_t)seed_len);
    strncpy(ctx->current_seed_hex, new_hex, sizeof(ctx->current_seed_hex) - 1);
    ctx->cache_initialized = 1;

    for (int i = 0; i < ctx->num_threads; i++) {
        if (ctx->workers[i].vm) {
            rx_destroy_vm((rx_vm *)ctx->workers[i].vm);
            ctx->workers[i].vm = NULL;
        }
        ctx->workers[i].vm = rx_create_vm(0, ctx->cache, NULL);
    }

    LOG_INFO("[MINER] Cache reinitialized with seed: %.16s...", new_hex);
    LeaveCriticalSection(&ctx->cache_lock);
}

void *miner_get_vm(miner_ctx_t *ctx, int worker_id) {
    if (worker_id < 0 || worker_id >= ctx->num_threads) return NULL;
    return ctx->workers[worker_id].vm;
}

int miner_start(miner_ctx_t *ctx) {
    ctx->running = 1;
    stratum_set_running(ctx->stratum, 1);

    ctx->workers = (worker_t *)calloc(ctx->num_threads, sizeof(worker_t));
    ctx->thread_handles = (HANDLE *)calloc(ctx->num_threads, sizeof(HANDLE));

    LOG_INFO("[MINER] Initializing RandomX cache (this takes ~30 seconds)...");

    ctx->cache = rx_alloc_cache(0);
    if (!ctx->cache) {
        LOG_ERR("[MINER] Failed to allocate cache");
        return -1;
    }

    uint8_t default_seed[32] = {0};
    rx_init_cache(ctx->cache, default_seed, 32);
    seed_to_hex(default_seed, 32, ctx->current_seed_hex);
    ctx->cache_initialized = 1;

    LOG_INFO("[MINER] Cache initialized (will reinit on first seed_hash from pool)");

    for (int i = 0; i < ctx->num_threads; i++) {
        ctx->workers[i].id = i;
        ctx->workers[i].vm = rx_create_vm(0, ctx->cache, NULL);
        ctx->workers[i].stratum = ctx->stratum;
        ctx->workers[i].miner = ctx;
        ctx->workers[i].hashes = 0;
        ctx->workers[i].start_time = 0;
        ctx->workers[i].should_stop = 0;
    }

    LOG_INFO("[MINER] Starting %d threads...", ctx->num_threads);

    for (int i = 0; i < ctx->num_threads; i++) {
        ctx->thread_handles[i] = CreateThread(NULL, 0, thread_entry, &ctx->workers[i], 0, NULL);
        if (!ctx->thread_handles[i]) {
            LOG_ERR("[MINER] Failed to create thread %d", i);
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
