#include "crypto/randomx/randomx.h"
#include "crypto/randomx/randomx_internal.h"
#include "common/log.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <excpt.h>
#include <windows.h>

#define NUM_THREADS 14
#define HASHES_PER_THREAD 100

typedef struct {
    rx_vm *vm;
    const uint8_t *input;
    size_t input_len;
    uint8_t hash[32];
    volatile LONG hashes_done;
    int target_hashes;
    volatile int crashed;
    LARGE_INTEGER t0;
    LARGE_INTEGER t1;
    LARGE_INTEGER freq;
} mt_ctx_t;

static DWORD WINAPI mt_worker(LPVOID param) {
    mt_ctx_t *ctx = (mt_ctx_t *)param;
    __try {
        QueryPerformanceCounter(&ctx->t0);
        for (int i = 0; i < ctx->target_hashes; i++) {
            rx_calculate_hash(ctx->vm, ctx->input, ctx->input_len, ctx->hash);
            InterlockedIncrement(&ctx->hashes_done);
        }
        QueryPerformanceCounter(&ctx->t1);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        ctx->crashed = 1;
    }
    return 0;
}

static void run_benchmark(const char *name, int use_jit, rx_cache *cache, rx_dataset *dataset) {
    printf("\n========================================\n");
    printf("BENCHMARK: %s\n", name);
    printf("========================================\n"); fflush(stdout);

    printf("Creating VM (%s mode)...\n", use_jit ? "JIT" : "Interpreter"); fflush(stdout);
    rx_vm *vm = rx_create_vm(1, use_jit, 0, cache, dataset);
    if (!vm) { printf("[FAIL] VM alloc\n"); return; }

    uint8_t hash[32];
    const char *input = "benchmark input for hashrate test";

    printf("Warming up (3 hashes)...\n"); fflush(stdout);
    __try {
        for (int w = 0; w < 3; w++)
            rx_calculate_hash(vm, (const uint8_t*)input, strlen(input), hash);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        printf("[FAIL] VM crashed during warm-up\n");
        rx_destroy_vm(vm);
        return;
    }

    int st_hashes = 100;
    printf("Running %d single-threaded hashes...\n", st_hashes); fflush(stdout);

    LARGE_INTEGER t0, t1, freq;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t0);
    __try {
        for (int i = 0; i < st_hashes; i++) {
            rx_calculate_hash(vm, (const uint8_t*)input, strlen(input), hash);
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        printf("[FAIL] VM crashed during ST benchmark\n");
        rx_destroy_vm(vm);
        return;
    }
    QueryPerformanceCounter(&t1);
    double st_elapsed = (double)(t1.QuadPart - t0.QuadPart) / freq.QuadPart;
    double st_hps = st_hashes / st_elapsed;

    printf("\n");
    printf("=== %s SINGLE-THREADED ===\n", name);
    printf("Mode:         %s\n", use_jit ? "JIT" : "Interpreter");
    printf("Hashes:       %d\n", st_hashes);
    printf("Time:         %.3f s\n", st_elapsed);
    printf("Hashrate:     %.2f H/s\n", st_hps);
    printf("Time/hash:    %.1f ms/hash\n", (st_elapsed / st_hashes) * 1000.0);
    printf("Hash sample:  ");
    for (int i = 0; i < 8; i++) printf("%02x", hash[i]);
    printf("...\n"); fflush(stdout);

    rx_destroy_vm(vm);
}

static void run_mt_benchmark(const char *name, int use_jit, rx_cache *cache, rx_dataset *dataset) {
    printf("\n========================================\n");
    printf("BENCHMARK: %s (MT)", name);
    printf("========================================\n"); fflush(stdout);

    mt_ctx_t *ctxs = (mt_ctx_t *)calloc(NUM_THREADS, sizeof(mt_ctx_t));
    HANDLE *threads = (HANDLE *)calloc(NUM_THREADS, sizeof(HANDLE));
    const char *input = "benchmark input for hashrate test";

    for (int t = 0; t < NUM_THREADS; t++) {
        ctxs[t].vm = rx_create_vm(1, use_jit, 0, cache, dataset);
        if (!ctxs[t].vm) {
            printf("[FAIL] VM alloc for thread %d\n", t);
            for (int j = 0; j < t; j++) rx_destroy_vm(ctxs[j].vm);
            free(ctxs); free(threads);
            return;
        }
        ctxs[t].input = (const uint8_t*)input;
        ctxs[t].input_len = strlen(input);
        ctxs[t].hashes_done = 0;
        ctxs[t].target_hashes = HASHES_PER_THREAD;
        ctxs[t].crashed = 0;
        QueryPerformanceFrequency(&ctxs[t].freq);

        uint8_t warmup[32];
        __try {
            rx_calculate_hash(ctxs[t].vm, (const uint8_t*)input, strlen(input), warmup);
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            printf("[FAIL] Thread %d crashed on warm-up\n", t);
            for (int j = 0; j <= t; j++) rx_destroy_vm(ctxs[j].vm);
            free(ctxs); free(threads);
            return;
        }
    }

    printf("Running %d threads x %d hashes each...\n", NUM_THREADS, HASHES_PER_THREAD); fflush(stdout);

    LARGE_INTEGER mt0, mt1, freq;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&mt0);

    for (int t = 0; t < NUM_THREADS; t++) {
        threads[t] = CreateThread(NULL, 0, mt_worker, &ctxs[t], 0, NULL);
    }
    WaitForMultipleObjects(NUM_THREADS, threads, TRUE, 60000);
    QueryPerformanceCounter(&mt1);

    int any_crash = 0;
    int total_hashes = 0;
    for (int t = 0; t < NUM_THREADS; t++) {
        if (ctxs[t].crashed) any_crash = 1;
        total_hashes += ctxs[t].hashes_done;
        CloseHandle(threads[t]);
    }

    double mt_elapsed = (double)(mt1.QuadPart - mt0.QuadPart) / freq.QuadPart;
    double mt_hps = total_hashes / mt_elapsed;

    printf("\n");
    printf("=== %s MULTI-THREADED (%dT) ===\n", name, NUM_THREADS);
    printf("Mode:         %s\n", use_jit ? "JIT" : "Interpreter");
    printf("Threads:      %d\n", NUM_THREADS);
    printf("Hashes:       %d\n", total_hashes);
    printf("Time:         %.3f s\n", mt_elapsed);
    printf("Hashrate:     %.2f H/s\n", mt_hps);
    if (any_crash) printf("WARNING:      Some threads crashed!\n");
    printf("Hash sample:  ");
    for (int i = 0; i < 8; i++) printf("%02x", ctxs[0].hash[i]);
    printf("...\n"); fflush(stdout);

    for (int t = 0; t < NUM_THREADS; t++) rx_destroy_vm(ctxs[t].vm);
    free(ctxs); free(threads);
}

int main(void) {
    uint8_t key[32] = {0x01};

    printf("[BENCH] Allocating cache (256 MB)...\n"); fflush(stdout);
    rx_cache *cache = rx_alloc_cache(0);
    if (!cache) { printf("[FAIL] cache alloc\n"); return 1; }

    printf("[BENCH] Initializing cache (Argon2d, ~30s)...\n"); fflush(stdout);
    rx_init_cache(cache, key, 32);
    printf("[BENCH] Cache ready\n"); fflush(stdout);

    printf("[BENCH] Allocating dataset (2.1 GB)...\n"); fflush(stdout);
    rx_dataset *dataset = rx_alloc_dataset(0);
    if (!dataset) { printf("[FAIL] dataset alloc\n"); return 1; }

    printf("[BENCH] Initializing dataset (%d threads)...\n", NUM_THREADS); fflush(stdout);
    LARGE_INTEGER t0, t1, freq;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t0);
    rx_init_dataset(dataset, cache, 0, RX_DATASET_ITEMS, NUM_THREADS, NUM_THREADS);
    QueryPerformanceCounter(&t1);
    double ds_time = (double)(t1.QuadPart - t0.QuadPart) / freq.QuadPart;
    printf("[BENCH] Dataset ready in %.1f s (%d threads)\n", ds_time, NUM_THREADS); fflush(stdout);

    run_benchmark("JIT", 1, cache, dataset);
    run_benchmark("Interpreter", 0, cache, dataset);

    run_mt_benchmark("JIT", 1, cache, dataset);
    run_mt_benchmark("Interpreter", 0, cache, dataset);

    printf("\n========================================\n");
    printf("BENCHMARK COMPLETE\n");
    printf("========================================\n\n"); fflush(stdout);

    rx_free_dataset(dataset);
    rx_free_cache(cache);
    return 0;
}
