#include "crypto/randomx/randomx.h"
#include "crypto/randomx/randomx_internal.h"
#include "common/log.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <excpt.h>
#include <windows.h>

typedef struct {
    rx_vm *vm;
    const uint8_t *input;
    size_t input_len;
    uint8_t *hash;
    volatile int done;
    volatile int crashed;
} jit_run_ctx_t;

static DWORD WINAPI jit_run_thread(LPVOID param) {
    jit_run_ctx_t *ctx = (jit_run_ctx_t *)param;
    __try {
        rx_calculate_hash(ctx->vm, ctx->input, ctx->input_len, ctx->hash);
        ctx->done = 1;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        ctx->crashed = 1;
        ctx->done = 1;
    }
    return 0;
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

    printf("[BENCH] Initializing dataset (14 threads)...\n"); fflush(stdout);
    LARGE_INTEGER t0, t1, freq;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t0);
    rx_init_dataset(dataset, cache, 0, RX_DATASET_ITEMS, 14, 14);
    QueryPerformanceCounter(&t1);
    double ds_time = (double)(t1.QuadPart - t0.QuadPart) / freq.QuadPart;
    printf("[BENCH] Dataset ready in %.1f s\n", ds_time); fflush(stdout);

    printf("[BENCH] Creating JIT VM (full mode)...\n"); fflush(stdout);
    rx_vm *vm = rx_create_vm(1, 0, 0, cache, dataset);
    if (!vm) { printf("[FAIL] VM alloc\n"); return 1; }

    uint8_t hash[32];
    const char *input = "benchmark input for hashrate test";

    printf("[BENCH] Warming up (1 hash, 10s timeout)...\n"); fflush(stdout);
    {
        jit_run_ctx_t ctx = { vm, (const uint8_t*)input, strlen(input), hash, 0, 0 };
        HANDLE h = CreateThread(NULL, 0, jit_run_thread, &ctx, 0, NULL);
        WaitForSingleObject(h, 10000);
        if (ctx.crashed) {
            printf("[FAIL] JIT crashed (falling back to interpreter)\n");
            TerminateThread(h, 1);
            CloseHandle(h);
            rx_destroy_vm(vm);
            vm = rx_create_vm(1, 0, 0, cache, dataset);
            if (!vm) { printf("[FAIL] VM alloc (interpreter)\n"); return 1; }
        } else if (!ctx.done) {
            printf("[FAIL] JIT hung (timeout after 10s)\n");
            TerminateThread(h, 1);
            CloseHandle(h);
            rx_destroy_vm(vm); rx_free_dataset(dataset); rx_free_cache(cache);
            return 1;
        } else {
            CloseHandle(h);
        }
    }
    printf("[BENCH] Warm-up done\n"); fflush(stdout);

    int num_hashes = 10;
    printf("[BENCH] Running %d hashes...\n", num_hashes); fflush(stdout);
    QueryPerformanceCounter(&t0);
    for (int i = 0; i < num_hashes; i++) {
        rx_calculate_hash(vm, (const uint8_t*)input, strlen(input), hash);
    }
    QueryPerformanceCounter(&t1);
    double elapsed = (double)(t1.QuadPart - t0.QuadPart) / freq.QuadPart;
    double hps = num_hashes / elapsed;

    printf("\n");
    printf("=== RESULTS ===\n");
    printf("Hashes:      %d\n", num_hashes);
    printf("Time:         %.3f s\n", elapsed);
    printf("Hashrate:     %.2f H/s\n", hps);
    printf("Hash sample:  ");
    for (int i = 0; i < 8; i++) printf("%02x", hash[i]);
    printf("...\n");

    rx_destroy_vm(vm);
    rx_free_dataset(dataset);
    rx_free_cache(cache);
    return 0;
}
