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
} run_ctx_t;

static DWORD WINAPI vm_run_thread(LPVOID param) {
    run_ctx_t *ctx = (run_ctx_t *)param;
    __try {
        rx_calculate_hash(ctx->vm, ctx->input, ctx->input_len, ctx->hash);
        ctx->done = 1;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        ctx->crashed = 1;
        ctx->done = 1;
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

    printf("Warming up (1 hash)...\n"); fflush(stdout);
    __try {
        rx_calculate_hash(vm, (const uint8_t*)input, strlen(input), hash);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        printf("[FAIL] VM crashed during warm-up\n");
        rx_destroy_vm(vm);
        return;
    }
    printf("Warm-up done\n"); fflush(stdout);

    int num_hashes = 20;
    printf("Running %d hashes...\n", num_hashes); fflush(stdout);

    LARGE_INTEGER t0, t1, freq;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t0);
    __try {
        for (int i = 0; i < num_hashes; i++) {
            rx_calculate_hash(vm, (const uint8_t*)input, strlen(input), hash);
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        printf("[FAIL] VM crashed during benchmark\n");
        rx_destroy_vm(vm);
        return;
    }
    QueryPerformanceCounter(&t1);
    double elapsed = (double)(t1.QuadPart - t0.QuadPart) / freq.QuadPart;
    double hps = num_hashes / elapsed;

    printf("\n");
    printf("=== %s RESULTS ===\n", name);
    printf("Mode:         %s\n", use_jit ? "JIT" : "Interpreter");
    printf("Hashes:       %d\n", num_hashes);
    printf("Time:         %.3f s\n", elapsed);
    printf("Hashrate:     %.2f H/s\n", hps);
    printf("Time/hash:    %.1f ms/hash\n", (elapsed / num_hashes) * 1000.0);
    printf("Hash sample:  ");
    for (int i = 0; i < 8; i++) printf("%02x", hash[i]);
    printf("...\n"); fflush(stdout);

    rx_destroy_vm(vm);
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
    printf("[BENCH] Dataset ready in %.1f s (14 threads)\n", ds_time); fflush(stdout);

    // Test JIT
    run_benchmark("JIT Mode", 1, cache, dataset);

    // Test Interpreter
    run_benchmark("Interpreter Mode", 0, cache, dataset);

    printf("\n========================================\n");
    printf("BENCHMARK COMPLETE\n");
    printf("========================================\n\n"); fflush(stdout);

    rx_free_dataset(dataset);
    rx_free_cache(cache);
    return 0;
}
