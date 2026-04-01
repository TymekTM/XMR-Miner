#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <windows.h>
#include "crypto/randomx/randomx_internal.h"
#include "common/cpu.h"
#include "common/log.h"

static void enable_huge_pages() {
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

typedef struct {
    double blake2_ms;
    double aes_fill_ms;
    double jit_gen_ms;
    double vm_run_ms;
    double final_hash_ms;
    double total_ms;
} profile_t;

static void profile_single_hash(rx_vm *vm, const uint8_t *seed, size_t seed_len, profile_t *p) {
    LARGE_INTEGER freq, t0, t1;
    QueryPerformanceFrequency(&freq);

    uint8_t tempHash[64];

    QueryPerformanceCounter(&t0);
    blake2b(vm->tempHash, sizeof(vm->tempHash), seed, seed_len, NULL, 0);
    QueryPerformanceCounter(&t1);
    p->blake2_ms = (double)(t1.QuadPart - t0.QuadPart) / freq.QuadPart * 1000.0;

    QueryPerformanceCounter(&t0);
    rx_vm_init_scratchpad(vm, vm->tempHash);
    QueryPerformanceCounter(&t1);
    p->aes_fill_ms = (double)(t1.QuadPart - t0.QuadPart) / freq.QuadPart * 1000.0;

    rx_reset_float_state();

    QueryPerformanceCounter(&t0);
    extern void rx_jit_generate_program(rx_jit*, rx_program*, rx_program_config*, rx_cache*);
    if (vm->useJit && vm->jit) {
        rx_jit_generate_program(vm->jit, &vm->program, &vm->config, vm->cachePtr);
    }
    QueryPerformanceCounter(&t1);
    p->jit_gen_ms = (double)(t1.QuadPart - t0.QuadPart) / freq.QuadPart * 1000.0;

    QueryPerformanceCounter(&t0);
    for (int chain = 0; chain < RX_PROGRAM_COUNT - 1; chain++) {
        rx_vm_run(vm, vm->tempHash);
        blake2b(vm->tempHash, sizeof(vm->tempHash), &vm->reg, sizeof(rx_register_file), NULL, 0);
    }
    rx_vm_run(vm, vm->tempHash);
    QueryPerformanceCounter(&t1);
    p->vm_run_ms = (double)(t1.QuadPart - t0.QuadPart) / freq.QuadPart * 1000.0;

    QueryPerformanceCounter(&t0);
    rx_vm_get_final_result(vm, tempHash);
    QueryPerformanceCounter(&t1);
    p->final_hash_ms = (double)(t1.QuadPart - t0.QuadPart) / freq.QuadPart * 1000.0;
}

int main() {
    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
    enable_huge_pages();

    printf("=== Single-thread JIT profile ===\n\n");

    rx_cache *cache = rx_alloc_cache(1);
    uint8_t key[] = "test_key_123456";
    rx_init_cache(cache, key, sizeof(key));

    rx_dataset *dataset = rx_alloc_dataset(1);
    rx_init_dataset_cached(dataset, cache, 0, RX_DATASET_ITEMS, 8, 8);

    rx_vm *vm = rx_create_vm(1, 1, 1, cache, dataset);
    printf("VM: large_pages=%d jit=%d dataset=%p\n\n", vm->large_pages, vm->useJit, (void*)vm->mem.memory);

    const int WARMUP = 5;
    const int ITERS = 50;
    uint8_t seed[32] = {0};

    printf("Warming up (%d hashes)...\n", WARMUP);
    for (int i = 0; i < WARMUP; i++) {
        rx_calculate_hash(vm, seed, sizeof(seed), seed);
    }

    profile_t totals = {0};
    profile_t *samples = (profile_t*)calloc(ITERS, sizeof(profile_t));

    LARGE_INTEGER freq, wall0, wall1;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&wall0);

    for (int i = 0; i < ITERS; i++) {
        profile_single_hash(vm, seed, sizeof(seed), &samples[i]);
        totals.blake2_ms += samples[i].blake2_ms;
        totals.aes_fill_ms += samples[i].aes_fill_ms;
        totals.jit_gen_ms += samples[i].jit_gen_ms;
        totals.vm_run_ms += samples[i].vm_run_ms;
        totals.final_hash_ms += samples[i].final_hash_ms;
    }

    QueryPerformanceCounter(&wall1);
    double wall_total = (double)(wall1.QuadPart - wall0.QuadPart) / freq.QuadPart;

    printf("\n=== PROFILE (%d hashes) ===\n", ITERS);
    printf("Component       Avg (ms)  Total (ms)  %% of hash\n");
    printf("blake2          %8.3f   %8.1f    %5.1f%%\n",
        totals.blake2_ms / ITERS, totals.blake2_ms,
        totals.blake2_ms / (wall_total * 1000.0) * 100.0);
    printf("aes_fill        %8.3f   %8.1f    %5.1f%%\n",
        totals.aes_fill_ms / ITERS, totals.aes_fill_ms,
        totals.aes_fill_ms / (wall_total * 1000.0) * 100.0);
    printf("jit_generate    %8.3f   %8.1f    %5.1f%%\n",
        totals.jit_gen_ms / ITERS, totals.jit_gen_ms,
        totals.jit_gen_ms / (wall_total * 1000.0) * 100.0);
    printf("vm_run (8x)     %8.3f   %8.1f    %5.1f%%\n",
        totals.vm_run_ms / ITERS, totals.vm_run_ms,
        totals.vm_run_ms / (wall_total * 1000.0) * 100.0);
    printf("final_hash      %8.3f   %8.1f    %5.1f%%\n",
        totals.final_hash_ms / ITERS, totals.final_hash_ms,
        totals.final_hash_ms / (wall_total * 1000.0) * 100.0);
    printf("------------------------------------------------\n");
    printf("Total           %8.3f   %8.1f\n",
        wall_total * 1000.0 / ITERS, wall_total * 1000.0);
    printf("\nSingle-thread hashrate: %.1f H/s\n", ITERS / wall_total);
    printf("Estimated 16-thread:   %.1f H/s\n", ITERS / wall_total * 16);

    rx_destroy_vm(vm);
    rx_free_dataset(dataset);
    rx_free_cache(cache);
    free(samples);
    return 0;
}
