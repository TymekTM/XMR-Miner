#include "crypto/randomx/randomx.h"
#include "crypto/randomx/randomx_internal.h"
#include <stdio.h>
#include <windows.h>
#include <string.h>

int main() {
    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);

    printf("Allocating cache...\n"); fflush(stdout);
    rx_cache* cache = rx_alloc_cache(1);
    rx_init_cache(cache, (const uint8_t*)"test key 000", 12);

    printf("Allocating dataset...\n"); fflush(stdout);
    rx_dataset* dataset = rx_alloc_dataset(1);
    rx_init_dataset_cached(dataset, cache, 0, RX_DATASET_ITEMS, 8, 8);

    printf("Creating VM...\n"); fflush(stdout);
    rx_vm* vm = rx_create_vm(RX_FLAG_JIT | RX_FLAG_DEFAULT, cache, dataset);

    uint8_t input[76];
    memset(input, 0x42, sizeof(input));

    LARGE_INTEGER freq, t0, t1;
    QueryPerformanceFrequency(&freq);

    double t_fill_init = 0, t_jit_gen = 0, t_blake2b_reg = 0, t_blake2b_blob = 0;
    double t_hash_and_fill = 0, t_full_hash = 0, t_hash_next = 0;

    printf("\n--- 1. fill_aes4rx4 + vm_initialize (no JIT) ---\n"); fflush(stdout);
    {
        int N = 100000;
        uint8_t seed[32] = {0};
        QueryPerformanceCounter(&t0);
        for (int i = 0; i < N; i++) {
            memcpy(seed, &i, 4);
            rx_fill_aes4rx4(seed, sizeof(rx_program), &vm->program);
            vm_initialize(vm);
        }
        QueryPerformanceCounter(&t1);
        double total_us = (double)(t1.QuadPart - t0.QuadPart) / freq.QuadPart * 1e6;
        t_fill_init = total_us / N;
        printf("  %d calls: %.1f us total, %.3f us/call\n", N, total_us, t_fill_init);
    }

    printf("\n--- 2. JIT generate only (same program, cached) ---\n"); fflush(stdout);
    {
        uint8_t seed[32] = {0};
        rx_fill_aes4rx4(seed, sizeof(rx_program), &vm->program);
        vm_initialize(vm);
        rx_jit_generate_program(vm->jit, &vm->program, &vm->config, vm->cachePtr);
        int N = 1000;
        QueryPerformanceCounter(&t0);
        for (int i = 0; i < N; i++) {
            rx_jit_generate_program(vm->jit, &vm->program, &vm->config, vm->cachePtr);
        }
        QueryPerformanceCounter(&t1);
        double total_us = (double)(t1.QuadPart - t0.QuadPart) / freq.QuadPart * 1e6;
        t_jit_gen = total_us / N;
        printf("  %d calls: %.1f us total, %.3f us/call\n", N, total_us, t_jit_gen);
    }

    printf("\n--- 3. JIT compile full (fresh program each time) ---\n"); fflush(stdout);
    {
        uint8_t seed[32] = {0};
        int N = 1000;
        QueryPerformanceCounter(&t0);
        for (int i = 0; i < N; i++) {
            memcpy(seed, &i, 4);
            rx_fill_aes4rx4(seed, sizeof(rx_program), &vm->program);
            vm_initialize(vm);
            rx_jit_generate_program(vm->jit, &vm->program, &vm->config, vm->cachePtr);
        }
        QueryPerformanceCounter(&t1);
        double total_us = (double)(t1.QuadPart - t0.QuadPart) / freq.QuadPart * 1e6;
        printf("  %d calls: %.1f us total, %.3f us/call\n", N, total_us, total_us / N);
        printf("  (fill+init=%.3f, jit_gen=%.3f, difference=%.3f = loop+superscalar overhead)\n",
            t_fill_init, t_jit_gen, total_us/N - t_fill_init - t_jit_gen);
    }

    printf("\n--- 4. blake2b(64B regfile) ---\n"); fflush(stdout);
    {
        uint8_t hash[64];
        int N = 100000;
        QueryPerformanceCounter(&t0);
        for (int i = 0; i < N; i++) {
            blake2b(hash, 32, &vm->reg, sizeof(rx_register_file), NULL, 0);
        }
        QueryPerformanceCounter(&t1);
        double total_us = (double)(t1.QuadPart - t0.QuadPart) / freq.QuadPart * 1e6;
        t_blake2b_reg = total_us / N;
        printf("  %d calls: %.1f us total, %.3f us/call\n", N, total_us, t_blake2b_reg);
    }

    printf("\n--- 5. blake2b(76B blob) ---\n"); fflush(stdout);
    {
        uint8_t hash[32];
        int N = 100000;
        QueryPerformanceCounter(&t0);
        for (int i = 0; i < N; i++) {
            blake2b(hash, 32, input, sizeof(input), NULL, 0);
        }
        QueryPerformanceCounter(&t1);
        double total_us = (double)(t1.QuadPart - t0.QuadPart) / freq.QuadPart * 1e6;
        t_blake2b_blob = total_us / N;
        printf("  %d calls: %.1f us total, %.3f us/call\n", N, total_us, t_blake2b_blob);
    }

    printf("\n--- 6. hash_and_fill_aes1rx4 (2MB scratchpad) ---\n"); fflush(stdout);
    {
        uint8_t hash[64];
        uint8_t fill_seed[64] = {0};
        int N = 200;
        QueryPerformanceCounter(&t0);
        for (int i = 0; i < N; i++) {
            rx_hash_and_fill_aes1rx4(vm->scratchpad, RX_SCRATCHPAD_L3, hash, fill_seed);
        }
        QueryPerformanceCounter(&t1);
        double total_us = (double)(t1.QuadPart - t0.QuadPart) / freq.QuadPart * 1e6;
        t_hash_and_fill = total_us / N;
        printf("  %d calls: %.1f ms total, %.1f us/call\n", N, total_us/1000, t_hash_and_fill);
    }

    printf("\n--- 7. rx_vm_init_scratchpad (fill_aes1rx4, 2MB) ---\n"); fflush(stdout);
    {
        int N = 1000;
        uint8_t key[64] = {0};
        QueryPerformanceCounter(&t0);
        for (int i = 0; i < N; i++) {
            rx_vm_init_scratchpad(vm, key);
        }
        QueryPerformanceCounter(&t1);
        double total_us = (double)(t1.QuadPart - t0.QuadPart) / freq.QuadPart * 1e6;
        printf("  %d calls: %.1f ms total, %.1f us/call\n", N, total_us/1000, total_us/N);
    }

    printf("\n--- 8. Full hash (rx_calculate_hash, 76B input) ---\n"); fflush(stdout);
    {
        uint8_t hash[64];
        int N = 100;
        QueryPerformanceCounter(&t0);
        for (int i = 0; i < N; i++) {
            rx_calculate_hash(vm, input, sizeof(input), hash);
        }
        QueryPerformanceCounter(&t1);
        double total_us = (double)(t1.QuadPart - t0.QuadPart) / freq.QuadPart * 1e6;
        t_full_hash = total_us / N;
        printf("  %d hashes: %.1f ms total, %.1f us/hash, %.0f H/s\n", N, total_us/1000, t_full_hash, N / (total_us / 1e6));
    }

    printf("\n--- 9. hash_first + 100x hash_next (batch) ---\n"); fflush(stdout);
    {
        uint8_t hash[64];
        int N = 100;
        rx_calculate_hash_first(vm, input, sizeof(input));
        QueryPerformanceCounter(&t0);
        for (int i = 0; i < N; i++) {
            rx_calculate_hash_next(vm, input, sizeof(input), hash);
        }
        QueryPerformanceCounter(&t1);
        double total_us = (double)(t1.QuadPart - t0.QuadPart) / freq.QuadPart * 1e6;
        t_hash_next = total_us / N;
        printf("  %d hash_next: %.1f ms total, %.1f us/call, %.0f H/s\n", N, total_us/1000, t_hash_next, N / (total_us / 1e6));
    }

    printf("\n========================================\n");
    printf("TIMING BREAKDOWN (per hash_next call):\n");
    printf("  blake2b(blob, 76B):     %8.2f us  (%4.1f%%)\n", t_blake2b_blob, t_blake2b_blob/t_hash_next*100);
    printf("  fill+init:              %8.2f us  (%4.1f%%)\n", t_fill_init, t_fill_init/t_hash_next*100);
    printf("  JIT generate:           %8.2f us  (%4.1f%%)\n", t_jit_gen, t_jit_gen/t_hash_next*100);
    printf("  blake2b(reg, 64B) x9:   %8.2f us  (%4.1f%%)\n", t_blake2b_reg*9, t_blake2b_reg*9/t_hash_next*100);
    printf("  hash_and_fill x8:       %8.2f us  (%4.1f%%)\n", t_hash_and_fill*8, t_hash_and_fill*8/t_hash_next*100);
    printf("  MEASURED hash_next:     %8.2f us\n", t_hash_next);
    printf("  DERIVED VM exec (8ch):  %8.2f us  (%4.1f%%)\n",
        t_hash_next - t_blake2b_blob - t_fill_init - t_jit_gen - t_blake2b_reg*9 - t_hash_and_fill*8,
        (t_hash_next - t_blake2b_blob - t_fill_init - t_jit_gen - t_blake2b_reg*9 - t_hash_and_fill*8)/t_hash_next*100);
    printf("  VM exec per chain:      %8.2f us\n",
        (t_hash_next - t_blake2b_blob - t_fill_init - t_jit_gen - t_blake2b_reg*9 - t_hash_and_fill*8)/8);
    printf("========================================\n");

    rx_destroy_vm(vm);
    rx_free_dataset(dataset);
    rx_free_cache(cache);
    return 0;
}
