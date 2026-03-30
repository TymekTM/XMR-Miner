#include "crypto/randomx/randomx.h"
#include "crypto/randomx/randomx_internal.h"
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <time.h>

extern void vm_initialize(rx_vm *vm);
extern void rx_vm_init_scratchpad(rx_vm *vm, void *seed);

int main(void) {
    uint8_t key[32] = {0x01};
    rx_cache *cache = rx_alloc_cache(1);
    rx_init_cache(cache, key, 32);
    rx_dataset *dataset = rx_alloc_dataset(1);
    rx_init_dataset_cached(dataset, cache, 0, RX_DATASET_ITEMS, 8, 8);

    uint8_t blob[76];
    memset(blob, 0x41, 76);

    rx_vm *vm_jit = rx_create_vm(1, 1, 1, cache, dataset);
    rx_vm *vm_interp = rx_create_vm(1, 0, 1, cache, dataset);

    const int iterations = 1000;
    
    printf("Warming up...\n");
    uint8_t hashInterp[32];
    uint8_t hashJit[32];
    extern void rx_calculate_hash(rx_vm* vm, const void* input, size_t input_size, void* output);

    // Interpreter run
    printf("Running Interpreter benchmark (%d iterations)...\n", iterations);
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    
    QueryPerformanceCounter(&start);
    for(int i=0; i<iterations; i++) {
        // slightly mutate the blob to get a new hash
        blob[0] = (uint8_t)i;
        blob[1] = (uint8_t)(i >> 8);
        rx_calculate_hash(vm_interp, blob, 76, hashInterp);
    }
    QueryPerformanceCounter(&end);
    double timeInterp = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;
    double hrInterp = iterations / timeInterp;
    
    // Reset blob
    memset(blob, 0x41, 76);

    // JIT run
    printf("Running JIT benchmark (%d iterations)...\n", iterations);
    
    QueryPerformanceCounter(&start);
    for(int i=0; i<iterations; i++) {
        blob[0] = (uint8_t)i;
        blob[1] = (uint8_t)(i >> 8);
        rx_calculate_hash(vm_jit, blob, 76, hashJit);
    }
    QueryPerformanceCounter(&end);
    double timeJit = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;
    double hrJit = iterations / timeJit;

    // TIME JIT COMPILATION ALONE (after benchmark to not pollute cache)
    LARGE_INTEGER j_start, j_end;
    QueryPerformanceCounter(&j_start);
    for(int i=0; i<100; i++) {
        rx_fill_aes4rx4(vm_jit->tempHash, sizeof(rx_program), &vm_jit->program);
        vm_initialize(vm_jit);
        extern void rx_jit_generate_program(rx_jit*, rx_program*, rx_program_config*, rx_cache*);
        rx_jit_generate_program(vm_jit->jit, &vm_jit->program, &vm_jit->config, vm_jit->cachePtr);
    }
    QueryPerformanceCounter(&j_end);
    double jit_compile_time = (double)(j_end.QuadPart - j_start.QuadPart) / freq.QuadPart / 100.0;
    printf("Average JIT compilation time per program: %.6f ms\n", jit_compile_time * 1000.0);

    printf("\n==== FINAL HASH (Iter %d) ====\n", iterations - 1);
    printf("INTERP: ");
    for(int i=0; i<32; i++) printf("%02x", hashInterp[i]);
    printf("\nJIT   : ");
    for(int i=0; i<32; i++) printf("%02x", hashJit[i]);
    printf("\n");

    if (memcmp(hashInterp, hashJit, 32) == 0) {
        printf("\nSUCCESS: Hashes match perfectly!\n");
    } else {
        printf("\nERROR: Hashes diverge!\n");
        return 1;
    }

    printf("\n==== PERFORMANCE ====\n");
    printf("Interpreter: %.2f H/s (Time: %.3f s)\n", hrInterp, timeInterp);
    printf("JIT        : %.2f H/s (Time: %.3f s)\n", hrJit, timeJit);
    printf("Speedup    : %.2fx\n", hrJit / hrInterp);

    rx_destroy_vm(vm_jit);
    rx_destroy_vm(vm_interp);
    rx_free_dataset(dataset);
    rx_free_cache(cache);

    return 0;
}
