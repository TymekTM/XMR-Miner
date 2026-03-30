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
    rx_cache *cache = rx_alloc_cache(0);
    rx_init_cache(cache, key, 32);
    rx_dataset *dataset = rx_alloc_dataset(0);
    rx_init_dataset_cached(dataset, cache, 0, RX_DATASET_ITEMS, 8, 8);

    uint8_t blob[76];
    memset(blob, 0x41, 76);

    rx_vm *vm_jit = rx_create_vm(1, 1, 0, cache, dataset);
    rx_vm *vm_interp = rx_create_vm(1, 0, 0, cache, dataset);

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
