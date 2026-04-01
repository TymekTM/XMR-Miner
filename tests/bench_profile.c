#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <windows.h>
#include "crypto/randomx/randomx_internal.h"
#include "common/cpu.h"
#include "common/log.h"

#define ITERATIONS 2000

double get_time() {
    LARGE_INTEGER freq, counter;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&counter);
    return (double)counter.QuadPart / freq.QuadPart;
}

int main() {
    rx_cache *cache = rx_alloc_cache(1);
    uint8_t key[] = "test_key_123456";
    rx_init_cache(cache, key, sizeof(key));
    
    rx_dataset *dataset = rx_alloc_dataset(1);
    rx_init_dataset_cached(dataset, cache, 0, RX_DATASET_ITEMS, 8, 8);
    
    rx_vm *vm = rx_create_vm(1, 1, 1, cache, dataset);
    
    uint8_t seed[32] = {0};
    
    double t_blake2 = 0;
    double t_init = 0;
    double t_run = 0;
    double t_result = 0;
    double t_other = 0;
    
    for (int i = 0; i < ITERATIONS; i++) {
        double t0 = get_time();
        
        uint32_t saved_mxcsr = _mm_getcsr();
        blake2b(vm->tempHash, sizeof(vm->tempHash), seed, sizeof(seed), NULL, 0);
        
        double t1 = get_time();
        rx_vm_init_scratchpad(vm, vm->tempHash);
        
        double t2 = get_time();
        rx_reset_float_state();
        for (int chain = 0; chain < RX_PROGRAM_COUNT - 1; chain++) {
            rx_vm_run(vm, vm->tempHash);
            blake2b(vm->tempHash, sizeof(vm->tempHash), &vm->reg, sizeof(rx_register_file), NULL, 0);
        }
        rx_vm_run(vm, vm->tempHash);
        
        double t3 = get_time();
        rx_vm_get_final_result(vm, seed);
        _mm_setcsr(saved_mxcsr);
        
        double t4 = get_time();
        
        t_blake2 += (t1 - t0);
        t_init += (t2 - t1);
        t_run += (t3 - t2);
        t_result += (t4 - t3);
    }
    
    printf("Blake2b: %.4f s\n", t_blake2);
    printf("Init Scratchpad: %.4f s\n", t_init);
    printf("VM Run: %.4f s\n", t_run);
    printf("Get Final Result: %.4f s\n", t_result);
    
    rx_destroy_vm(vm);
    rx_free_dataset(dataset);
    rx_free_cache(cache);
    return 0;
}
