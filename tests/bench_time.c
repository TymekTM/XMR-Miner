#include "crypto/randomx/randomx.h"
#include "crypto/randomx/randomx_internal.h"
#include <stdio.h>
#include <string.h>
#include <windows.h>

extern void vm_initialize(rx_vm *vm);
extern void rx_vm_init_scratchpad(rx_vm *vm, void *seed);
extern void rx_jit_generate_program(rx_jit*, rx_program*, rx_program_config*, rx_cache*);

int main(void) {
    rx_cache *cache = rx_alloc_cache(1);
    rx_init_cache(cache, "test", 4);
    rx_dataset *dataset = rx_alloc_dataset(1);
    rx_init_dataset_cached(dataset, cache, 0, RX_DATASET_ITEMS, 8, 8);
    rx_vm *vm = rx_create_vm(1, 1, 1, cache, dataset);

    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    
    // Time JIT compilation alone
    QueryPerformanceCounter(&start);
    for (int i = 0; i < 1000; i++) {
        rx_fill_aes4rx4(vm->tempHash, sizeof(rx_program), &vm->program);
        vm_initialize(vm);
        rx_jit_generate_program(vm->jit, &vm->program, &vm->config, vm->cachePtr);
    }
    QueryPerformanceCounter(&end);
    double compile_time = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;
    printf("1000 JIT compilations took %.5f s\n", compile_time);

    // Time execution alone
    typedef void (*ProgramFunc)(rx_register_file*, rx_memory_regs*, uint8_t*, uint32_t);
    ProgramFunc func = (ProgramFunc)vm->jit->compiler->code;
    
    QueryPerformanceCounter(&start);
    for (int i = 0; i < 1000; i++) {
        func(&vm->reg, &vm->mem, vm->scratchpad, RX_PROGRAM_ITERATIONS);
    }
    QueryPerformanceCounter(&end);
    double exec_time = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;
    printf("1000 executions took %.5f s\n", exec_time);
    
    return 0;
}
