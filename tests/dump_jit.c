#include "crypto/randomx/randomx.h"
#include "crypto/randomx/randomx_internal.h"
#include "common/log.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>

extern void rx_vm_run(rx_vm *vm, void *seed);

int main(void) {
    uint8_t key[32] = {0x01};
    printf("[1] start\n"); fflush(stdout);

    rx_cache *cache = rx_alloc_cache(0);
    printf("[2] cache alloc\n"); fflush(stdout);
    rx_init_cache(cache, key, 32);
    printf("[3] cache init\n"); fflush(stdout);

    rx_vm *vm = rx_create_vm(0, 0, 0, cache, NULL);
    printf("[4] vm created useJit=%d lightClient=%d\n", vm->useJit, vm->lightClient); fflush(stdout);

    printf("[4a] fill\n"); fflush(stdout);
    rx_fill_aes4rx4(key, sizeof(rx_program), &vm->program);
    printf("[4b] fill done\n"); fflush(stdout);
    printf("[4c] interpreter\n"); fflush(stdout);
    rx_vm_run(vm, key);
    printf("[4d] interpreter ok\n"); fflush(stdout);

    printf("[5] JIT gen\n"); fflush(stdout);
    rx_jit_generate_program_light(vm->jit, &vm->program, &vm->config, vm->cachePtr, vm->datasetOffset);
    
    typedef void (*ProgramFunc)(rx_register_file*, rx_memory_regs*, uint8_t*, uint32_t);
    ProgramFunc func = (ProgramFunc)rx_jit_get_program_func(vm->jit);
    
    rx_memory_regs memRegs;
    memRegs.mx = vm->mem.mx;
    memRegs.ma = vm->mem.ma;
    memRegs.memory = vm->mem.memory;
    printf("[6] func=%p mem=%p\n", (void*)func, (void*)memRegs.memory); fflush(stdout);
    
    __try {
        func(&vm->reg, &memRegs, vm->scratchpad, 1);
        printf("[7] func returned\n"); fflush(stdout);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        printf("[7] SEH 0x%08lx\n", GetExceptionCode()); fflush(stdout);
    }

    rx_destroy_vm(vm);
    rx_free_cache(cache);
    printf("[8] done\n"); fflush(stdout);
    return 0;
}
