#include "crypto/randomx/randomx.h"
#include "crypto/randomx/randomx_internal.h"
#include <stdio.h>
#include <string.h>

extern void vm_initialize(rx_vm *vm);
extern void rx_jit_generate_program(rx_jit*, rx_program*, rx_program_config*, rx_cache*);
extern uint8_t* rx_jit_get_code_ptr(rx_jit* jit);

int main(void) {
    rx_cache *cache = rx_alloc_cache(1);
    rx_init_cache(cache, "test", 4);
    rx_dataset *dataset = rx_alloc_dataset(1);
    rx_init_dataset_cached(dataset, cache, 0, RX_DATASET_ITEMS, 8, 8);
    rx_vm *vm = rx_create_vm(1, 1, 1, cache, dataset);

    rx_fill_aes4rx4(vm->tempHash, sizeof(rx_program), &vm->program);
    vm_initialize(vm);
    rx_jit_generate_program(vm->jit, &vm->program, &vm->config, vm->cachePtr);

    uint8_t* code = rx_jit_get_code_ptr(vm->jit);
    
    // Dump to file
    FILE* f = fopen("jit_dump.bin", "wb");
    fwrite(code, 1, 16384, f); // dump first 16KB
    fclose(f);
    
    printf("JIT code dumped to jit_dump.bin\n");
    return 0;
}
