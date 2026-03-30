#include "crypto/randomx/randomx.h"
#include "crypto/randomx/randomx_internal.h"
#include <stdio.h>
#include <string.h>
#include <windows.h>

extern void vm_initialize(rx_vm *vm);
extern void rx_vm_init_scratchpad(rx_vm *vm, void *seed);
extern void compile_program(rx_program *prog, rx_bytecode bc[RX_PROGRAM_SIZE],
                            uint64_t *r, rx_vec_f128 *f, rx_vec_f128 *e, rx_vec_f128 *a);
extern uint8_t* rx_jit_get_code_ptr(rx_jit *jit);
extern int rx_jit_get_instruction_offset(rx_jit *jit, int index);
extern int rx_jit_get_num_instructions(rx_jit *jit);

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

    uint8_t tempHash[64];
    blake2b(tempHash, sizeof(tempHash), blob, 76, NULL, 0);

    uint8_t tempHashJitSeed[64];
    memcpy(tempHashJitSeed, tempHash, 64);

    rx_vm_init_scratchpad(vm_jit, tempHashJitSeed);
    rx_vm_init_scratchpad(vm_interp, tempHash);
    
    // Ensure both have identical scratchpad
    memcpy(vm_jit->scratchpad, vm_interp->scratchpad, RX_SCRATCHPAD_L3);
    rx_reset_float_state();

    // Do NOT generate program manually. Just let rx_vm_run_n do it for BOTH.

    printf("Before Interpreter...\n"); fflush(stdout);
    extern void rx_calculate_hash(rx_vm* vm, const void* input, size_t input_size, void* output);

    uint8_t hashInterp[32];
    rx_calculate_hash(vm_interp, blob, 76, hashInterp);
    printf("After Interpreter...\n"); fflush(stdout);

    printf("Before JIT...\n"); fflush(stdout);
    vm_jit->useJit = 1;
    uint8_t hashJit[32];
    rx_calculate_hash(vm_jit, blob, 76, hashJit);
    printf("After JIT...\n"); fflush(stdout);

    printf("\n==== FINAL HASH ====\n");
    printf("INTERP: ");
    for(int i=0; i<32; i++) printf("%02x", hashInterp[i]);
    printf("\nJIT   : ");
    for(int i=0; i<32; i++) printf("%02x", hashJit[i]);
    printf("\n");

    if (memcmp(hashInterp, hashJit, 32) == 0) {
        printf("\nSUCCESS: Hashes match perfectly!\n");
    } else {
        printf("\nERROR: Hashes diverge!\n");
    }
    
    // Also dump E registers loaded from A?
    
    rx_destroy_vm(vm_jit);
    rx_destroy_vm(vm_interp);
    rx_free_dataset(dataset);
    rx_free_cache(cache);
    return 0;
}
