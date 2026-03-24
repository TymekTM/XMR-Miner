#include "crypto/randomx/randomx.h"
#include <stdio.h>
#include <string.h>
#include <windows.h>

void dump_hex(const char *label, uint8_t *data, int len) {
    printf("%s:\n", label);
    for (int i = 0; i < len && i < 256; i++) {
        printf("%02x ", data[i]);
        if ((i+1) % 16 == 0) printf("\n");
    }
    printf("\n\n");
}

int main(void) {
    uint8_t key[32] = {0x01};
    uint8_t hash[32];
    const char *input = "test";

    printf("[1] Allocating cache...\n");
    rx_cache *cache = rx_alloc_cache(0);
    if (!cache) return 1;

    printf("[2] Initializing cache...\n");
    rx_init_cache(cache, key, 32);

    printf("[3] Creating JIT VM...\n");
    rx_vm *vm = rx_create_vm(1, 1, 0, cache, NULL);  // lightClient mode
    if (!vm) return 1;

    printf("[4] Generating first program...\n");
    rx_fill_aes4rx4(key, sizeof(vm->program), &vm->program);

    extern rx_jit *rx_jit_create(void);
    extern void rx_jit_generate_program_light(rx_jit*, rx_program*, rx_program_config*, rx_cache*, uint32_t);
    extern void* rx_jit_get_program_func(rx_jit*);

    if (vm->jit) {
        vm_initialize(vm);
        rx_jit_generate_program_light(vm->jit, &vm->program, &vm->config, vm->cachePtr, 0);

        extern rx_jit;
        uint8_t *code = ((struct JitCompiler_dummy {uint8_t *code;} *)vm->jit)->code;

        dump_hex("Prologue (first 64 bytes)", code, 64);
        dump_hex("After prologue (449-513)", code + 449, 64);
    }

    rx_destroy_vm(vm);
    rx_free_cache(cache);
    printf("[Done]\n");
    return 0;
}
