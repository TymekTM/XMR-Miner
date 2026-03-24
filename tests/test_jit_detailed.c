#include "crypto/randomx/randomx.h"
#include <stdio.h>
#include <string.h>
#include <windows.h>

int main(void) {
    uint8_t key[32] = {0x01};
    uint8_t hash[32];
    const char *input = "test input";

    printf("[1] Allocating cache...\n");
    rx_cache *cache = rx_alloc_cache(0);
    if (!cache) return 1;

    printf("[2] Initializing cache...\n");
    rx_init_cache(cache, key, 32);

    printf("[3] Creating INTERPRETER VM (use_jit=0)...\n");
    rx_vm *vm_interp = rx_create_vm(1, 0, 0, cache, NULL);
    if (!vm_interp) return 1;

    printf("[4] Creating JIT VM (use_jit=1)...\n");
    rx_vm *vm_jit = rx_create_vm(1, 1, 0, cache, NULL);
    if (!vm_jit) return 1;

    printf("\n[5] Testing INTERPRETER...\n");
    {
        __try {
            printf("  Hash 1: computing...\n"); fflush(stdout);
            rx_calculate_hash(vm_interp, (const uint8_t*)input, strlen(input), hash);
            printf("  Hash 1: "); for (int i = 0; i < 8; i++) printf("%02x", hash[i]); printf("\n");

            printf("  Hash 2: computing...\n"); fflush(stdout);
            rx_calculate_hash(vm_interp, (const uint8_t*)input, strlen(input), hash);
            printf("  Hash 2: "); for (int i = 0; i < 8; i++) printf("%02x", hash[i]); printf("\n");
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            printf("  INTERPRETER CRASHED\n");
        }
    }

    printf("\n[6] Testing JIT...\n");
    {
        __try {
            printf("  Hash 1: computing...\n"); fflush(stdout);
            rx_calculate_hash(vm_jit, (const uint8_t*)input, strlen(input), hash);
            printf("  Hash 1: "); for (int i = 0; i < 8; i++) printf("%02x", hash[i]); printf("\n");

            printf("  Hash 2: computing...\n"); fflush(stdout);
            rx_calculate_hash(vm_jit, (const uint8_t*)input, strlen(input), hash);
            printf("  Hash 2: "); for (int i = 0; i < 8; i++) printf("%02x", hash[i]); printf("\n");
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            printf("  JIT CRASHED at hash\n");
        }
    }

    rx_destroy_vm(vm_interp);
    rx_destroy_vm(vm_jit);
    rx_free_cache(cache);
    printf("\n[Done]\n");
    return 0;
}
