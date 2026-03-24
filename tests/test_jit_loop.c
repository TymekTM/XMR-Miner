#include "crypto/randomx/randomx.h"
#include <stdio.h>
#include <string.h>
#include <windows.h>

int main(void) {
    uint8_t key[32] = {0x01};
    uint8_t hash[32];
    const char *input = "test input for jit debug";

    printf("[1] Allocating cache...\n"); fflush(stdout);
    rx_cache *cache = rx_alloc_cache(0);
    if (!cache) { printf("[FAIL]\n"); return 1; }

    printf("[2] Initializing cache...\n"); fflush(stdout);
    rx_init_cache(cache, key, 32);

    printf("[3] Creating JIT VM...\n"); fflush(stdout);
    rx_vm *vm = rx_create_vm(1, 1, 0, cache, NULL);
    if (!vm) { printf("[FAIL]\n"); return 1; }

    printf("[4] Computing hashes (5x) with JIT...\n"); fflush(stdout);

    for (int h = 0; h < 5; h++) {
        printf("  Hash %d: ", h+1);
        fflush(stdout);

        __try {
            rx_calculate_hash(vm, (const uint8_t*)input, strlen(input), hash);
            printf("OK - ");
            for (int i = 0; i < 8; i++) printf("%02x", hash[i]);
            printf("\n");
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            printf("SEH 0x%08lx\n", GetExceptionCode());
            break;
        }
    }

    rx_destroy_vm(vm);
    rx_free_cache(cache);
    printf("[Done]\n");
    return 0;
}
