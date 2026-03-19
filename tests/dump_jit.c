#include "crypto/randomx/randomx.h"
#include "crypto/randomx/randomx_internal.h"
#include "common/log.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <excpt.h>
#include <windows.h>

int main(void) {
    uint8_t key[32] = {0x01};

    rx_cache *cache = rx_alloc_cache(0);
    rx_init_cache(cache, key, 32);
    printf("[DUMP] Cache ready\n"); fflush(stdout);

    rx_vm *vm = rx_create_vm(0, 1, 0, cache, NULL);
    if (!vm) { printf("FAIL: vm\n"); return 1; }
    printf("[DUMP] VM created, useJit=%d\n", vm->useJit); fflush(stdout);

    uint8_t hash[32];
    const char *input = "test";

    printf("[DUMP] About to call rx_calculate_hash...\n"); fflush(stdout);
    __try {
        rx_calculate_hash(vm, (const uint8_t*)input, strlen(input), hash);
        printf("[DUMP] OK hash: ");
        for (int i = 0; i < 8; i++) printf("%02x", hash[i]);
        printf("\n");
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        printf("[DUMP] CRASHED: 0x%08lx at PC\n", GetExceptionCode());
        printf("[DUMP] useJit=%d\n", vm->useJit);
    }

    rx_destroy_vm(vm);
    rx_free_cache(cache);
    return 0;
}
