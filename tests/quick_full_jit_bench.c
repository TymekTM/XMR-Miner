#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <time.h>
#include "crypto/randomx/randomx.h"
#include "crypto/randomx/randomx_internal.h"

typedef struct {
    void (*func)(rx_register_file*, rx_memory_regs*, uint8_t*, uint32_t);
    rx_vm *vm;
    int done;
    int crashed;
} jit_test_t;

DWORD WINAPI test_thread(LPVOID arg) {
    jit_test_t *ctx = (jit_test_t *)arg;
    __try {
        ctx->func(&ctx->vm->reg, NULL, ctx->vm->scratchpad, 1);
        ctx->done = 1;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ctx->crashed = 1;
    }
    return 0;
}

int main(void) {
    uint8_t key[32] = {0x01};

    printf("[QUICK] Allocating cache\n"); fflush(stdout);
    rx_cache *cache = rx_alloc_cache(0);
    if (!cache) {
        printf("[FAIL] cache alloc\n");
        return 1;
    }

    printf("[QUICK] Initializing cache\n"); fflush(stdout);
    rx_init_cache(cache, key, 32);
    printf("[QUICK] Cache ready\n"); fflush(stdout);

    // Create VM with JIT but WITHOUT dataset (light/cache mode)
    printf("[QUICK] Creating VM with JIT (cache only, full config)\n"); fflush(stdout);
    rx_vm *vm = rx_create_vm(1, 1, 0, cache, NULL);
    if (!vm) {
        printf("[FAIL] VM alloc\n");
        rx_free_cache(cache);
        return 1;
    }

    // Check if JIT is actually enabled
    printf("[QUICK] VM useJit field offset check\n");
    int *vm_ptr = (int *)vm;
    printf("[QUICK] First int in VM: %d\n", vm_ptr[0]);
    printf("[QUICK] Second int in VM: %d\n", vm_ptr[1]);

    printf("[QUICK] Testing hash computation\n"); fflush(stdout);
    const char *input = "test";
    uint8_t hash[32];

    clock_t start = clock();
    rx_calculate_hash(vm, input, strlen(input), hash);
    clock_t end = clock();

    double ms = 1000.0 * (end - start) / CLOCKS_PER_SEC;
    printf("[QUICK] Hash computed in %.2f ms\n", ms);
    printf("[QUICK] Hash: ");
    for (int i = 0; i < 8; i++) printf("%02x", hash[i]);
    printf("...\n");

    rx_destroy_vm(vm);
    rx_free_cache(cache);

    printf("[QUICK] Done\n");
    return 0;
}
