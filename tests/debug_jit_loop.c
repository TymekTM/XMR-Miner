#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include "crypto/randomx/randomx.h"
#include "crypto/randomx/randomx_internal.h"

int main(void) {
    uint8_t key[32] = {0x01};

    printf("[DEBUG] Allocating cache\n"); fflush(stdout);
    rx_cache *cache = rx_alloc_cache(0);
    if (!cache) {
        printf("[FAIL] cache alloc\n");
        return 1;
    }

    printf("[DEBUG] Initializing cache\n"); fflush(stdout);
    rx_init_cache(cache, key, 32);

    printf("[DEBUG] Allocating dataset (small)\n"); fflush(stdout);
    rx_dataset *dataset = rx_alloc_dataset(0);
    if (!dataset) {
        printf("[FAIL] dataset alloc\n");
        return 1;
    }

    printf("[DEBUG] Initializing dataset (1 thread, small)\n"); fflush(stdout);
    rx_init_dataset(dataset, cache, 0, 1024, 1, 1);  // Init only 1024 items for speed

    printf("[DEBUG] Creating JIT VM with full dataset\n"); fflush(stdout);
    rx_vm *vm = rx_create_vm(1, 1, 0, cache, dataset);
    if (!vm) {
        printf("[FAIL] VM alloc\n");
        return 1;
    }

    printf("[DEBUG] Testing single hash iteration\n"); fflush(stdout);
    const char *input = "test";
    uint8_t hash[32];

    // Try to hash - but with a timeout thread
    typedef struct {
        rx_vm *vm;
        const char *input;
        int input_len;
        uint8_t *output;
        int done;
        int crashed;
    } hash_ctx_t;

    hash_ctx_t ctx = {vm, input, strlen(input), hash, 0, 0};

    printf("[DEBUG] Creating timeout thread\n"); fflush(stdout);
    HANDLE thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)(void*)&rx_calculate_hash,
                                  &ctx, 0, NULL);
    if (!thread) {
        printf("[FAIL] CreateThread\n");
        return 1;
    }

    printf("[DEBUG] Waiting for hash with 5s timeout\n"); fflush(stdout);
    DWORD status = WaitForSingleObject(thread, 5000);  // 5 second timeout

    if (status == WAIT_TIMEOUT) {
        printf("[ERROR] Hash computation timed out (probable infinite loop)!\n");
        TerminateThread(thread, 1);
        CloseHandle(thread);
    } else if (status == WAIT_OBJECT_0) {
        printf("[DEBUG] Hash completed successfully\n");
        printf("[DEBUG] Hash: ");
        for (int i = 0; i < 8; i++) printf("%02x", hash[i]);
        printf("...\n");
    } else {
        printf("[ERROR] WaitForSingleObject failed: %lu\n", status);
    }

    CloseHandle(thread);
    rx_destroy_vm(vm);
    rx_free_dataset(dataset);
    rx_free_cache(cache);

    printf("[DEBUG] Done\n");
    return 0;
}
