#include "crypto/randomx/randomx.h"
#include "crypto/randomx/randomx_internal.h"
#include <stdio.h>
#include <string.h>
#include <windows.h>

static LONG CALLBACK veh_handler(PEXCEPTION_POINTERS info) {
    printf("ACCESS_VIOLATION!\n");
    printf("  Fault address: 0x%016I64X\n", (uint64_t)info->ExceptionRecord->ExceptionInformation[1]);
    printf("  RIP: 0x%016I64X\n", (uint64_t)info->ContextRecord->Rip);
    printf("  RAX: 0x%016I64X  RBX: 0x%016I64X  RCX: 0x016I64X\n",
        info->ContextRecord->Rax, info->ContextRecord->Rbx, info->ContextRecord->Rcx);
    printf("  RDX: 0x%016I64X  RBP: 0x%016I64X  RSI: 0x016I64X\n",
        info->ContextRecord->Rdx, info->ContextRecord->Rbp, info->ContextRecord->Rsi);
    printf("  RDI: 0x%016I64X  R8:  0x%016I64X  R9:  0x016I64X\n",
        info->ContextRecord->Rdi, info->ContextRecord->R8, info->ContextRecord->R9);
    printf("  R10: 0x016I64X  R11: 0x016I64X  R12: 0x016I64X\n",
        info->ContextRecord->R10, info->ContextRecord->R11, info->ContextRecord->R12);
    printf("  R13: 0x016I64X  R14: 0x016I64X  R15: 0x016I64X\n",
        info->ContextRecord->R13, info->ContextRecord->R14, info->ContextRecord->R15);
    printf("  RSP: 0x016I64X\n", info->ContextRecord->Rsp);
    return EXCEPTION_CONTINUE_SEARCH;
}

int main(void) {
    const char *key = "test key 000";
    rx_cache *cache = rx_alloc_cache(0);
    rx_init_cache(cache, key, strlen(key));

    rx_dataset *dataset = rx_alloc_dataset(0);
    rx_init_dataset(dataset, cache, 0, RX_DATASET_ITEMS + RX_DATASET_EXTRA_ITEMS, 8, 8);

    rx_vm *vm_j = rx_create_vm(RX_FLAG_JIT, cache, dataset);
    rx_vm *vm_i = rx_create_vm(RX_FLAG_DEFAULT, cache, dataset);

    AddVectoredExceptionHandler(1, veh_handler);

    int trial = 0;
    while (1) {
        char input[80];
        snprintf(input, sizeof(input), "test input number %d for trial %d", trial * 7, trial);

        printf("Trial %d: input='%s'\n", trial, input);
        fflush(stdout);

        uint8_t hash_j[32], hash_i[32];
        int crashed = 0;

        __try {
            rx_calculate_hash(vm_j, input, strlen(input), hash_j);
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            printf("  JIT CRASHED on trial %d!\n", trial);
            crashed = 1;
        }

        if (!crashed) {
            __try {
                rx_calculate_hash(vm_i, input, strlen(input), hash_i);
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                printf("  INTERP CRASHED on trial %d!\n", trial);
                crashed = 1;
            }
        }

        if (!crashed) {
            if (memcmp(hash_j, hash_i, 32) == 0) {
                printf("  PASS\n");
            } else {
                printf("  MISMATCH (JIT vs interpreter differ)\n");
            }
        }

        trial++;
        if (trial >= 20) break;
    }

    RemoveVectoredExceptionHandler(1, veh_handler);

    rx_destroy_vm(vm_j);
    rx_destroy_vm(vm_i);
    rx_free_dataset(dataset);
    rx_free_cache(cache);
    return 0;
}
