#include "crypto/randomx/randomx_internal.h"
#include <stdio.h>
#include <string.h>
#include <windows.h>

typedef void (*ProgramFunc)(rx_register_file*, rx_memory_regs*, uint8_t*, uint32_t);

static int crash_count = 0;

static LONG CALLBACK veh_handler(PEXCEPTION_POINTERS ep) {
    if (ep->ExceptionRecord->ExceptionCode == 0xC0000005 && crash_count < 3) {
        crash_count++;
        printf("[VEH #%d] CRASH at RIP=%p (offset from code start unknown), RSP=%p\n",
            crash_count, (void*)ep->ContextRecord->Rip, (void*)ep->ContextRecord->Rsp);
        printf("[VEH] RCX=%p RDX=%p R8=%p R9=%p\n",
            (void*)ep->ContextRecord->Rcx, (void*)ep->ContextRecord->Rdx,
            (void*)ep->ContextRecord->R8, (void*)ep->ContextRecord->R9);
        printf("[VEH] RAX=%p RBX=%p RBP=%p RSI=%p RDI=%p\n",
            (void*)ep->ContextRecord->Rax, (void*)ep->ContextRecord->Rbx,
            (void*)ep->ContextRecord->Rbp, (void*)ep->ContextRecord->Rsi,
            (void*)ep->ContextRecord->Rdi);
        printf("[VEH] R10=%p R11=%p R12=%p R13=%p R14=%p R15=%p\n",
            (void*)ep->ContextRecord->R10, (void*)ep->ContextRecord->R11,
            (void*)ep->ContextRecord->R12, (void*)ep->ContextRecord->R13,
            (void*)ep->ContextRecord->R14, (void*)ep->ContextRecord->R15);
        printf("[VEH] Access: %s addr=%p\n",
            ep->ExceptionRecord->ExceptionInformation[0] == 0 ? "READ" : "WRITE",
            (void*)ep->ExceptionRecord->ExceptionInformation[1]);
        fflush(stdout);
        ep->ContextRecord->Rip += 2;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

int main(void) {
    uint8_t key[32] = {0x01};

    printf("Allocating cache...\n"); fflush(stdout);
    rx_cache *cache = rx_alloc_cache(0);
    if (!cache) { printf("FAIL\n"); return 1; }

    printf("Init cache...\n"); fflush(stdout);
    rx_init_cache(cache, key, 32);
    printf("Cache ready\n"); fflush(stdout);

    printf("Allocating dataset...\n"); fflush(stdout);
    rx_dataset *dataset = rx_alloc_dataset(0);
    if (!dataset) { printf("FAIL\n"); return 1; }
    rx_init_dataset_cached(dataset, cache, 0, RX_DATASET_ITEMS, 8, 8);
    printf("Dataset ready (%p)\n", (void*)dataset->memory); fflush(stdout);

    rx_vm *vm = rx_create_vm(1, 1, 0, cache, dataset);
    if (!vm) { printf("FAIL vm\n"); return 1; }
    printf("VM ready, scratchpad=%p\n", (void*)vm->scratchpad); fflush(stdout);

    PVOID veh = AddVectoredExceptionHandler(1, veh_handler);

    uint8_t hash[32];
    printf("Computing hash...\n"); fflush(stdout);
    rx_calculate_hash(vm, key, 32, hash);

    RemoveVectoredExceptionHandler(veh);

    printf("Hash: ");
    for (int i = 0; i < 32; i++) printf("%02x", hash[i]);
    printf("\n");
    printf("Crashes caught by VEH: %d\n", crash_count);

    rx_destroy_vm(vm);
    rx_free_dataset(dataset);
    rx_free_cache(cache);
    return 0;
}
