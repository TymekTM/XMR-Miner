#include "crypto/randomx/randomx.h"
#include "crypto/randomx/randomx_internal.h"
#include <stdio.h>
#include <string.h>
#include <windows.h>

int main(void) {
    const char *key = "test key 000";
    rx_cache *cache = rx_alloc_cache(0);
    rx_init_cache(cache, key, strlen(key));

    rx_dataset *dataset = rx_alloc_dataset(0);
    rx_init_dataset(dataset, cache, 0, RX_DATASET_ITEMS + RX_DATASET_EXTRA_ITEMS, 8, 8);

    const char *input = "This is a test";
    uint8_t tempHash[64];
    blake2b(tempHash, 64, input, strlen(input), NULL, 0);

    rx_vm *vm_j = rx_create_vm(RX_FLAG_JIT, cache, dataset);
    rx_vm *vm_i = rx_create_vm(RX_FLAG_DEFAULT, cache, dataset);

    printf("vm_j useJit=%d jit=%p\n", vm_j->useJit, (void*)vm_j->jit);
    printf("vm_i useJit=%d jit=%p\n", vm_i->useJit, (void*)vm_i->jit);

    rx_vm_init_scratchpad(vm_j, tempHash);
    rx_vm_init_scratchpad(vm_i, tempHash);

    uint8_t sp_j[32], sp_i[32];
    memcpy(sp_j, vm_j->scratchpad, 32);
    memcpy(sp_i, vm_i->scratchpad, 32);
    printf("Scratchpad match: %s\n", memcmp(sp_j, sp_i, 32) == 0 ? "YES" : "NO");

    printf("Running rx_vm_run (interpreter)...\n"); fflush(stdout);
    rx_vm_run(vm_i, tempHash);
    printf("  interp R0=0x%016llx\n", (unsigned long long)vm_i->reg.r[0]);

    printf("Running rx_vm_run (JIT)...\n"); fflush(stdout);
    rx_vm_run(vm_j, tempHash);
    printf("  JIT R0=0x%016llx\n", (unsigned long long)vm_j->reg.r[0]);

    printf("\nScratchpad after vm_run:\n");
    memcpy(sp_j, vm_j->scratchpad, 32);
    memcpy(sp_i, vm_i->scratchpad, 32);
    printf("  First 32 bytes match: %s\n", memcmp(sp_j, sp_i, 32) == 0 ? "YES" : "NO");

    printf("\nNow testing: does JIT useJit still set?\n");
    printf("  vm_j useJit=%d\n", vm_j->useJit);

    printf("\nTesting with useJit forced off on JIT VM:\n");
    vm_j->useJit = 0;
    rx_vm_init_scratchpad(vm_j, tempHash);
    rx_vm_run(vm_j, tempHash);
    printf("  JIT-then-interp R0=0x%016llx\n", (unsigned long long)vm_j->reg.r[0]);

    rx_destroy_vm(vm_j);
    rx_destroy_vm(vm_i);
    rx_free_dataset(dataset);
    rx_free_cache(cache);
    return 0;
}
