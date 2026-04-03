#include "crypto/randomx/randomx.h"
#include "crypto/randomx/randomx_internal.h"
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <immintrin.h>

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

    uint8_t seed_j[64], seed_i[64];
    memcpy(seed_j, tempHash, 64);
    memcpy(seed_i, tempHash, 64);

    printf("vm_j useJit=%d jit=%p\n", vm_j->useJit, (void*)vm_j->jit);

    rx_vm_run(vm_j, seed_j);
    rx_vm_run(vm_i, seed_i);

    printf("After rx_vm_run:\n");
    for (int i = 0; i < 8; i++) {
        int m = (vm_j->reg.r[i] == vm_i->reg.r[i]);
        printf("  R%d: JIT=0x%016llx  Int=0x%016llx  %s\n", i,
            (unsigned long long)vm_j->reg.r[i],
            (unsigned long long)vm_i->reg.r[i],
            m ? "OK" : "MISMATCH");
    }

    printf("\nNow force JIT VM to use interpreter:\n");
    vm_j->useJit = 0;
    memcpy(seed_j, tempHash, 64);
    rx_vm_run(vm_j, seed_j);

    for (int i = 0; i < 8; i++) {
        int m = (vm_j->reg.r[i] == vm_i->reg.r[i]);
        printf("  R%d: JIT-as-intp=0x%016llx  Int=0x%016llx  %s\n", i,
            (unsigned long long)vm_j->reg.r[i],
            (unsigned long long)vm_i->reg.r[i],
            m ? "OK" : "MISMATCH");
    }

    printf("\nRe-enable JIT and run again:\n");
    vm_j->useJit = 1;
    memcpy(seed_j, tempHash, 64);
    rx_vm_run(vm_j, seed_j);

    for (int i = 0; i < 8; i++) {
        int m = (vm_j->reg.r[i] == vm_i->reg.r[i]);
        printf("  R%d: JIT=0x%016llx  Int=0x%016llx  %s\n", i,
            (unsigned long long)vm_j->reg.r[i],
            (unsigned long long)vm_i->reg.r[i],
            m ? "OK" : "MISMATCH");
    }

    rx_destroy_vm(vm_j);
    rx_destroy_vm(vm_i);
    rx_free_dataset(dataset);
    rx_free_cache(cache);
    return 0;
}
