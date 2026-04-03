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

    rx_vm *vm = rx_create_vm(RX_FLAG_JIT, cache, dataset);

    uint8_t tempHash[64];
    blake2b(tempHash, 64, "This is a test", 14, NULL, 0);

    rx_vm_run(vm, tempHash);

    extern void rx_jit_dump_code(rx_jit *jit);
    if (vm->jit) rx_jit_dump_code(vm->jit);

    rx_destroy_vm(vm);
    rx_free_dataset(dataset);
    rx_free_cache(cache);
    return 0;
}
