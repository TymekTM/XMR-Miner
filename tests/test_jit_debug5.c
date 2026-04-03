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

    printf("tempHash: "); for (int i=0;i<32;i++) printf("%02x",tempHash[i]); printf("\n"); fflush(stdout);

    rx_vm *vm_j = rx_create_vm(RX_FLAG_JIT, cache, dataset);
    rx_vm *vm_i = rx_create_vm(RX_FLAG_DEFAULT, cache, dataset);

    printf("vm_j scratchpad=%p size=%u\n", (void*)vm_j->scratchpad, (unsigned)RX_SCRATCHPAD_L3);
    printf("vm_i scratchpad=%p size=%u\n", (void*)vm_i->scratchpad, (unsigned)RX_SCRATCHPAD_L3);

    uint8_t tempHash_j[64], tempHash_i[64];
    memcpy(tempHash_j, tempHash, 64);
    memcpy(tempHash_i, tempHash, 64);

    rx_vm_init_scratchpad(vm_j, tempHash_j);
    rx_vm_init_scratchpad(vm_i, tempHash_i);

    int sp_match = (memcmp(vm_j->scratchpad, vm_i->scratchpad, RX_SCRATCHPAD_L3) == 0);
    printf("Full scratchpad match: %s\n", sp_match ? "YES" : "NO");

    if (!sp_match) {
        uint8_t *p1 = vm_j->scratchpad, *p2 = vm_i->scratchpad;
        for (uint32_t off = 0; off < RX_SCRATCHPAD_L3; off += 64) {
            if (memcmp(p1 + off, p2 + off, 64) != 0) {
                printf("  First mismatch at offset %u\n", off);
                printf("    JIT:  "); for (int i=0;i<8;i++) printf("%02x",p1[off+i]); printf("...\n");
                printf("    Int:  "); for (int i=0;i<8;i++) printf("%02x",p2[off+i]); printf("...\n");
                break;
            }
        }
    }

    rx_destroy_vm(vm_j);
    rx_destroy_vm(vm_i);
    rx_free_dataset(dataset);
    rx_free_cache(cache);
    return 0;
}
