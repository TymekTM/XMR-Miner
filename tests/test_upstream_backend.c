#include "crypto/randomx/randomx.h"

#include <stdio.h>
#include <string.h>

int main(void) {
    static const char key[] = "test key 000";
    static const char input[] = "This is a test";
    static const unsigned char expected[32] = {
        0x63, 0x91, 0x83, 0xaa, 0xe1, 0xbf, 0x4c, 0x9a,
        0x35, 0x88, 0x4c, 0xb4, 0x6b, 0x09, 0xca, 0xd9,
        0x17, 0x5f, 0x04, 0xef, 0xd7, 0x68, 0x4e, 0x72,
        0x62, 0xa0, 0xac, 0x1c, 0x2f, 0x0b, 0x4e, 0x3f
    };
    unsigned char direct[32];
    unsigned char batch[32];
    unsigned char final_hash[32];

    rx_cache *cache = rx_alloc_cache(0);
    rx_dataset *dataset = rx_alloc_dataset(0);
    if (!cache || !dataset) {
        printf("[FAIL] allocation\n");
        return 1;
    }
    rx_init_cache(cache, key, sizeof(key) - 1);
    rx_init_dataset(dataset, cache, 0,
                    RX_DATASET_ITEMS + RX_DATASET_EXTRA_ITEMS, 8, 8);

    rx_vm *direct_vm = rx_create_vm(RX_FLAG_JIT, cache, dataset);
    rx_vm *batch_vm = rx_create_vm(RX_FLAG_JIT, cache, dataset);
    if (!direct_vm || !batch_vm) {
        printf("[FAIL] VM creation\n");
        return 1;
    }

    rx_calculate_hash(direct_vm, input, sizeof(input) - 1, direct);
    if (memcmp(direct, expected, sizeof(direct)) != 0) {
        printf("[FAIL] official vector\n");
        return 1;
    }

    rx_calculate_hash_first(batch_vm, input, sizeof(input) - 1);
    rx_calculate_hash_next(batch_vm, input, sizeof(input) - 1, batch);
    rx_calculate_hash_last(batch_vm, final_hash);
    if (memcmp(batch, direct, sizeof(batch)) != 0 ||
        memcmp(final_hash, direct, sizeof(final_hash)) != 0) {
        printf("[FAIL] batch API\n");
        return 1;
    }

    rx_destroy_vm(direct_vm);
    rx_destroy_vm(batch_vm);
    rx_free_dataset(dataset);
    rx_free_cache(cache);
    printf("[PASS] official vector and batch API\n");
    return 0;
}
