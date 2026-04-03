#include "crypto/randomx/randomx.h"
#include <stdio.h>
#include <string.h>
#include <windows.h>

static void hex_dump(const char *label, const uint8_t *data, int len) {
    printf("  %s: ", label);
    for (int i = 0; i < len; i++) printf("%02x", data[i]);
    printf("\n");
}

int main(void) {
    const char *key = "test key 000";
    size_t key_len = strlen(key);

    printf("[TEST] Allocating cache...\n"); fflush(stdout);
    rx_cache *cache = rx_alloc_cache(0);
    if (!cache) { printf("[FAIL] cache alloc\n"); return 1; }
    rx_init_cache(cache, key, key_len);

    printf("[TEST] Allocating dataset...\n"); fflush(stdout);
    rx_dataset *dataset = rx_alloc_dataset(0);
    if (!dataset) { printf("[FAIL] dataset alloc\n"); return 1; }

    printf("[TEST] Initializing dataset...\n"); fflush(stdout);
    rx_init_dataset(dataset, cache, 0, RX_DATASET_ITEMS + RX_DATASET_EXTRA_ITEMS, 8, 8);

    int pass = 1;

    const char *inputs[] = {
        "This is a test",
        "Lorem ipsum dolor sit amet",
        "randomx test vector 12345",
        "another test input for verification",
        NULL
    };

    for (int test = 0; inputs[test]; test++) {
        const char *input = inputs[test];

        rx_vm *vm_interp = rx_create_vm(RX_FLAG_DEFAULT, cache, dataset);
        rx_vm *vm_jit = rx_create_vm(RX_FLAG_JIT, cache, dataset);
        if (!vm_interp || !vm_jit) { printf("[FAIL] VM alloc\n"); return 1; }

        uint8_t hash_interp[32], hash_jit[32];
        rx_calculate_hash(vm_interp, input, strlen(input), hash_interp);
        rx_calculate_hash(vm_jit, input, strlen(input), hash_jit);

        int match = (memcmp(hash_interp, hash_jit, 32) == 0);
        printf("[TEST #%d] \"%s\" -> %s\n", test + 1, input, match ? "MATCH" : "MISMATCH");
        if (!match) {
            hex_dump("  interp", hash_interp, 32);
            hex_dump("  jit  ", hash_jit, 32);
            pass = 0;
        }

        rx_destroy_vm(vm_interp);
        rx_destroy_vm(vm_jit);
    }

    printf("\n[TEST] Batch API: JIT vs interpreter...\n"); fflush(stdout);
    {
        rx_vm *vm_interp = rx_create_vm(RX_FLAG_DEFAULT, cache, dataset);
        rx_vm *vm_jit = rx_create_vm(RX_FLAG_JIT, cache, dataset);
        uint8_t blob[76];
        memset(blob, 0, sizeof(blob));
        blob[0] = 0x10; blob[1] = 0x03; blob[2] = 0xe3;

        uint8_t hash_i[32], hash_j[32];
        int batch_pass = 1;

        rx_calculate_hash_first(vm_jit, blob, sizeof(blob));
        for (int i = 0; i < 20; i++) {
            *(uint32_t *)(blob + 39) = (uint32_t)(i + 1);
            rx_calculate_hash_next(vm_jit, blob, sizeof(blob), hash_j);

            *(uint32_t *)(blob + 39) = (uint32_t)(i + 1);
            rx_calculate_hash(vm_interp, blob, sizeof(blob), hash_i);

            if (memcmp(hash_i, hash_j, 32) != 0) {
                printf("[BATCH] MISMATCH at nonce %d\n", i + 1);
                hex_dump("  interp", hash_i, 32);
                hex_dump("  jit  ", hash_j, 32);
                batch_pass = 0;
                pass = 0;
                break;
            }
        }
        if (batch_pass) printf("[BATCH] All 20 nonces match: PASS\n");

        rx_destroy_vm(vm_interp);
        rx_destroy_vm(vm_jit);
    }

    rx_free_dataset(dataset);
    rx_free_cache(cache);

    printf("\n[TEST] Overall JIT correctness: %s\n", pass ? "PASS" : "FAIL");
    return pass ? 0 : 1;
}
