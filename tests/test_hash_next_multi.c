#include "crypto/randomx/randomx.h"
#include "crypto/randomx/randomx_internal.h"
#include <stdio.h>
#include <string.h>
#include <windows.h>

static void hex_dump(const char *label, const uint8_t *data, int len) {
    printf("  %s: ", label);
    for (int i = 0; i < len; i++) printf("%02x", data[i]);
    printf("\n");
}

int main(void) {
    uint8_t key[32] = {0x01};

    printf("[TEST] Allocating cache...\n"); fflush(stdout);
    rx_cache *cache = rx_alloc_cache(0);
    if (!cache) { printf("[FAIL] cache alloc\n"); return 1; }

    printf("[TEST] Initializing cache...\n"); fflush(stdout);
    rx_init_cache(cache, key, 32);

    printf("[TEST] Initializing dataset...\n"); fflush(stdout);
    rx_dataset *dataset = rx_alloc_dataset(0);
    if (!dataset) { printf("[FAIL] dataset alloc\n"); return 1; }
    rx_init_dataset_cached(dataset, cache, 0, RX_DATASET_ITEMS, 8, 8);

    rx_vm *vm_jit = rx_create_vm(1, 1, 0, cache, dataset);
    if (!vm_jit) { printf("[FAIL] JIT VM alloc\n"); return 1; }

    rx_vm *vm_interp = rx_create_vm(1, 0, 0, cache, dataset);
    if (!vm_interp) { printf("[FAIL] interp VM alloc\n"); return 1; }

    uint8_t blob[76];
    memset(blob, 0x41, 76);
    *(uint32_t *)(blob + 39) = 0;

    uint8_t hash_full[32], hash_first_next[32], hash_next2[32], hash_next3[32];

    printf("\n=== Test 1: rx_calculate_hash vs hash_first+hash_next (same blob, nonce=0) ===\n");
    rx_calculate_hash(vm_jit, blob, 76, hash_full);
    rx_calculate_hash_first(vm_jit, blob, 76);
    rx_calculate_hash_next(vm_jit, blob, 76, hash_first_next);
    hex_dump("full_hash  ", hash_full, 8);
    hex_dump("first+next ", hash_first_next, 8);
    printf("  Match: %s\n", memcmp(hash_full, hash_first_next, 32) == 0 ? "YES" : "NO");

    printf("\n=== Test 2: hash_next called twice (nonce 0 then nonce 1) WITHOUT re-init ===\n");
    *(uint32_t *)(blob + 39) = 0;
    rx_calculate_hash_first(vm_jit, blob, 76);
    rx_calculate_hash_next(vm_jit, blob, 76, hash_next2);
    hex_dump("nonce=0 (2nd call) ", hash_next2, 8);

    *(uint32_t *)(blob + 39) = 1;
    rx_calculate_hash_next(vm_jit, blob, 76, hash_next3);
    hex_dump("nonce=1 (no re-init)", hash_next3, 8);

    printf("\n=== Test 3: hash_first+hash_next with FRESH init for nonce=1 ===\n");
    *(uint32_t *)(blob + 39) = 1;
    rx_calculate_hash_first(vm_jit, blob, 76);
    rx_calculate_hash_next(vm_jit, blob, 76, hash_first_next);
    hex_dump("nonce=1 (fresh init)", hash_first_next, 8);
    printf("  Match (test2 vs test3 nonce=1): %s\n",
           memcmp(hash_next3, hash_first_next, 32) == 0 ? "YES (hash_next multi-call OK)" : "NO (hash_next multi-call BUG!)");

    printf("\n=== Test 4: Same with interpreter ===\n");
    *(uint32_t *)(blob + 39) = 0;
    rx_calculate_hash_first(vm_interp, blob, 76);
    rx_calculate_hash_next(vm_interp, blob, 76, hash_next2);

    *(uint32_t *)(blob + 39) = 1;
    rx_calculate_hash_next(vm_interp, blob, 76, hash_next3);

    *(uint32_t *)(blob + 39) = 1;
    rx_calculate_hash_first(vm_interp, blob, 76);
    rx_calculate_hash_next(vm_interp, blob, 76, hash_first_next);

    hex_dump("interp nonce=1 (no re-init)", hash_next3, 8);
    hex_dump("interp nonce=1 (fresh init)", hash_first_next, 8);
    printf("  Match: %s\n",
           memcmp(hash_next3, hash_first_next, 32) == 0 ? "YES" : "NO");

    printf("\n=== Test 5: hash_first called with nonce=0, hash_next with nonce=1 (correct pattern?) ===\n");
    *(uint32_t *)(blob + 39) = 0;
    rx_calculate_hash_first(vm_jit, blob, 76);

    *(uint32_t *)(blob + 39) = 1;
    rx_calculate_hash_next(vm_jit, blob, 76, hash_next2);
    hex_dump("first(nonce=0)+next(nonce=1)", hash_next2, 8);

    *(uint32_t *)(blob + 39) = 1;
    rx_calculate_hash_first(vm_jit, blob, 76);
    rx_calculate_hash_next(vm_jit, blob, 76, hash_first_next);
    hex_dump("first(nonce=1)+next(nonce=1)", hash_first_next, 8);
    printf("  Match: %s\n",
           memcmp(hash_next2, hash_first_next, 32) == 0 ? "YES" : "NO");

    rx_destroy_vm(vm_jit);
    rx_destroy_vm(vm_interp);
    rx_free_dataset(dataset);
    rx_free_cache(cache);
    return 0;
}
