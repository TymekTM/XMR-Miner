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

    uint8_t hash_jit[32], hash_interp[32];
    int match = 1;

    printf("\n=== Verifying rx_calculate_hash produces different hashes per nonce ===\n");
    for (uint32_t nonce = 0; nonce < 5; nonce++) {
        *(uint32_t *)(blob + 39) = nonce;
        rx_calculate_hash(vm_jit, blob, 76, hash_jit);
        rx_calculate_hash(vm_interp, blob, 76, hash_interp);
        int m = (memcmp(hash_jit, hash_interp, 32) == 0);
        if (!m) match = 0;
        printf("  nonce=%u jit=%s interp=%s %s\n", nonce,
            hash_jit[0] == hash_jit[1] ? "DUPE" : "ok",
            m ? "MATCH" : "MISMATCH",
            m ? "OK" : "FAIL");
        hex_dump("  jit", hash_jit, 8);
        hex_dump("  int", hash_interp, 8);
    }

    printf("\n  All JIT/interp match: %s\n", match ? "YES" : "NO");

    printf("\n=== Measuring rx_calculate_hash speed (10 hashes, JIT) ===\n");
    LARGE_INTEGER freq, t0, t1;
    QueryPerformanceFrequency(&freq);
    *(uint32_t *)(blob + 39) = 0;
    QueryPerformanceCounter(&t0);
    for (int i = 0; i < 10; i++) {
        *(uint32_t *)(blob + 39) = (uint32_t)i;
        rx_calculate_hash(vm_jit, blob, 76, hash_jit);
    }
    QueryPerformanceCounter(&t1);
    double elapsed_ms = (double)(t1.QuadPart - t0.QuadPart) / freq.QuadPart * 1000.0;
    printf("  10 hashes in %.1f ms = %.0f H/s\n", elapsed_ms, 10000.0 / elapsed_ms);

    rx_destroy_vm(vm_jit);
    rx_destroy_vm(vm_interp);
    rx_free_dataset(dataset);
    rx_free_cache(cache);
    return match ? 0 : 1;
}
