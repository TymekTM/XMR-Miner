#include "crypto/randomx/randomx.h"
#include <stdio.h>
#include <string.h>

static void hex_dump(const char *label, const uint8_t *d, int n) {
    printf("  %s: ", label);
    for (int i = 0; i < n; i++) printf("%02x", d[i]);
    printf("\n");
}

static uint32_t read_u32_le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

int main(void) {
    rx_cache *cache = rx_alloc_cache(1);
    rx_init_cache(cache, (const uint8_t*)"pool_sim_seed_123", 17);
    rx_dataset *dataset = rx_alloc_dataset(1);
    printf("[DIAG] Loading cached dataset...\n"); fflush(stdout);
    rx_init_dataset_cached(dataset, cache, 0, RX_DATASET_ITEMS, 8, 8);

    rx_vm *vm_jit = rx_create_vm(RX_FLAG_JIT, cache, dataset);
    rx_vm *vm_interp = rx_create_vm(RX_FLAG_DEFAULT, cache, dataset);

    uint8_t blob[76];
    memset(blob, 0, sizeof(blob));
    blob[0] = 0x10; blob[1] = 0x03; blob[2] = 0xe3;

    printf("=== DIAG 1: full hash (rx_calculate_hash) JIT vs interp ===\n");
    for (int nonce = 1; nonce <= 3; nonce++) {
        *(uint32_t *)(blob + 39) = (uint32_t)nonce;
        uint8_t hj[32], hi[32];
        rx_calculate_hash(vm_jit, blob, sizeof(blob), hj);
        rx_calculate_hash(vm_interp, blob, sizeof(blob), hi);
        int match = (memcmp(hj, hi, 32) == 0);
        printf("  nonce=%d jit=%08x interp=%08x %s\n",
               nonce, read_u32_le(hj), read_u32_le(hi), match ? "MATCH" : "MISMATCH");
        if (!match) { hex_dump("  jit ", hj, 32); hex_dump("  int", hi, 32); }
    }

    printf("\n=== DIAG 2: batch API step-by-step for nonce=1 ===\n");
    *(uint32_t *)(blob + 39) = 1;

    uint8_t full_hash[32];
    rx_calculate_hash(vm_jit, blob, sizeof(blob), full_hash);
    hex_dump("  full_hash(rx_calc)", full_hash, 32);

    uint8_t batch_next_hash[32];
    rx_calculate_hash_first(vm_jit, blob, sizeof(blob));
    *(uint32_t *)(blob + 39) = 1;
    rx_calculate_hash_next(vm_jit, blob, sizeof(blob), batch_next_hash);
    hex_dump("  hash_next(same_blob)", batch_next_hash, 32);

    uint8_t last_hash[32];
    rx_calculate_hash_first(vm_jit, blob, sizeof(blob));
    rx_calculate_hash_last(vm_jit, last_hash);
    hex_dump("  hash_first+hash_last", last_hash, 32);

    printf("  full == hash_last? %s\n",
           memcmp(full_hash, last_hash, 32) == 0 ? "YES ***" : "NO");
    printf("  full == hash_next?  %s\n",
           memcmp(full_hash, batch_next_hash, 32) == 0 ? "YES" : "NO (expected)");

    printf("\n=== DIAG 3: off-by-one check: hash_next gives PREVIOUS blob's hash? ===\n");
    {
        rx_calculate_hash_first(vm_jit, blob, sizeof(blob));

        uint8_t h_prev_full[32], h_next_out[32];

        *(uint32_t *)(blob + 39) = 100;
        rx_calculate_hash(vm_jit, blob, sizeof(blob), h_prev_full);

        *(uint32_t *)(blob + 39) = 200;
        rx_calculate_hash_next(vm_jit, blob, sizeof(blob), h_next_out);

        hex_dump("  full(nonce=100)", h_prev_full, 32);
        hex_dump("  next(after set200)", h_next_out, 32);
        printf("  hash_next(nonce=200) == full(nonce=100)? %s\n",
               memcmp(h_next_out, h_prev_full, 32) == 0 ? "YES (off-by-1 confirmed)" : "NO");
    }

    printf("\n=== DIAG 4: what does pool actually need? ===\n");
    printf("  Monero stratum submits: nonce_hex + result_hex + commit_hex\n");
    printf("  result_hex = hash output\n");
    printf("  commit_hex = blake2b(blob || hash)\n");
    printf("  Pool verifies by running rx_calculate_hash(reconstructed_blob)\n");
    printf("\n  CONCLUSION needed:\n");
    printf("    If pool uses rx_calculate_hash -> we must send full_hash result\n");
    printf("    If pool uses batch verify     -> we can send hash_next result\n");

    rx_destroy_vm(vm_jit);
    rx_destroy_vm(vm_interp);
    rx_free_dataset(dataset);
    rx_free_cache(cache);
    return 0;
}
