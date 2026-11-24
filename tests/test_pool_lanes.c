/*
 * Checks the multi-lane pool pipeline used by the miner worker
 * (pool_lanes_hash_next): every reported (nonce, hash) pair must equal
 * rx_calculate_hash of the blob carrying that nonce, nonces must cover the
 * worker's stride pattern without gaps or duplicates, and a restart (job
 * change) must re-prime the pipeline.
 */
#include "crypto/randomx/randomx.h"
#include "miner/pool_utils.h"

#include <stdio.h>
#include <string.h>

int main(void) {
    const char key[] = "test key 000";
    rx_cache *cache = rx_alloc_cache(1);
    rx_init_cache(cache, key, sizeof(key) - 1);
    rx_dataset *ds = rx_alloc_dataset(1);
    rx_init_dataset_cached(ds, cache, 0, RX_DATASET_ITEMS + RX_DATASET_EXTRA_ITEMS, 4, 4);
    rx_vm *ref = rx_create_vm(RX_FLAG_JIT, cache, ds);
    int checks = 0, failures = 0;

    for (int lanes = 2; lanes <= 4; lanes++) {
        rx_vm_group *g = rx_create_vm_group(lanes, RX_FLAG_DEFAULT, cache, ds);
        if (!g) { printf("[FAIL] group alloc lanes=%d\n", lanes); return 1; }
        pool_lane_state st;
        memset(&st, 0, sizeof(st));
        int active = 0;
        uint8_t blob[76];
        memset(blob, 0x11, sizeof(blob));
        const int nonce_off = 39, stride = 4, worker_offset = 1;
        uint32_t nonce = 1000 + worker_offset;
        uint32_t expect_next = nonce;
        for (int call = 0; call < 4; call++) {
            if (call == 2) {           /* simulated job change */
                blob[5] ^= 0xFF;
                active = 0;
                nonce = 5000 + worker_offset;
                expect_next = nonce;
            }
            uint32_t sn[POOL_MAX_LANES];
            uint8_t h[POOL_MAX_LANES][32];
            int K = pool_lanes_hash_next(g, &st, &active, blob, sizeof(blob), nonce_off,
                                         &nonce, stride, sn, h);
            checks++;
            if (K != lanes) { failures++; printf("[FAIL] K=%d\n", K); }
            for (int l = 0; l < K; l++) {
                uint8_t b2[76], want[32];
                memcpy(b2, blob, sizeof(b2));
                memcpy(b2 + nonce_off, &sn[l], 4);
                rx_calculate_hash(ref, b2, sizeof(b2), want);
                checks += 2;
                if (memcmp(want, h[l], 32) != 0) {
                    failures++;
                    printf("[FAIL] lanes=%d call=%d lane=%d hash mismatch (nonce %u)\n", lanes, call, l, sn[l]);
                }
                if (sn[l] != expect_next) {
                    failures++;
                    printf("[FAIL] lanes=%d call=%d lane=%d nonce %u, expected %u\n", lanes, call, l, sn[l], expect_next);
                }
                expect_next += stride;
            }
        }
        rx_destroy_vm_group(g);
    }
    /* T5: heterogeneous multi-worker nonce uniqueness (P=2L, P=3L, E=1L sharing stride=3) */
    {
        const int stride = 3;
        uint32_t seen[64];
        int nseen = 0;
        uint32_t n0 = 100 + 0, n1 = 100 + 1, n2 = 100 + 2;
        rx_vm_group *g2 = rx_create_vm_group(2, RX_FLAG_DEFAULT, cache, ds);
        rx_vm_group *g3 = rx_create_vm_group(3, RX_FLAG_DEFAULT, cache, ds);
        pool_lane_state s2, s3;
        memset(&s2, 0, sizeof(s2)); memset(&s3, 0, sizeof(s3));
        int a2 = 0, a3 = 0;
        uint8_t blob[76];
        memset(blob, 0x22, sizeof(blob));
        uint8_t h[POOL_MAX_LANES][32];
        uint32_t sn[POOL_MAX_LANES];
        for (int c = 0; c < 3; c++) {
            int k2 = pool_lanes_hash_next(g2, &s2, &a2, blob, sizeof(blob), 39, &n0, stride, sn, h);
            for (int l = 0; l < k2; l++) seen[nseen++] = sn[l];
            int k3 = pool_lanes_hash_next(g3, &s3, &a3, blob, sizeof(blob), 39, &n1, stride, sn, h);
            for (int l = 0; l < k3; l++) seen[nseen++] = sn[l];
            /* Worker 2 (1-lane) advances by stride */
            seen[nseen++] = n2;
            n2 += stride;
        }
        int dup = 0;
        for (int i = 0; i < nseen; i++)
            for (int j = i + 1; j < nseen; j++)
                if (seen[i] == seen[j]) dup++;
        checks++;
        if (dup) { failures++; printf("[FAIL] heterogeneous workers had %d nonce collisions\n", dup); }
        rx_destroy_vm_group(g2);
        rx_destroy_vm_group(g3);
    }
    rx_destroy_vm(ref);
    rx_free_dataset(ds);
    rx_free_cache(cache);
    printf("%s: %d checks, %d failures\n", failures ? "[FAIL]" : "[PASS]", checks, failures);
    return failures ? 1 : 0;
}
