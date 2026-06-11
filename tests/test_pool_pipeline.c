#include "crypto/randomx/randomx.h"
#include "miner/pool_utils.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    static const uint8_t key[] = "test key 000";
    uint8_t blob[76] = {0};
    uint8_t reference_blob[76];
    uint8_t pipeline_hash[32], reference_hash[32];
    uint8_t pipeline_commitment[32], reference_commitment[32];
    uint32_t queued_nonce = 100;
    const uint32_t stride = 7;
    const int nonce_offset = 39;

    rx_cache *cache = rx_alloc_cache(0);
    if (!cache) return 1;
    rx_init_cache(cache, key, sizeof(key) - 1);

    rx_vm *pipeline = rx_create_vm(RX_FLAG_DEFAULT, cache, NULL);
    rx_vm *reference = rx_create_vm(RX_FLAG_DEFAULT, cache, NULL);
    if (!pipeline || !reference) return 1;

    memcpy(blob + nonce_offset, &queued_nonce, sizeof(queued_nonce));
    rx_calculate_hash_first(pipeline, blob, sizeof(blob));

    uint32_t share_nonce = pool_pipeline_hash_next(
        pipeline, blob, sizeof(blob), nonce_offset, &queued_nonce,
        stride, pipeline_hash);

    memcpy(reference_blob, blob, sizeof(blob));
    memcpy(reference_blob + nonce_offset, &share_nonce, sizeof(share_nonce));
    rx_calculate_hash(reference, reference_blob, sizeof(reference_blob), reference_hash);

    if (share_nonce != 100 || queued_nonce != 107 ||
        memcmp(pipeline_hash, reference_hash, sizeof(reference_hash)) != 0) {
        printf("[FAIL] pipeline hash is not associated with the submitted nonce\n");
        return 1;
    }

    pool_calculate_commitment(blob, sizeof(blob), nonce_offset, share_nonce,
                              pipeline_hash, pipeline_commitment);
    rx_calculate_commitment(reference_blob, sizeof(reference_blob), reference_hash,
                            reference_commitment);
    if (memcmp(pipeline_commitment, reference_commitment,
               sizeof(reference_commitment)) != 0) {
        printf("[FAIL] commitment is not associated with the submitted nonce\n");
        return 1;
    }

    printf("[PASS] pipeline hash, nonce and commitment are associated\n");
    rx_destroy_vm(pipeline);
    rx_destroy_vm(reference);
    rx_free_cache(cache);
    return 0;
}
