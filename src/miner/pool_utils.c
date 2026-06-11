#include "pool_utils.h"

#include <stdlib.h>
#include <string.h>

uint32_t pool_pipeline_hash_next(rx_vm *vm, uint8_t *blob, size_t blob_len,
                                 int nonce_offset, uint32_t *queued_nonce,
                                 uint32_t nonce_stride, uint8_t hash[32]) {
    uint32_t share_nonce = *queued_nonce;
    uint32_t next_nonce = share_nonce + nonce_stride;

    memcpy(blob + nonce_offset, &next_nonce, sizeof(next_nonce));
    rx_calculate_hash_next(vm, blob, blob_len, hash);
    *queued_nonce = next_nonce;
    return share_nonce;
}

void pool_calculate_commitment(const uint8_t *blob, size_t blob_len,
                               int nonce_offset, uint32_t share_nonce,
                               const uint8_t hash[32], uint8_t commitment[32]) {
    uint8_t stack_blob[256];
    uint8_t *share_blob = stack_blob;

    if (blob_len > sizeof(stack_blob)) {
        share_blob = (uint8_t *)malloc(blob_len);
        if (!share_blob) {
            memset(commitment, 0, 32);
            return;
        }
    }

    memcpy(share_blob, blob, blob_len);
    memcpy(share_blob + nonce_offset, &share_nonce, sizeof(share_nonce));
    rx_calculate_commitment(share_blob, blob_len, hash, commitment);

    if (share_blob != stack_blob)
        free(share_blob);
}
