#pragma once

#include "crypto/randomx/randomx.h"
#include <stddef.h>
#include <stdint.h>

uint32_t pool_pipeline_hash_next(rx_vm *vm, uint8_t *blob, size_t blob_len,
                                 int nonce_offset, uint32_t *queued_nonce,
                                 uint32_t nonce_stride, uint8_t hash[32]);

void pool_calculate_commitment(const uint8_t *blob, size_t blob_len,
                               int nonce_offset, uint32_t share_nonce,
                               const uint8_t hash[32], uint8_t commitment[32]);
