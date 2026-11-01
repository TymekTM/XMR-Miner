#pragma once

#include "crypto/randomx/randomx.h"
#include <stddef.h>
#include <stdint.h>

uint32_t pool_pipeline_hash_next(rx_vm *vm, uint8_t *blob, size_t blob_len,
                                 int nonce_offset, uint32_t *queued_nonce,
                                 uint32_t nonce_stride, uint8_t hash[32]);

#define POOL_MAX_LANES 4
#define POOL_LANE_BLOB_MAX 256

typedef struct {
    uint32_t queued[POOL_MAX_LANES];
    uint8_t blob[POOL_MAX_LANES][POOL_LANE_BLOB_MAX];
} pool_lane_state;

/*
 * Multi-lane pipeline (rx_vm_group). Lane l works on nonces
 * *nonce + l*stride, advancing by lanes*stride per call. When *active is 0 the
 * pipeline is (re)started with hash_first. On return share_nonce[l] and
 * hash[l] hold one finished (nonce, hash) pair per lane. Returns the number of
 * lanes, or 0 if blob_len is too large.
 */
int pool_lanes_hash_next(rx_vm_group *g, pool_lane_state *st, int *active,
                         const uint8_t *blob, size_t blob_len, int nonce_offset,
                         uint32_t *nonce, uint32_t stride,
                         uint32_t share_nonce[POOL_MAX_LANES],
                         uint8_t hash[POOL_MAX_LANES][32]);

void pool_calculate_commitment(const uint8_t *blob, size_t blob_len,
                               int nonce_offset, uint32_t share_nonce,
                               const uint8_t hash[32], uint8_t commitment[32]);
