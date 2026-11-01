#pragma once

#include "common/osdep.h"

typedef struct miner_ctx miner_ctx_t;
typedef struct stratum_ctx stratum_ctx_t;

typedef struct {
    int id;
    volatile void *vm;
    volatile void *vm2;
    int use_dual;
    stratum_ctx_t *stratum;
    miner_ctx_t *miner;
    u64 hashes;
    u64 start_time;
    int should_stop;
    uint32_t nonce_offset;
    uint32_t nonce_stride;
    uint32_t loop_count;
    uint64_t extranonce2_counter;
    char initial_seed[65];
    int current_rx_flags;
    char current_algo[32];
    int batch_active;
    int lanes;          /* >1: multi-lane group hashing (rx_vm_group) */
} worker_t;

void worker_run(worker_t *w);
