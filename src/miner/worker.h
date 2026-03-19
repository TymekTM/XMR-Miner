#pragma once

#include "common/osdep.h"

typedef struct miner_ctx miner_ctx_t;
typedef struct stratum_ctx stratum_ctx_t;

typedef struct {
    int id;
    void *vm;
    stratum_ctx_t *stratum;
    miner_ctx_t *miner;
    u64 hashes;
    u64 start_time;
    int should_stop;
} worker_t;

void worker_run(worker_t *w);
