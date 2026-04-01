#pragma once

#include "common/osdep.h"

typedef struct miner_ctx miner_ctx_t;
typedef struct stratum_ctx stratum_ctx_t;

miner_ctx_t *miner_create(int num_threads, int huge_pages, int physical_cores, int mode, stratum_ctx_t *stratum);
void miner_destroy(miner_ctx_t *ctx);
int miner_start(miner_ctx_t *ctx, const uint8_t *initial_seed, int initial_seed_len);
void miner_stop(miner_ctx_t *ctx);
void miner_reinit_cache(miner_ctx_t *ctx, const uint8_t *seed, int seed_len);
void *miner_get_vm(miner_ctx_t *ctx, int worker_id);
