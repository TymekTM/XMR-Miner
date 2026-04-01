#pragma once

#include "common/osdep.h"

#define STRATUM_BUF_SIZE 65536
#define STRATUM_MAX_EXTRANONCE1 16
#define STRATUM_EXTRANONCE2_SIZE 8

typedef struct {
    char *pool_url;
    int   pool_port;
    char *wallet;
    char *worker_name;
    char *password;
} stratum_config_t;

typedef struct {
    char    *job_id;
    char    *blob;
    char    *target;
    char    *seed_hash;
    char    *algo;
    char    *prev_hash;
    char    *coinb1;
    char    *coinb2;
    char    *version_hex;
    char    *ntime_hex;
    char    *extranonce1;
    int      extranonce2_size;
    uint64_t height;
    uint64_t target_u64;
    double   difficulty;
    int      has_blob;
} stratum_job_t;

#define STRATUM_PROTO_MONERO 0
#define STRATUM_PROTO_STANDARD 1

typedef struct stratum_ctx stratum_ctx_t;

stratum_ctx_t *stratum_create(const stratum_config_t *cfg);
void stratum_destroy(stratum_ctx_t *ctx);
int stratum_connect(stratum_ctx_t *ctx);
void stratum_disconnect(stratum_ctx_t *ctx);
int stratum_login(stratum_ctx_t *ctx);
int stratum_submit_share(stratum_ctx_t *ctx, const char *job_id,
                         const char *nonce_hex, const char *result_hex,
                         const char *en2_hex, const char *ntime_hex,
                         const char *commitment_hex);
stratum_job_t *stratum_get_job(stratum_ctx_t *ctx);
void stratum_copy_job(stratum_ctx_t *ctx, stratum_job_t *out);
void stratum_free_job_copy(stratum_job_t *job);
int stratum_get_protocol(stratum_ctx_t *ctx);
int stratum_recv(stratum_ctx_t *ctx);
int stratum_running(const stratum_ctx_t *ctx);
void stratum_set_running(stratum_ctx_t *ctx, int val);
