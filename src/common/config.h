#pragma once

#include "osdep.h"

#define MAX_STRATUM_URL 256
#define MAX_WALLET_ADDR 128
#define MAX_WORKER_NAME 64
#define MAX_POOL_PASS   64

typedef struct {
    char pool_url[MAX_STRATUM_URL];
    int  pool_port;
    char wallet[MAX_WALLET_ADDR];
    char worker[MAX_WORKER_NAME];
    char password[MAX_POOL_PASS];
    int  threads;
    int  huge_pages;
    int  log_level;
    int  verbose;
} config_t;

void config_set_defaults(config_t *cfg);
int  config_parse_args(config_t *cfg, int argc, char **argv);
void config_print(const config_t *cfg);
