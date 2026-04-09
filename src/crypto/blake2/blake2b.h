#pragma once

#include "common/osdep.h"

#define BLAKE2B_BLOCKBYTES 128
#define BLAKE2B_OUTBYTES   64
#define BLAKE2B_KEYBYTES   64
#define BLAKE2B_SALTBYTES  16
#define BLAKE2B_PERSONALBYTES 16

typedef struct {
    u64 h[8];
    u64 t[2];
    u64 f[2];
    u8  buf[BLAKE2B_BLOCKBYTES];
    int buflen;
    int outlen;
    u8  last_node;
} blake2b_state;

int blake2b_init(blake2b_state *S, size_t outlen);
int blake2b_init_key(blake2b_state *S, size_t outlen, const void *key, size_t keylen);
int blake2b_update(blake2b_state *S, const void *in, size_t inlen);
int blake2b_final(blake2b_state *S, void *out, size_t outlen);

int blake2b(void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen);
void rx_blake2b_regfile(void *out, const void *regfile);
