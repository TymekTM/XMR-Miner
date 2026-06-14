#pragma once

#include "common/osdep.h"
#include "crypto/randomx/randomx.h"
#include "stratum/stratum.h"

#define BLOB_MAX_SIZE 256

void hex_decode(const char *hex, uint8_t *out, int max_bytes);
void hex_encode(const uint8_t *data, int len, char *out);
void hex_encode_rev(const uint8_t *data, int len, char *out);
int hex_decode_seed(const char *hex, uint8_t *out);

int algo_to_rx_flags(const char *algo);

int encode_varint(uint64_t val, uint8_t *out);
int decode_varint(const uint8_t *p, int max_bytes);

int get_monero_nonce_offset(const uint8_t *blob, int blob_len);

void format_nonce_hex(uint32_t nonce, int is_monero, char *out, size_t out_size);

int share_meets_target(const uint8_t *hash, uint64_t target, int is_monero);

int build_hashing_blob(stratum_job_t *job, uint8_t *blob, uint32_t nonce);
