#pragma once

#include "common/osdep.h"

#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE   32

typedef struct {
    u32 enc_key[60];
    u32 dec_key[60];
    int nr;
} aes_ctx;

void aes256_init(aes_ctx *ctx, const u8 key[AES_KEY_SIZE]);
void aes256_encrypt_block(const aes_ctx *ctx, const u8 in[16], u8 out[16]);
void aes256_decrypt_block(const aes_ctx *ctx, const u8 in[16], u8 out[16]);

void aes256_encrypt_block_ni(const u8 *round_keys, const u8 in[16], u8 out[16]);
void aes256_key_expansion_dec_ni(aes_ctx *ctx, const u8 key[AES_KEY_SIZE]);
void aes256_decrypt_block_ni(const aes_ctx *ctx, const u8 in[16], u8 out[16]);
int aes_ni_available(void);
