#include "keccak.h"
#include <string.h>
#include <stdlib.h>

#define KECCAK_ROUNDS 24
#define KECCAK_STATE_SIZE 25

static const uint64_t keccak_round_constants[KECCAK_ROUNDS] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808AULL,
    0x8000000080008000ULL, 0x000000000000808BULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008AULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000AULL,
    0x000000008000808BULL, 0x800000000000008BULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800AULL, 0x800000008000000AULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
};

static const int keccak_rotations[25] = {
     0,  1, 62, 28, 27,
    36, 44,  6, 55, 20,
     3, 10, 43, 25, 39,
    41, 45, 15, 21,  8,
    18,  2, 61, 56, 14
};

#define ROTL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

void keccakf1600(uint64_t *state) {
    uint64_t C[5], D[5], B[25];
    for (int round = 0; round < KECCAK_ROUNDS; round++) {
        C[0] = state[0] ^ state[5] ^ state[10] ^ state[15] ^ state[20];
        C[1] = state[1] ^ state[6] ^ state[11] ^ state[16] ^ state[21];
        C[2] = state[2] ^ state[7] ^ state[12] ^ state[17] ^ state[22];
        C[3] = state[3] ^ state[8] ^ state[13] ^ state[18] ^ state[23];
        C[4] = state[4] ^ state[9] ^ state[14] ^ state[19] ^ state[24];

        D[0] = C[4] ^ ROTL64(C[1], 1);
        D[1] = C[0] ^ ROTL64(C[2], 1);
        D[2] = C[1] ^ ROTL64(C[3], 1);
        D[3] = C[2] ^ ROTL64(C[4], 1);
        D[4] = C[3] ^ ROTL64(C[0], 1);

        state[0] ^= D[0]; state[5] ^= D[0]; state[10] ^= D[0]; state[15] ^= D[0]; state[20] ^= D[0];
        state[1] ^= D[1]; state[6] ^= D[1]; state[11] ^= D[1]; state[16] ^= D[1]; state[21] ^= D[1];
        state[2] ^= D[2]; state[7] ^= D[2]; state[12] ^= D[2]; state[17] ^= D[2]; state[22] ^= D[2];
        state[3] ^= D[3]; state[8] ^= D[3]; state[13] ^= D[3]; state[18] ^= D[3]; state[23] ^= D[3];
        state[4] ^= D[4]; state[9] ^= D[4]; state[14] ^= D[4]; state[19] ^= D[4]; state[24] ^= D[4];

        B[0]  = ROTL64(state[0], 0);   B[1]  = ROTL64(state[5], 1);   B[2]  = ROTL64(state[10], 62);
        B[3]  = ROTL64(state[15], 28);  B[4]  = ROTL64(state[20], 27);
        B[5]  = ROTL64(state[16], 36);  B[6]  = ROTL64(state[21], 44);  B[7]  = ROTL64(state[1], 6);
        B[8]  = ROTL64(state[6], 55);   B[9]  = ROTL64(state[11], 20);
        B[10] = ROTL64(state[2], 3);    B[11] = ROTL64(state[7], 10);  B[12] = ROTL64(state[12], 43);
        B[13] = ROTL64(state[17], 25);  B[14] = ROTL64(state[22], 39);
        B[15] = ROTL64(state[3], 41);   B[16] = ROTL64(state[8], 45);  B[17] = ROTL64(state[13], 15);
        B[18] = ROTL64(state[18], 21);  B[19] = ROTL64(state[23], 8);
        B[20] = ROTL64(state[24], 18);  B[21] = ROTL64(state[4], 2);   B[22] = ROTL64(state[9], 61);
        B[23] = ROTL64(state[14], 56);  B[24] = ROTL64(state[19], 14);

        state[0]  = B[0]  ^ (~B[1]  & B[2]);
        state[1]  = B[1]  ^ (~B[2]  & B[3]);
        state[2]  = B[2]  ^ (~B[3]  & B[4]);
        state[3]  = B[3]  ^ (~B[4]  & B[0]);
        state[4]  = B[4]  ^ (~B[0]  & B[1]);
        state[5]  = B[5]  ^ (~B[6]  & B[7]);
        state[6]  = B[6]  ^ (~B[7]  & B[8]);
        state[7]  = B[7]  ^ (~B[8]  & B[9]);
        state[8]  = B[8]  ^ (~B[9]  & B[5]);
        state[9]  = B[9]  ^ (~B[5]  & B[6]);
        state[10] = B[10] ^ (~B[11] & B[12]);
        state[11] = B[11] ^ (~B[12] & B[13]);
        state[12] = B[12] ^ (~B[13] & B[14]);
        state[13] = B[13] ^ (~B[14] & B[10]);
        state[14] = B[14] ^ (~B[10] & B[11]);
        state[15] = B[15] ^ (~B[16] & B[17]);
        state[16] = B[16] ^ (~B[17] & B[18]);
        state[17] = B[17] ^ (~B[18] & B[19]);
        state[18] = B[18] ^ (~B[19] & B[15]);
        state[19] = B[19] ^ (~B[15] & B[16]);
        state[20] = B[20] ^ (~B[21] & B[22]);
        state[21] = B[21] ^ (~B[22] & B[23]);
        state[22] = B[22] ^ (~B[23] & B[24]);
        state[23] = B[23] ^ (~B[24] & B[20]);
        state[24] = B[24] ^ (~B[20] & B[21]);

        state[0] ^= keccak_round_constants[round];
    }
}

void keccak1600(uint64_t *state) {
    keccakf1600(state);
}

static void keccak_absorb(uint64_t *state, const uint8_t *data, size_t len) {
    size_t rate = 136;
    size_t i = 0;
    while (i < len) {
        size_t block_size = len - i;
        if (block_size > rate) block_size = rate;
        size_t j;
        for (j = 0; j + 8 <= block_size; j += 8)
            state[j / 8] ^= *(const uint64_t *)(data + i + j);
        for (; j < block_size; j++)
            state[j / 8] ^= (uint64_t)data[i + j] << (8 * (j % 8));
        keccakf1600(state);
        i += block_size;
    }
}

static void keccak_squeeze(uint64_t *state, uint8_t *output, size_t len) {
    size_t rate = 136;
    size_t i = 0;
    while (i < len) {
        size_t block_size = len - i;
        if (block_size > rate) block_size = rate;
        size_t j;
        for (j = 0; j + 8 <= block_size; j += 8)
            *(uint64_t *)(output + i + j) = state[j / 8];
        for (; j < block_size; j++)
            output[i + j] = (uint8_t)(state[j / 8] >> (8 * (j % 8)));
        keccakf1600(state);
        i += block_size;
    }
}

void keccak256(const uint8_t *data, size_t len, uint8_t *hash) {
    uint64_t state[KECCAK_STATE_SIZE] = {0};
    size_t padded_len = len + 1;
    if (padded_len > 136) {
        size_t rem = padded_len % 136;
        padded_len += (rem == 0) ? 0 : (136 - rem);
    }
    else padded_len = 136;
    uint8_t padded_stack[512];
    uint8_t *padded = padded_stack;
    if (padded_len > sizeof(padded_stack)) {
        padded = (uint8_t *)calloc(padded_len, 1);
        if (!padded) return;
    }
    memset(padded, 0, padded_len);
    memcpy(padded, data, len);
    padded[len] = 0x01;
    padded[padded_len - 1] |= 0x80;
    keccak_absorb(state, padded, padded_len);
    keccak_squeeze(state, hash, 32);
    if (padded != padded_stack) free(padded);
}
