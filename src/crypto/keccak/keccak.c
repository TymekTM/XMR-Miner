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
        for (int x = 0; x < 5; x++)
            C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];

        for (int x = 0; x < 5; x++) {
            D[x] = C[(x + 4) % 5] ^ ROTL64(C[(x + 1) % 5], 1);
            for (int y = 0; y < 5; y++)
                state[x + 5 * y] ^= D[x];
        }

        for (int x = 0; x < 5; x++)
            for (int y = 0; y < 5; y++)
                B[y + 5 * ((2 * x + 3 * y) % 5)] = ROTL64(state[x + 5 * y], keccak_rotations[x + 5 * y]);

        for (int x = 0; x < 5; x++)
            for (int y = 0; y < 5; y++)
                state[x + 5 * y] = B[x + 5 * y] ^ ((~B[(x + 1) % 5 + 5 * y]) & B[(x + 2) % 5 + 5 * y]);

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
