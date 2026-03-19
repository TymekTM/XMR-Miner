#pragma once

#include "common/osdep.h"
#include "blake2b.h"

#define BLAKE2_GEN_DATA_SIZE 64
#define BLAKE2_GEN_MAX_SEED 60

typedef struct {
    u8 data[BLAKE2_GEN_DATA_SIZE];
    int data_index;
} blake2_generator_t;

typedef blake2_generator_t blake2_gen;

void blake2_generator_init(blake2_generator_t *gen, const void *seed, size_t seed_len);

static inline void blake2_gen_check(blake2_generator_t *gen, size_t bytes_needed) {
    if ((size_t)gen->data_index + bytes_needed > BLAKE2_GEN_DATA_SIZE) {
        blake2b(gen->data, BLAKE2_GEN_DATA_SIZE, gen->data, BLAKE2_GEN_DATA_SIZE, NULL, 0);
        gen->data_index = 0;
    }
}

static inline void blake2_generator_next(blake2_generator_t *gen, void *out, size_t len) {
    while (len > 0) {
        blake2_gen_check(gen, len);
        size_t avail = (size_t)(BLAKE2_GEN_DATA_SIZE - gen->data_index);
        size_t take = len < avail ? len : avail;
        memcpy(out, gen->data + gen->data_index, take);
        out = (u8 *)out + take;
        len -= take;
        gen->data_index += (int)take;
    }
}

static inline void blake2_gen_init(blake2_gen *gen, const void *seed, size_t seed_len) {
    blake2_generator_init(gen, seed, seed_len);
}

static inline uint8_t gen_get_byte(blake2_gen *gen) {
    uint8_t out;
    blake2_generator_next(gen, &out, 1);
    return out;
}

static inline uint32_t gen_get_uint32(blake2_gen *gen) {
    uint32_t out;
    blake2_generator_next(gen, &out, 4);
    return out;
}
