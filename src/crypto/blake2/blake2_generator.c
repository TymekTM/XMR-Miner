#include "blake2_generator.h"
#include <string.h>

static inline void blake2_gen_check(blake2_generator_t *gen, size_t bytes_needed) {
    if ((size_t)gen->data_index + bytes_needed > BLAKE2_GEN_DATA_SIZE) {
        blake2b(gen->data, BLAKE2_GEN_DATA_SIZE, gen->data, BLAKE2_GEN_DATA_SIZE, NULL, 0);
        gen->data_index = 0;
    }
}

void blake2_generator_init(blake2_generator_t *gen, const void *seed, size_t seed_len) {
    memset(gen->data, 0, sizeof(gen->data));
    if (seed_len > BLAKE2_GEN_MAX_SEED)
        seed_len = BLAKE2_GEN_MAX_SEED;
    memcpy(gen->data, seed, seed_len);
    gen->data_index = BLAKE2_GEN_DATA_SIZE;
}

void blake2_generator_next(blake2_generator_t *gen, void *out, size_t len) {
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
