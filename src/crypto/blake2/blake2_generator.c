#include "blake2_generator.h"
#include <string.h>

void blake2_generator_init(blake2_generator_t *gen, const void *seed, size_t seed_len) {
    memset(gen->data, 0, sizeof(gen->data));
    if (seed_len > BLAKE2_GEN_MAX_SEED)
        seed_len = BLAKE2_GEN_MAX_SEED;
    memcpy(gen->data, seed, seed_len);
    gen->data_index = BLAKE2_GEN_DATA_SIZE;
}
