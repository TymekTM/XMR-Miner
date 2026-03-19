#include "randomx_internal.h"
#include "crypto/blake2/blake2_generator.h"
#include "crypto/argon2/argon2.h"
#include <string.h>

static const uint64_t ssMul0 = 6364136223846793005ULL;
static const uint64_t ssAdd1 = 9298411001130361340ULL;
static const uint64_t ssAdd2 = 12065312585734608966ULL;
static const uint64_t ssAdd3 = 9306329213124626780ULL;
static const uint64_t ssAdd4 = 5281919268842080866ULL;
static const uint64_t ssAdd5 = 10536153434571861004ULL;
static const uint64_t ssAdd6 = 3398623926847679864ULL;
static const uint64_t ssAdd7 = 9549104520008361294ULL;

static void ss_execute(uint64_t r[8], const rx_superscalar_program *prog, const uint64_t *reciprocals) {
    for (uint32_t i = 0; i < prog->size; i++) {
        const rx_instruction *instr = &prog->buffer[i];
        int dst = instr->dst % 8;
        int src = instr->src % 8;
        uint32_t imm = read_u32_le((const u8 *)&instr->imm32);

        switch (instr->opcode) {
        case RX_SS_ISUB_R:
            r[dst] -= r[src];
            break;
        case RX_SS_IXOR_R:
            r[dst] ^= r[src];
            break;
        case RX_SS_IADD_RS:
            r[dst] += r[src] << ((instr->mod >> 2) & 3);
            break;
        case RX_SS_IMUL_R:
            r[dst] *= r[src];
            break;
        case RX_SS_IROR_C:
            r[dst] = rx_rotr(r[dst], imm);
            break;
        case RX_SS_IADD_C7:
        case RX_SS_IADD_C8:
        case RX_SS_IADD_C9:
            r[dst] += (uint64_t)(int64_t)(int32_t)imm;
            break;
        case RX_SS_IXOR_C7:
        case RX_SS_IXOR_C8:
        case RX_SS_IXOR_C9:
            r[dst] ^= (uint64_t)(int64_t)(int32_t)imm;
            break;
        case RX_SS_IMULH_R:
            r[dst] = rx_mulh(r[dst], r[src]);
            break;
        case RX_SS_ISMULH_R:
            r[dst] = (uint64_t)rx_smulh(rx_u64_to_s64(r[dst]), rx_u64_to_s64(r[src]));
            break;
        case RX_SS_IMUL_RCP: {
            uint64_t rcp = reciprocals ? reciprocals[imm] : 0;
            r[dst] *= rcp;
            break;
        }
        default:
            break;
        }
    }
}

void rx_init_cache_internal(rx_cache *cache, const void *key, size_t key_size) {
    argon2_hash(ARGON2_D, RX_ARGON_ITERATIONS, RX_ARGON_MEMORY, RX_ARGON_LANES,
                 key, key_size, RX_ARGON_SALT, RX_ARGON_SALT_LEN,
                 NULL, 0, NULL, 0,
                 NULL, 0, cache->memory);

    blake2_gen gen;
    blake2_gen_init(&gen, key, key_size);

    int total_rcp = 0;
    for (int i = 0; i < RX_CACHE_ACCESSES; i++) {
        generate_superscalar(&cache->programs[i], &gen);
        for (uint32_t j = 0; j < cache->programs[i].size; j++) {
            if (cache->programs[i].buffer[j].opcode == RX_SS_IMUL_RCP) {
                total_rcp++;
            }
        }
    }

    if (total_rcp > 0) {
        cache->reciprocalCache = (uint64_t *)malloc((size_t)total_rcp * sizeof(uint64_t));
        cache->reciprocalCapacity = total_rcp;
        cache->reciprocalCount = 0;
        for (int i = 0; i < RX_CACHE_ACCESSES; i++) {
            for (uint32_t j = 0; j < cache->programs[i].size; j++) {
                if (cache->programs[i].buffer[j].opcode == RX_SS_IMUL_RCP) {
                    uint32_t imm = read_u32_le((const u8 *)&cache->programs[i].buffer[j].imm32);
                    cache->reciprocalCache[cache->reciprocalCount++] = rx_reciprocal(imm);
                    write_u32_le((u8 *)&cache->programs[i].buffer[j].imm32, (u32)cache->reciprocalCount - 1);
                }
            }
        }
    }
}

static inline uint8_t *get_mix_block(uint64_t reg_val, uint8_t *memory) {
    uint32_t mask = (uint32_t)(RX_CACHE_SIZE / RX_CACHE_LINE_SIZE - 1);
    return memory + (reg_val & mask) * RX_CACHE_LINE_SIZE;
}

void rx_init_dataset_item(rx_cache *cache, uint8_t *out, uint64_t item_number) {
    uint64_t rl[8];
    rl[0] = (item_number + 1) * ssMul0;
    rl[1] = rl[0] ^ ssAdd1;
    rl[2] = rl[0] ^ ssAdd2;
    rl[3] = rl[0] ^ ssAdd3;
    rl[4] = rl[0] ^ ssAdd4;
    rl[5] = rl[0] ^ ssAdd5;
    rl[6] = rl[0] ^ ssAdd6;
    rl[7] = rl[0] ^ ssAdd7;

    uint64_t reg_val = item_number;
    for (int i = 0; i < RX_CACHE_ACCESSES; i++) {
        uint8_t *mix_block = get_mix_block(reg_val, cache->memory);
        _mm_prefetch((const char *)mix_block, _MM_HINT_NTA);

        rx_superscalar_program *prog = &cache->programs[i];
        uint64_t r[8];
        memcpy(r, rl, sizeof(r));
        ss_execute(r, prog, cache->reciprocalCache);

        for (int q = 0; q < 8; q++)
            r[q] ^= read_u64_le(mix_block + 8 * q);
        memcpy(rl, r, sizeof(rl));

        reg_val = rl[prog->addrReg];
    }
    memcpy(out, rl, RX_CACHE_LINE_SIZE);
}

void rx_init_dataset_internal(rx_dataset *ds, rx_cache *cache, uint32_t start_item, uint32_t count) {
    uint8_t *ptr = ds->memory + (size_t)start_item * RX_CACHE_LINE_SIZE;
    for (uint32_t i = 0; i < count; i++, ptr += RX_CACHE_LINE_SIZE)
        rx_init_dataset_item(cache, ptr, start_item + i);
}
