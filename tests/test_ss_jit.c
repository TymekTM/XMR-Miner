#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <windows.h>
#include "crypto/randomx/randomx_internal.h"
#include "crypto/blake2/blake2_generator.h"

static const uint64_t ssMul0 = 6364136223846793005ULL;
static const uint64_t ssAdd1 = 9298411001130361340ULL;
static const uint64_t ssAdd2 = 12065312585734608966ULL;
static const uint64_t ssAdd3 = 9306329213124626780ULL;
static const uint64_t ssAdd4 = 5281919268842080866ULL;
static const uint64_t ssAdd5 = 10536153434571861004ULL;
static const uint64_t ssAdd6 = 3398623926847679864ULL;
static const uint64_t ssAdd7 = 9549104520008361294ULL;

#define DS_CACHE_MASK ((uint32_t)(RX_CACHE_SIZE / RX_CACHE_LINE_SIZE - 1))

static void ss_execute(uint64_t r[8], const rx_superscalar_program *prog, const uint64_t *reciprocals) {
    for (uint32_t i = 0; i < prog->size; i++) {
        const rx_instruction *instr = &prog->buffer[i];
        int dst = instr->dst % 8;
        int src = instr->src % 8;
        switch (instr->opcode) {
        case RX_SS_ISUB_R: r[dst] -= r[src]; break;
        case RX_SS_IXOR_R: r[dst] ^= r[src]; break;
        case RX_SS_IADD_RS: r[dst] += r[src] << ((instr->mod >> 2) & 3); break;
        case RX_SS_IMUL_R: r[dst] *= r[src]; break;
        case RX_SS_IROR_C: r[dst] = rx_rotr(r[dst], instr->imm32); break;
        case RX_SS_IADD_C7: case RX_SS_IADD_C8: case RX_SS_IADD_C9:
            r[dst] += (uint64_t)(int64_t)(int32_t)instr->imm32; break;
        case RX_SS_IXOR_C7: case RX_SS_IXOR_C8: case RX_SS_IXOR_C9:
            r[dst] ^= (uint64_t)(int64_t)(int32_t)instr->imm32; break;
        case RX_SS_IMULH_R: r[dst] = rx_mulh(r[dst], r[src]); break;
        case RX_SS_ISMULH_R: r[dst] = (uint64_t)rx_smulh(rx_u64_to_s64(r[dst]), rx_u64_to_s64(r[src])); break;
        case RX_SS_IMUL_RCP: { uint32_t idx = instr->imm32; r[dst] *= reciprocals[idx]; break; }
        }
    }
}

int main() {
    printf("[TEST] Superscalar JIT diagnostic\n");
    fflush(stdout);

    uint8_t seed[32] = {0};
    rx_cache *cache = rx_alloc_cache(0);
    if (!cache) { printf("[FAIL] alloc cache\n"); return 1; }
    printf("[I] Cache allocated, initializing...\n");
    fflush(stdout);

    rx_init_cache(cache, seed, 32);
    printf("[I] Cache initialized\n");
    fflush(stdout);

    for (int i = 0; i < RX_CACHE_ACCESSES; i++) {
        printf("[I] Program %d: size=%u addrReg=%d fn=%p code=%p\n",
            i, cache->programs[i].size, cache->programs[i].addrReg,
            cache->programs[i].fn, (void*)cache->programs[i].code);
        fflush(stdout);
    }

    printf("[I] Testing single program JIT vs interpreter...\n");
    fflush(stdout);

    uint64_t rl_interp[8] = {0};
    uint64_t base = 1 * ssMul0;
    rl_interp[0] = base;
    rl_interp[1] = base ^ ssAdd1;
    rl_interp[2] = base ^ ssAdd2;
    rl_interp[3] = base ^ ssAdd3;
    rl_interp[4] = base ^ ssAdd4;
    rl_interp[5] = base ^ ssAdd5;
    rl_interp[6] = base ^ ssAdd6;
    rl_interp[7] = base ^ ssAdd7;

    printf("[I] Input: %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx\n",
        (unsigned long long)rl_interp[0], (unsigned long long)rl_interp[1],
        (unsigned long long)rl_interp[2], (unsigned long long)rl_interp[3],
        (unsigned long long)rl_interp[4], (unsigned long long)rl_interp[5],
        (unsigned long long)rl_interp[6], (unsigned long long)rl_interp[7]);
    fflush(stdout);

    uint64_t rl_jit[8];
    memcpy(rl_jit, rl_interp, 64);

    printf("[I] Running interpreter on program 0...\n");
    fflush(stdout);
    ss_execute(rl_interp, &cache->programs[0], cache->reciprocalCache);
    printf("[I] Interpreter done\n");
    fflush(stdout);

    if (cache->programs[0].fn) {
        printf("[I] Running JIT on program 0...\n");
        fflush(stdout);
        __try {
            cache->programs[0].fn(rl_jit);
            printf("[I] JIT done\n");
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            printf("[CRASH] Exception 0x%08X\n", GetExceptionCode());
        }
        fflush(stdout);

        int match = (memcmp(rl_interp, rl_jit, 64) == 0);
        printf("[I] Interp: %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx\n",
            (unsigned long long)rl_interp[0], (unsigned long long)rl_interp[1],
            (unsigned long long)rl_interp[2], (unsigned long long)rl_interp[3],
            (unsigned long long)rl_interp[4], (unsigned long long)rl_interp[5],
            (unsigned long long)rl_interp[6], (unsigned long long)rl_interp[7]);
        printf("[I] JIT:    %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx\n",
            (unsigned long long)rl_jit[0], (unsigned long long)rl_jit[1],
            (unsigned long long)rl_jit[2], (unsigned long long)rl_jit[3],
            (unsigned long long)rl_jit[4], (unsigned long long)rl_jit[5],
            (unsigned long long)rl_jit[6], (unsigned long long)rl_jit[7]);
        printf("[%s] JIT vs Interp: %s\n", match ? "PASS" : "FAIL", match ? "MATCH" : "MISMATCH");
    } else {
        printf("[WARN] No JIT function, skipping JIT test\n");
    }

    printf("[I] Testing all 8 programs...\n");
    fflush(stdout);
    for (int p = 0; p < RX_CACHE_ACCESSES; p++) {
        uint64_t ri[8], rj[8];
        base = 1 * ssMul0;
        ri[0] = base; ri[1] = base ^ ssAdd1; ri[2] = base ^ ssAdd2; ri[3] = base ^ ssAdd3;
        ri[4] = base ^ ssAdd4; ri[5] = base ^ ssAdd5; ri[6] = base ^ ssAdd6; ri[7] = base ^ ssAdd7;
        memcpy(rj, ri, 64);

        uint8_t *mix_block = cache->memory + ((ri[0] & DS_CACHE_MASK) << 6);
        uint64_t *ml64 = (uint64_t *)mix_block;
        ri[0] ^= ml64[0]; ri[1] ^= ml64[1]; ri[2] ^= ml64[2]; ri[3] ^= ml64[3];
        ri[4] ^= ml64[4]; ri[5] ^= ml64[5]; ri[6] ^= ml64[6]; ri[7] ^= ml64[7];
        rj[0] ^= ml64[0]; rj[1] ^= ml64[1]; rj[2] ^= ml64[2]; rj[3] ^= ml64[3];
        rj[4] ^= ml64[4]; rj[5] ^= ml64[5]; rj[6] ^= ml64[6]; rj[7] ^= ml64[7];

        ss_execute(ri, &cache->programs[p], cache->reciprocalCache);
        if (cache->programs[p].fn) {
            __try {
                cache->programs[p].fn(rj);
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                printf("[CRASH] Program %d: exception 0x%08X\n", p, GetExceptionCode());
                continue;
            }
            int match = (memcmp(ri, rj, 64) == 0);
            printf("[%s] Program %d: %s\n", match ? "PASS" : "FAIL", p, match ? "MATCH" : "MISMATCH");
            if (!match) {
                printf("  Interp: %016llx %016llx %016llx %016llx\n",
                    (unsigned long long)ri[0], (unsigned long long)ri[1],
                    (unsigned long long)ri[2], (unsigned long long)ri[3]);
                printf("  JIT:    %016llx %016llx %016llx %016llx\n",
                    (unsigned long long)rj[0], (unsigned long long)rj[1],
                    (unsigned long long)rj[2], (unsigned long long)rj[3]);
            }
        }
        fflush(stdout);
    }

    rx_free_cache(cache);
    printf("[I] Done\n");
    return 0;
}
