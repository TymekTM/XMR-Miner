#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <windows.h>
#include "crypto/randomx/randomx_internal.h"

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
        case RX_SS_IMUL_RCP: r[dst] *= reciprocals[instr->imm32]; break;
        }
    }
}

static int crashed_prog = -1;
static int crashed_step = 0;

int main() {
    printf("[TEST] JIT crash isolation test\n");
    fflush(stdout);

    uint8_t seed[32] = {0};
    rx_cache *cache = rx_alloc_cache(0);
    rx_init_cache(cache, seed, 32);
    printf("[I] Cache initialized\n");
    fflush(stdout);

    for (int p = 0; p < RX_CACHE_ACCESSES; p++) {
        printf("\n[Program %d] size=%u addrReg=%d fn=%p\n",
            p, cache->programs[p].size, cache->programs[p].addrReg,
            (void*)cache->programs[p].fn);
        fflush(stdout);

        if (cache->programs[p].fn == NULL) {
            printf("  [SKIP] No JIT function\n");
            continue;
        }

        uint64_t rl_interp[8], rl_jit[8];
        uint64_t base = 1 * ssMul0;
        rl_interp[0] = base;
        rl_interp[1] = base ^ ssAdd1;
        rl_interp[2] = base ^ ssAdd2;
        rl_interp[3] = base ^ ssAdd3;
        rl_interp[4] = base ^ ssAdd4;
        rl_interp[5] = base ^ ssAdd5;
        rl_interp[6] = base ^ ssAdd6;
        rl_interp[7] = base ^ ssAdd7;
        memcpy(rl_jit, rl_interp, 64);

        ss_execute(rl_interp, &cache->programs[p], cache->reciprocalCache);
        printf("  Interp OK: %016llx %016llx %016llx %016llx\n",
            (unsigned long long)rl_interp[0], (unsigned long long)rl_interp[1],
            (unsigned long long)rl_interp[2], (unsigned long long)rl_interp[3]);

        crashed_prog = p;
        crashed_step = 0;

        __try {
            cache->programs[p].fn(rl_jit);
            crashed_prog = -1;
            int match = memcmp(rl_interp, rl_jit, 64) == 0;
            printf("  JIT OK:    %016llx %016llx %016llx %016llx [%s]\n",
                (unsigned long long)rl_jit[0], (unsigned long long)rl_jit[1],
                (unsigned long long)rl_jit[2], (unsigned long long)rl_jit[3],
                match ? "MATCH" : "MISMATCH");
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            printf("  [CRASH!] Exception code: 0x%08X\n", GetExceptionCode());
            printf("  Interp was: %016llx %016llx %016llx %016llx\n",
                (unsigned long long)rl_interp[0], (unsigned long long)rl_interp[1],
                (unsigned long long)rl_interp[2], (unsigned long long)rl_interp[3]);
        }
        fflush(stdout);
    }

    rx_free_cache(cache);
    printf("\n[DONE]\n");
    return 0;
}
