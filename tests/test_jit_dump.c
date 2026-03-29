#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <windows.h>
#include "crypto/randomx/randomx_internal.h"

int main() {
    printf("[DUMP] Dumping JIT code for all programs\n");
    fflush(stdout);

    uint8_t seed[32] = {0};
    rx_cache *cache = rx_alloc_cache(0);
    rx_init_cache(cache, seed, 32);
    printf("[I] Cache initialized\n");
    fflush(stdout);

    for (int p = 0; p < RX_CACHE_ACCESSES; p++) {
        rx_superscalar_program *prog = &cache->programs[p];
        printf("\n[Program %d] size=%u addrReg=%d fn=%p code=%p code_size=%u\n",
            p, prog->size, prog->addrReg, (void*)prog->fn, (void*)prog->code, 8192);
        fflush(stdout);

        if (!prog->code) {
            printf("  No JIT code\n");
            continue;
        }

        printf("  First 128 bytes of JIT code:\n    ");
        for (int i = 0; i < 128 && i < 8192; i++) {
            printf("%02X ", prog->code[i]);
            if ((i + 1) % 32 == 0) printf("\n    ");
        }
        printf("\n");
        fflush(stdout);

        printf("  Last 16 bytes:\n    ");
        for (int i = 4096 - 16; i < 4096; i++) {
            printf("%02X ", prog->code[i]);
        }
        printf("\n");
        fflush(stdout);

        int has_mulx = 0, has_imul = 0, has_lea = 0, has_smulh = 0;
        for (uint32_t i = 0; i < prog->size; i++) {
            rx_instruction *ins = &prog->buffer[i];
            switch (ins->opcode) {
            case RX_SS_IMULH_R: has_mulx = 1; printf("  [%u] IMULH_R dst=%d src=%d\n", i, ins->dst%8, ins->src%8); break;
            case RX_SS_ISMULH_R: has_smulh = 1; printf("  [%u] ISMULH_R dst=%d src=%d\n", i, ins->dst%8, ins->src%8); break;
            case RX_SS_IADD_RS: if ((ins->mod >> 2) & 3) { has_lea = 1; printf("  [%u] IADD_RS dst=%d src=%d shift=%d\n", i, ins->dst%8, ins->src%8, (ins->mod>>2)&3); } break;
            case RX_SS_IMUL_RCP: has_imul = 1; break;
            }
        }
        printf("  has_mulx=%d has_smulh=%d has_lea=%d has_imul_rcp=%d\n",
            has_mulx, has_smulh, has_lea, has_imul);
        fflush(stdout);

        {
            uint64_t rl[8];
            rl[0] = 12345; rl[1] = 67890; rl[2] = 0xDEAD; rl[3] = 0xBEEF;
            rl[4] = 11111; rl[5] = 22222; rl[6] = 33333; rl[7] = 44444;
            printf("  Calling JIT fn...");
            fflush(stdout);
            __try {
                prog->fn(rl);
                printf(" OK! r0=%016llx\n", (unsigned long long)rl[0]);
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                printf(" CRASH! code=0x%08X\n", GetExceptionCode());
            }
            fflush(stdout);
        }
    }

    for (int i = 0; i < RX_CACHE_ACCESSES; i++)
        ss_jit_free(&cache->programs[i]);
    rx_free_cache(cache);
    printf("[DONE]\n");
    return 0;
}
