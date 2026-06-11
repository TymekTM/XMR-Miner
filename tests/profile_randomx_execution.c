#include "crypto/randomx/randomx.h"
#include "crypto/randomx/randomx_internal.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *op_name[RX_OP_COUNT] = {
    "IADD_RS", "IADD_M", "ISUB_R", "ISUB_M", "IMUL_R", "IMUL_M",
    "IMULH_R", "IMULH_M", "ISMULH_R", "ISMULH_M", "IMUL_RCP",
    "INEG_R", "IXOR_R", "IXOR_M", "IROR_R", "IROL_R", "ISWAP_R",
    "FSWAP_R", "FADD_R", "FADD_M", "FSUB_R", "FSUB_M", "FSCAL_R",
    "FMUL_R", "FDIV_M", "FSQRT_R", "CBRANCH", "CFROUND", "ISTORE",
    "NOP"
};

int main(int argc, char **argv) {
    static const uint8_t key[] = "dynamic profile key";
    int hashes = argc > 1 ? atoi(argv[1]) : 2;
    uint8_t input[76];
    uint8_t output[32];
    rx_execution_profile profile;

    if (hashes < 1) hashes = 1;
    memset(input, 0x42, sizeof(input));
    memset(&profile, 0, sizeof(profile));

    rx_cache *cache = rx_alloc_cache(0);
    if (!cache) {
        printf("[FAIL] cache allocation\n");
        return 1;
    }
    rx_init_cache(cache, key, sizeof(key) - 1);
    rx_vm *vm = rx_create_vm(RX_FLAG_DEFAULT, cache, NULL);
    if (!vm) {
        printf("[FAIL] VM allocation\n");
        rx_free_cache(cache);
        return 1;
    }

    rx_set_execution_profile(&profile);
    for (int i = 0; i < hashes; ++i) {
        memcpy(input + 39, &i, sizeof(i));
        rx_calculate_hash(vm, input, sizeof(input), output);
    }
    rx_set_execution_profile(NULL);

    uint64_t total = 0;
    for (int op = 0; op < RX_OP_COUNT; ++op)
        total += profile.instructions[op];

    printf("RandomX dynamic execution profile: %d hashes\n", hashes);
    printf("  programs:     %llu\n", (unsigned long long)profile.programs);
    printf("  iterations:   %llu\n", (unsigned long long)profile.iterations);
    printf("  instructions: %llu (%.1f/iteration)\n",
           (unsigned long long)total,
           profile.iterations ? (double)total / profile.iterations : 0.0);
    printf("  branches:     %llu, taken %llu (%.2f%%)\n",
           (unsigned long long)profile.branches,
           (unsigned long long)profile.branches_taken,
           profile.branches ? 100.0 * profile.branches_taken / profile.branches : 0.0);

    for (int op = 0; op < RX_OP_COUNT; ++op) {
        if (profile.instructions[op]) {
            printf("  %-10s %12llu %6.2f%%\n", op_name[op],
                   (unsigned long long)profile.instructions[op],
                   total ? 100.0 * profile.instructions[op] / total : 0.0);
        }
    }

    printf("  hottest branch PCs:\n");
    for (int rank = 0; rank < 12; ++rank) {
        int best = -1;
        for (int pc = 0; pc < RX_PROGRAM_SIZE_V1; ++pc) {
            if (profile.branch_pc[pc] &&
                (best < 0 || profile.branch_pc[pc] > profile.branch_pc[best])) {
                best = pc;
            }
        }
        if (best < 0) break;
        printf("    pc %3d: %10llu, taken %6.2f%%\n", best,
               (unsigned long long)profile.branch_pc[best],
               100.0 * profile.branch_taken_pc[best] / profile.branch_pc[best]);
        profile.branch_pc[best] = 0;
    }

    rx_destroy_vm(vm);
    rx_free_cache(cache);
    return 0;
}
