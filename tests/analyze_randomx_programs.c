#include "crypto/randomx/randomx_internal.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern rx_jit *rx_jit_create(void);
extern void rx_jit_destroy(rx_jit *jit);
extern void rx_jit_generate_program(rx_jit *jit, rx_program *prog,
                                    rx_program_config *config, rx_cache *cache);
extern int rx_jit_get_short_branch_count(rx_jit *jit);
extern int rx_jit_get_generated_code_size(rx_jit *jit);
extern void compile_program(rx_program *prog,
                            rx_bytecode bytecode[RX_PROGRAM_MAX_SIZE],
                            uint64_t *r, rx_vec_f128 *f,
                            rx_vec_f128 *e, rx_vec_f128 *a);

static int vector_index(rx_vec_f128 *pointer, rx_vec_f128 *base) {
    uintptr_t address = (uintptr_t)pointer;
    uintptr_t start = (uintptr_t)base;
    uintptr_t end = start + sizeof(rx_vec_f128) * RX_REG_FLT_COUNT;
    if (address >= start && address < end &&
        ((address - start) % sizeof(rx_vec_f128)) == 0) {
        return (int)((address - start) / sizeof(rx_vec_f128));
    }
    return -1;
}

static int opcode_type(uint8_t opcode) {
    if (opcode < RX_CEIL_RX_IADD_RS) return RX_OP_IADD_RS;
    if (opcode < RX_CEIL_RX_IADD_M) return RX_OP_IADD_M;
    if (opcode < RX_CEIL_RX_ISUB_R) return RX_OP_ISUB_R;
    if (opcode < RX_CEIL_RX_ISUB_M) return RX_OP_ISUB_M;
    if (opcode < RX_CEIL_RX_IMUL_R) return RX_OP_IMUL_R;
    if (opcode < RX_CEIL_RX_IMUL_M) return RX_OP_IMUL_M;
    if (opcode < RX_CEIL_RX_IMULH_R) return RX_OP_IMULH_R;
    if (opcode < RX_CEIL_RX_IMULH_M) return RX_OP_IMULH_M;
    if (opcode < RX_CEIL_RX_ISMULH_R) return RX_OP_ISMULH_R;
    if (opcode < RX_CEIL_RX_ISMULH_M) return RX_OP_ISMULH_M;
    if (opcode < RX_CEIL_RX_IMUL_RCP) return RX_OP_IMUL_RCP;
    if (opcode < RX_CEIL_RX_INEG_R) return RX_OP_INEG_R;
    if (opcode < RX_CEIL_RX_IXOR_R) return RX_OP_IXOR_R;
    if (opcode < RX_CEIL_RX_IXOR_M) return RX_OP_IXOR_M;
    if (opcode < RX_CEIL_RX_IROR_R) return RX_OP_IROR_R;
    if (opcode < RX_CEIL_RX_IROL_R) return RX_OP_IROL_R;
    if (opcode < RX_CEIL_RX_ISWAP_R) return RX_OP_ISWAP_R;
    if (opcode < RX_CEIL_RX_FSWAP_R) return RX_OP_FSWAP_R;
    if (opcode < RX_CEIL_RX_FADD_R) return RX_OP_FADD_R;
    if (opcode < RX_CEIL_RX_FADD_M) return RX_OP_FADD_M;
    if (opcode < RX_CEIL_RX_FSUB_R) return RX_OP_FSUB_R;
    if (opcode < RX_CEIL_RX_FSUB_M) return RX_OP_FSUB_M;
    if (opcode < RX_CEIL_RX_FSCAL_R) return RX_OP_FSCAL_R;
    if (opcode < RX_CEIL_RX_FMUL_R) return RX_OP_FMUL_R;
    if (opcode < RX_CEIL_RX_FDIV_M) return RX_OP_FDIV_M;
    if (opcode < RX_CEIL_RX_FSQRT_R) return RX_OP_FSQRT_R;
    if (opcode < RX_CEIL_RX_CBRANCH) return RX_OP_CBRANCH;
    if (opcode < RX_CEIL_RX_CFROUND) return RX_OP_CFROUND;
    if (opcode < RX_CEIL_RX_ISTORE) return RX_OP_ISTORE;
    return RX_OP_NOP;
}

int main(int argc, char **argv) {
    int programs = 100000;
    uint64_t total_branches = 0;
    uint64_t short_branches = 0;
    uint64_t invalid_reciprocals = 0;
    uint64_t self_swaps = 0;
    uint64_t zero_rotates = 0;
    uint64_t adjacent_fscal_pairs = 0;
    uint64_t adjacent_fswap_pairs = 0;
    uint64_t safe_fscal_pairs = 0;
    uint64_t safe_fswap_pairs = 0;
    uint64_t total_code_size = 0;
    int min_code_size = INT32_MAX;
    int max_code_size = 0;
    rx_jit *jit = rx_jit_create();

    if (argc > 1) {
        programs = atoi(argv[1]);
    }
    if (programs < 1 || !jit) {
        printf("[FAIL] invalid program count or JIT allocation\n");
        return 1;
    }

    for (int p = 0; p < programs; ++p) {
        uint64_t seed[8] = {
            UINT64_C(0x0123456789abcdef) ^ (uint64_t)p,
            UINT64_C(0xfedcba9876543210) + (uint64_t)p,
            UINT64_C(0x9e3779b97f4a7c15) * ((uint64_t)p + 1)
        };
        rx_program program;
        rx_program_config config;
        rx_bytecode bytecode[RX_PROGRAM_MAX_SIZE];
        uint64_t r[RX_REGISTERS_COUNT] = {0};
        rx_vec_f128 f[RX_REG_FLT_COUNT] = {0};
        rx_vec_f128 e[RX_REG_FLT_COUNT] = {0};
        rx_vec_f128 a[RX_REG_FLT_COUNT] = {0};
        uint8_t branch_target[RX_PROGRAM_SIZE_V1] = {0};
        int pending_fscal[RX_REG_FLT_COUNT] = {-1, -1, -1, -1};
        int pending_fswap_f[RX_REG_FLT_COUNT] = {-1, -1, -1, -1};
        int pending_fswap_e[RX_REG_FLT_COUNT] = {-1, -1, -1, -1};

        rx_fill_aes4rx4(seed, sizeof(program), &program);
        memset(&config, 0, sizeof(config));
        config.eMask[0] = rx_get_float_mask(program.entropyBuffer[14]);
        config.eMask[1] = rx_get_float_mask(program.entropyBuffer[15]);
        compile_program(&program, bytecode, r, f, e, a);
        for (int i = 0; i < RX_PROGRAM_SIZE_V1; ++i) {
            if (bytecode[i].type == RX_OP_CBRANCH) {
                int target = bytecode[i].target + 1;
                if (target >= 0 && target < RX_PROGRAM_SIZE_V1) {
                    branch_target[target] = 1;
                }
            }
        }

        for (int i = 0; i < RX_PROGRAM_SIZE_V1; ++i) {
            rx_instruction *instr = &program.programBuffer[i];
            int type = opcode_type(instr->opcode);
            int dst = instr->dst % RX_REGISTERS_COUNT;
            int src = instr->src % RX_REGISTERS_COUNT;

            if (type == RX_OP_CBRANCH) {
                total_branches++;
            } else if (type == RX_OP_IMUL_RCP &&
                       is_zero_or_power_of_2(instr->imm32)) {
                invalid_reciprocals++;
            } else if (type == RX_OP_ISWAP_R && dst == src) {
                self_swaps++;
            } else if ((type == RX_OP_IROR_R || type == RX_OP_IROL_R) &&
                       dst == src && (instr->imm32 & 63) == 0) {
                zero_rotates++;
            }

            if (i > 0) {
                rx_instruction *previous = &program.programBuffer[i - 1];
                int previous_type = opcode_type(previous->opcode);
                if (type == RX_OP_FSCAL_R && previous_type == RX_OP_FSCAL_R &&
                    (instr->dst % RX_REG_FLT_COUNT) ==
                    (previous->dst % RX_REG_FLT_COUNT)) {
                    adjacent_fscal_pairs++;
                }
                if (type == RX_OP_FSWAP_R && previous_type == RX_OP_FSWAP_R &&
                    (instr->dst % RX_REGISTERS_COUNT) ==
                    (previous->dst % RX_REGISTERS_COUNT)) {
                    adjacent_fswap_pairs++;
                }
            }

            if (branch_target[i] || type == RX_OP_CBRANCH) {
                for (int reg = 0; reg < RX_REG_FLT_COUNT; ++reg) {
                    pending_fscal[reg] = -1;
                    pending_fswap_f[reg] = -1;
                    pending_fswap_e[reg] = -1;
                }
            }

            int f_dst = vector_index(bytecode[i].fdst, f);
            int e_dst = vector_index(bytecode[i].fdst, e);
            if (type == RX_OP_FSCAL_R && f_dst >= 0) {
                if (pending_fscal[f_dst] >= 0) {
                    safe_fscal_pairs++;
                    pending_fscal[f_dst] = -1;
                } else {
                    pending_fscal[f_dst] = i;
                }
                pending_fswap_f[f_dst] = -1;
            } else if (type == RX_OP_FSWAP_R) {
                if (f_dst >= 0) {
                    if (pending_fswap_f[f_dst] >= 0) {
                        safe_fswap_pairs++;
                        pending_fswap_f[f_dst] = -1;
                    } else {
                        pending_fswap_f[f_dst] = i;
                    }
                    pending_fscal[f_dst] = -1;
                } else if (e_dst >= 0) {
                    if (pending_fswap_e[e_dst] >= 0) {
                        safe_fswap_pairs++;
                        pending_fswap_e[e_dst] = -1;
                    } else {
                        pending_fswap_e[e_dst] = i;
                    }
                }
            } else {
                if (f_dst >= 0) {
                    pending_fscal[f_dst] = -1;
                    pending_fswap_f[f_dst] = -1;
                }
                if (e_dst >= 0) {
                    pending_fswap_e[e_dst] = -1;
                }
            }
        }

        rx_jit_generate_program(jit, &program, &config, NULL);
        short_branches += (uint64_t)rx_jit_get_short_branch_count(jit);
        int code_size = rx_jit_get_generated_code_size(jit);
        total_code_size += (uint64_t)code_size;
        if (code_size < min_code_size) min_code_size = code_size;
        if (code_size > max_code_size) max_code_size = code_size;
    }

    printf("RandomX V1 program analysis: %d programs\n", programs);
    printf("  CBRANCH:          %llu total, %.3f/program\n",
           (unsigned long long)total_branches,
           (double)total_branches / programs);
    printf("  short CBRANCH:    %llu (%.2f%%)\n",
           (unsigned long long)short_branches,
           total_branches ? 100.0 * short_branches / total_branches : 0.0);
    printf("  generated code:   %.1f bytes avg, %d min, %d max\n",
           (double)total_code_size / programs, min_code_size, max_code_size);
    printf("  invalid IMUL_RCP: %llu (already removed)\n",
           (unsigned long long)invalid_reciprocals);
    printf("  self ISWAP:       %llu (already removed)\n",
           (unsigned long long)self_swaps);
    printf("  zero rotate:      %llu candidate identities\n",
           (unsigned long long)zero_rotates);
    printf("  FSCAL pairs:      %llu adjacent cancellations\n",
           (unsigned long long)adjacent_fscal_pairs);
    printf("  FSWAP pairs:      %llu adjacent cancellations\n",
           (unsigned long long)adjacent_fswap_pairs);
    printf("  safe FSCAL pairs: %llu path-safe cancellations\n",
           (unsigned long long)safe_fscal_pairs);
    printf("  safe FSWAP pairs: %llu path-safe cancellations\n",
           (unsigned long long)safe_fswap_pairs);

    rx_jit_destroy(jit);
    return 0;
}
