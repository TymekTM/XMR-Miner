#include "randomx_internal.h"
#include "common/log.h"
#include <string.h>
#include <excpt.h>

static inline uint32_t load32_le(const void *p) {
    uint32_t v;
    memcpy(&v, p, 4);
    return v;
}

static inline uint64_t load64_le(const void *p) {
    uint64_t v;
    memcpy(&v, p, 8);
    return v;
}

static inline void store64_le(void *p, uint64_t v) { memcpy(p, &v, 8); }

static uint64_t rx_zero_val = 0;

static inline void *get_sp_addr(rx_bytecode *ibc, uint8_t *sp) {
    uint32_t addr = (uint32_t)((*ibc->isrc + ibc->imm) & ibc->memMask);
    return sp + addr;
}

static void mask_reg_exp_mantissa(rx_program_config *cfg, rx_vec_f128 *x) {
    rx_vec_f128 mm = rx_set_f128(RX_DYN_MANTISSA_MASK, RX_DYN_MANTISSA_MASK);
    rx_vec_f128 em = rx_load_f128((const double *)cfg->eMask);
    *x = rx_and_f128(*x, mm);
    *x = rx_or_f128(*x, em);
}

static void compile_program(rx_program *prog, rx_bytecode bc[RX_PROGRAM_SIZE],
                             uint64_t *r, rx_vec_f128 *f, rx_vec_f128 *e, rx_vec_f128 *a) {
    int reg_usage[RX_REGISTERS_COUNT];
    for (int i = 0; i < RX_REGISTERS_COUNT; i++) reg_usage[i] = -1;

    for (unsigned i = 0; i < RX_PROGRAM_SIZE; i++) {
        rx_instruction *instr = &prog->programBuffer[i];
        rx_bytecode *ibc = &bc[i];
        int opcode = instr->opcode;
        int dst, src;

        if (opcode < RX_CEIL_RX_IADD_RS) {
            dst = instr->dst % RX_REGISTERS_COUNT;
            src = instr->src % RX_REGISTERS_COUNT;
            ibc->type = RX_OP_IADD_RS;
            ibc->idst = &r[dst];
            ibc->isrc = &r[src];
            ibc->shift = (instr->mod >> 2) & 3;
            ibc->imm = (dst == 5) ? rx_sign_extend_32(load32_le(&instr->imm32)) : 0;
            reg_usage[dst] = i;
            continue;
        }
        if (opcode < RX_CEIL_RX_IADD_M) {
            dst = instr->dst % RX_REGISTERS_COUNT;
            src = instr->src % RX_REGISTERS_COUNT;
            ibc->type = RX_OP_IADD_M;
            ibc->idst = &r[dst];
            ibc->imm = rx_sign_extend_32(load32_le(&instr->imm32));
            if (src != dst) {
                ibc->isrc = &r[src];
                ibc->memMask = ((instr->mod & 3) != 0) ? RX_SPL1_MASK : RX_SPL2_MASK;
            } else {
                ibc->isrc = &rx_zero_val;
                ibc->memMask = RX_SPL3_MASK;
            }
            reg_usage[dst] = i;
            continue;
        }
        if (opcode < RX_CEIL_RX_ISUB_R) {
            dst = instr->dst % RX_REGISTERS_COUNT;
            src = instr->src % RX_REGISTERS_COUNT;
            ibc->type = RX_OP_ISUB_R;
            ibc->idst = &r[dst];
            if (src != dst) {
                ibc->isrc = &r[src];
            } else {
                ibc->imm = rx_sign_extend_32(load32_le(&instr->imm32));
                ibc->isrc = &ibc->imm;
            }
            reg_usage[dst] = i;
            continue;
        }
        if (opcode < RX_CEIL_RX_ISUB_M) {
            dst = instr->dst % RX_REGISTERS_COUNT;
            src = instr->src % RX_REGISTERS_COUNT;
            ibc->type = RX_OP_ISUB_M;
            ibc->idst = &r[dst];
            ibc->imm = rx_sign_extend_32(load32_le(&instr->imm32));
            if (src != dst) {
                ibc->isrc = &r[src];
                ibc->memMask = ((instr->mod & 3) != 0) ? RX_SPL1_MASK : RX_SPL2_MASK;
            } else {
                ibc->isrc = &rx_zero_val;
                ibc->memMask = RX_SPL3_MASK;
            }
            reg_usage[dst] = i;
            continue;
        }
        if (opcode < RX_CEIL_RX_IMUL_R) {
            dst = instr->dst % RX_REGISTERS_COUNT;
            src = instr->src % RX_REGISTERS_COUNT;
            ibc->type = RX_OP_IMUL_R;
            ibc->idst = &r[dst];
            if (src != dst) {
                ibc->isrc = &r[src];
            } else {
                ibc->imm = rx_sign_extend_32(load32_le(&instr->imm32));
                ibc->isrc = &ibc->imm;
            }
            reg_usage[dst] = i;
            continue;
        }
        if (opcode < RX_CEIL_RX_IMUL_M) {
            dst = instr->dst % RX_REGISTERS_COUNT;
            src = instr->src % RX_REGISTERS_COUNT;
            ibc->type = RX_OP_IMUL_M;
            ibc->idst = &r[dst];
            ibc->imm = rx_sign_extend_32(load32_le(&instr->imm32));
            if (src != dst) {
                ibc->isrc = &r[src];
                ibc->memMask = ((instr->mod & 3) != 0) ? RX_SPL1_MASK : RX_SPL2_MASK;
            } else {
                ibc->isrc = &rx_zero_val;
                ibc->memMask = RX_SPL3_MASK;
            }
            reg_usage[dst] = i;
            continue;
        }
        if (opcode < RX_CEIL_RX_IMULH_R) {
            dst = instr->dst % RX_REGISTERS_COUNT;
            src = instr->src % RX_REGISTERS_COUNT;
            ibc->type = RX_OP_IMULH_R;
            ibc->idst = &r[dst];
            ibc->isrc = &r[src];
            reg_usage[dst] = i;
            continue;
        }
        if (opcode < RX_CEIL_RX_IMULH_M) {
            dst = instr->dst % RX_REGISTERS_COUNT;
            src = instr->src % RX_REGISTERS_COUNT;
            ibc->type = RX_OP_IMULH_M;
            ibc->idst = &r[dst];
            ibc->imm = rx_sign_extend_32(load32_le(&instr->imm32));
            if (src != dst) {
                ibc->isrc = &r[src];
                ibc->memMask = ((instr->mod & 3) != 0) ? RX_SPL1_MASK : RX_SPL2_MASK;
            } else {
                ibc->isrc = &rx_zero_val;
                ibc->memMask = RX_SPL3_MASK;
            }
            reg_usage[dst] = i;
            continue;
        }
        if (opcode < RX_CEIL_RX_ISMULH_R) {
            dst = instr->dst % RX_REGISTERS_COUNT;
            src = instr->src % RX_REGISTERS_COUNT;
            ibc->type = RX_OP_ISMULH_R;
            ibc->idst = &r[dst];
            ibc->isrc = &r[src];
            reg_usage[dst] = i;
            continue;
        }
        if (opcode < RX_CEIL_RX_ISMULH_M) {
            dst = instr->dst % RX_REGISTERS_COUNT;
            src = instr->src % RX_REGISTERS_COUNT;
            ibc->type = RX_OP_ISMULH_M;
            ibc->idst = &r[dst];
            ibc->imm = rx_sign_extend_32(load32_le(&instr->imm32));
            if (src != dst) {
                ibc->isrc = &r[src];
                ibc->memMask = ((instr->mod & 3) != 0) ? RX_SPL1_MASK : RX_SPL2_MASK;
            } else {
                ibc->isrc = &rx_zero_val;
                ibc->memMask = RX_SPL3_MASK;
            }
            reg_usage[dst] = i;
            continue;
        }
        if (opcode < RX_CEIL_RX_IMUL_RCP) {
            uint32_t divisor = load32_le(&instr->imm32);
            if (!is_zero_or_power_of_2(divisor)) {
                dst = instr->dst % RX_REGISTERS_COUNT;
                ibc->type = RX_OP_IMUL_R;
                ibc->idst = &r[dst];
                ibc->imm = rx_reciprocal(divisor);
                ibc->isrc = &ibc->imm;
                reg_usage[dst] = i;
            } else {
                ibc->type = RX_OP_NOP;
            }
            continue;
        }
        if (opcode < RX_CEIL_RX_INEG_R) {
            dst = instr->dst % RX_REGISTERS_COUNT;
            ibc->type = RX_OP_INEG_R;
            ibc->idst = &r[dst];
            reg_usage[dst] = i;
            continue;
        }
        if (opcode < RX_CEIL_RX_IXOR_R) {
            dst = instr->dst % RX_REGISTERS_COUNT;
            src = instr->src % RX_REGISTERS_COUNT;
            ibc->type = RX_OP_IXOR_R;
            ibc->idst = &r[dst];
            if (src != dst) {
                ibc->isrc = &r[src];
            } else {
                ibc->imm = rx_sign_extend_32(load32_le(&instr->imm32));
                ibc->isrc = &ibc->imm;
            }
            reg_usage[dst] = i;
            continue;
        }
        if (opcode < RX_CEIL_RX_IXOR_M) {
            dst = instr->dst % RX_REGISTERS_COUNT;
            src = instr->src % RX_REGISTERS_COUNT;
            ibc->type = RX_OP_IXOR_M;
            ibc->idst = &r[dst];
            ibc->imm = rx_sign_extend_32(load32_le(&instr->imm32));
            if (src != dst) {
                ibc->isrc = &r[src];
                ibc->memMask = ((instr->mod & 3) != 0) ? RX_SPL1_MASK : RX_SPL2_MASK;
            } else {
                ibc->isrc = &rx_zero_val;
                ibc->memMask = RX_SPL3_MASK;
            }
            reg_usage[dst] = i;
            continue;
        }
        if (opcode < RX_CEIL_RX_IROR_R) {
            dst = instr->dst % RX_REGISTERS_COUNT;
            src = instr->src % RX_REGISTERS_COUNT;
            ibc->type = RX_OP_IROR_R;
            ibc->idst = &r[dst];
            if (src != dst) {
                ibc->isrc = &r[src];
            } else {
                ibc->imm = load32_le(&instr->imm32);
                ibc->isrc = &ibc->imm;
            }
            reg_usage[dst] = i;
            continue;
        }
        if (opcode < RX_CEIL_RX_IROL_R) {
            dst = instr->dst % RX_REGISTERS_COUNT;
            src = instr->src % RX_REGISTERS_COUNT;
            ibc->type = RX_OP_IROL_R;
            ibc->idst = &r[dst];
            if (src != dst) {
                ibc->isrc = &r[src];
            } else {
                ibc->imm = load32_le(&instr->imm32);
                ibc->isrc = &ibc->imm;
            }
            reg_usage[dst] = i;
            continue;
        }
        if (opcode < RX_CEIL_RX_ISWAP_R) {
            dst = instr->dst % RX_REGISTERS_COUNT;
            src = instr->src % RX_REGISTERS_COUNT;
            if (src != dst) {
                ibc->type = RX_OP_ISWAP_R;
                ibc->idst = &r[dst];
                ibc->isrc = &r[src];
                reg_usage[dst] = i;
                reg_usage[src] = i;
            } else {
                ibc->type = RX_OP_NOP;
            }
            continue;
        }
        if (opcode < RX_CEIL_RX_FSWAP_R) {
            dst = instr->dst % RX_REGISTERS_COUNT;
            ibc->type = RX_OP_FSWAP_R;
            if (dst < RX_REG_FLT_COUNT)
                ibc->fdst = &f[dst];
            else
                ibc->fdst = &e[dst - RX_REG_FLT_COUNT];
            continue;
        }
        if (opcode < RX_CEIL_RX_FADD_R) {
            dst = instr->dst % RX_REG_FLT_COUNT;
            src = instr->src % RX_REG_FLT_COUNT;
            ibc->type = RX_OP_FADD_R;
            ibc->fdst = &f[dst];
            ibc->fsrc = &a[src];
            continue;
        }
        if (opcode < RX_CEIL_RX_FADD_M) {
            dst = instr->dst % RX_REG_FLT_COUNT;
            src = instr->src % RX_REGISTERS_COUNT;
            ibc->type = RX_OP_FADD_M;
            ibc->fdst = &f[dst];
            ibc->isrc = &r[src];
            ibc->memMask = ((instr->mod & 3) != 0) ? RX_SPL1_MASK : RX_SPL2_MASK;
            ibc->imm = rx_sign_extend_32(load32_le(&instr->imm32));
            continue;
        }
        if (opcode < RX_CEIL_RX_FSUB_R) {
            dst = instr->dst % RX_REG_FLT_COUNT;
            src = instr->src % RX_REG_FLT_COUNT;
            ibc->type = RX_OP_FSUB_R;
            ibc->fdst = &f[dst];
            ibc->fsrc = &a[src];
            continue;
        }
        if (opcode < RX_CEIL_RX_FSUB_M) {
            dst = instr->dst % RX_REG_FLT_COUNT;
            src = instr->src % RX_REGISTERS_COUNT;
            ibc->type = RX_OP_FSUB_M;
            ibc->fdst = &f[dst];
            ibc->isrc = &r[src];
            ibc->memMask = ((instr->mod & 3) != 0) ? RX_SPL1_MASK : RX_SPL2_MASK;
            ibc->imm = rx_sign_extend_32(load32_le(&instr->imm32));
            continue;
        }
        if (opcode < RX_CEIL_RX_FSCAL_R) {
            dst = instr->dst % RX_REG_FLT_COUNT;
            ibc->type = RX_OP_FSCAL_R;
            ibc->fdst = &f[dst];
            continue;
        }
        if (opcode < RX_CEIL_RX_FMUL_R) {
            dst = instr->dst % RX_REG_FLT_COUNT;
            src = instr->src % RX_REG_FLT_COUNT;
            ibc->type = RX_OP_FMUL_R;
            ibc->fdst = &e[dst];
            ibc->fsrc = &a[src];
            continue;
        }
        if (opcode < RX_CEIL_RX_FDIV_M) {
            dst = instr->dst % RX_REG_FLT_COUNT;
            src = instr->src % RX_REGISTERS_COUNT;
            ibc->type = RX_OP_FDIV_M;
            ibc->fdst = &e[dst];
            ibc->isrc = &r[src];
            ibc->memMask = ((instr->mod & 3) != 0) ? RX_SPL1_MASK : RX_SPL2_MASK;
            ibc->imm = rx_sign_extend_32(load32_le(&instr->imm32));
            continue;
        }
        if (opcode < RX_CEIL_RX_FSQRT_R) {
            dst = instr->dst % RX_REG_FLT_COUNT;
            ibc->type = RX_OP_FSQRT_R;
            ibc->fdst = &e[dst];
            continue;
        }
        if (opcode < RX_CEIL_RX_CBRANCH) {
            int creg = instr->dst % RX_REGISTERS_COUNT;
            ibc->type = RX_OP_CBRANCH;
            ibc->idst = &r[creg];
            ibc->target = reg_usage[creg];
            int shift = (instr->mod >> 4) + RX_JUMP_OFFSET;
            ibc->imm = rx_sign_extend_32(load32_le(&instr->imm32)) | (1ULL << shift);
            if (shift > 0) ibc->imm &= ~(1ULL << (shift - 1));
            ibc->memMask = RX_CONDITION_MASK << shift;
            for (int j = 0; j < RX_REGISTERS_COUNT; j++) reg_usage[j] = i;
            continue;
        }
        if (opcode < RX_CEIL_RX_CFROUND) {
            src = instr->src % RX_REGISTERS_COUNT;
            ibc->type = RX_OP_CFROUND;
            ibc->isrc = &r[src];
            ibc->imm = load32_le(&instr->imm32) & 63;
            continue;
        }
        if (opcode < RX_CEIL_RX_ISTORE) {
            dst = instr->dst % RX_REGISTERS_COUNT;
            src = instr->src % RX_REGISTERS_COUNT;
            ibc->type = RX_OP_ISTORE;
            ibc->idst = &r[dst];
            ibc->isrc = &r[src];
            ibc->imm = rx_sign_extend_32(load32_le(&instr->imm32));
            int mod_cond = instr->mod >> 4;
            if (mod_cond < RX_STORE_L3_COND)
                ibc->memMask = ((instr->mod & 3) != 0) ? RX_SPL1_MASK : RX_SPL2_MASK;
            else
                ibc->memMask = RX_SPL3_MASK;
            continue;
        }
        ibc->type = RX_OP_NOP;
    }
}

static void vm_initialize(rx_vm *vm) {
    for (int i = 0; i < RX_REG_FLT_COUNT; i++) {
        uint64_t ent0 = vm->program.entropyBuffer[2 * i];
        uint64_t ent1 = vm->program.entropyBuffer[2 * i + 1];
        uint64_t bits0 = rx_get_small_positive_float_bits(ent0);
        uint64_t bits1 = rx_get_small_positive_float_bits(ent1);
        store64_le((uint8_t *)&vm->reg.a[i][0], bits0);
        store64_le((uint8_t *)&vm->reg.a[i][1], bits1);
    }
    uint32_t mem_ma = (uint32_t)(vm->program.entropyBuffer[8] & RX_CACHE_LINE_ALIGN_MASK);
    uint32_t mem_mx = (uint32_t)vm->program.entropyBuffer[10];
    vm->mem.mx_ma = ((uint64_t)mem_ma << 32) | mem_mx;
    uint64_t addrRegs = vm->program.entropyBuffer[12];
    vm->config.readReg0 = 0 + (int)(addrRegs & 1);
    addrRegs >>= 1;
    vm->config.readReg1 = 2 + (int)(addrRegs & 1);
    addrRegs >>= 1;
    vm->config.readReg2 = 4 + (int)(addrRegs & 1);
    addrRegs >>= 1;
    vm->config.readReg3 = 6 + (int)(addrRegs & 1);
    vm->datasetOffset = (uint32_t)(vm->program.entropyBuffer[13] % (RX_DATASET_EXTRA_ITEMS + 1)) * RX_CACHE_LINE_SIZE;
    store64_le((uint8_t *)&vm->config.eMask[0], rx_get_float_mask(vm->program.entropyBuffer[14]));
    store64_le((uint8_t *)&vm->config.eMask[1], rx_get_float_mask(vm->program.entropyBuffer[15]));
}

void rx_vm_run(rx_vm *vm, void *seed) {
    rx_fill_aes4rx4(seed, sizeof(rx_program), &vm->program);
    vm_initialize(vm);

    if (0 && vm->useJit && vm->jit) {  // DISABLED: JIT complex and crashes in light mode
        __try {
            extern void rx_jit_generate_program(rx_jit*, rx_program*, rx_program_config*, rx_cache*);
            extern void rx_jit_generate_program_light(rx_jit*, rx_program*, rx_program_config*, rx_cache*, uint32_t);
            extern void* rx_jit_get_program_func(rx_jit*);
            if (vm->lightClient) {
                printf("[DEBUG] Generating light program...\n"); fflush(stdout);
                rx_jit_generate_program_light(vm->jit, &vm->program, &vm->config, vm->cachePtr, vm->datasetOffset);
                printf("[DEBUG] Light program generated OK\n"); fflush(stdout);
            } else {
                printf("[DEBUG] Generating full program...\n"); fflush(stdout);
                rx_jit_generate_program(vm->jit, &vm->program, &vm->config, vm->cachePtr);
                printf("[DEBUG] Full program generated OK\n"); fflush(stdout);
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            printf("[ERROR] Exception during JIT generation: 0x%08lx\n", GetExceptionCode());
            vm->useJit = 0;
        }

        printf("[DEBUG] Getting function pointer (code at %p)...\n", rx_jit_get_program_func(vm->jit)); fflush(stdout);
        typedef void (*ProgramFunc)(rx_register_file*, rx_memory_regs*, uint8_t*, uint32_t);
        extern void* rx_jit_get_program_func(rx_jit*);
        ProgramFunc func = (ProgramFunc)rx_jit_get_program_func(vm->jit);

        if (!func) {
            printf("[ERROR] JIT function pointer is NULL!\n");
            vm->useJit = 0;
        } else {
            printf("[DEBUG] Function pointer: %p\n", (void*)func);
            printf("[DEBUG] First 8 bytes of code: %02x %02x %02x %02x %02x %02x %02x %02x\n",
                ((uint8_t*)func)[0], ((uint8_t*)func)[1], ((uint8_t*)func)[2], ((uint8_t*)func)[3],
                ((uint8_t*)func)[4], ((uint8_t*)func)[5], ((uint8_t*)func)[6], ((uint8_t*)func)[7]);

            __try {
                rx_memory_regs memRegs;
                memRegs.mx_ma = vm->mem.mx_ma;
                memRegs.memory = vm->lightClient ? vm->mem.memory : vm->mem.memory + vm->datasetOffset;
                printf("[DEBUG] memRegs.mx_ma = 0x%llx\n", memRegs.mx_ma);
                printf("[DEBUG] memRegs.memory = %p\n", memRegs.memory);
                printf("[DEBUG] scratchpad = %p\n", vm->scratchpad);
                printf("[DEBUG] RX_PROGRAM_ITERATIONS = %u\n", RX_PROGRAM_ITERATIONS);
                printf("[DEBUG] Calling JIT function...\n"); fflush(stdout);
                func(&vm->reg, &memRegs, vm->scratchpad, RX_PROGRAM_ITERATIONS);
                printf("[DEBUG] JIT function returned OK\n"); fflush(stdout);
                vm->mem.mx_ma = memRegs.mx_ma;
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                printf("[ERROR] Exception during JIT execution: 0x%08lx\n", GetExceptionCode());
                vm->useJit = 0;
            }
        }
        if (vm->useJit) { return; }
    }

    uint64_t r[RX_REGISTERS_COUNT];
    rx_vec_f128 f[RX_REG_FLT_COUNT];
    rx_vec_f128 e[RX_REG_FLT_COUNT];
    rx_vec_f128 a[RX_REG_FLT_COUNT];

    for (int i = 0; i < RX_REG_FLT_COUNT; i++) {
        a[i] = rx_load_f128(&vm->reg.a[i][0]);
        f[i] = rx_load_f128(&vm->reg.f[i][0]);
        e[i] = rx_load_f128(&vm->reg.e[i][0]);
    }
    memset(r, 0, sizeof(r));

    rx_bytecode bc[RX_PROGRAM_SIZE];
    compile_program(&vm->program, bc, r, f, e, a);

    uint32_t spAddr0 = (uint32_t)vm->mem.mx_ma;
    uint32_t spAddr1 = (uint32_t)(vm->mem.mx_ma >> 32);
    uint32_t mem_mx = spAddr0;
    uint32_t mem_ma = spAddr1;
    uint8_t *sp = vm->scratchpad;
    uint8_t *mem = vm->mem.memory;

    for (unsigned ic = 0; ic < RX_PROGRAM_ITERATIONS; ic++) {
        uint64_t spMix = r[vm->config.readReg0] ^ r[vm->config.readReg1];
        spAddr0 ^= (uint32_t)spMix;
        spAddr0 &= RX_SPL3_MASK64;
        spAddr1 ^= (uint32_t)(spMix >> 32);
        spAddr1 &= RX_SPL3_MASK64;

        for (unsigned i = 0; i < RX_REGISTERS_COUNT; i++)
            r[i] ^= load64_le(sp + spAddr0 + 8 * i);

        for (unsigned i = 0; i < RX_REG_FLT_COUNT; i++)
            f[i] = rx_cvt_int_f128(sp + spAddr1 + 8 * i);

        for (unsigned i = 0; i < RX_REG_FLT_COUNT; i++) {
            rx_vec_f128 raw = rx_cvt_int_f128(sp + spAddr1 + 8 * (RX_REG_FLT_COUNT + i));
            mask_reg_exp_mantissa(&vm->config, &raw);
            e[i] = raw;
        }

        rx_vec_f128 fscal_mask = rx_set1_f128(0x80F0000000000000ULL);
        for (int pc = 0; pc < RX_PROGRAM_SIZE; pc++) {
            rx_bytecode *ibc = &bc[pc];
            switch (ibc->type) {
            case RX_OP_IADD_RS:
                *ibc->idst += (*ibc->isrc << ibc->shift) + ibc->imm;
                break;
            case RX_OP_IADD_M:
                *ibc->idst += load64_le(get_sp_addr(ibc, sp));
                break;
            case RX_OP_ISUB_R:
                *ibc->idst -= *ibc->isrc;
                break;
            case RX_OP_ISUB_M:
                *ibc->idst -= load64_le(get_sp_addr(ibc, sp));
                break;
            case RX_OP_IMUL_R:
                *ibc->idst *= *ibc->isrc;
                break;
            case RX_OP_IMUL_M:
                *ibc->idst *= load64_le(get_sp_addr(ibc, sp));
                break;
            case RX_OP_IMULH_R:
                *ibc->idst = rx_mulh(*ibc->idst, *ibc->isrc);
                break;
            case RX_OP_IMULH_M:
                *ibc->idst = rx_mulh(*ibc->idst, load64_le(get_sp_addr(ibc, sp)));
                break;
            case RX_OP_ISMULH_R:
                *ibc->idst = (uint64_t)rx_smulh(rx_u64_to_s64(*ibc->idst), rx_u64_to_s64(*ibc->isrc));
                break;
            case RX_OP_ISMULH_M:
                *ibc->idst = (uint64_t)rx_smulh(rx_u64_to_s64(*ibc->idst), rx_u64_to_s64(load64_le(get_sp_addr(ibc, sp))));
                break;
            case RX_OP_INEG_R:
                *ibc->idst = ~(*ibc->idst) + 1;
                break;
            case RX_OP_IXOR_R:
                *ibc->idst ^= *ibc->isrc;
                break;
            case RX_OP_IXOR_M:
                *ibc->idst ^= load64_le(get_sp_addr(ibc, sp));
                break;
            case RX_OP_IROR_R:
                *ibc->idst = rx_rotr(*ibc->idst, *ibc->isrc & 63);
                break;
            case RX_OP_IROL_R:
                *ibc->idst = rx_rotl(*ibc->idst, *ibc->isrc & 63);
                break;
            case RX_OP_ISWAP_R: {
                uint64_t tmp = *ibc->isrc;
                *ibc->isrc = *ibc->idst;
                *ibc->idst = tmp;
                break;
            }
            case RX_OP_FSWAP_R:
                *ibc->fdst = rx_swap_f128(*ibc->fdst);
                break;
            case RX_OP_FADD_R:
                *ibc->fdst = rx_add_f128(*ibc->fdst, *ibc->fsrc);
                break;
            case RX_OP_FADD_M: {
                rx_vec_f128 fsrc = rx_cvt_int_f128(get_sp_addr(ibc, sp));
                *ibc->fdst = rx_add_f128(*ibc->fdst, fsrc);
                break;
            }
            case RX_OP_FSUB_R:
                *ibc->fdst = rx_sub_f128(*ibc->fdst, *ibc->fsrc);
                break;
            case RX_OP_FSUB_M: {
                rx_vec_f128 fsrc = rx_cvt_int_f128(get_sp_addr(ibc, sp));
                *ibc->fdst = rx_sub_f128(*ibc->fdst, fsrc);
                break;
            }
            case RX_OP_FSCAL_R: {
                *ibc->fdst = rx_xor_f128(*ibc->fdst, fscal_mask);
                break;
            }
            case RX_OP_FMUL_R:
                *ibc->fdst = rx_mul_f128(*ibc->fdst, *ibc->fsrc);
                break;
            case RX_OP_FDIV_M: {
                rx_vec_f128 fsrc = rx_cvt_int_f128(get_sp_addr(ibc, sp));
                mask_reg_exp_mantissa(&vm->config, &fsrc);
                *ibc->fdst = rx_div_f128(*ibc->fdst, fsrc);
                break;
            }
            case RX_OP_FSQRT_R:
                *ibc->fdst = rx_sqrt_f128(*ibc->fdst);
                break;
            case RX_OP_CBRANCH:
                *ibc->idst += ibc->imm;
                if ((*ibc->idst & ibc->memMask) == 0) {
                    pc = ibc->target;
                }
                break;
            case RX_OP_CFROUND: {
                uint64_t isrc_val = rx_rotr(*ibc->isrc, (unsigned int)ibc->imm);
                rx_set_rounding_mode((uint32_t)(isrc_val & 3));
                break;
            }
            case RX_OP_ISTORE:
                store64_le(sp + ((*ibc->idst + ibc->imm) & ibc->memMask), *ibc->isrc);
                break;
            case RX_OP_NOP:
            default:
                break;
            }
        }

        uint64_t readPtr = vm->datasetOffset + (mem_ma & RX_CACHE_LINE_ALIGN_MASK);
        mem_mx ^= r[vm->config.readReg2] ^ r[vm->config.readReg3];

        uint64_t prefetchAddr = vm->datasetOffset + (mem_mx & RX_CACHE_LINE_ALIGN_MASK);
        _mm_prefetch((const char *)(mem + prefetchAddr), _MM_HINT_NTA);

        if (vm->lightClient) {
            uint64_t lcPtr = readPtr;
            lcPtr -= lcPtr % RX_CACHE_LINE_SIZE;
            uint64_t itemNum = lcPtr / RX_CACHE_LINE_SIZE;
            rx_init_dataset_item(vm->cachePtr, vm->datasetItem, itemNum);
            uint64_t *dsLine = (uint64_t *)vm->datasetItem;
            for (int i = 0; i < RX_REGISTERS_COUNT; i++)
                r[i] ^= dsLine[i];
        } else {
            uint64_t *dsLine = (uint64_t *)(mem + readPtr);
            for (int i = 0; i < RX_REGISTERS_COUNT; i++)
                r[i] ^= dsLine[i];
        }

        uint32_t tmp = mem_mx;
        mem_mx = mem_ma;
        mem_ma = tmp;

        for (unsigned i = 0; i < RX_REGISTERS_COUNT; i++)
            store64_le(sp + spAddr1 + 8 * i, r[i]);

        for (unsigned i = 0; i < RX_REG_FLT_COUNT; i++)
            f[i] = rx_xor_f128(f[i], e[i]);

        for (unsigned i = 0; i < RX_REG_FLT_COUNT; i++)
            rx_store_f128((double *)(sp + spAddr0 + 16 * i), f[i]);

        spAddr0 = 0;
        spAddr1 = 0;
    }

    memcpy(vm->reg.r, r, sizeof(r));
    for (int i = 0; i < RX_REG_FLT_COUNT; i++) {
        rx_store_f128(&vm->reg.f[i][0], f[i]);
        rx_store_f128(&vm->reg.e[i][0], e[i]);
    }
}

void rx_vm_init_scratchpad(rx_vm *vm, void *seed) {
    rx_fill_aes1rx4(seed, RX_SCRATCHPAD_L3, vm->scratchpad);
    _mm_sfence();
}

void rx_vm_get_final_result(rx_vm *vm, void *out) {
    rx_hash_aes1rx4(vm->scratchpad, RX_SCRATCHPAD_L3, &vm->reg.a);
    blake2b(out, RX_HASH_SIZE, &vm->reg, sizeof(rx_register_file), NULL, 0);
}

void rx_calculate_hash(rx_vm *vm, const void *input, size_t input_size, void *output) {
    uint32_t saved_mxcsr = _mm_getcsr();
    blake2b(vm->tempHash, sizeof(vm->tempHash), input, input_size, NULL, 0);
    rx_vm_init_scratchpad(vm, vm->tempHash);
    rx_reset_float_state();
    for (int chain = 0; chain < RX_PROGRAM_COUNT - 1; chain++) {
        rx_vm_run(vm, vm->tempHash);
        blake2b(vm->tempHash, sizeof(vm->tempHash), &vm->reg, sizeof(rx_register_file), NULL, 0);
    }
    rx_vm_run(vm, vm->tempHash);
    rx_vm_get_final_result(vm, output);
    _mm_setcsr(saved_mxcsr);
}

void rx_calculate_hash_first(rx_vm *vm, const void *input, size_t input_size) {
    uint32_t saved_mxcsr = _mm_getcsr();
    blake2b(vm->tempHash, sizeof(vm->tempHash), input, input_size, NULL, 0);
    rx_vm_init_scratchpad(vm, vm->tempHash);
    _mm_setcsr(saved_mxcsr);
}

void rx_calculate_hash_next(rx_vm *vm, const void *next_input, size_t next_input_size, void *output) {
    uint32_t saved_mxcsr = _mm_getcsr();
    rx_reset_float_state();
    for (int chain = 0; chain < RX_PROGRAM_COUNT - 1; chain++) {
        rx_vm_run(vm, vm->tempHash);
        blake2b(vm->tempHash, sizeof(vm->tempHash), &vm->reg, sizeof(rx_register_file), NULL, 0);
    }
    rx_vm_run(vm, vm->tempHash);
    blake2b(vm->tempHash, sizeof(vm->tempHash), next_input, next_input_size, NULL, 0);
    rx_hash_and_fill_aes1rx4(vm->scratchpad, RX_SCRATCHPAD_L3, &vm->reg.a, vm->tempHash);
    blake2b(output, RX_HASH_SIZE, &vm->reg, sizeof(rx_register_file), NULL, 0);
    _mm_setcsr(saved_mxcsr);
}

void rx_calculate_hash_last(rx_vm *vm, void *output) {
    uint32_t saved_mxcsr = _mm_getcsr();
    rx_reset_float_state();
    for (int chain = 0; chain < RX_PROGRAM_COUNT - 1; chain++) {
        rx_vm_run(vm, vm->tempHash);
        blake2b(vm->tempHash, sizeof(vm->tempHash), &vm->reg, sizeof(rx_register_file), NULL, 0);
    }
    rx_vm_run(vm, vm->tempHash);
    rx_vm_get_final_result(vm, output);
    _mm_setcsr(saved_mxcsr);
}

rx_cache *rx_alloc_cache(int large_pages) {
    rx_cache *c = (rx_cache *)calloc(1, sizeof(rx_cache));
    if (!c) return NULL;
    c->large_pages = large_pages;
    if (large_pages) {
        c->memory = (uint8_t *)VirtualAlloc(NULL, RX_CACHE_SIZE, MEM_RESERVE | MEM_COMMIT | MEM_LARGE_PAGES, PAGE_READWRITE);
        if (!c->memory) c->large_pages = 0;
    }
    if (!c->memory)
        c->memory = (uint8_t *)calloc(1, RX_CACHE_SIZE);
    if (!c->memory) { free(c); return NULL; }
    return c;
}

void rx_init_cache(rx_cache *cache, const void *key, size_t key_size) {
    rx_init_cache_internal(cache, key, key_size);
}

void *rx_get_cache_memory(rx_cache *cache) { return cache->memory; }

void rx_free_cache(rx_cache *cache) {
    if (!cache) return;
    if (cache->memory) {
        if (cache->large_pages)
            VirtualFree(cache->memory, 0, MEM_RELEASE);
        else
            free(cache->memory);
    }
    if (cache->reciprocalCache) free(cache->reciprocalCache);
    free(cache);
}

rx_dataset *rx_alloc_dataset(int large_pages) {
    rx_dataset *ds = (rx_dataset *)calloc(1, sizeof(rx_dataset));
    if (!ds) return NULL;
    ds->large_pages = large_pages;
    if (large_pages) {
        ds->memory = (uint8_t *)VirtualAlloc(NULL, (size_t)RX_DATASET_SIZE, MEM_RESERVE | MEM_COMMIT | MEM_LARGE_PAGES, PAGE_READWRITE);
        if (!ds->memory) ds->large_pages = 0;
    }
    if (!ds->memory)
        ds->memory = (uint8_t *)calloc(1, (size_t)RX_DATASET_SIZE);
    if (!ds->memory) { free(ds); return NULL; }
    return ds;
}

void rx_init_dataset(rx_dataset *ds, rx_cache *cache, uint32_t start, uint32_t count, int num_threads, int num_physical_cores) {
    rx_init_dataset_internal(ds, cache, start, count, num_threads, num_physical_cores);
}

extern int rx_try_load_dataset_cache(rx_dataset *ds, const uint8_t *seed, size_t seed_len,
                                       uint32_t start_item, uint32_t count);
extern int rx_save_dataset_cache(rx_dataset *ds, const uint8_t *seed, size_t seed_len,
                                   uint32_t start_item, uint32_t count);

void rx_init_dataset_cached(rx_dataset *ds, rx_cache *cache, uint32_t start, uint32_t count,
                              int num_threads, int num_physical_cores) {
    if (rx_try_load_dataset_cache(ds, cache->seed, cache->seed_len, start, count)) {
        return;
    }
    rx_init_dataset_internal(ds, cache, start, count, num_threads, num_physical_cores);
    rx_save_dataset_cache(ds, cache->seed, cache->seed_len, start, count);
}

void *rx_get_dataset_memory(rx_dataset *ds) { return ds->memory; }

void rx_free_dataset(rx_dataset *ds) {
    if (!ds) return;
    if (ds->memory) {
        if (ds->large_pages)
            VirtualFree(ds->memory, 0, MEM_RELEASE);
        else
            free(ds->memory);
    }
    free(ds);
}

rx_vm *rx_create_vm(int full_mem, int use_jit, int large_pages, rx_cache *cache, rx_dataset *dataset) {
    rx_vm *vm = (rx_vm *)calloc(1, sizeof(rx_vm));
    if (!vm) return NULL;
    vm->fullMem = full_mem;
    vm->useJit = use_jit;
    vm->lightClient = (!dataset && cache) ? 1 : 0;
    vm->cachePtr = cache;
    vm->datasetPtr = dataset;
    if (dataset) vm->mem.memory = dataset->memory;
    else if (cache) vm->mem.memory = cache->memory;
    vm->scratchpad = NULL;
    vm->large_pages = 0;
    if (large_pages) {
        vm->scratchpad = (uint8_t *)VirtualAlloc(NULL, RX_SCRATCHPAD_L3, MEM_RESERVE | MEM_COMMIT | MEM_LARGE_PAGES, PAGE_READWRITE);
        if (vm->scratchpad) vm->large_pages = 1;
    }
    if (!vm->scratchpad)
        vm->scratchpad = (uint8_t *)_aligned_malloc(RX_SCRATCHPAD_L3, 64);
    if (!vm->scratchpad) { free(vm); return NULL; }
    if (use_jit) {
        extern rx_jit *rx_jit_create(void);
        vm->jit = rx_jit_create();
    }
    return vm;
}

void rx_destroy_vm(rx_vm *vm) {
    if (!vm) return;
    if (vm->scratchpad) {
        if (vm->large_pages)
            VirtualFree(vm->scratchpad, 0, MEM_RELEASE);
        else
            _aligned_free(vm->scratchpad);
    }
    if (vm->jit) {
        extern void rx_jit_destroy(rx_jit *jit);
        rx_jit_destroy(vm->jit);
    }
    free(vm);
}
