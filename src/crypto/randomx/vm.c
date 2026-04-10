#include "randomx_internal.h"
#include "common/log.h"
#include "crypto/blake2/blake2b.h"
#include <string.h>
#include <stdio.h>

extern void rx_jit_generate_program(rx_jit*, rx_program*, rx_program_config*, rx_cache*);
extern void rx_jit_generate_program_light(rx_jit*, rx_program*, rx_program_config*, rx_cache*, uint32_t);
extern void* rx_jit_get_program_func(rx_jit*);

#ifdef _WIN32
static int enable_lock_pages_privilege(void) {
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return 0;
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!LookupPrivilegeValueA(NULL, SE_LOCK_MEMORY_NAME, &tp.Privileges[0].Luid)) {
        CloseHandle(token);
        return 0;
    }
    int ok = AdjustTokenPrivileges(token, FALSE, &tp, 0, NULL, NULL) && GetLastError() == 0;
    CloseHandle(token);
    return ok;
}
#endif


static __forceinline uint32_t load32_le(const void *p) {
    return *(const uint32_t *)p;
}

static __forceinline uint64_t load64_le(const void *p) {
    return *(const uint64_t *)p;
}

static __forceinline void store64_le(void *p, uint64_t v) { *(uint64_t *)p = v; }

static uint64_t rx_zero_val = 0;

void compile_program(rx_program *prog, rx_bytecode bc[RX_PROGRAM_MAX_SIZE],
                              uint64_t *r, rx_vec_f128 *f, rx_vec_f128 *e, rx_vec_f128 *a) {
    int reg_usage[RX_REGISTERS_COUNT];
    for (int i = 0; i < RX_REGISTERS_COUNT; i++) reg_usage[i] = -1;

    for (unsigned i = 0; i < RX_PROGRAM_MAX_SIZE; i++) {
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

__forceinline void vm_initialize(rx_vm *vm) {
    for (int i = 0; i < RX_REG_FLT_COUNT; i++) {
        uint64_t ent0 = vm->program.entropyBuffer[2 * i];
        uint64_t ent1 = vm->program.entropyBuffer[2 * i + 1];
        uint64_t bits0 = rx_get_small_positive_float_bits(ent0);
        uint64_t bits1 = rx_get_small_positive_float_bits(ent1);
        vm->reg.a[i][0] = *(double *)&bits0;
        vm->reg.a[i][1] = *(double *)&bits1;
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
    vm->config.eMask[0] = rx_get_float_mask(vm->program.entropyBuffer[14]);
    vm->config.eMask[1] = rx_get_float_mask(vm->program.entropyBuffer[15]);
}

void rx_vm_run_n(rx_vm *vm, void *seed, uint32_t iterations) {
    rx_fill_aes4rx4(seed, sizeof(rx_program), &vm->program);
    vm_initialize(vm);

    if (vm->useJit && vm->jit) {
        if (vm->lightClient) {
            rx_jit_generate_program_light(vm->jit, &vm->program, &vm->config, vm->cachePtr, vm->datasetOffset);
        } else {
            rx_jit_generate_program(vm->jit, &vm->program, &vm->config, vm->cachePtr);
        }

        typedef void (*ProgramFunc)(rx_register_file*, rx_memory_regs*, uint8_t*, uint32_t);
        ProgramFunc func = (ProgramFunc)rx_jit_get_program_func(vm->jit);

        if (func) {
            rx_memory_regs memRegs;
            memRegs.mx_ma = vm->mem.mx_ma;
            memRegs.memory = vm->lightClient ? vm->mem.memory : vm->mem.memory + vm->datasetOffset;
            func(&vm->reg, &memRegs, vm->scratchpad, iterations);
            vm->mem.mx_ma = memRegs.mx_ma;
            return;
        }
        vm->useJit = 0;
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

    rx_bytecode bc[RX_PROGRAM_MAX_SIZE];
    int progSize = vm->flagV2 ? RX_PROGRAM_SIZE_V2 : RX_PROGRAM_SIZE_V1;
    compile_program(&vm->program, bc, r, f, e, a);

    uint32_t spAddr0 = (uint32_t)vm->mem.mx_ma;
    uint32_t spAddr1 = (uint32_t)(vm->mem.mx_ma >> 32);
    uint32_t mem_mx = spAddr0;
    uint32_t mem_ma = spAddr1;
    uint8_t * __restrict sp = vm->scratchpad;
    uint8_t * __restrict mem = vm->mem.memory;

    rx_vec_f128 fscal_mask = rx_set1_f128(0x80F0000000000000ULL);
    rx_vec_f128 fdiv_mm = rx_set_f128(RX_DYN_MANTISSA_MASK, RX_DYN_MANTISSA_MASK);
    rx_vec_f128 fdiv_em = rx_load_f128((const double *)vm->config.eMask);

    for (unsigned ic = 0; ic < iterations; ic++) {
        uint64_t spMix = r[vm->config.readReg0] ^ r[vm->config.readReg1];
        spAddr0 ^= (uint32_t)spMix;
        spAddr0 &= RX_SPL3_MASK64;
        spAddr1 ^= (uint32_t)(spMix >> 32);
        spAddr1 &= RX_SPL3_MASK64;

        uint64_t *sp0 = (uint64_t *)(sp + spAddr0);
        uint64_t *sp1 = (uint64_t *)(sp + spAddr1);

        _mm_prefetch((const char *)sp0 + 64, _MM_HINT_T0);
        _mm_prefetch((const char *)sp1 + 64, _MM_HINT_T0);

        {
            __m128i s0 = _mm_loadu_si128((__m128i *)sp0);
            __m128i s1 = _mm_loadu_si128((__m128i *)(sp0 + 2));
            __m128i s2 = _mm_loadu_si128((__m128i *)(sp0 + 4));
            __m128i s3 = _mm_loadu_si128((__m128i *)(sp0 + 6));
            __m128i r0 = _mm_loadu_si128((__m128i *)r);
            __m128i r1 = _mm_loadu_si128((__m128i *)(r + 2));
            __m128i r2 = _mm_loadu_si128((__m128i *)(r + 4));
            __m128i r3 = _mm_loadu_si128((__m128i *)(r + 6));
            _mm_storeu_si128((__m128i *)r, _mm_xor_si128(s0, r0));
            _mm_storeu_si128((__m128i *)(r + 2), _mm_xor_si128(s1, r1));
            _mm_storeu_si128((__m128i *)(r + 4), _mm_xor_si128(s2, r2));
            _mm_storeu_si128((__m128i *)(r + 6), _mm_xor_si128(s3, r3));
        }

        f[0] = rx_cvt_int_f128(&sp1[0]);
        f[1] = rx_cvt_int_f128(&sp1[1]);
        f[2] = rx_cvt_int_f128(&sp1[2]);
        f[3] = rx_cvt_int_f128(&sp1[3]);

        {
            rx_vec_f128 raw0 = rx_cvt_int_f128(&sp1[4]);
            rx_vec_f128 raw1 = rx_cvt_int_f128(&sp1[5]);
            rx_vec_f128 raw2 = rx_cvt_int_f128(&sp1[6]);
            rx_vec_f128 raw3 = rx_cvt_int_f128(&sp1[7]);
            e[0] = rx_or_f128(rx_and_f128(raw0, fdiv_mm), fdiv_em);
            e[1] = rx_or_f128(rx_and_f128(raw1, fdiv_mm), fdiv_em);
            e[2] = rx_or_f128(rx_and_f128(raw2, fdiv_mm), fdiv_em);
            e[3] = rx_or_f128(rx_and_f128(raw3, fdiv_mm), fdiv_em);
        }

        for (int pc = 0; pc < progSize; pc++) {
            rx_bytecode *ibc = &bc[pc];
            switch (ibc->type) {
            case RX_OP_IADD_RS:
                *ibc->idst += (*ibc->isrc << ibc->shift) + ibc->imm;
                break;
            case RX_OP_IADD_M: {
                uint32_t addr = (uint32_t)((*ibc->isrc + ibc->imm) & ibc->memMask);
                *ibc->idst += *(uint64_t *)(sp + addr);
                break;
            }
            case RX_OP_ISUB_R:
                *ibc->idst -= *ibc->isrc;
                break;
            case RX_OP_ISUB_M: {
                uint32_t addr = (uint32_t)((*ibc->isrc + ibc->imm) & ibc->memMask);
                *ibc->idst -= *(uint64_t *)(sp + addr);
                break;
            }
            case RX_OP_IMUL_R:
                *ibc->idst *= *ibc->isrc;
                break;
            case RX_OP_IMUL_M: {
                uint32_t addr = (uint32_t)((*ibc->isrc + ibc->imm) & ibc->memMask);
                *ibc->idst *= *(uint64_t *)(sp + addr);
                break;
            }
            case RX_OP_IMULH_R:
                *ibc->idst = rx_mulh(*ibc->idst, *ibc->isrc);
                break;
            case RX_OP_IMULH_M: {
                uint32_t addr = (uint32_t)((*ibc->isrc + ibc->imm) & ibc->memMask);
                *ibc->idst = rx_mulh(*ibc->idst, *(uint64_t *)(sp + addr));
                break;
            }
            case RX_OP_ISMULH_R:
                *ibc->idst = (uint64_t)rx_smulh((int64_t)*ibc->idst, (int64_t)*ibc->isrc);
                break;
            case RX_OP_ISMULH_M: {
                uint32_t addr = (uint32_t)((*ibc->isrc + ibc->imm) & ibc->memMask);
                *ibc->idst = (uint64_t)rx_smulh((int64_t)*ibc->idst, (int64_t)*(uint64_t *)(sp + addr));
                break;
            }
            case RX_OP_INEG_R:
                *ibc->idst = ~(*ibc->idst) + 1;
                break;
            case RX_OP_IXOR_R:
                *ibc->idst ^= *ibc->isrc;
                break;
            case RX_OP_IXOR_M: {
                uint32_t addr = (uint32_t)((*ibc->isrc + ibc->imm) & ibc->memMask);
                *ibc->idst ^= *(uint64_t *)(sp + addr);
                break;
            }
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
                uint32_t addr = (uint32_t)((*ibc->isrc + ibc->imm) & ibc->memMask);
                rx_vec_f128 fsrc = rx_cvt_int_f128(sp + addr);
                *ibc->fdst = rx_add_f128(*ibc->fdst, fsrc);
                break;
            }
            case RX_OP_FSUB_R:
                *ibc->fdst = rx_sub_f128(*ibc->fdst, *ibc->fsrc);
                break;
            case RX_OP_FSUB_M: {
                uint32_t addr = (uint32_t)((*ibc->isrc + ibc->imm) & ibc->memMask);
                rx_vec_f128 fsrc = rx_cvt_int_f128(sp + addr);
                *ibc->fdst = rx_sub_f128(*ibc->fdst, fsrc);
                break;
            }
            case RX_OP_FSCAL_R:
                *ibc->fdst = rx_xor_f128(*ibc->fdst, fscal_mask);
                break;
            case RX_OP_FMUL_R:
                *ibc->fdst = rx_mul_f128(*ibc->fdst, *ibc->fsrc);
                break;
            case RX_OP_FDIV_M: {
                uint32_t addr = (uint32_t)((*ibc->isrc + ibc->imm) & ibc->memMask);
                rx_vec_f128 fsrc = rx_cvt_int_f128(sp + addr);
                fsrc = rx_or_f128(rx_and_f128(fsrc, fdiv_mm), fdiv_em);
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
                if (!vm->flagV2 || (isrc_val & 60) == 0) {
                    rx_set_rounding_mode((uint32_t)(isrc_val & 3));
                }
                break;
            }
            case RX_OP_ISTORE: {
                uint32_t addr = (uint32_t)((*ibc->idst + ibc->imm) & ibc->memMask);
                *(uint64_t *)(sp + addr) = *ibc->isrc;
                break;
            }
            case RX_OP_NOP:
            default:
                break;
            }
        }

        uint64_t readPtr = vm->datasetOffset + (mem_ma & RX_CACHE_LINE_ALIGN_MASK);
        if (vm->flagV2) {
            mem_ma ^= r[vm->config.readReg2] ^ r[vm->config.readReg3];
        } else {
            mem_mx ^= r[vm->config.readReg2] ^ r[vm->config.readReg3];
        }

        uint32_t prefetchReg = vm->flagV2 ? mem_ma : mem_mx;
        uint64_t prefetchAddr = vm->datasetOffset + (prefetchReg & RX_CACHE_LINE_ALIGN_MASK);
        _mm_prefetch((const char *)(mem + prefetchAddr), _MM_HINT_T0);
        _mm_prefetch((const char *)(mem + prefetchAddr) + 64, _MM_HINT_T2);

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
            __m128i d0 = _mm_load_si128((__m128i *)dsLine);
            __m128i d1 = _mm_load_si128((__m128i *)(dsLine + 2));
            __m128i d2 = _mm_load_si128((__m128i *)(dsLine + 4));
            __m128i d3 = _mm_load_si128((__m128i *)(dsLine + 6));
            __m128i r0 = _mm_loadu_si128((__m128i *)r);
            __m128i r1 = _mm_loadu_si128((__m128i *)(r + 2));
            __m128i r2 = _mm_loadu_si128((__m128i *)(r + 4));
            __m128i r3 = _mm_loadu_si128((__m128i *)(r + 6));
            _mm_storeu_si128((__m128i *)r, _mm_xor_si128(r0, d0));
            _mm_storeu_si128((__m128i *)(r + 2), _mm_xor_si128(r1, d1));
            _mm_storeu_si128((__m128i *)(r + 4), _mm_xor_si128(r2, d2));
            _mm_storeu_si128((__m128i *)(r + 6), _mm_xor_si128(r3, d3));
        }

        uint32_t tmp = mem_mx;
        mem_mx = mem_ma;
        mem_ma = tmp;

        {
            uint64_t *sp1s = (uint64_t *)(sp + spAddr1);
            _mm_storeu_si128((__m128i *)sp1s, _mm_loadu_si128((__m128i *)r));
            _mm_storeu_si128((__m128i *)(sp1s + 2), _mm_loadu_si128((__m128i *)(r + 2)));
            _mm_storeu_si128((__m128i *)(sp1s + 4), _mm_loadu_si128((__m128i *)(r + 4)));
            _mm_storeu_si128((__m128i *)(sp1s + 6), _mm_loadu_si128((__m128i *)(r + 6)));
        }

        if (vm->flagV2) {
            rx_vec_i128 freg[RX_REG_FLT_COUNT];
            rx_vec_i128 ekey;
            for (int i = 0; i < RX_REG_FLT_COUNT; i++)
                freg[i] = rx_cast_f2i(f[i]);
            for (int i = 0; i < RX_REG_FLT_COUNT; i++) {
                ekey = rx_cast_f2i(e[i]);
                freg[0] = _mm_aesenc_si128(freg[0], ekey);
                freg[1] = _mm_aesdec_si128(freg[1], ekey);
                freg[2] = _mm_aesenc_si128(freg[2], ekey);
                freg[3] = _mm_aesdec_si128(freg[3], ekey);
            }
            for (int i = 0; i < RX_REG_FLT_COUNT; i++)
                f[i] = rx_cast_i2f(freg[i]);
        } else {
            f[0] = rx_xor_f128(f[0], e[0]);
            f[1] = rx_xor_f128(f[1], e[1]);
            f[2] = rx_xor_f128(f[2], e[2]);
            f[3] = rx_xor_f128(f[3], e[3]);
        }

        rx_store_f128((double *)(sp + spAddr0), f[0]);
        rx_store_f128((double *)(sp + spAddr0 + 16), f[1]);
        rx_store_f128((double *)(sp + spAddr0 + 32), f[2]);
        rx_store_f128((double *)(sp + spAddr0 + 48), f[3]);

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
}

void rx_vm_run(rx_vm *vm, void *seed) {
    rx_vm_run_n(vm, seed, RX_PROGRAM_ITERATIONS);
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
        rx_blake2b_regfile(vm->tempHash, &vm->reg);
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
        rx_blake2b_regfile(vm->tempHash, &vm->reg);
    }
    rx_vm_run(vm, vm->tempHash);
    rx_blake2b_blob(vm->tempHash, next_input, next_input_size);
    rx_hash_and_fill_aes1rx4(vm->scratchpad, RX_SCRATCHPAD_L3, &vm->reg.a, vm->tempHash);
    blake2b(output, RX_HASH_SIZE, &vm->reg, sizeof(rx_register_file), NULL, 0);
    _mm_setcsr(saved_mxcsr);
}

void rx_calculate_hash_last(rx_vm *vm, void *output) {
    uint32_t saved_mxcsr = _mm_getcsr();
    rx_reset_float_state();
    for (int chain = 0; chain < RX_PROGRAM_COUNT - 1; chain++) {
        rx_vm_run(vm, vm->tempHash);
        rx_blake2b_regfile(vm->tempHash, &vm->reg);
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
    for (int i = 0; i < RX_CACHE_ACCESSES; i++)
        ss_jit_free(&cache->programs[i]);
    free(cache);
}

rx_dataset *rx_alloc_dataset(int large_pages) {
    rx_dataset *ds = (rx_dataset *)calloc(1, sizeof(rx_dataset));
    if (!ds) return NULL;
    ds->large_pages = 0;

    size_t alloc_size = (size_t)RX_DATASET_SIZE;
#ifdef _WIN32
    if (large_pages && enable_lock_pages_privilege()) {
        size_t large_page_min = 2097152;
        size_t aligned_size = ((alloc_size + large_page_min - 1) / large_page_min) * large_page_min;
        ds->memory = (uint8_t *)VirtualAlloc(NULL, aligned_size, MEM_RESERVE | MEM_COMMIT | MEM_LARGE_PAGES, PAGE_READWRITE);
        if (ds->memory) {
            ds->large_pages = 1;
            LOG_INFO("[DATASET] Allocated %.0f MB (LARGE PAGES)", (double)alloc_size / (1024*1024));
        } else {
            LOG_INFO("[DATASET] Large pages failed, using regular pages");
        }
    }
    if (!ds->memory) {
        LOG_INFO("[DATASET] Using regular pages");
        ds->memory = (uint8_t *)VirtualAlloc(NULL, alloc_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (ds->memory) {
            LOG_INFO("[DATASET] Allocated %.0f MB (regular pages)", (double)alloc_size / (1024*1024));
        }
    }
#endif
    if (!ds->memory) { free(ds); return NULL; }
    VirtualLock(ds->memory, alloc_size);
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
#ifdef _WIN32
        LARGE_INTEGER t0, t1, freq;
        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&t0);
        volatile uint8_t touch = 0;
        size_t page_size = 4096;
        size_t total = (size_t)RX_DATASET_SIZE;
        for (size_t i = 0; i < total; i += page_size) {
            touch = ds->memory[i];
        }
        (void)touch;
        QueryPerformanceCounter(&t1);
        double dt = (double)(t1.QuadPart - t0.QuadPart) / freq.QuadPart;
        LOG_INFO("[DATASET] Touched %.0f MB pages (%.1f s)", (double)total / (1024*1024), dt);
#endif
        return;
    }
    rx_init_dataset_internal(ds, cache, start, count, num_threads, num_physical_cores);
    rx_save_dataset_cache(ds, cache->seed, cache->seed_len, start, count);
}

void *rx_get_dataset_memory(rx_dataset *ds) { return ds->memory; }

void rx_free_dataset(rx_dataset *ds) {
    if (!ds) return;
    if (ds->memory) {
        VirtualFree(ds->memory, 0, MEM_RELEASE);
    }
    free(ds);
}

rx_vm *rx_create_vm(int flags, rx_cache *cache, rx_dataset *dataset) {
    rx_vm *vm = (rx_vm *)calloc(1, sizeof(rx_vm));
    if (!vm) return NULL;
    int use_jit = (flags & RX_FLAG_JIT) != 0;
    int large_pages = 1;
    vm->fullMem = (dataset != NULL) ? 1 : 0;
    vm->useJit = use_jit;
    vm->lightClient = (!dataset && cache) ? 1 : 0;
    vm->flagV2 = (flags & RX_FLAG_V2) != 0;
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
    VirtualLock(vm->scratchpad, RX_SCRATCHPAD_L3);
    vm->mxcsrState = RX_MXCSR_DEFAULT;
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

void rx_vm_run_dual(rx_vm *vm1, rx_vm *vm2, void *seed1, void *seed2, uint32_t iterations) {
    rx_fill_aes4rx4(seed1, sizeof(rx_program), &vm1->program);
    rx_fill_aes4rx4(seed2, sizeof(rx_program), &vm2->program);
    
    vm_initialize(vm1);
    vm_initialize(vm2);

    if (vm1->useJit && vm1->jit && vm2->useJit && vm2->jit) {
        extern void rx_jit_generate_program_dual_interleaved(rx_jit*, rx_program*, rx_program_config*, rx_program*, rx_program_config*, rx_cache*);
        extern void* rx_jit_get_program_func(rx_jit*);

        rx_jit_generate_program_dual_interleaved(vm1->jit, &vm1->program, &vm1->config,
                                                  &vm2->program, &vm2->config, vm1->cachePtr);

        typedef void (*DualInterleavedFunc)(RxDualParams*);
        DualInterleavedFunc func = (DualInterleavedFunc)rx_jit_get_program_func(vm1->jit);

        if (func) {
            uint8_t *ds1 = vm1->lightClient ? vm1->mem.memory : vm1->mem.memory + vm1->datasetOffset;
            uint8_t *ds2 = vm2->lightClient ? vm2->mem.memory : vm2->mem.memory + vm2->datasetOffset;

            RxDualParams params;
            params.reg1 = &vm1->reg;
            params.reg2 = &vm2->reg;
            params.mx_ma1 = vm1->mem.mx_ma;
            params.mx_ma2 = vm2->mem.mx_ma;
            params.sp1 = vm1->scratchpad;
            params.sp2 = vm2->scratchpad;
            params.dataset1 = ds1;
            params.dataset2 = ds2;
            params.iterations = iterations;
            params.pad = 0;
            params.mxcsr1 = vm1->mxcsrState;
            params.mxcsr2 = vm2->mxcsrState;

            func(&params);

            vm1->mem.mx_ma = params.mx_ma1;
            vm2->mem.mx_ma = params.mx_ma2;
            vm1->mxcsrState = params.mxcsr1;
            vm2->mxcsrState = params.mxcsr2;
            return;
        }
    }

    rx_vm_run_n(vm1, seed1, iterations);
    rx_vm_run_n(vm2, seed2, iterations);
}

void rx_calculate_hash_dual(rx_vm *vm1, rx_vm *vm2, const void *input1, size_t input1_size, const void *input2, size_t input2_size, void *output1, void *output2) {
    uint32_t saved_mxcsr = _mm_getcsr();

    vm1->mxcsrState = RX_MXCSR_DEFAULT;
    vm2->mxcsrState = RX_MXCSR_DEFAULT;
    
    blake2b(vm1->tempHash, sizeof(vm1->tempHash), input1, input1_size, NULL, 0);
    blake2b(vm2->tempHash, sizeof(vm2->tempHash), input2, input2_size, NULL, 0);
    
    rx_vm_init_scratchpad(vm1, vm1->tempHash);
    rx_vm_init_scratchpad(vm2, vm2->tempHash);
    
    rx_reset_float_state();
    
    for (int chain = 0; chain < RX_PROGRAM_COUNT - 1; chain++) {
        rx_vm_run_dual(vm1, vm2, vm1->tempHash, vm2->tempHash, RX_PROGRAM_ITERATIONS);
        
        blake2b(vm1->tempHash, sizeof(vm1->tempHash), &vm1->reg, sizeof(rx_register_file), NULL, 0);
        blake2b(vm2->tempHash, sizeof(vm2->tempHash), &vm2->reg, sizeof(rx_register_file), NULL, 0);
    }
    
    rx_vm_run_dual(vm1, vm2, vm1->tempHash, vm2->tempHash, RX_PROGRAM_ITERATIONS);
    
    rx_vm_get_final_result(vm1, output1);
    rx_vm_get_final_result(vm2, output2);
    
    _mm_setcsr(saved_mxcsr);
}

void rx_calculate_commitment(const void *input, size_t input_size, const void *hash_in, void *com_out) {
    blake2b_state state;
    blake2b_init(&state, RX_HASH_SIZE);
    blake2b_update(&state, input, input_size);
    blake2b_update(&state, hash_in, RX_HASH_SIZE);
    blake2b_final(&state, com_out, RX_HASH_SIZE);
}
