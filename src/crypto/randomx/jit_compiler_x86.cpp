#include "randomx_internal.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>


#define RX_DATASET_BASE_MASK  (RX_DATASET_BASE_SIZE - 64)
#define RX_CACHE_MASK         ((RX_ARGON_MEMORY * 16) - 1)
#define RX_SCRATCHPAD_MASK    (RX_SCRATCHPAD_L3 - 64)
#define RX_CODE_ALIGN         4096
#define RX_MAX_INSTR_CODE     64
#define RX_SUPER_INSTR_MAX    20
#define RX_SUPER_PROG_HDR     128
#define RX_PROGRAM_CODE_SIZE  (((RX_CODE_ALIGN + RX_MAX_INSTR_CODE * RX_PROGRAM_SIZE - 1) / RX_CODE_ALIGN + 1) * RX_CODE_ALIGN)
#define RX_SUPER_CODE_SIZE    (((RX_CODE_ALIGN + (RX_SUPER_PROG_HDR + RX_SUPER_INSTR_MAX * RX_SUPERSCALAR_MAX_SIZE) * RX_CACHE_ACCESSES - 1) / RX_CODE_ALIGN + 1) * RX_CODE_ALIGN)
#define RX_TOTAL_CODE_SIZE    (RX_PROGRAM_CODE_SIZE + RX_SUPER_CODE_SIZE)
#define RX_SUPER_OFFSET       RX_PROGRAM_CODE_SIZE
#define RX_REGISTER_NEEDS_SIB     4
#define RX_REGISTER_NEEDS_DISP    5
#define RX_CONDITION_OFFSET       8
#define RX_STORE_L3_CONDITION     14

static const int PROLOGUE_SIZE = 211;
static const int FIRST_LOAD_SIZE = 72;
static const int CONSTANTS_SIZE = 48;
static const int IMUL_RCP_SIZE = 188;
static const int LOOP_LOAD_SIZE = 152;
static const int PREFETCH_SP_SIZE = 26;
static const int LOOP_STORE_SIZE = 76;
static const int READ_DATASET_SIZE = 66;
static const int EPILOGUE_SIZE = 184;
static const int EMASK_OFFSET_IN_CONSTANTS = 16;

static const uint8_t code_prologue[] = {
    0x53, 0x55, 0x57, 0x56, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x81, 0xec, 0x50,
    0x00, 0x00, 0x00, 0xf3, 0x0f, 0x7f, 0x74, 0x24, 0x40, 0xf3, 0x0f, 0x7f, 0x7c, 0x24, 0x30, 0xf3,
    0x44, 0x0f, 0x7f, 0x44, 0x24, 0x20, 0xf3, 0x44, 0x0f, 0x7f, 0x4c, 0x24, 0x10, 0xf3, 0x44, 0x0f,
    0x7f, 0x54, 0x24, 0x00, 0x48, 0x81, 0xec, 0x50, 0x00, 0x00, 0x00, 0xf3, 0x44, 0x0f, 0x7f, 0x5c,
    0x24, 0x40, 0xf3, 0x44, 0x0f, 0x7f, 0x64, 0x24, 0x30, 0xf3, 0x44, 0x0f, 0x7f, 0x6c, 0x24, 0x20,
    0xf3, 0x44, 0x0f, 0x7f, 0x74, 0x24, 0x10, 0xf3, 0x44, 0x0f, 0x7f, 0x7c, 0x24, 0x00,
    0x51, 0x52,
    0x48,
    0x8b, 0x2a, 0x48, 0x8b, 0x7a, 0x08, 0x48, 0x8b, 0xc5, 0x48, 0xc1, 0xe8, 0x20, 0x25, 0xc0, 0xff,
    0xff, 0x7f, 0x0f, 0x18, 0x04, 0x07, 0x4c, 0x89, 0xc6, 0x49, 0x8b, 0xd9, 0x48, 0x8b, 0xc5, 0x48,
    0xc1, 0xcd, 0x20, 0x4d, 0x33, 0xc0, 0x4d, 0x33, 0xc9, 0x4d, 0x33, 0xd2, 0x4d, 0x33, 0xdb, 0x4d,
    0x33, 0xe4, 0x4d, 0x33, 0xed, 0x4d, 0x33, 0xf6, 0x4d, 0x33, 0xff, 0x48, 0x8d, 0x49, 0x78, 0x66,
    0x44, 0x0f, 0x28, 0x41, 0x48, 0x66, 0x44, 0x0f, 0x28, 0x49, 0x58, 0x66, 0x44, 0x0f, 0x28, 0x51,
    0x68, 0x66, 0x44, 0x0f, 0x28, 0x59, 0x78, 0x66, 0x44, 0x0f, 0x28, 0x2d, 0x00, 0x00, 0x00, 0x00,
    0x66, 0x44, 0x0f, 0x28, 0x35, 0x00, 0x00, 0x00, 0x00, 0x66, 0x44, 0x0f, 0x28, 0x3d, 0x00, 0x00,
    0x00, 0x00,
};

static const uint8_t code_first_load[] = {
    0x48, 0x8b, 0xd0, 0x25, 0xc0, 0xff, 0x1f, 0x00,     0x48, 0xc1, 0xca, 0x20, 0x81, 0xe2, 0xc0, 0xff,
    0x1f, 0x00, 0x48, 0x81, 0xec, 0x28, 0x00, 0x00, 0x00, 0xc7, 0x04, 0x24, 0xc0, 0x9f, 0x00, 0x00,
    0xc7, 0x44, 0x24, 0x04, 0xc0, 0xbf, 0x00, 0x00, 0xc7, 0x44, 0x24, 0x08, 0xc0, 0xdf, 0x00, 0x00,
    0xc7, 0x44, 0x24, 0x0c, 0xc0, 0xff, 0x00, 0x00, 0xc7, 0x44, 0x24, 0x20, 0xff, 0xff, 0xff, 0xff,
    0x90, 0x90, 0x90, 0xe9, 0x00, 0x00, 0x00, 0x00,
};

static const uint8_t code_constants[] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x80,
};

static const uint8_t code_imul_rcp[] = {
    0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x51, 0x48, 0xb9, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x51, 0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x51, 0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x51, 0x48, 0xb9, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x51, 0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x51, 0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x51, 0x48, 0xb9, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x51, 0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x51, 0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x51, 0x48, 0xb9,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x51, 0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x51, 0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x51, 0x48,
    0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x51, 0x48, 0xb9, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x51, 0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x51,
    0x48, 0x81, 0xc4, 0x80, 0x00, 0x00, 0x00, 0xe9, 0x00, 0x00, 0x00, 0x00,
};

static const uint8_t code_loop_load[] = {
    0x48, 0x8d, 0x0c, 0x06, 0x48, 0x89, 0x4c, 0x24, 0x10, 0x4c, 0x33, 0x01, 0x4c, 0x33, 0x49, 0x08,
    0x4c, 0x33, 0x51, 0x10, 0x4c, 0x33, 0x59, 0x18, 0x4c, 0x33, 0x61, 0x20, 0x4c, 0x33, 0x69, 0x28,
    0x4c, 0x33, 0x71, 0x30, 0x4c, 0x33, 0x79, 0x38, 0x48, 0x8d, 0x0c, 0x16, 0x48, 0x89, 0x4c, 0x24,
    0x18,
    0xf3, 0x0f, 0x7e, 0x01, 0xf3, 0x0f, 0xe6, 0xc0,
    0xf3, 0x0f, 0x7e, 0x49, 0x08, 0xf3, 0x0f, 0xe6, 0xc9,
    0xf3, 0x0f, 0x7e, 0x51, 0x10, 0xf3, 0x0f, 0xe6, 0xd2,
    0xf3, 0x0f, 0x7e, 0x59, 0x18, 0xf3, 0x0f, 0xe6, 0xdb,
    0xf3, 0x0f, 0x7e, 0x61, 0x20, 0xf3, 0x0f, 0xe6, 0xe4,
    0xf3, 0x0f, 0x7e, 0x69, 0x28, 0xf3, 0x0f, 0xe6, 0xed,
    0xf3, 0x0f, 0x7e, 0x71, 0x30, 0xf3, 0x0f, 0xe6, 0xf6,
    0xf3, 0x0f, 0x7e, 0x79, 0x38, 0xf3, 0x0f, 0xe6, 0xff,
    0x41, 0x0f, 0x54, 0xe5, 0x41, 0x0f, 0x54, 0xed,
    0x41, 0x0f, 0x54, 0xf5, 0x41, 0x0f, 0x54, 0xfd, 0x41, 0x0f, 0x56, 0xe6, 0x41, 0x0f, 0x56, 0xee,
    0x41, 0x0f, 0x56, 0xf6, 0x41, 0x0f, 0x56, 0xfe,
};

static const uint8_t code_prefetch_sp[] = {
    0x48, 0x8b, 0xd0, 0x25, 0xc0, 0xff, 0x1f, 0x00,     0x0f, 0x18, 0x0c, 0x06, 0x48, 0xc1, 0xca, 0x20,
    0x81, 0xe2, 0xc0, 0xff, 0x1f, 0x00, 0x0f, 0x18, 0x0c, 0x16,
};

static const uint8_t code_loop_store[] = {
    0x48, 0x8b, 0x4c, 0x24, 0x18, 0x4c, 0x89, 0x01, 0x4c, 0x89, 0x49, 0x08, 0x4c, 0x89, 0x51, 0x10,
    0x4c, 0x89, 0x59, 0x18, 0x4c, 0x89, 0x61, 0x20, 0x4c, 0x89, 0x69, 0x28, 0x4c, 0x89, 0x71, 0x30,
    0x4c, 0x89, 0x79, 0x38, 0x48, 0x8b, 0x4c, 0x24, 0x10, 0x66, 0x0f, 0x57, 0xc4, 0x66, 0x0f, 0x57,
    0xcd, 0x66, 0x0f, 0x57, 0xd6, 0x66, 0x0f, 0x57, 0xdf, 0x66, 0x0f, 0x29, 0x01, 0x66, 0x0f, 0x29,
    0x49, 0x10, 0x66, 0x0f, 0x29, 0x51, 0x20, 0x66, 0x0f, 0x29, 0x59, 0x30,
};

static const uint8_t code_read_dataset[] = {
    0x89, 0xcd, 0x81, 0xe1, 0xc0, 0xff, 0xff, 0x7f,     0x4c, 0x33, 0x04, 0x0f, 0x48, 0xc1, 0xcd, 0x20,
    0x48, 0x33, 0xe8, 0x8b, 0xd5, 0x81, 0xe2, 0xc0, 0xff, 0xff, 0x7f, 0x0f, 0x18, 0x04, 0x17, 0x4c,
    0x33, 0x4c, 0x0f, 0x08, 0x4c, 0x33, 0x54, 0x0f, 0x10, 0x4c, 0x33, 0x5c, 0x0f, 0x18, 0x4c, 0x33,
    0x64, 0x0f, 0x20, 0x4c, 0x33, 0x6c, 0x0f, 0x28, 0x4c, 0x33, 0x74, 0x0f, 0x30, 0x4c, 0x33, 0x7c,
    0x0f, 0x38,
};

static const uint8_t code_epilogue[] = {
    0x48, 0x81, 0xc4, 0x28, 0x00, 0x00, 0x00, 0x5a, 0x59, 0x4c, 0x89, 0x01, 0x4c, 0x89, 0x49, 0x08,
    0x4c, 0x89, 0x51, 0x10, 0x4c, 0x89, 0x59, 0x18, 0x4c, 0x89, 0x61, 0x20, 0x4c, 0x89, 0x69, 0x28,
    0x4c, 0x89, 0x71, 0x30, 0x4c, 0x89, 0x79, 0x38, 0x66, 0x0f, 0x7f, 0x41, 0x40, 0x66, 0x0f, 0x7f,
    0x49, 0x50, 0x66, 0x0f, 0x7f, 0x51, 0x60, 0x66, 0x0f, 0x7f, 0x59, 0x70, 0x48, 0x8d, 0x49, 0x40,
    0x66, 0x0f, 0x7f, 0x61, 0x40, 0x66, 0x0f, 0x7f, 0x69, 0x50, 0x66, 0x0f, 0x7f, 0x71, 0x60, 0x66,
    0x0f, 0x7f, 0x79, 0x70, 0x48, 0x89, 0x2a,
    0xf3, 0x44, 0x0f, 0x6f, 0x7c, 0x24, 0x00,
    0xf3, 0x44, 0x0f, 0x6f, 0x74, 0x24, 0x10,
    0xf3, 0x44, 0x0f, 0x6f, 0x6c, 0x24, 0x20,
    0xf3, 0x44, 0x0f, 0x6f, 0x64, 0x24, 0x30,
    0xf3, 0x44, 0x0f, 0x6f, 0x5c, 0x24, 0x40,
    0x48, 0x81, 0xc4, 0x50, 0x00, 0x00, 0x00,
    0xf3, 0x44, 0x0f, 0x6f, 0x54, 0x24, 0x00,
    0xf3, 0x44, 0x0f, 0x6f, 0x4c, 0x24, 0x10,
    0xf3, 0x44, 0x0f, 0x6f, 0x44, 0x24, 0x20,
    0xf3, 0x0f, 0x6f, 0x7c, 0x24, 0x30,
    0xf3, 0x0f, 0x6f, 0x74, 0x24, 0x40,
    0x48, 0x81, 0xc4, 0x50, 0x00, 0x00, 0x00,
    0x41, 0x5f, 0x41, 0x5e, 0x41, 0x5d, 0x41, 0x5c, 0x5e, 0x5f, 0x5d, 0x5b,
    0xc3, 0x90, 0x90,
};


static const int EPILOGUE_OFFSET = RX_PROGRAM_CODE_SIZE + RX_SUPER_CODE_SIZE - EPILOGUE_SIZE;

static uint64_t randomx_reciprocal_fast_impl(uint32_t divisor);

static inline uint32_t align_up(uint32_t val, uint32_t align) {
    return (val + align - 1) & ~(align - 1);
}

struct JitCompiler {
    uint8_t* code;
    int32_t pos;
    int32_t instructionOffsets[RX_PROGRAM_SIZE]; int instructionCount;
    int registerUsage[RX_REGISTERS_COUNT];
    rx_cache* cache;
    rx_cache* superscalar_cache;

    void emitByte(uint8_t b) { code[pos++] = b; }
    void emit32(uint32_t v) { memcpy(code + pos, &v, 4); pos += 4; }
    void emit64(uint64_t v) { memcpy(code + pos, &v, 8); pos += 8; }
    void emit(const uint8_t* src, int len) { memcpy(code + pos, src, len); pos += len; }

    void alignCode(int align) {
        while (pos % align) {
            int n = align - (pos % align);
            if (n > 8) n = 8;
            static const int nopLen[] = {1,2,3,4,5,6,7,8};
            static const uint8_t nopBytes[][8] = {
                {0x90},
                {0x66,0x90},
                {0x66,0x66,0x90},
                {0x0F,0x1F,0x00},
                {0x0F,0x1F,0x40,0x00},
                {0x0F,0x1F,0x44,0x00,0x00},
                {0x66,0x0F,0x1F,0x44,0x00,0x00},
                {0x0F,0x1F,0x80,0x00,0x00,0x00,0x00},
            };
            int idx = n - 1;
            if (idx >= 8) idx = 7;
            for (int i = 0; i < nopLen[idx] && pos % align; i++)
                emitByte(nopBytes[idx][i]);
        }
    }

    int32_t getImm32(rx_instruction* instr) {
        uint32_t v;
        memcpy(&v, &instr->imm32, 4);
        return (int32_t)v;
    }

    int getModShift(rx_instruction* instr) { return (instr->mod >> 2) & 3; }
    int getModCond(rx_instruction* instr) { return instr->mod >> 4; }
    int getModMem(rx_instruction* instr) { return instr->mod & 3; }

    void genSIB(int scale, int index, int base) {
        emitByte((scale << 6) | ((index & 7) << 3) | (base & 7));
    }

    void genAddressReg(rx_instruction* instr, bool useRax) {
        int src = instr->src;
        int dst = useRax ? 0 : 1;
        emitByte(0x41);
        emitByte(0x8D);
        emitByte(0x80 | (src & 7) | ((dst & 7) << 3));
        if (src == RX_REGISTER_NEEDS_SIB) {
            emitByte(0x24);
        }
        emit32((uint32_t)getImm32(instr));
        if (useRax) {
            emitByte(0x25);
        } else {
            emitByte(0x81);
            emitByte(0xE1);
        }
        emit32(getModMem(instr) ? RX_SPL1_MASK : RX_SPL2_MASK);
    }

    void genAddressRegDst(rx_instruction* instr) {
        int dst = instr->dst;
        emitByte(0x41);
        emitByte(0x8D);
        emitByte(0x80 | (dst & 7));
        if (dst == RX_REGISTER_NEEDS_SIB) {
            emitByte(0x24);
        }
        emit32((uint32_t)getImm32(instr));
        emitByte(0x25);
        if (getModCond(instr) < RX_STORE_L3_CONDITION) {
            emit32(getModMem(instr) ? RX_SPL1_MASK : RX_SPL2_MASK);
        } else {
            emit32(RX_SPL3_MASK);
        }
    }

    void genAddressImm(rx_instruction* instr) {
        emit32((uint32_t)getImm32(instr) & RX_SPL3_MASK);
    }

    void emitMov64RM(int dst_gpr, int src_gpr) {
        emitByte(0x49);
        emitByte(0x8B);
        emitByte(0xC0 | ((dst_gpr & 7) << 3) | (src_gpr & 7));
    }

    void h_IADD_RS(rx_instruction* instr, int i);
    void h_IADD_M(rx_instruction* instr, int i);
    void h_ISUB_R(rx_instruction* instr, int i);
    void h_ISUB_M(rx_instruction* instr, int i);
    void h_IMUL_R(rx_instruction* instr, int i);
    void h_IMUL_M(rx_instruction* instr, int i);
    void h_IMULH_R(rx_instruction* instr, int i);
    void h_IMULH_M(rx_instruction* instr, int i);
    void h_ISMULH_R(rx_instruction* instr, int i);
    void h_ISMULH_M(rx_instruction* instr, int i);
    void h_IMUL_RCP(rx_instruction* instr, int i);
    void h_INEG_R(rx_instruction* instr, int i);
    void h_IXOR_R(rx_instruction* instr, int i);
    void h_IXOR_M(rx_instruction* instr, int i);
    void h_IROR_R(rx_instruction* instr, int i);
    void h_IROL_R(rx_instruction* instr, int i);
    void h_ISWAP_R(rx_instruction* instr, int i);
    void h_FSWAP_R(rx_instruction* instr, int i);
    void h_FADD_R(rx_instruction* instr, int i);
    void h_FADD_M(rx_instruction* instr, int i);
    void h_FSUB_R(rx_instruction* instr, int i);
    void h_FSUB_M(rx_instruction* instr, int i);
    void h_FSCAL_R(rx_instruction* instr, int i);
    void h_FMUL_R(rx_instruction* instr, int i);
    void h_FDIV_M(rx_instruction* instr, int i);
    void h_FSQRT_R(rx_instruction* instr, int i);
    void h_CBRANCH(rx_instruction* instr, int i);
    void h_CFROUND(rx_instruction* instr, int i);
    void h_ISTORE(rx_instruction* instr, int i);
    void h_NOP(rx_instruction* instr, int i);

    typedef void (JitCompiler::*InstrGen)(rx_instruction*, int);

    static InstrGen engine[256];

    void generateCode(rx_instruction* instr, int i) {
        instructionOffsets[instructionCount++] = pos;
        (this->*engine[instr->opcode])(instr, i);
    }

    void fixupCallOffsets(uint8_t* data, int size, int dataStartPos) {
        for (int i = 0; i < size - 4; i++) {
            if (data[i] == 0xE8) {
                int32_t oldOff;
                memcpy(&oldOff, &data[i + 1], 4);
                int32_t callPos = dataStartPos + i;
                int32_t newOff = RX_SUPER_OFFSET - (callPos + 5);
                memcpy(&data[i + 1], &newOff, 4);
            }
        }
    }

    void generateProgramPrologue(rx_program* prog, rx_program_config* pcfg, int loopBeginPos) {
        instructionCount = 0;
        for (int i = 0; i < RX_REGISTERS_COUNT; i++) registerUsage[i] = -1;

        memcpy(code + pos, code_loop_load, LOOP_LOAD_SIZE);
        pos += LOOP_LOAD_SIZE;

        for (unsigned i = 0; i < RX_PROGRAM_SIZE; i++) {
            rx_instruction* instr = &prog->programBuffer[i];
            instr->src %= RX_REGISTERS_COUNT;
            instr->dst %= RX_REGISTERS_COUNT;
            generateCode(instr, i);
        }

        emitByte(0x49); emitByte(0x8B); emitByte(0xC0 + pcfg->readReg2);
        emitByte(0x49); emitByte(0x33); emitByte(0xC0 + pcfg->readReg3);
    }

    void generateProgramEpilogue(rx_program* prog, rx_program_config* pcfg, int loopBeginPos) {

        emitByte(0x89); emitByte(0xE9);
        emitByte(0x81); emitByte(0xE1);
        emit32(0x7FFFFFC0);
        emitByte(0x4C); emitByte(0x33); emitByte(0x04); emitByte(0x0F);
        emitByte(0x4C); emitByte(0x33); emitByte(0x4C); emitByte(0x0F); emitByte(0x08);
        emitByte(0x4C); emitByte(0x33); emitByte(0x54); emitByte(0x0F); emitByte(0x10);
        emitByte(0x4C); emitByte(0x33); emitByte(0x5C); emitByte(0x0F); emitByte(0x18);
        emitByte(0x4C); emitByte(0x33); emitByte(0x64); emitByte(0x0F); emitByte(0x20);
        emitByte(0x4C); emitByte(0x33); emitByte(0x6C); emitByte(0x0F); emitByte(0x28);
        emitByte(0x4C); emitByte(0x33); emitByte(0x74); emitByte(0x0F); emitByte(0x30);
        emitByte(0x4C); emitByte(0x33); emitByte(0x7C); emitByte(0x0F); emitByte(0x38);

        emitByte(0x89); emitByte(0xC1);
        emitByte(0x48); emitByte(0xC1); emitByte(0xCD); emitByte(0x20);
        emitByte(0x48); emitByte(0x33); emitByte(0xE9);

        emitByte(0x89); emitByte(0xE8);
        emitByte(0x25); emit32(0x7FFFFFC0);
        emitByte(0x0F); emitByte(0x18); emitByte(0x0C); emitByte(0x07);

        memcpy(code + pos, code_loop_store, LOOP_STORE_SIZE);
        pos += LOOP_STORE_SIZE;

        emitByte(0x49); emitByte(0x8B); emitByte(0xC0 + pcfg->readReg0);
        emitByte(0x49); emitByte(0x33); emitByte(0xC0 + pcfg->readReg1);
        emit(code_prefetch_sp, PREFETCH_SP_SIZE);

        emitByte(0x83); emitByte(0xEB); emitByte(0x01);
        int jnzPos = pos;
        emitByte(0x0F); emitByte(0x85); emit32(0);
        emitByte(0xE9); emit32(0);

        {
            int32_t patch = loopBeginPos - (jnzPos + 6);
            memcpy(code + jnzPos + 2, &patch, 4);
        }
        {
            int32_t patch = EPILOGUE_OFFSET - (jnzPos + 11);
            memcpy(code + jnzPos + 7, &patch, 4);
        }
    }

    void generateProgram(rx_program* prog, rx_program_config* pcfg) {
        int pos = 0;

        memcpy(code + pos, code_prologue, PROLOGUE_SIZE);

        pos += PROLOGUE_SIZE;

        memcpy(code + pos, code_first_load, FIRST_LOAD_SIZE);
        pos += FIRST_LOAD_SIZE;

        pos = ((pos + 63) & ~63);

        int constantsPos = pos;
        memcpy(code + pos, code_constants, CONSTANTS_SIZE);
        pos += CONSTANTS_SIZE;

        pos = ((pos + 63) & ~63);

        int imulRcpPos = pos;
        memcpy(code + pos, code_imul_rcp, IMUL_RCP_SIZE);
        pos += IMUL_RCP_SIZE;

        pos = ((pos + 63) & ~63);

        int loopBeginPos = pos;
        code[pos] = 0x90;
        pos += 1;

        memcpy(code + EPILOGUE_OFFSET, code_epilogue, EPILOGUE_SIZE);

        int movapd13_patch = 189;
        int32_t rel = constantsPos - (movapd13_patch + 4);
        memcpy(code + movapd13_patch, &rel, 4);

        int movapd14_patch = 198;
        rel = (constantsPos + 16) - (movapd14_patch + 4);
        memcpy(code + movapd14_patch, &rel, 4);

        int movapd15_patch = 207;
        rel = (constantsPos + 32) - (movapd15_patch + 4);
        memcpy(code + movapd15_patch, &rel, 4);

        int jmpImulPos = PROLOGUE_SIZE + FIRST_LOAD_SIZE - 4;
        rel = imulRcpPos - (jmpImulPos + 4);
        memcpy(code + jmpImulPos, &rel, 4);

        int jmpLoopPos = imulRcpPos + IMUL_RCP_SIZE - 4;
        rel = loopBeginPos - (jmpLoopPos + 4);
        memcpy(code + jmpLoopPos, &rel, 4);

        memcpy(code + constantsPos + EMASK_OFFSET_IN_CONSTANTS, pcfg->eMask, sizeof(pcfg->eMask));

        pos = loopBeginPos + 1;
        this->pos = pos;
        generateProgramPrologue(prog, pcfg, loopBeginPos);

        generateProgramEpilogue(prog, pcfg, loopBeginPos);
    }

    void generateSuperscalarCode(rx_instruction* instr) {
        int opcode = instr->opcode;
        if (opcode == RX_SS_ISUB_R) {
            emitByte(0x4D); emitByte(0x2B); emitByte(0xC0 | (8 * instr->dst + instr->src));
        } else if (opcode == RX_SS_IXOR_R) {
            emitByte(0x4D); emitByte(0x33); emitByte(0xC0 | (8 * instr->dst + instr->src));
        } else if (opcode == RX_SS_IADD_RS) {
            emitByte(0x4F); emitByte(0x8D); emitByte(0x04 | (8 * instr->dst));
            genSIB(getModShift(instr), instr->src, instr->dst);
        } else if (opcode == RX_SS_IMUL_R) {
            emitByte(0x4D); emitByte(0x0F); emitByte(0xAF); emitByte(0xC0 | (8 * instr->dst + instr->src));
        } else if (opcode == RX_SS_IROR_C) {
            emitByte(0x49); emitByte(0xC1); emitByte(0xC8 | instr->dst);
            emitByte(getImm32(instr) & 63);
        } else if (opcode == RX_SS_IADD_C7) {
            emitByte(0x49); emitByte(0x81); emitByte(0xC0 | instr->dst);
            emit32((uint32_t)getImm32(instr));
        } else if (opcode == RX_SS_IADD_C8) {
            emitByte(0x49); emitByte(0x81); emitByte(0xC0 | instr->dst);
            emit32((uint32_t)getImm32(instr));
            emitByte(0x90);
        } else if (opcode == RX_SS_IADD_C9) {
            emitByte(0x49); emitByte(0x81); emitByte(0xC0 | instr->dst);
            emit32((uint32_t)getImm32(instr));
            emitByte(0x90); emitByte(0x90);
        } else if (opcode == RX_SS_IXOR_C7) {
            emitByte(0x49); emitByte(0x81); emitByte(0xF0 | instr->dst);
            emit32((uint32_t)getImm32(instr));
        } else if (opcode == RX_SS_IXOR_C8) {
            emitByte(0x49); emitByte(0x81); emitByte(0xF0 | instr->dst);
            emit32((uint32_t)getImm32(instr));
            emitByte(0x90);
        } else if (opcode == RX_SS_IXOR_C9) {
            emitByte(0x49); emitByte(0x81); emitByte(0xF0 | instr->dst);
            emit32((uint32_t)getImm32(instr));
            emitByte(0x90); emitByte(0x90);
        } else if (opcode == RX_SS_IMULH_R) {
            emitMov64RM(0, instr->dst);
            emitByte(0x49); emitByte(0xF7); emitByte(0xE0 | instr->src);
            emitByte(0x4C); emitByte(0x8B); emitByte(0xC2 | (8 * instr->dst));
        } else if (opcode == RX_SS_ISMULH_R) {
            emitMov64RM(0, instr->dst);
            emitByte(0x49); emitByte(0xF7); emitByte(0xE8 | instr->src);
            emitByte(0x4C); emitByte(0x8B); emitByte(0xC2 | (8 * instr->dst));
        } else if (opcode == RX_SS_IMUL_RCP) {
            uint32_t rcp_index = (uint32_t)getImm32(instr);
            uint64_t rcp_val = 0;
            if (cache && cache->reciprocalCache && rcp_index < (uint32_t)cache->reciprocalCount) {
                rcp_val = cache->reciprocalCache[rcp_index];
            } else {
                rcp_val = rx_reciprocal(rcp_index);
            }
            emitByte(0x48); emitByte(0xB8); emit64(rcp_val);
            emitByte(0x4C); emitByte(0x0F); emitByte(0xAF); emitByte(0xC0 | (8 * instr->dst));
        }
    }

    void generateSuperscalarHash(rx_cache* cache) {
        pos = RX_SUPER_OFFSET;
        if (pos >= (int32_t)RX_TOTAL_CODE_SIZE) return;

        static const uint64_t r0_mul = 6364136223846793005ULL;
        static const uint64_t r1_add = 9298411001130361340ULL;
        static const uint64_t r2_add = 12065312585734608966ULL;
        static const uint64_t r3_add = 9306329213124626780ULL;
        static const uint64_t r4_add = 5281919268842080866ULL;
        static const uint64_t r5_add = 10536153434571861004ULL;
        static const uint64_t r6_add = 3398623926847679864ULL;
        static const uint64_t r7_add = 9549104520008361294ULL;

        emitByte(0x4C); emitByte(0x8D); emitByte(0xC3);

        emitByte(0x48); emitByte(0x21); emitByte(0xDB);
        emitByte(0x48); emitByte(0xC1); emitByte(0xE3); emitByte(0x06);
        emitByte(0x48); emitByte(0x01); emitByte(0xFB);
        emitByte(0x0F); emitByte(0x18); emitByte(0x04); emitByte(0x17);

        emitByte(0x4C); emitByte(0x33); emitByte(0x03);
        emitByte(0x4C); emitByte(0x33); emitByte(0x0B);
        emitByte(0x4C); emitByte(0x33); emitByte(0x13);
        emitByte(0x4C); emitByte(0x33); emitByte(0x1B);
        emitByte(0x4C); emitByte(0x33); emitByte(0x23);
        emitByte(0x4C); emitByte(0x33); emitByte(0x2B);
        emitByte(0x4C); emitByte(0x33); emitByte(0x33);
        emitByte(0x4C); emitByte(0x33); emitByte(0x3B);

        for (unsigned j = 0; j < RX_CACHE_ACCESSES; j++) {
            rx_superscalar_program* prog = &cache->programs[j];
            for (unsigned i = 0; i < prog->size; i++)
                generateSuperscalarCode(&prog->buffer[i]);

            emitByte(0x4C); emitByte(0x33); emitByte(0x03);
            emitByte(0x4C); emitByte(0x33); emitByte(0x0B);
            emitByte(0x4C); emitByte(0x33); emitByte(0x13);
            emitByte(0x4C); emitByte(0x33); emitByte(0x1B);
            emitByte(0x4C); emitByte(0x33); emitByte(0x23);
            emitByte(0x4C); emitByte(0x33); emitByte(0x2B);
            emitByte(0x4C); emitByte(0x33); emitByte(0x33);
            emitByte(0x4C); emitByte(0x33); emitByte(0x3B);

            if (j < RX_CACHE_ACCESSES - 1) {
                emitMov64RM(0, prog->addrReg);
                emitByte(0x48); emitByte(0x21); emitByte(0xDB);
                emitByte(0x48); emitByte(0xC1); emitByte(0xE3); emitByte(0x06);
                emitByte(0x48); emitByte(0x01); emitByte(0xFB);
                emitByte(0x0F); emitByte(0x18); emitByte(0x04); emitByte(0x17);
                alignCode(16);
            }
        }

        emitByte(0x4B); emitByte(0xF7); emitByte(0xE0 | 8);
        emitByte(0x4C); emitByte(0x8B); emitByte(0xC2);
        emitByte(0x4B); emitByte(0xF7); emitByte(0xE0 | 9);
        emitByte(0x4C); emitByte(0x8B); emitByte(0xC2);
        emitByte(0x4B); emitByte(0xF7); emitByte(0xE0 | 10);
        emitByte(0x4C); emitByte(0x8B); emitByte(0xC2);
        emitByte(0x4B); emitByte(0xF7); emitByte(0xE0 | 11);
        emitByte(0x4C); emitByte(0x8B); emitByte(0xC2);
        emitByte(0x4B); emitByte(0xF7); emitByte(0xE0 | 12);
        emitByte(0x4C); emitByte(0x8B); emitByte(0xC2);
        emitByte(0x4B); emitByte(0xF7); emitByte(0xE0 | 13);
        emitByte(0x4C); emitByte(0x8B); emitByte(0xC2);
        emitByte(0x4B); emitByte(0xF7); emitByte(0xE0 | 14);
        emitByte(0x4C); emitByte(0x8B); emitByte(0xC2);
        emitByte(0x4B); emitByte(0xF7); emitByte(0xE0 | 15);
        emitByte(0x4C); emitByte(0x8B); emitByte(0xC2);

        emitByte(0x48); emitByte(0xF7); emitByte(0xE2);
        emitByte(0x48); emitByte(0xC1); emitByte(0xFA); emitByte(0x3F);
        emitByte(0x48); emitByte(0x01); emitByte(0xC2);
        emitByte(0x48); emitByte(0x01); emitByte(0xD0);
        emitByte(0x4C); emitByte(0x33); emitByte(0xC8);
        emitByte(0x4C); emitByte(0x33); emitByte(0xD1);
        emitByte(0x4C); emitByte(0x33); emitByte(0xDA);
        emitByte(0x4C); emitByte(0x33); emitByte(0xE3);
        emitByte(0x4C); emitByte(0x33); emitByte(0xEC);
        emitByte(0x4C); emitByte(0x33); emitByte(0xF5);
        emitByte(0x4C); emitByte(0x33); emitByte(0xFE);
        emitByte(0x49); emitByte(0x33); emitByte(0xC7);

        emitByte(0xC3);
    }

    void generateProgramLight(rx_program* prog, rx_program_config* pcfg, uint32_t datasetOffset) {
        memset(code, 0x90, RX_TOTAL_CODE_SIZE);
        pos = 0;

        // Prologue: set up registers for light mode
        // sub rsp, 0x100 - allocate stack space
        emitByte(0x48); emitByte(0x81); emitByte(0xEC); emit32(0x100);

        // mov rsi, r8 (scratchpad from third parameter)
        emitByte(0x49); emitByte(0x89); emitByte(0xC6);

        // mov rdi, [rdx+8] (memory pointer from second parameter)
        emitByte(0x48); emitByte(0x8B); emitByte(0x7A); emitByte(0x08);

        // mov rbp, [rdx] (mx_ma from second parameter)
        emitByte(0x48); emitByte(0x8B); emitByte(0x2A);

        // mov rbx, r9 (iteration count from fourth parameter)
        emitByte(0x4C); emitByte(0x89); emitByte(0xCB);

        // Clear all integer registers r8-r15 to 0 (these will hold RandomX register values)
        for (int i = 0; i < 8; i++) {
            emitByte(0x4D); emitByte(0x33); emitByte(0xC0 + (i * 9));
        }

        int loop_start = pos;

        // Copy loop_load
        memcpy(code + pos, code_loop_load, LOOP_LOAD_SIZE);
        pos += LOOP_LOAD_SIZE;

        instructionCount = 0;
        for (int i = 0; i < RX_REGISTERS_COUNT; i++) registerUsage[i] = -1;

        // eMask not used in light mode (no FP constant patching)

        // Generate all 256 instructions
        for (unsigned i = 0; i < RX_PROGRAM_SIZE; i++) {
            rx_instruction* instr = &prog->programBuffer[i];
            instr->src %= RX_REGISTERS_COUNT;
            instr->dst %= RX_REGISTERS_COUNT;
            generateCode(instr, i);
        }

        emitByte(0x48); emitByte(0x81); emitByte(0xC4); emit32(0x100);
        emitByte(0xC3);
    }
    void generateProgramSingleIter(rx_program* prog, rx_program_config* pcfg) {
        int pos = 0;

        memcpy(code + pos, code_prologue, PROLOGUE_SIZE);
        pos += PROLOGUE_SIZE;

        memcpy(code + pos, code_first_load, FIRST_LOAD_SIZE);
        pos += FIRST_LOAD_SIZE;

        pos = ((pos + 63) & ~63);

        int constantsPos = pos;
        memcpy(code + pos, code_constants, CONSTANTS_SIZE);
        pos += CONSTANTS_SIZE;

        pos = ((pos + 63) & ~63);

        int imulRcpPos = pos;
        memcpy(code + pos, code_imul_rcp, IMUL_RCP_SIZE);
        pos += IMUL_RCP_SIZE;

        pos = ((pos + 63) & ~63);

        int loopBeginPos = pos;
        code[pos] = 0x90;
        pos += 1;

        int movapd13_patch = 189;
        int32_t rel = constantsPos - (movapd13_patch + 4);
        memcpy(code + movapd13_patch, &rel, 4);

        int movapd14_patch = 198;
        rel = (constantsPos + 16) - (movapd14_patch + 4);
        memcpy(code + movapd14_patch, &rel, 4);

        int movapd15_patch = 207;
        rel = (constantsPos + 32) - (movapd15_patch + 4);
        memcpy(code + movapd15_patch, &rel, 4);

        int jmpImulPos = PROLOGUE_SIZE + FIRST_LOAD_SIZE - 4;
        rel = imulRcpPos - (jmpImulPos + 4);
        memcpy(code + jmpImulPos, &rel, 4);

        int jmpLoopPos = imulRcpPos + IMUL_RCP_SIZE - 4;
        rel = loopBeginPos - (jmpLoopPos + 4);
        memcpy(code + jmpLoopPos, &rel, 4);

        memcpy(code + constantsPos + EMASK_OFFSET_IN_CONSTANTS, pcfg->eMask, sizeof(pcfg->eMask));

        pos = loopBeginPos + 1;
        this->pos = pos;
        generateProgramPrologue(prog, pcfg, loopBeginPos);

        generateProgramEpilogueSingleIter(pcfg);
    }

    void generateProgramEpilogueSingleIter(rx_program_config* pcfg) {
        emitByte(0x89); emitByte(0xE9);
        emitByte(0x81); emitByte(0xE1); emit32(0x7FFFFFC0);
        emitByte(0x4C); emitByte(0x33); emitByte(0x04); emitByte(0x0F);
        emitByte(0x4C); emitByte(0x33); emitByte(0x4C); emitByte(0x0F); emitByte(0x08);
        emitByte(0x4C); emitByte(0x33); emitByte(0x54); emitByte(0x0F); emitByte(0x10);
        emitByte(0x4C); emitByte(0x33); emitByte(0x5C); emitByte(0x0F); emitByte(0x18);
        emitByte(0x4C); emitByte(0x33); emitByte(0x64); emitByte(0x0F); emitByte(0x20);
        emitByte(0x4C); emitByte(0x33); emitByte(0x6C); emitByte(0x0F); emitByte(0x28);
        emitByte(0x4C); emitByte(0x33); emitByte(0x74); emitByte(0x0F); emitByte(0x30);
        emitByte(0x4C); emitByte(0x33); emitByte(0x7C); emitByte(0x0F); emitByte(0x38);

        emitByte(0x89); emitByte(0xC1);
        emitByte(0x48); emitByte(0xC1); emitByte(0xCD); emitByte(0x20);
        emitByte(0x48); emitByte(0x33); emitByte(0xE9);

        emitByte(0x89); emitByte(0xE8);
        emitByte(0x25); emit32(0x7FFFFFC0);
        emitByte(0x0F); emitByte(0x18); emitByte(0x0C); emitByte(0x07);

        memcpy(code + pos, code_loop_store, LOOP_STORE_SIZE);
        pos += LOOP_STORE_SIZE;

        emitByte(0x49); emitByte(0x8B); emitByte(0xC0 + pcfg->readReg0);
        emitByte(0x49); emitByte(0x33); emitByte(0xC0 + pcfg->readReg1);
        emit(code_prefetch_sp, PREFETCH_SP_SIZE);

        emitByte(0x48); emitByte(0x83); emitByte(0x64); emitByte(0x24); emitByte(0x10); emitByte(0x00);
        emitByte(0x48); emitByte(0x83); emitByte(0x64); emitByte(0x24); emitByte(0x18); emitByte(0x00);

        memcpy(code + pos, code_epilogue, EPILOGUE_SIZE);
        pos += EPILOGUE_SIZE;
    }

    void emitSaveVmState(int base) {
        for (int i = 0; i < 8; i++) {
            emitByte(0x4C); emitByte(0x89); emitByte(0x84 + i * 8); emitByte(0x24);
            emit32(base + i * 8);
        }
        for (int i = 0; i < 8; i++) {
            emitByte(0xC5); emitByte(0xFD); emitByte(0x11); emitByte(0x84 + i * 8); emitByte(0x24);
            emit32(base + 64 + i * 16);
        }
        emitByte(0x48); emitByte(0x89); emitByte(0x84); emitByte(0x24); emit32(base + 192);
        emitByte(0x48); emitByte(0x89); emitByte(0x8C); emitByte(0x24); emit32(base + 200);
        emitByte(0x48); emitByte(0x89); emitByte(0x94); emitByte(0x24); emit32(base + 208);
        emitByte(0x48); emitByte(0x89); emitByte(0xB4); emitByte(0x24); emit32(base + 216);
        emitByte(0x48); emitByte(0x89); emitByte(0xBC); emitByte(0x24); emit32(base + 224);
        emitByte(0x48); emitByte(0x89); emitByte(0xAC); emitByte(0x24); emit32(base + 256);
        emitByte(0x8B); emitByte(0x04); emitByte(0x24);
        emitByte(0x89); emitByte(0x84); emitByte(0x24); emit32(base + 232);
        emitByte(0x8B); emitByte(0x44); emitByte(0x24); emitByte(0x04);
        emitByte(0x89); emitByte(0x84); emitByte(0x24); emit32(base + 236);
        emitByte(0x8B); emitByte(0x44); emitByte(0x24); emitByte(0x08);
        emitByte(0x89); emitByte(0x84); emitByte(0x24); emit32(base + 240);
        emitByte(0x8B); emitByte(0x44); emitByte(0x24); emitByte(0x0C);
        emitByte(0x89); emitByte(0x84); emitByte(0x24); emit32(base + 244);
        emitByte(0x8B); emitByte(0x44); emitByte(0x24); emitByte(0x20);
        emitByte(0x89); emitByte(0x84); emitByte(0x24); emit32(base + 248);
        emitByte(0x0F); emitByte(0xAE); emitByte(0x9C); emitByte(0x24); emit32(base + 252);
    }

    void emitLoadVmState(int base) {
        for (int i = 0; i < 8; i++) {
            emitByte(0x4C); emitByte(0x8B); emitByte(0x84 + i * 8); emitByte(0x24);
            emit32(base + i * 8);
        }
        for (int i = 0; i < 8; i++) {
            emitByte(0xC5); emitByte(0xFD); emitByte(0x10); emitByte(0x84 + i * 8); emitByte(0x24);
            emit32(base + 64 + i * 16);
        }
        emitByte(0x48); emitByte(0x8B); emitByte(0x8C); emitByte(0x24); emit32(base + 200);
        emitByte(0x48); emitByte(0x8B); emitByte(0x94); emitByte(0x24); emit32(base + 208);
        emitByte(0x48); emitByte(0x8B); emitByte(0xB4); emitByte(0x24); emit32(base + 216);
        emitByte(0x48); emitByte(0x8B); emitByte(0xBC); emitByte(0x24); emit32(base + 224);
        emitByte(0x48); emitByte(0x8B); emitByte(0xAC); emitByte(0x24); emit32(base + 256);
        emitByte(0x8B); emitByte(0x84); emitByte(0x24); emit32(base + 232);
        emitByte(0x89); emitByte(0x04); emitByte(0x24);
        emitByte(0x8B); emitByte(0x84); emitByte(0x24); emit32(base + 236);
        emitByte(0x89); emitByte(0x44); emitByte(0x24); emitByte(0x04);
        emitByte(0x8B); emitByte(0x84); emitByte(0x24); emit32(base + 240);
        emitByte(0x89); emitByte(0x44); emitByte(0x24); emitByte(0x08);
        emitByte(0x8B); emitByte(0x84); emitByte(0x24); emit32(base + 244);
        emitByte(0x89); emitByte(0x44); emitByte(0x24); emitByte(0x0C);
        emitByte(0x8B); emitByte(0x84); emitByte(0x24); emit32(base + 248);
        emitByte(0x89); emitByte(0x44); emitByte(0x24); emitByte(0x20);
        emitByte(0x0F); emitByte(0xAE); emitByte(0x94); emitByte(0x24); emit32(base + 252);
        emitByte(0x48); emitByte(0x8B); emitByte(0x84); emitByte(0x24); emit32(base + 192);
    }

    void emitSaveVmStateSlim(int base) {
        for (int i = 0; i < 8; i++) {
            emitByte(0x4C); emitByte(0x89); emitByte(0x84 + i * 8); emitByte(0x24);
            emit32(base + i * 8);
        }
        for (int i = 0; i < 8; i++) {
            emitByte(0xC5); emitByte(0xFD); emitByte(0x11); emitByte(0x84 + i * 8); emitByte(0x24);
            emit32(base + 64 + i * 16);
        }
        emitByte(0x48); emitByte(0x89); emitByte(0x84); emitByte(0x24); emit32(base + 192);
        emitByte(0x48); emitByte(0x89); emitByte(0x94); emitByte(0x24); emit32(base + 208);
        emitByte(0x48); emitByte(0x89); emitByte(0xB4); emitByte(0x24); emit32(base + 216);
        emitByte(0x48); emitByte(0x89); emitByte(0xBC); emitByte(0x24); emit32(base + 224);
        emitByte(0x48); emitByte(0x89); emitByte(0xAC); emitByte(0x24); emit32(base + 256);
        emitByte(0x8B); emitByte(0x04); emitByte(0x24);
        emitByte(0x89); emitByte(0x84); emitByte(0x24); emit32(base + 232);
        emitByte(0x8B); emitByte(0x44); emitByte(0x24); emitByte(0x04);
        emitByte(0x89); emitByte(0x84); emitByte(0x24); emit32(base + 236);
        emitByte(0x8B); emitByte(0x44); emitByte(0x24); emitByte(0x08);
        emitByte(0x89); emitByte(0x84); emitByte(0x24); emit32(base + 240);
        emitByte(0x8B); emitByte(0x44); emitByte(0x24); emitByte(0x0C);
        emitByte(0x89); emitByte(0x84); emitByte(0x24); emit32(base + 244);
        emitByte(0x8B); emitByte(0x44); emitByte(0x24); emitByte(0x20);
        emitByte(0x89); emitByte(0x84); emitByte(0x24); emit32(base + 248);
        emitByte(0x0F); emitByte(0xAE); emitByte(0x9C); emitByte(0x24); emit32(base + 252);
    }

    void emitLoadVmStateSlim(int base) {
        for (int i = 0; i < 8; i++) {
            emitByte(0x4C); emitByte(0x8B); emitByte(0x84 + i * 8); emitByte(0x24);
            emit32(base + i * 8);
        }
        emitByte(0x48); emitByte(0x8B); emitByte(0x94); emitByte(0x24); emit32(base + 208);
        emitByte(0x48); emitByte(0x8B); emitByte(0xB4); emitByte(0x24); emit32(base + 216);
        emitByte(0x48); emitByte(0x8B); emitByte(0xBC); emitByte(0x24); emit32(base + 224);
        emitByte(0x48); emitByte(0x8B); emitByte(0xAC); emitByte(0x24); emit32(base + 256);
        emitByte(0x8B); emitByte(0x84); emitByte(0x24); emit32(base + 232);
        emitByte(0x89); emitByte(0x04); emitByte(0x24);
        emitByte(0x8B); emitByte(0x84); emitByte(0x24); emit32(base + 236);
        emitByte(0x89); emitByte(0x44); emitByte(0x24); emitByte(0x04);
        emitByte(0x8B); emitByte(0x84); emitByte(0x24); emit32(base + 240);
        emitByte(0x89); emitByte(0x44); emitByte(0x24); emitByte(0x08);
        emitByte(0x8B); emitByte(0x84); emitByte(0x24); emit32(base + 244);
        emitByte(0x89); emitByte(0x44); emitByte(0x24); emitByte(0x0C);
        emitByte(0x8B); emitByte(0x84); emitByte(0x24); emit32(base + 248);
        emitByte(0x89); emitByte(0x44); emitByte(0x24); emitByte(0x20);
        emitByte(0x0F); emitByte(0xAE); emitByte(0x94); emitByte(0x24); emit32(base + 252);
        emitByte(0x48); emitByte(0x8B); emitByte(0x84); emitByte(0x24); emit32(base + 192);
    }

    void emitXmmSave(int reg, int disp) {
        if (reg < 8) {
            emitByte(0xC5); emitByte(0xFD); emitByte(0x7F); emitByte(0x84); emitByte(0x24);
        } else {
            emitByte(0xC5); emitByte(0x79); emitByte(0x7F); emitByte(0x84); emitByte(0x24);
        }
        emit32(disp);
    }

    void emitXmmLoad(int reg, int disp) {
        if (reg < 8) {
            emitByte(0xC5); emitByte(0xFD); emitByte(0x6F); emitByte(0x84); emitByte(0x24);
        } else {
            emitByte(0xC5); emitByte(0x79); emitByte(0x6F); emitByte(0x84); emitByte(0x24);
        }
        emit32(disp);
    }

    void emitSaveCalleeXmm() {
        emitByte(0x48); emitByte(0x81); emitByte(0xEC); emit32(0x50);
        emitByte(0xf3); emitByte(0x0f); emitByte(0x7f); emitByte(0x74); emitByte(0x24); emitByte(0x40);
        emitByte(0xf3); emitByte(0x0f); emitByte(0x7f); emitByte(0x7c); emitByte(0x24); emitByte(0x30);
        emitByte(0xf3); emitByte(0x44); emitByte(0x0f); emitByte(0x7f); emitByte(0x44); emitByte(0x24); emitByte(0x20);
        emitByte(0xf3); emitByte(0x44); emitByte(0x0f); emitByte(0x7f); emitByte(0x4c); emitByte(0x24); emitByte(0x10);
        emitByte(0xf3); emitByte(0x44); emitByte(0x0f); emitByte(0x7f); emitByte(0x54); emitByte(0x24); emitByte(0x00);
        emitByte(0x48); emitByte(0x81); emitByte(0xEC); emit32(0x50);
        emitByte(0xf3); emitByte(0x44); emitByte(0x0f); emitByte(0x7f); emitByte(0x5c); emitByte(0x24); emitByte(0x40);
        emitByte(0xf3); emitByte(0x44); emitByte(0x0f); emitByte(0x7f); emitByte(0x64); emitByte(0x24); emitByte(0x30);
        emitByte(0xf3); emitByte(0x44); emitByte(0x0f); emitByte(0x7f); emitByte(0x6c); emitByte(0x24); emitByte(0x20);
        emitByte(0xf3); emitByte(0x44); emitByte(0x0f); emitByte(0x7f); emitByte(0x74); emitByte(0x24); emitByte(0x10);
        emitByte(0xf3); emitByte(0x44); emitByte(0x0f); emitByte(0x7f); emitByte(0x7c); emitByte(0x24); emitByte(0x00);
    }

    void emitLoadCalleeXmm() {
        emitByte(0xf3); emitByte(0x44); emitByte(0x0f); emitByte(0x6f); emitByte(0x5c); emitByte(0x24); emitByte(0x40);
        emitByte(0xf3); emitByte(0x44); emitByte(0x0f); emitByte(0x6f); emitByte(0x64); emitByte(0x24); emitByte(0x30);
        emitByte(0xf3); emitByte(0x44); emitByte(0x0f); emitByte(0x6f); emitByte(0x6c); emitByte(0x24); emitByte(0x20);
        emitByte(0xf3); emitByte(0x44); emitByte(0x0f); emitByte(0x6f); emitByte(0x74); emitByte(0x24); emitByte(0x10);
        emitByte(0xf3); emitByte(0x44); emitByte(0x0f); emitByte(0x6f); emitByte(0x7c); emitByte(0x24); emitByte(0x00);
        emitByte(0x48); emitByte(0x81); emitByte(0xC4); emit32(0x50);
        emitByte(0xf3); emitByte(0x0f); emitByte(0x6f); emitByte(0x74); emitByte(0x24); emitByte(0x40);
        emitByte(0xf3); emitByte(0x0f); emitByte(0x6f); emitByte(0x7c); emitByte(0x24); emitByte(0x30);
        emitByte(0xf3); emitByte(0x44); emitByte(0x0f); emitByte(0x6f); emitByte(0x44); emitByte(0x24); emitByte(0x20);
        emitByte(0xf3); emitByte(0x44); emitByte(0x0f); emitByte(0x6f); emitByte(0x4c); emitByte(0x24); emitByte(0x10);
        emitByte(0xf3); emitByte(0x44); emitByte(0x0f); emitByte(0x6f); emitByte(0x54); emitByte(0x24); emitByte(0x00);
        emitByte(0x48); emitByte(0x81); emitByte(0xC4); emit32(0x50);
    }

    void generateProgramDualInterleaved(rx_program* prog1, rx_program_config* pcfg1,
                                        rx_program* prog2, rx_program_config* pcfg2) {
        this->cache = cache;
        memset(code, 0xCC, RX_TOTAL_CODE_SIZE);
        pos = 0;

        static const int VM_STATE_SIZE = 0x110;
        static const int XMM_SAVE = 0xA0;
        static const int FRAME_WORK = 0x260;
        static const int VM1_SAVE = 0x30;
        static const int VM2_SAVE = VM1_SAVE + VM_STATE_SIZE;
        static const int PARAMS_OFF = VM2_SAVE + VM_STATE_SIZE;

        emitByte(0x53); emitByte(0x55); emitByte(0x57); emitByte(0x56);
        emitByte(0x41); emitByte(0x54); emitByte(0x41); emitByte(0x55);
        emitByte(0x41); emitByte(0x56); emitByte(0x41); emitByte(0x57);
        emitSaveCalleeXmm();
        emitByte(0x48); emitByte(0x81); emitByte(0xEC); emit32(FRAME_WORK);

        emitByte(0x48); emitByte(0x89); emitByte(0x8C); emitByte(0x24); emit32(PARAMS_OFF);

        emitByte(0xE9); int jmpOverConsts1 = pos; emit32(0);

        pos = ((pos + 63) & ~63);

        int constantsPos1 = pos;
        memcpy(code + pos, code_constants, CONSTANTS_SIZE);
        pos += CONSTANTS_SIZE;
        memcpy(code + constantsPos1 + EMASK_OFFSET_IN_CONSTANTS, pcfg1->eMask, sizeof(pcfg1->eMask));

        int32_t rel;
        emitByte(0x66); emitByte(0x44); emitByte(0x0f); emitByte(0x28);
        emitByte(0x2D); rel = (constantsPos1 + 0) - (pos + 4); emit32(rel);
        emitByte(0xC5); emitByte(0x79); emitByte(0x28); emitByte(0x35);
        rel = (constantsPos1 + 16) - (pos + 4); emit32(rel);
        emitByte(0xC5); emitByte(0x79); emitByte(0x28); emitByte(0x3D);
        rel = (constantsPos1 + 32) - (pos + 4); emit32(rel);

        rel = pos - (jmpOverConsts1 + 4);
        memcpy(code + jmpOverConsts1, &rel, 4);

        emitByte(0xE9); int jmpOverConsts2 = pos; emit32(0);

        pos = ((pos + 63) & ~63);

        int constantsPos2 = pos;
        memcpy(code + pos, code_constants, CONSTANTS_SIZE);
        pos += CONSTANTS_SIZE;
        memcpy(code + constantsPos2 + EMASK_OFFSET_IN_CONSTANTS, pcfg2->eMask, sizeof(pcfg2->eMask));

        emitByte(0x66); emitByte(0x44); emitByte(0x0f); emitByte(0x28);
        emitByte(0x35); rel = (constantsPos2 + 0) - (pos + 4); emit32(rel);
        emitByte(0xC5); emitByte(0x79); emitByte(0x28); emitByte(0x35);
        rel = (constantsPos2 + 16) - (pos + 4); emit32(rel);
        emitByte(0xC5); emitByte(0x79); emitByte(0x28); emitByte(0x3D);
        rel = (constantsPos2 + 32) - (pos + 4); emit32(rel);

        rel = pos - (jmpOverConsts2 + 4);
        memcpy(code + jmpOverConsts2, &rel, 4);

        emitByte(0x48); emitByte(0x8B); emitByte(0x8C); emitByte(0x24); emit32(PARAMS_OFF);
        emitByte(0x48); emitByte(0x8B); emitByte(0x69); emitByte(0x10);
        emitByte(0x48); emitByte(0x8B); emitByte(0x79); emitByte(0x30);
        emitByte(0x48); emitByte(0x8B); emitByte(0x71); emitByte(0x20);
        emitByte(0x48); emitByte(0x8B); emitByte(0x09);
        emitByte(0x48); emitByte(0x8B); emitByte(0xC5);
        emitByte(0x48); emitByte(0xC1); emitByte(0xE8); emitByte(0x20);
        emitByte(0x25); emitByte(0xC0); emitByte(0xFF); emitByte(0xFF); emitByte(0x7F);
        emitByte(0x0F); emitByte(0x18); emitByte(0x0C); emitByte(0x07);
        emitByte(0x48); emitByte(0x8B); emitByte(0xC5);
        emitByte(0x48); emitByte(0xC1); emitByte(0xCD); emitByte(0x20);
        emitByte(0x4D); emitByte(0x33); emitByte(0xC0);
        emitByte(0x4D); emitByte(0x33); emitByte(0xC9);
        emitByte(0x4D); emitByte(0x33); emitByte(0xD2);
        emitByte(0x4D); emitByte(0x33); emitByte(0xDB);
        emitByte(0x4D); emitByte(0x33); emitByte(0xE4);
        emitByte(0x4D); emitByte(0x33); emitByte(0xED);
        emitByte(0x4D); emitByte(0x33); emitByte(0xF6);
        emitByte(0x4D); emitByte(0x33); emitByte(0xFF);
        emitByte(0x48); emitByte(0x8D); emitByte(0x49); emitByte(0x78);
        emitByte(0x66); emitByte(0x44); emitByte(0x0f); emitByte(0x28);
        emitByte(0x41); emitByte(0x48);
        emitByte(0x66); emitByte(0x44); emitByte(0x0f); emitByte(0x28);
        emitByte(0x49); emitByte(0x58);
        emitByte(0x66); emitByte(0x44); emitByte(0x0f); emitByte(0x28);
        emitByte(0x51); emitByte(0x68);
        emitByte(0x66); emitByte(0x44); emitByte(0x0f); emitByte(0x28);
        emitByte(0x59); emitByte(0x78);
        emitByte(0x48); emitByte(0x8B); emitByte(0xD0);
        emitByte(0x25); emitByte(0xC0); emitByte(0xFF); emitByte(0x1F); emitByte(0x00);
        emitByte(0x48); emitByte(0xC1); emitByte(0xCA); emitByte(0x20);
        emitByte(0x81); emitByte(0xE2); emitByte(0xC0); emitByte(0xFF); emitByte(0x1F); emitByte(0x00);
        emitByte(0xC7); emitByte(0x04); emitByte(0x24); emit32(0x9FC0);
        emitByte(0xC7); emitByte(0x44); emitByte(0x24); emitByte(0x04); emit32(0xBFC0);
        emitByte(0xC7); emitByte(0x44); emitByte(0x24); emitByte(0x08); emit32(0xDFC0);
        emitByte(0xC7); emitByte(0x44); emitByte(0x24); emitByte(0x0C); emit32(0xFFC0);
        emitByte(0xC7); emitByte(0x44); emitByte(0x24); emitByte(0x20); emit32(0xFFFFFFFF);

        emitByte(0x48); emitByte(0x8B); emitByte(0x8C); emitByte(0x24); emit32(PARAMS_OFF);
        emitByte(0x0F); emitByte(0xAE); emitByte(0x51); emitByte(0x48);

        emitSaveVmState(VM1_SAVE);

        emitByte(0x48); emitByte(0x8B); emitByte(0x8C); emitByte(0x24); emit32(PARAMS_OFF);
        emitByte(0x48); emitByte(0x8B); emitByte(0x69); emitByte(0x18);
        emitByte(0x48); emitByte(0x8B); emitByte(0x79); emitByte(0x38);
        emitByte(0x48); emitByte(0x8B); emitByte(0x71); emitByte(0x28);
        emitByte(0x48); emitByte(0x8B); emitByte(0x49); emitByte(0x08);
        emitByte(0x48); emitByte(0x8B); emitByte(0xC5);
        emitByte(0x48); emitByte(0xC1); emitByte(0xE8); emitByte(0x20);
        emitByte(0x25); emitByte(0xC0); emitByte(0xFF); emitByte(0xFF); emitByte(0x7F);
        emitByte(0x0F); emitByte(0x18); emitByte(0x0C); emitByte(0x07);
        emitByte(0x48); emitByte(0x8B); emitByte(0xC5);
        emitByte(0x48); emitByte(0xC1); emitByte(0xCD); emitByte(0x20);
        emitByte(0x48); emitByte(0x8B); emitByte(0xD0);
        emitByte(0x25); emitByte(0xC0); emitByte(0xFF); emitByte(0x1F); emitByte(0x00);
        emitByte(0x48); emitByte(0xC1); emitByte(0xCA); emitByte(0x20);
        emitByte(0x81); emitByte(0xE2); emitByte(0xC0); emitByte(0xFF); emitByte(0x1F); emitByte(0x00);

        emitByte(0x48); emitByte(0x8B); emitByte(0x8C); emitByte(0x24); emit32(PARAMS_OFF);
        emitByte(0x0F); emitByte(0xAE); emitByte(0x51); emitByte(0x4C);

        emitSaveVmState(VM2_SAVE);

        emitByte(0x48); emitByte(0x8B); emitByte(0x8C); emitByte(0x24); emit32(PARAMS_OFF);
        emitByte(0x8B); emitByte(0x99); emit32(0x40);

        emitByte(0x66); emitByte(0x44); emitByte(0x0f); emitByte(0x28);
        emitByte(0x2D); rel = (constantsPos1 + 0) - (pos + 4); emit32(rel);
        emitByte(0xC5); emitByte(0x79); emitByte(0x28); emitByte(0x3D);
        rel = (constantsPos1 + 32) - (pos + 4); emit32(rel);

        int outerLoopStart = pos;

        emitLoadVmStateSlim(VM1_SAVE);

        emitByte(0xC5); emitByte(0x79); emitByte(0x28); emitByte(0x35);
        rel = (constantsPos1 + 16) - (pos + 4); emit32(rel);

        emitByte(0x48); emitByte(0x8B); emitByte(0x8C); emitByte(0x24); emit32(PARAMS_OFF);
        emitByte(0x48); emitByte(0x8B); emitByte(0x09);
        emitByte(0x48); emitByte(0x8D); emitByte(0x49); emitByte(0x78);
        emitByte(0x66); emitByte(0x44); emitByte(0x0f); emitByte(0x28); emitByte(0x41); emitByte(0x48);
        emitByte(0x66); emitByte(0x44); emitByte(0x0f); emitByte(0x28); emitByte(0x49); emitByte(0x58);
        emitByte(0x66); emitByte(0x44); emitByte(0x0f); emitByte(0x28); emitByte(0x51); emitByte(0x68);
        emitByte(0x66); emitByte(0x44); emitByte(0x0f); emitByte(0x28); emitByte(0x59); emitByte(0x78);

        instructionCount = 0;
        for (int i = 0; i < RX_REGISTERS_COUNT; i++) registerUsage[i] = -1;
        memcpy(code + pos, code_loop_load, LOOP_LOAD_SIZE);
        pos += LOOP_LOAD_SIZE;
        for (unsigned i = 0; i < RX_PROGRAM_SIZE; i++) {
            rx_instruction* instr = &prog1->programBuffer[i];
            instr->src %= RX_REGISTERS_COUNT;
            instr->dst %= RX_REGISTERS_COUNT;
            generateCode(instr, i);
        }
        emitByte(0x49); emitByte(0x8B); emitByte(0xC0 + pcfg1->readReg2);
        emitByte(0x49); emitByte(0x33); emitByte(0xC0 + pcfg1->readReg3);

        emitByte(0x89); emitByte(0xE9);
        emitByte(0x81); emitByte(0xE1); emit32(0x7FFFFFC0);
        emitByte(0x4C); emitByte(0x33); emitByte(0x04); emitByte(0x0F);
        emitByte(0x4C); emitByte(0x33); emitByte(0x4C); emitByte(0x0F); emitByte(0x08);
        emitByte(0x4C); emitByte(0x33); emitByte(0x54); emitByte(0x0F); emitByte(0x10);
        emitByte(0x4C); emitByte(0x33); emitByte(0x5C); emitByte(0x0F); emitByte(0x18);
        emitByte(0x4C); emitByte(0x33); emitByte(0x64); emitByte(0x0F); emitByte(0x20);
        emitByte(0x4C); emitByte(0x33); emitByte(0x6C); emitByte(0x0F); emitByte(0x28);
        emitByte(0x4C); emitByte(0x33); emitByte(0x74); emitByte(0x0F); emitByte(0x30);
        emitByte(0x4C); emitByte(0x33); emitByte(0x7C); emitByte(0x0F); emitByte(0x38);
        emitByte(0x89); emitByte(0xC1);
        emitByte(0x48); emitByte(0xC1); emitByte(0xCD); emitByte(0x20);
        emitByte(0x48); emitByte(0x33); emitByte(0xE9);
        emitByte(0x89); emitByte(0xE8);
        emitByte(0x25); emit32(0x7FFFFFC0);
        emitByte(0x0F); emitByte(0x18); emitByte(0x0C); emitByte(0x07);
        memcpy(code + pos, code_loop_store, LOOP_STORE_SIZE);
        pos += LOOP_STORE_SIZE;
        emitByte(0x49); emitByte(0x8B); emitByte(0xC0 + pcfg1->readReg0);
        emitByte(0x49); emitByte(0x33); emitByte(0xC0 + pcfg1->readReg1);
        emit(code_prefetch_sp, PREFETCH_SP_SIZE);

        emitSaveVmStateSlim(VM1_SAVE);

        emitLoadVmStateSlim(VM2_SAVE);

        emitByte(0xC5); emitByte(0x79); emitByte(0x28); emitByte(0x35);
        rel = (constantsPos2 + 16) - (pos + 4); emit32(rel);

        emitByte(0x48); emitByte(0x8B); emitByte(0x8C); emitByte(0x24); emit32(PARAMS_OFF);
        emitByte(0x48); emitByte(0x8B); emitByte(0x49); emitByte(0x08);
        emitByte(0x48); emitByte(0x8D); emitByte(0x49); emitByte(0x78);
        emitByte(0x66); emitByte(0x44); emitByte(0x0f); emitByte(0x28); emitByte(0x41); emitByte(0x48);
        emitByte(0x66); emitByte(0x44); emitByte(0x0f); emitByte(0x28); emitByte(0x49); emitByte(0x58);
        emitByte(0x66); emitByte(0x44); emitByte(0x0f); emitByte(0x28); emitByte(0x51); emitByte(0x68);
        emitByte(0x66); emitByte(0x44); emitByte(0x0f); emitByte(0x28); emitByte(0x59); emitByte(0x78);

        instructionCount = 0;
        for (int i = 0; i < RX_REGISTERS_COUNT; i++) registerUsage[i] = -1;
        memcpy(code + pos, code_loop_load, LOOP_LOAD_SIZE);
        pos += LOOP_LOAD_SIZE;
        for (unsigned i = 0; i < RX_PROGRAM_SIZE; i++) {
            rx_instruction* instr = &prog2->programBuffer[i];
            instr->src %= RX_REGISTERS_COUNT;
            instr->dst %= RX_REGISTERS_COUNT;
            generateCode(instr, i);
        }
        emitByte(0x49); emitByte(0x8B); emitByte(0xC0 + pcfg2->readReg2);
        emitByte(0x49); emitByte(0x33); emitByte(0xC0 + pcfg2->readReg3);

        emitByte(0x89); emitByte(0xE9);
        emitByte(0x81); emitByte(0xE1); emit32(0x7FFFFFC0);
        emitByte(0x4C); emitByte(0x33); emitByte(0x04); emitByte(0x0F);
        emitByte(0x4C); emitByte(0x33); emitByte(0x4C); emitByte(0x0F); emitByte(0x08);
        emitByte(0x4C); emitByte(0x33); emitByte(0x54); emitByte(0x0F); emitByte(0x10);
        emitByte(0x4C); emitByte(0x33); emitByte(0x5C); emitByte(0x0F); emitByte(0x18);
        emitByte(0x4C); emitByte(0x33); emitByte(0x64); emitByte(0x0F); emitByte(0x20);
        emitByte(0x4C); emitByte(0x33); emitByte(0x6C); emitByte(0x0F); emitByte(0x28);
        emitByte(0x4C); emitByte(0x33); emitByte(0x74); emitByte(0x0F); emitByte(0x30);
        emitByte(0x4C); emitByte(0x33); emitByte(0x7C); emitByte(0x0F); emitByte(0x38);
        emitByte(0x89); emitByte(0xC1);
        emitByte(0x48); emitByte(0xC1); emitByte(0xCD); emitByte(0x20);
        emitByte(0x48); emitByte(0x33); emitByte(0xE9);
        emitByte(0x89); emitByte(0xE8);
        emitByte(0x25); emit32(0x7FFFFFC0);
        emitByte(0x0F); emitByte(0x18); emitByte(0x0C); emitByte(0x07);
        memcpy(code + pos, code_loop_store, LOOP_STORE_SIZE);
        pos += LOOP_STORE_SIZE;
        emitByte(0x49); emitByte(0x8B); emitByte(0xC0 + pcfg2->readReg0);
        emitByte(0x49); emitByte(0x33); emitByte(0xC0 + pcfg2->readReg1);
        emit(code_prefetch_sp, PREFETCH_SP_SIZE);

        emitSaveVmStateSlim(VM2_SAVE);

        emitByte(0x83); emitByte(0xEB); emitByte(0x01);
        emitByte(0x0F); emitByte(0x85);
        int loopBackPatch = pos;
        emit32(0);
        rel = outerLoopStart - (loopBackPatch + 4);
        memcpy(code + loopBackPatch, &rel, 4);

        emitByte(0x66); emitByte(0x44); emitByte(0x0f); emitByte(0x28);
        emitByte(0x2D); rel = (constantsPos1 + 0) - (pos + 4); emit32(rel);
        emitByte(0xC5); emitByte(0x79); emitByte(0x28); emitByte(0x35);
        rel = (constantsPos1 + 16) - (pos + 4); emit32(rel);
        emitByte(0xC5); emitByte(0x79); emitByte(0x28); emitByte(0x3D);
        rel = (constantsPos1 + 32) - (pos + 4); emit32(rel);
        emitLoadVmState(VM1_SAVE);

        emitByte(0x48); emitByte(0x8B); emitByte(0x8C); emitByte(0x24); emit32(PARAMS_OFF);
        emitByte(0x48); emitByte(0x8B); emitByte(0x09);

        for (int i = 0; i < 8; i++) {
            emitByte(0x4C); emitByte(0x89); emitByte(0x41 + i * 8); emitByte(i * 8);
        }
        for (int i = 0; i < 4; i++) {
            emitByte(0x66); emitByte(0x0f); emitByte(0x7f);
            emitByte(0x41 | (i << 3));
            emitByte(0x40 | (i * 16));
        }
        emitByte(0x48); emitByte(0x8D); emitByte(0x49); emitByte(0x40);
        for (int i = 0; i < 4; i++) {
            emitByte(0x66); emitByte(0x0f); emitByte(0x7f);
            emitByte(0x41 | ((i + 4) << 3));
            emitByte(0x40 | (i * 16));
        }
        emitByte(0x48); emitByte(0x8B); emitByte(0x8C); emitByte(0x24); emit32(PARAMS_OFF);
        emitByte(0x48); emitByte(0x89); emitByte(0x69); emitByte(0x10);

        emitByte(0x48); emitByte(0x8B); emitByte(0x8C); emitByte(0x24); emit32(PARAMS_OFF);
        emitByte(0x0F); emitByte(0xAE); emitByte(0x59); emitByte(0x48);

        emitByte(0x66); emitByte(0x44); emitByte(0x0f); emitByte(0x28);
        emitByte(0x35); rel = (constantsPos2 + 0) - (pos + 4); emit32(rel);
        emitByte(0xC5); emitByte(0x79); emitByte(0x28); emitByte(0x35);
        rel = (constantsPos2 + 16) - (pos + 4); emit32(rel);
        emitByte(0xC5); emitByte(0x79); emitByte(0x28); emitByte(0x3D);
        rel = (constantsPos2 + 32) - (pos + 4); emit32(rel);
        emitLoadVmState(VM2_SAVE);

        emitByte(0x48); emitByte(0x8B); emitByte(0x8C); emitByte(0x24); emit32(PARAMS_OFF);
        emitByte(0x48); emitByte(0x8B); emitByte(0x49); emitByte(0x08);
        for (int i = 0; i < 8; i++) {
            emitByte(0x4C); emitByte(0x89); emitByte(0x41 + i * 8); emitByte(i * 8);
        }
        for (int i = 0; i < 4; i++) {
            emitByte(0x66); emitByte(0x0f); emitByte(0x7f);
            emitByte(0x41 | (i << 3));
            emitByte(0x40 | (i * 16));
        }
        emitByte(0x48); emitByte(0x8D); emitByte(0x49); emitByte(0x40);
        for (int i = 0; i < 4; i++) {
            emitByte(0x66); emitByte(0x0f); emitByte(0x7f);
            emitByte(0x41 | ((i + 4) << 3));
            emitByte(0x40 | (i * 16));
        }
        emitByte(0x48); emitByte(0x8B); emitByte(0x8C); emitByte(0x24); emit32(PARAMS_OFF);
        emitByte(0x48); emitByte(0x89); emitByte(0x69); emitByte(0x18);

        emitByte(0x48); emitByte(0x8B); emitByte(0x8C); emitByte(0x24); emit32(PARAMS_OFF);
        emitByte(0x0F); emitByte(0xAE); emitByte(0x59); emitByte(0x4C);

        emitByte(0x48); emitByte(0x81); emitByte(0xC4); emit32(FRAME_WORK);
        emitLoadCalleeXmm();
        emitByte(0x41); emitByte(0x5F); emitByte(0x41); emitByte(0x5E);
        emitByte(0x41); emitByte(0x5D); emitByte(0x41); emitByte(0x5C);
        emitByte(0x5E); emitByte(0x5F); emitByte(0x5D); emitByte(0x5B);
        emitByte(0xC3);
    }
};

#define REP1(x) x,
#define REP2(x) REP1(x) x,
#define REP3(x) REP2(x) x,
#define REP4(x) REP3(x) x,
#define REP5(x) REP4(x) x,
#define REP6(x) REP5(x) x,
#define REP7(x) REP6(x) x,
#define REP8(x) REP7(x) x,
#define REP15(x) REP8(x) REP7(x)
#define REP16(x) REP8(x) REP8(x)
#define REP25(x) REP16(x) REP8(x) REP1(x)
#define REP32(x) REP16(x) REP16(x)
#define REPN(x,n) REP##n(x)

JitCompiler::InstrGen JitCompiler::engine[256] = {
    REPN(&JitCompiler::h_IADD_RS, 16)
    REPN(&JitCompiler::h_IADD_M, 7)
    REPN(&JitCompiler::h_ISUB_R, 16)
    REPN(&JitCompiler::h_ISUB_M, 7)
    REPN(&JitCompiler::h_IMUL_R, 16)
    REPN(&JitCompiler::h_IMUL_M, 4)
    REPN(&JitCompiler::h_IMULH_R, 4)
    REPN(&JitCompiler::h_IMULH_M, 1)
    REPN(&JitCompiler::h_ISMULH_R, 4)
    REPN(&JitCompiler::h_ISMULH_M, 1)
    REPN(&JitCompiler::h_IMUL_RCP, 8)
    REPN(&JitCompiler::h_INEG_R, 2)
    REPN(&JitCompiler::h_IXOR_R, 15)
    REPN(&JitCompiler::h_IXOR_M, 5)
    REPN(&JitCompiler::h_IROR_R, 8)
    REPN(&JitCompiler::h_IROL_R, 2)
    REPN(&JitCompiler::h_ISWAP_R, 4)
    REPN(&JitCompiler::h_FSWAP_R, 4)
    REPN(&JitCompiler::h_FADD_R, 16)
    REPN(&JitCompiler::h_FADD_M, 5)
    REPN(&JitCompiler::h_FSUB_R, 16)
    REPN(&JitCompiler::h_FSUB_M, 5)
    REPN(&JitCompiler::h_FSCAL_R, 6)
    REPN(&JitCompiler::h_FMUL_R, 32)
    REPN(&JitCompiler::h_FDIV_M, 4)
    REPN(&JitCompiler::h_FSQRT_R, 6)
    REPN(&JitCompiler::h_CBRANCH, 25)
    REPN(&JitCompiler::h_CFROUND, 1)
    REPN(&JitCompiler::h_ISTORE, 16)
};

#undef REPN
#undef REP1
#undef REP2
#undef REP3
#undef REP4
#undef REP5
#undef REP6
#undef REP7
#undef REP8
#undef REP16
#undef REP25
#undef REP32

static void init_engine() {
}

void JitCompiler::h_IADD_RS(rx_instruction* instr, int i) {
    registerUsage[instr->dst] = i;
    emitByte(0x4F); emitByte(0x8D);
    if (instr->dst == RX_REGISTER_NEEDS_DISP)
        emitByte(0xAC);
    else
        emitByte(0x04 | (8 * instr->dst));
    genSIB(getModShift(instr), instr->src, instr->dst);
    if (instr->dst == RX_REGISTER_NEEDS_DISP)
        emit32((uint32_t)getImm32(instr));
}

void JitCompiler::h_IADD_M(rx_instruction* instr, int i) {
    registerUsage[instr->dst] = i;
    if (instr->src != instr->dst) {
        genAddressReg(instr, true);
        emitByte(0x4C); emitByte(0x03); emitByte(0x04 | (8 * instr->dst)); emitByte(0x06);
    } else {
        emitByte(0x4C); emitByte(0x03); emitByte(0x86 | (8 * instr->dst));
        genAddressImm(instr);
    }
}

void JitCompiler::h_ISUB_R(rx_instruction* instr, int i) {
    registerUsage[instr->dst] = i;
    if (instr->src != instr->dst) {
        emitByte(0x4D); emitByte(0x2B); emitByte(0xC0 | (8 * instr->dst + instr->src));
    } else {
        emitByte(0x49); emitByte(0x81); emitByte(0xE8 | instr->dst);
        emit32((uint32_t)getImm32(instr));
    }
}

void JitCompiler::h_ISUB_M(rx_instruction* instr, int i) {
    registerUsage[instr->dst] = i;
    if (instr->src != instr->dst) {
        genAddressReg(instr, true);
        emitByte(0x4C); emitByte(0x2B); emitByte(0x04 | (8 * instr->dst)); emitByte(0x06);
    } else {
        emitByte(0x4C); emitByte(0x2B); emitByte(0x86 | (8 * instr->dst));
        genAddressImm(instr);
    }
}

void JitCompiler::h_IMUL_R(rx_instruction* instr, int i) {
    registerUsage[instr->dst] = i;
    if (instr->src != instr->dst) {
        emitByte(0x4D); emitByte(0x0F); emitByte(0xAF); emitByte(0xC0 | (8 * instr->dst + instr->src));
    } else {
        emitByte(0x4D); emitByte(0x69); emitByte(0xC0 | (9 * instr->dst));
        emit32((uint32_t)getImm32(instr));
    }
}

void JitCompiler::h_IMUL_M(rx_instruction* instr, int i) {
    registerUsage[instr->dst] = i;
    if (instr->src != instr->dst) {
        genAddressReg(instr, true);
        emitByte(0x4C); emitByte(0x0F); emitByte(0xAF); emitByte(0x04 | (8 * instr->dst)); emitByte(0x06);
    } else {
        emitByte(0x4C); emitByte(0x0F); emitByte(0xAF); emitByte(0x86 | (8 * instr->dst));
        genAddressImm(instr);
    }
}

void JitCompiler::h_IMULH_R(rx_instruction* instr, int i) {
    registerUsage[instr->dst] = i;
    emitMov64RM(0, instr->dst);
    emitByte(0x49); emitByte(0xF7); emitByte(0xE0 | instr->src);
    emitByte(0x4C); emitByte(0x8B); emitByte(0xC2 | (8 * instr->dst));
}

void JitCompiler::h_IMULH_M(rx_instruction* instr, int i) {
    registerUsage[instr->dst] = i;
    if (instr->src != instr->dst) {
        genAddressReg(instr, false);
        emitByte(0x0F); emitByte(0x18); emitByte(0x04); emitByte(0x0E);
        emitMov64RM(0, instr->dst);
        emitByte(0x48); emitByte(0xF7); emitByte(0x24); emitByte(0x0E);
    } else {
        emitMov64RM(0, instr->dst);
        emitByte(0x48); emitByte(0xF7); emitByte(0xA6);
        genAddressImm(instr);
    }
    emitByte(0x4C); emitByte(0x8B); emitByte(0xC2 | (8 * instr->dst));
}

void JitCompiler::h_ISMULH_R(rx_instruction* instr, int i) {
    registerUsage[instr->dst] = i;
    emitMov64RM(0, instr->dst);
    emitByte(0x49); emitByte(0xF7); emitByte(0xE8 | instr->src);
    emitByte(0x4C); emitByte(0x8B); emitByte(0xC2 | (8 * instr->dst));
}

void JitCompiler::h_ISMULH_M(rx_instruction* instr, int i) {
    registerUsage[instr->dst] = i;
    if (instr->src != instr->dst) {
        genAddressReg(instr, false);
        emitByte(0x0F); emitByte(0x18); emitByte(0x04); emitByte(0x0E);
        emitMov64RM(0, instr->dst);
        emitByte(0x48); emitByte(0xF7); emitByte(0x2C); emitByte(0x0E);
    } else {
        emitMov64RM(0, instr->dst);
        emitByte(0x48); emitByte(0xF7); emitByte(0xAE);
        genAddressImm(instr);
    }
    emitByte(0x4C); emitByte(0x8B); emitByte(0xC2 | (8 * instr->dst));
}

void JitCompiler::h_IMUL_RCP(rx_instruction* instr, int i) {
    uint32_t divisor = (uint32_t)getImm32(instr);
    if (!is_zero_or_power_of_2(divisor)) {
        registerUsage[instr->dst] = i;
        emitByte(0x48); emitByte(0xB8); emit64(rx_reciprocal(divisor));
        emitByte(0x4C); emitByte(0x0F); emitByte(0xAF); emitByte(0xC0 | (8 * instr->dst));
    }
}

void JitCompiler::h_INEG_R(rx_instruction* instr, int i) {
    registerUsage[instr->dst] = i;
    emitByte(0x49); emitByte(0xF7); emitByte(0xD8 | instr->dst);
}

void JitCompiler::h_IXOR_R(rx_instruction* instr, int i) {
    registerUsage[instr->dst] = i;
    if (instr->src != instr->dst) {
        emitByte(0x4D); emitByte(0x33); emitByte(0xC0 | (8 * instr->dst + instr->src));
    } else {
        emitByte(0x49); emitByte(0x81); emitByte(0xF0 | instr->dst);
        emit32((uint32_t)getImm32(instr));
    }
}

void JitCompiler::h_IXOR_M(rx_instruction* instr, int i) {
    registerUsage[instr->dst] = i;
    if (instr->src != instr->dst) {
        genAddressReg(instr, true);
        emitByte(0x4C); emitByte(0x33); emitByte(0x04 | (8 * instr->dst)); emitByte(0x06);
    } else {
        emitByte(0x4C); emitByte(0x33); emitByte(0x86 | (8 * instr->dst));
        genAddressImm(instr);
    }
}

void JitCompiler::h_IROR_R(rx_instruction* instr, int i) {
    registerUsage[instr->dst] = i;
    if (instr->src != instr->dst) {
        emitByte(0x41); emitByte(0x8B); emitByte(0xC8 | instr->src);
        emitByte(0x49); emitByte(0xD3); emitByte(0xC8 | instr->dst);
    } else {
        emitByte(0x49); emitByte(0xC1); emitByte(0xC8 | instr->dst);
        emitByte(getImm32(instr) & 63);
    }
}

void JitCompiler::h_IROL_R(rx_instruction* instr, int i) {
    registerUsage[instr->dst] = i;
    if (instr->src != instr->dst) {
        emitByte(0x41); emitByte(0x8B); emitByte(0xC8 | instr->src);
        emitByte(0x49); emitByte(0xD3); emitByte(0xC0 | instr->dst);
    } else {
        emitByte(0x49); emitByte(0xC1); emitByte(0xC0 | instr->dst);
        emitByte(getImm32(instr) & 63);
    }
}

void JitCompiler::h_ISWAP_R(rx_instruction* instr, int i) {
    if (instr->src != instr->dst) {
        registerUsage[instr->dst] = i;
        registerUsage[instr->src] = i;
        emitByte(0x4D); emitByte(0x87); emitByte(0xC0 | instr->src | (8 * instr->dst));
    }
}

void JitCompiler::h_FSWAP_R(rx_instruction* instr, int i) {
    emitByte(0xC5);
    emitByte(((15 - instr->dst) << 3) | 0x81);
    emitByte(0xC6);
    emitByte(0xC0 | (9 * instr->dst));
    emitByte(1);
}

void JitCompiler::h_FADD_R(rx_instruction* instr, int i) {
    instr->dst %= RX_REG_FLT_COUNT;
    instr->src %= RX_REG_FLT_COUNT;
    emitByte(0xC4); emitByte(0xC1);
    emitByte(((15 - instr->dst) << 3) | 1);
    emitByte(0x58);
    emitByte(0xC0 | (instr->dst << 3) | instr->src);
}

void JitCompiler::h_FADD_M(rx_instruction* instr, int i) {
    instr->dst %= RX_REG_FLT_COUNT;
    genAddressReg(instr, true);
    emitByte(0x0F); emitByte(0x18); emitByte(0x04); emitByte(0x06);
    emitByte(0xC4); emitByte(0x61); emitByte(0x7A); emitByte(0xE6); emitByte(0x24); emitByte(0x06);
    emitByte(0xC4); emitByte(0xC1);
    emitByte(((15 - instr->dst) << 3) | 1);
    emitByte(0x58);
    emitByte(0xC4 | (instr->dst << 3));
}

void JitCompiler::h_FSUB_R(rx_instruction* instr, int i) {
    instr->dst %= RX_REG_FLT_COUNT;
    instr->src %= RX_REG_FLT_COUNT;
    emitByte(0xC4); emitByte(0xC1);
    emitByte(((15 - instr->dst) << 3) | 1);
    emitByte(0x5C);
    emitByte(0xC0 | (instr->dst << 3) | instr->src);
}

void JitCompiler::h_FSUB_M(rx_instruction* instr, int i) {
    instr->dst %= RX_REG_FLT_COUNT;
    genAddressReg(instr, true);
    emitByte(0x0F); emitByte(0x18); emitByte(0x04); emitByte(0x06);
    emitByte(0xC4); emitByte(0x61); emitByte(0x7A); emitByte(0xE6); emitByte(0x24); emitByte(0x06);
    emitByte(0xC4); emitByte(0xC1);
    emitByte(((15 - instr->dst) << 3) | 1);
    emitByte(0x5C);
    emitByte(0xC4 | (instr->dst << 3));
}

void JitCompiler::h_FSCAL_R(rx_instruction* instr, int i) {
    instr->dst %= RX_REG_FLT_COUNT;
    emitByte(0xC4); emitByte(0xC1);
    emitByte(((15 - instr->dst) << 3)); // pp=0
    emitByte(0x57);
    emitByte(0xC7 | (instr->dst << 3));
}

void JitCompiler::h_FMUL_R(rx_instruction* instr, int i) {
    instr->dst %= RX_REG_FLT_COUNT;
    instr->src %= RX_REG_FLT_COUNT;
    emitByte(0xC4); emitByte(0xC1);
    emitByte(((11 - instr->dst) << 3) | 1);
    emitByte(0x59);
    emitByte(0xE0 | (instr->dst << 3) | instr->src);
}

void JitCompiler::h_FDIV_M(rx_instruction* instr, int i) {
    instr->dst %= RX_REG_FLT_COUNT;
    genAddressReg(instr, true);
    emitByte(0x0F); emitByte(0x18); emitByte(0x04); emitByte(0x06);
    emitByte(0xC4); emitByte(0x61); emitByte(0x7A); emitByte(0xE6); emitByte(0x24); emitByte(0x06);
    emitByte(0xC4); emitByte(0x41); emitByte(0x18); emitByte(0x54); emitByte(0xE5);
    emitByte(0xC4); emitByte(0x41); emitByte(0x18); emitByte(0x56); emitByte(0xE6);
    emitByte(0xC4); emitByte(0xC1);
    emitByte(((11 - instr->dst) << 3) | 1);
    emitByte(0x5E);
    emitByte(0xE4 | (instr->dst << 3));
}

void JitCompiler::h_FSQRT_R(rx_instruction* instr, int i) {
    instr->dst %= RX_REG_FLT_COUNT;
    emitByte(0xC5); emitByte(0xF9); emitByte(0x51); emitByte(0xE4 | (9 * instr->dst)); // vsqrtpd xmm(dst+4), xmm(dst+4)
}

void JitCompiler::h_CFROUND(rx_instruction* instr, int i) {
    emitMov64RM(0, instr->src);
    int rotate = (13 - (getImm32(instr) & 63)) & 63;
    if (rotate != 0) {
        emitByte(0x48); emitByte(0xC1); emitByte(0xC0); emitByte(rotate);
    }
    emitByte(0x25); emitByte(0x00); emitByte(0x60); emitByte(0x00); emitByte(0x00);
    emitByte(0x0D); emitByte(0xC0); emitByte(0x9F); emitByte(0x00); emitByte(0x00);
    emitByte(0x89); emitByte(0x04); emitByte(0x24);
    emitByte(0x0F); emitByte(0xAE); emitByte(0x14); emitByte(0x24);
}

void JitCompiler::h_CBRANCH(rx_instruction* instr, int i) {
    int reg = instr->dst;
    int target = registerUsage[reg] + 1;
    emitByte(0x49); emitByte(0x81); emitByte(0xC0 | reg);
    int shift = getModCond(instr) + RX_CONDITION_OFFSET;
    uint32_t imm = (uint32_t)getImm32(instr) | (1UL << shift);
    if (RX_CONDITION_OFFSET > 0 || shift > 0)
        imm &= ~(1UL << (shift - 1));
    emit32(imm);
    emitByte(0x49); emitByte(0xF7); emitByte(0xC0 | reg);
    emit32(RX_CONDITION_MASK << shift);
    emitByte(0x0F); emitByte(0x84); emit32(instructionOffsets[target] - (pos + 4));
    for (unsigned j = 0; j < RX_REGISTERS_COUNT; j++)
        registerUsage[j] = i;
}

void JitCompiler::h_ISTORE(rx_instruction* instr, int i) {
    genAddressRegDst(instr);
    emitByte(0x4C); emitByte(0x89); emitByte(0x04 | (8 * instr->src)); emitByte(0x06);
}

void JitCompiler::h_NOP(rx_instruction* instr, int i) {
    emitByte(0x90);
}

static uint64_t randomx_reciprocal_fast_impl(uint32_t divisor) {
    uint64_t result;
    unsigned long index;
    _BitScanReverse64(&index, divisor);
    result = (uint64_t)1 << (index + 1);
    result /= divisor;
    return result;
}

extern "C" {

struct rx_jit {
    JitCompiler* compiler;
};

rx_jit* rx_jit_create(void) {
    init_engine();
    rx_jit* jit = (rx_jit*)calloc(1, sizeof(rx_jit));
    jit->compiler = new JitCompiler();
    jit->compiler->superscalar_cache = NULL;

    jit->compiler->code = (uint8_t*)VirtualAlloc(NULL, RX_TOTAL_CODE_SIZE,
        MEM_RESERVE | MEM_COMMIT | MEM_LARGE_PAGES, PAGE_EXECUTE_READWRITE);
    if (!jit->compiler->code) {
        jit->compiler->code = (uint8_t*)VirtualAlloc(NULL, RX_TOTAL_CODE_SIZE,
            MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    }
    if (!jit->compiler->code) { delete jit->compiler; free(jit); return NULL; }
    return jit;
}

void rx_jit_destroy(rx_jit* jit) {
    if (!jit) return;
    if (jit->compiler->code) VirtualFree(jit->compiler->code, 0, MEM_RELEASE);
    delete jit->compiler;
    free(jit);
}

void rx_jit_generate_program(rx_jit* jit, rx_program* prog, rx_program_config* pcfg, rx_cache* cache) {
    jit->compiler->cache = cache;
    memset(jit->compiler->code, 0xCC, RX_TOTAL_CODE_SIZE);
    jit->compiler->generateProgram(prog, pcfg);
    if (cache && cache != jit->compiler->superscalar_cache) {
        jit->compiler->superscalar_cache = cache;
        jit->compiler->generateSuperscalarHash(cache);
    }
    memcpy(jit->compiler->code + EPILOGUE_OFFSET, code_epilogue, EPILOGUE_SIZE);
}

void rx_jit_generate_program_light(rx_jit* jit, rx_program* prog, rx_program_config* pcfg,
                                     rx_cache* cache, uint32_t datasetOffset) {
    jit->compiler->cache = cache;
    jit->compiler->generateSuperscalarHash(cache);
    jit->compiler->generateProgramLight(prog, pcfg, datasetOffset);
}

void* rx_jit_get_program_func(rx_jit* jit) {
    return (void*)jit->compiler->code;
}

uint8_t* rx_jit_get_code_ptr(rx_jit* jit) {
    return jit->compiler->code;
}

int rx_jit_get_instruction_offset(rx_jit* jit, int index) {
    if (index < 0 || index >= (int)jit->compiler->instructionCount)
        return -1;
    return jit->compiler->instructionOffsets[index];
}

int rx_jit_get_num_instructions(rx_jit* jit) {
    return (int)jit->compiler->instructionCount;
}

}

extern "C" {
void rx_jit_generate_program_single_iter(rx_jit* jit, rx_program* prog, rx_program_config* pcfg, rx_cache* cache) {
    jit->compiler->cache = cache;
    memset(jit->compiler->code, 0xCC, RX_TOTAL_CODE_SIZE);
    jit->compiler->generateProgramSingleIter(prog, pcfg);
    if (cache) {
        jit->compiler->generateSuperscalarHash(cache);
    }
}

void rx_jit_generate_program_dual_interleaved(rx_jit* jit, rx_program* prog1, rx_program_config* pcfg1,
                                               rx_program* prog2, rx_program_config* pcfg2, rx_cache* cache) {
    jit->compiler->cache = cache;
    memset(jit->compiler->code, 0xCC, RX_TOTAL_CODE_SIZE);
    jit->compiler->generateProgramDualInterleaved(prog1, pcfg1, prog2, pcfg2);
    if (cache) {
        jit->compiler->generateSuperscalarHash(cache);
    }
}
}
