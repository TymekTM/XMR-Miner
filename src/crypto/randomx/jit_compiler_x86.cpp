#include "randomx_internal.h"

#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <vector>

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

static const int PROLOGUE_SIZE = 448;
static const int LOOP_LOAD_SIZE = 120;
static const int PREFETCH_SP_SIZE = 26;
static const int EPILOGUE_SIZE = 256;
static const int EMASK_OFFSET = PROLOGUE_SIZE - 48;

static const uint8_t code_prologue[] = {
    0x48, 0x81, 0xec, 0xc8, 0x01, 0x00, 0x00, 0x48, 0x89, 0x9c, 0x24, 0xe0, 0x00, 0x00, 0x00, 0x48,
    0x89, 0xac, 0x24, 0xe8, 0x00, 0x00, 0x00, 0x48, 0x89, 0xb4, 0x24, 0xf0, 0x00, 0x00, 0x00, 0x48,
    0x89, 0xbc, 0x24, 0xf8, 0x00, 0x00, 0x00, 0x4c, 0x89, 0xa4, 0x24, 0x00, 0x01, 0x00, 0x00, 0x4c,
    0x89, 0xac, 0x24, 0x08, 0x01, 0x00, 0x00, 0x4c, 0x89, 0xb4, 0x24, 0x10, 0x01, 0x00, 0x00, 0x4c,
    0x89, 0xbc, 0x24, 0x18, 0x01, 0x00, 0x00, 0x66, 0x0f, 0x7f, 0xb4, 0x24, 0x20, 0x01, 0x00, 0x00,
    0x66, 0x0f, 0x7f, 0xbc, 0x24, 0x30, 0x01, 0x00, 0x00, 0x66, 0x44, 0x0f, 0x7f, 0x84, 0x24, 0x40,
    0x01, 0x00, 0x00, 0x66, 0x44, 0x0f, 0x7f, 0x8c, 0x24, 0x50, 0x01, 0x00, 0x00, 0x66, 0x44, 0x0f,
    0x7f, 0x94, 0x24, 0x60, 0x01, 0x00, 0x00, 0x66, 0x44, 0x0f, 0x7f, 0x9c, 0x24, 0x70, 0x01, 0x00,
    0x00, 0x66, 0x44, 0x0f, 0x7f, 0xa4, 0x24, 0x80, 0x01, 0x00, 0x00, 0x66, 0x44, 0x0f, 0x7f, 0xac,
    0x24, 0x90, 0x01, 0x00, 0x00, 0x66, 0x44, 0x0f, 0x7f, 0xb4, 0x24, 0xa0, 0x01, 0x00, 0x00, 0x66,
    0x44, 0x0f, 0x7f, 0xbc, 0x24, 0xb0, 0x01, 0x00, 0x00, 0x48, 0x89, 0x8c, 0x24, 0xc0, 0x01, 0x00,
    0x00, 0x48, 0x8b, 0x2a, 0x48, 0x8b, 0x7a, 0x08, 0x49, 0x8b, 0xf0, 0x49, 0x8b, 0xd9, 0x48, 0x8b,
    0xc5, 0x44, 0x8b, 0xc5, 0x48, 0xc1, 0xcd, 0x20, 0x44, 0x8b, 0xcd, 0x41, 0x81, 0xe0, 0xc0, 0xff,
    0xff, 0x7f, 0x41, 0x81, 0xe1, 0xc0, 0xff, 0xff, 0x7f, 0x42, 0x0f, 0x18, 0x04, 0x07, 0x42, 0x0f,
    0x18, 0x04, 0x0f, 0x4d, 0x33, 0xc0, 0x4d, 0x33, 0xc9, 0x4d, 0x33, 0xd2, 0x4d, 0x33, 0xdb, 0x4d,
    0x33, 0xe4, 0x4d, 0x33, 0xed, 0x4d, 0x33, 0xf6, 0x4d, 0x33, 0xff, 0x48, 0x8d, 0x49, 0x78, 0x66,
    0x44, 0x0f, 0x28, 0x41, 0x48, 0x66, 0x44, 0x0f, 0x28, 0x49, 0x58, 0x66, 0x44, 0x0f, 0x28, 0x51,
    0x68, 0x66, 0x44, 0x0f, 0x28, 0x59, 0x78, 0x66, 0x44, 0x0f, 0x28, 0x2d, 0x60, 0x00, 0x00, 0x00,
    0x66, 0x44, 0x0f, 0x28, 0x35, 0x67, 0x00, 0x00, 0x00, 0x66, 0x44, 0x0f, 0x28, 0x3d, 0x6e, 0x00,
    0x00, 0x00, 0x48, 0x8b, 0xd0, 0x25, 0xc0, 0xff, 0x1f, 0x00, 0x48, 0xc1, 0xca, 0x20, 0x81, 0xe2,
    0xc0, 0xff, 0x1f, 0x00, 0xe9, 0x77, 0x00, 0x00, 0x00, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x0f,
    0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x0f, 0x1f,
    0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x66, 0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x80,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x0f, 0x1f, 0x84, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x90,
};

static const uint8_t code_loop_load[] = {
    0x48, 0x8d, 0x0c, 0x06, 0x48, 0x89, 0x4c, 0x24, 0x08, 0x4c, 0x33, 0x01, 0x4c, 0x33, 0x49, 0x08,
    0x4c, 0x33, 0x51, 0x10, 0x4c, 0x33, 0x59, 0x18, 0x4c, 0x33, 0x61, 0x20, 0x4c, 0x33, 0x69, 0x28,
    0x4c, 0x33, 0x71, 0x30, 0x4c, 0x33, 0x79, 0x38, 0x48, 0x8d, 0x0c, 0x16, 0x48, 0x89, 0x4c, 0x24,
    0x10, 0xf3, 0x0f, 0xe6, 0x01, 0xf3, 0x0f, 0xe6, 0x49, 0x08, 0xf3, 0x0f, 0xe6, 0x51, 0x10, 0xf3,
    0x0f, 0xe6, 0x59, 0x18, 0xf3, 0x0f, 0xe6, 0x61, 0x20, 0xf3, 0x0f, 0xe6, 0x69, 0x28, 0xf3, 0x0f,
    0xe6, 0x71, 0x30, 0xf3, 0x0f, 0xe6, 0x79, 0x38, 0x41, 0x0f, 0x54, 0xe5, 0x41, 0x0f, 0x54, 0xed,
    0x41, 0x0f, 0x54, 0xf5, 0x41, 0x0f, 0x54, 0xfd, 0x41, 0x0f, 0x56, 0xe6, 0x41, 0x0f, 0x56, 0xee,
    0x41, 0x0f, 0x56, 0xf6, 0x41, 0x0f, 0x56, 0xfe,
};

static const uint8_t code_prefetch_sp[] = {
    0x48, 0x8b, 0xd0, 0x25, 0xc0, 0xff, 0x1f, 0x00, 0x0f, 0x18, 0x0c, 0x06, 0x48, 0xc1, 0xca, 0x20,
    0x81, 0xe2, 0xc0, 0xff, 0x1f, 0x00, 0x0f, 0x18, 0x0c, 0x16,
};

static const uint8_t code_loop_store[] = {
    0x48, 0x8b, 0x4c, 0x24, 0x10, 0x4c, 0x89, 0x01, 0x4c, 0x89, 0x49, 0x08, 0x4c, 0x89, 0x51, 0x10,
    0x4c, 0x89, 0x59, 0x18, 0x4c, 0x89, 0x61, 0x20, 0x4c, 0x89, 0x69, 0x28, 0x4c, 0x89, 0x71, 0x30,
    0x4c, 0x89, 0x79, 0x38, 0x48, 0x8b, 0x4c, 0x24, 0x08, 0x66, 0x0f, 0x57, 0xc4, 0x66, 0x0f, 0x57,
    0xcd, 0x66, 0x0f, 0x57, 0xd6, 0x66, 0x0f, 0x57, 0xdf, 0x66, 0x0f, 0x29, 0x01, 0x66, 0x0f, 0x29,
    0x49, 0x10, 0x66, 0x0f, 0x29, 0x51, 0x20, 0x66, 0x0f, 0x29, 0x59, 0x30,
};
static const int LOOP_STORE_SIZE = sizeof(code_loop_store);

static const uint8_t code_read_dataset[] = {
    0x8b, 0xcd, 0x81, 0xe1, 0xc0, 0xff, 0xff, 0x7f, 0x4c, 0x33, 0x04, 0x0f, 0x48, 0xc1, 0xcd, 0x20,
    0x48, 0x33, 0xe8, 0x8b, 0xd5, 0x81, 0xe2, 0xc0, 0xff, 0xff, 0x7f, 0x0f, 0x18, 0x04, 0x17, 0x4c,
    0x33, 0x4c, 0x0f, 0x08, 0x4c, 0x33, 0x54, 0x0f, 0x10, 0x4c, 0x33, 0x5c, 0x0f, 0x18, 0x4c, 0x33,
    0x64, 0x0f, 0x20, 0x4c, 0x33, 0x6c, 0x0f, 0x28, 0x4c, 0x33, 0x74, 0x0f, 0x30, 0x4c, 0x33, 0x7c,
    0x0f, 0x38,
};
static const int READ_DATASET_SIZE = sizeof(code_read_dataset);

static const uint8_t code_epilogue[] = {
    0x48, 0x8b, 0x8c, 0x24, 0xc0, 0x01, 0x00, 0x00, 0x4c, 0x89, 0x01, 0x4c, 0x89, 0x49, 0x08, 0x4c,
    0x89, 0x51, 0x10, 0x4c, 0x89, 0x59, 0x18, 0x4c, 0x89, 0x61, 0x20, 0x4c, 0x89, 0x69, 0x28, 0x4c,
    0x89, 0x71, 0x30, 0x4c, 0x89, 0x79, 0x38, 0x66, 0x0f, 0x7f, 0x41, 0x40, 0x66, 0x0f, 0x7f, 0x49,
    0x50, 0x66, 0x0f, 0x7f, 0x51, 0x60, 0x66, 0x0f, 0x7f, 0x59, 0x70, 0x48, 0x8d, 0x49, 0x40, 0x66,
    0x0f, 0x7f, 0x61, 0x40, 0x66, 0x0f, 0x7f, 0x69, 0x50, 0x66, 0x0f, 0x7f, 0x71, 0x60, 0x66, 0x0f,
    0x7f, 0x79, 0x70, 0x66, 0x44, 0x0f, 0x6f, 0xbc, 0x24, 0xb0, 0x01, 0x00, 0x00, 0x66, 0x44, 0x0f,
    0x6f, 0xb4, 0x24, 0xa0, 0x01, 0x00, 0x00, 0x66, 0x44, 0x0f, 0x6f, 0xac, 0x24, 0x90, 0x01, 0x00,
    0x00, 0x66, 0x44, 0x0f, 0x6f, 0xa4, 0x24, 0x80, 0x01, 0x00, 0x00, 0x66, 0x44, 0x0f, 0x6f, 0x9c,
    0x24, 0x70, 0x01, 0x00, 0x00, 0x66, 0x44, 0x0f, 0x6f, 0x94, 0x24, 0x60, 0x01, 0x00, 0x00, 0x66,
    0x44, 0x0f, 0x6f, 0x8c, 0x24, 0x50, 0x01, 0x00, 0x00, 0x66, 0x44, 0x0f, 0x6f, 0x84, 0x24, 0x40,
    0x01, 0x00, 0x00, 0x66, 0x0f, 0x6f, 0xbc, 0x24, 0x30, 0x01, 0x00, 0x00, 0x66, 0x0f, 0x6f, 0xb4,
    0x24, 0x20, 0x01, 0x00, 0x00, 0x4c, 0x8b, 0xbc, 0x24, 0x18, 0x01, 0x00, 0x00, 0x4c, 0x8b, 0xb4,
    0x24, 0x10, 0x01, 0x00, 0x00, 0x4c, 0x8b, 0xac, 0x24, 0x08, 0x01, 0x00, 0x00, 0x4c, 0x8b, 0xa4,
    0x24, 0x00, 0x01, 0x00, 0x00, 0x48, 0x8b, 0xbc, 0x24, 0xf8, 0x00, 0x00, 0x00, 0x48, 0x8b, 0xb4,
    0x24, 0xf0, 0x00, 0x00, 0x00, 0x48, 0x8b, 0xac, 0x24, 0xe8, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x9c,
    0x24, 0xe0, 0x00, 0x00, 0x00,     0x48, 0x81, 0xc4, 0xc8, 0x01, 0x00, 0x00, 0xc3, 0x0f, 0x1f, 0x00,
};


static const int EPILOGUE_OFFSET = RX_PROGRAM_CODE_SIZE + RX_SUPER_CODE_SIZE - EPILOGUE_SIZE;

static uint64_t randomx_reciprocal_fast_impl(uint32_t divisor);

static inline uint32_t align_up(uint32_t val, uint32_t align) {
    return (val + align - 1) & ~(align - 1);
}

struct JitCompiler {
    uint8_t* code;
    int32_t pos;
    std::vector<int32_t> instructionOffsets;
    int registerUsage[RX_REGISTERS_COUNT];
    rx_cache* cache;

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
        instructionOffsets.push_back(pos);
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

    void generateProgramPrologue(rx_program* prog, rx_program_config* pcfg) {
        instructionOffsets.clear();
        for (int i = 0; i < RX_REGISTERS_COUNT; i++) registerUsage[i] = -1;

        pos = PROLOGUE_SIZE;
        memcpy(code + EMASK_OFFSET, pcfg->eMask, sizeof(pcfg->eMask));
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

    void generateProgramEpilogue(rx_program* prog, rx_program_config* pcfg) {
        emitByte(0x4C); emitByte(0x8B); emitByte(0xC0 + pcfg->readReg0);
        emitByte(0x4C); emitByte(0x33); emitByte(0xC0 + pcfg->readReg1);

        emit(code_prefetch_sp, PREFETCH_SP_SIZE);

        int loopStoreStart = pos;
        memcpy(code + pos, code_loop_store, LOOP_STORE_SIZE);
        pos += LOOP_STORE_SIZE;

        emitByte(0x83); emitByte(0xEB); emitByte(0x01);
        int jnzPos = pos;
        emitByte(0x0F); emitByte(0x85); emit32(0);
        emitByte(0xE9); emit32(0);

        {
            int32_t patch = PROLOGUE_SIZE - (jnzPos + 6);
            memcpy(code + jnzPos + 2, &patch, 4);
        }
        {
            int32_t patch = EPILOGUE_OFFSET - (jnzPos + 11);
            memcpy(code + jnzPos + 7, &patch, 4);
        }
    }

    void generateProgram(rx_program* prog, rx_program_config* pcfg) {
        memcpy(code, code_prologue, PROLOGUE_SIZE);
        memcpy(code + EPILOGUE_OFFSET, code_epilogue, EPILOGUE_SIZE);

        generateProgramPrologue(prog, pcfg);

        memcpy(code + pos, code_read_dataset, READ_DATASET_SIZE);
        pos += READ_DATASET_SIZE;

        generateProgramEpilogue(prog, pcfg);

        printf("[JIT] codeSize=%d epilogueOffset=%d\n", pos, EPILOGUE_OFFSET); fflush(stdout);
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
            emitMov64RM(instr->dst, instr->dst);
            emitByte(0x49); emitByte(0xF7); emitByte(0xE0 | instr->src);
            emitByte(0x4C); emitByte(0x8B); emitByte(0xC2 | (8 * instr->dst));
        } else if (opcode == RX_SS_ISMULH_R) {
            emitMov64RM(instr->dst, instr->dst);
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
                emitMov64RM(prog->addrReg, prog->addrReg);
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
        memcpy(code, code_prologue, PROLOGUE_SIZE);
        memcpy(code + EPILOGUE_OFFSET, code_epilogue, EPILOGUE_SIZE);

        generateProgramPrologue(prog, pcfg);

        emitByte(0x83); emitByte(0xC3);
        emit32(datasetOffset / RX_CACHE_LINE_SIZE);
        emitByte(0xE8);
        emit32(RX_SUPER_OFFSET - (pos + 4));

        memcpy(code + pos, code_epilogue, EPILOGUE_SIZE);
        fixupCallOffsets(code + pos, EPILOGUE_SIZE, pos);
        pos += EPILOGUE_SIZE;

        generateProgramEpilogue(prog, pcfg);
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
    emitMov64RM(instr->dst, instr->dst);
    emitByte(0x49); emitByte(0xF7); emitByte(0xE0 | instr->src);
    emitByte(0x4C); emitByte(0x8B); emitByte(0xC2 | (8 * instr->dst));
}

void JitCompiler::h_IMULH_M(rx_instruction* instr, int i) {
    registerUsage[instr->dst] = i;
    if (instr->src != instr->dst) {
        genAddressReg(instr, false);
        emitMov64RM(instr->dst, instr->dst);
        emitByte(0x48); emitByte(0xF7); emitByte(0x24); emitByte(0x0E);
    } else {
        emitMov64RM(instr->dst, instr->dst);
        emitByte(0x48); emitByte(0xF7); emitByte(0xA6);
        genAddressImm(instr);
    }
    emitByte(0x4C); emitByte(0x8B); emitByte(0xC2 | (8 * instr->dst));
}

void JitCompiler::h_ISMULH_R(rx_instruction* instr, int i) {
    registerUsage[instr->dst] = i;
    emitMov64RM(instr->dst, instr->dst);
    emitByte(0x49); emitByte(0xF7); emitByte(0xE8 | instr->src);
    emitByte(0x4C); emitByte(0x8B); emitByte(0xC2 | (8 * instr->dst));
}

void JitCompiler::h_ISMULH_M(rx_instruction* instr, int i) {
    registerUsage[instr->dst] = i;
    if (instr->src != instr->dst) {
        genAddressReg(instr, false);
        emitMov64RM(instr->dst, instr->dst);
        emitByte(0x48); emitByte(0xF7); emitByte(0x2C); emitByte(0x0E);
    } else {
        emitMov64RM(instr->dst, instr->dst);
        emitByte(0x48); emitByte(0xF7); emitByte(0xAE);
        genAddressImm(instr);
    }
    emitByte(0x4C); emitByte(0x8B); emitByte(0xC2 | (8 * instr->dst));
}

void JitCompiler::h_IMUL_RCP(rx_instruction* instr, int i) {
    uint32_t divisor = (uint32_t)getImm32(instr);
    if (!is_zero_or_power_of_2(divisor)) {
        registerUsage[instr->dst] = i;
        emitByte(0x48); emitByte(0xB8); emit64(randomx_reciprocal_fast_impl(divisor));
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
    emitByte(0x66); emitByte(0x0F); emitByte(0xC6); emitByte(0xC0 | (9 * instr->dst)); emitByte(1);
}

void JitCompiler::h_FADD_R(rx_instruction* instr, int i) {
    instr->dst %= RX_REG_FLT_COUNT;
    instr->src %= RX_REG_FLT_COUNT;
    emitByte(0x66); emitByte(0x41); emitByte(0x0F); emitByte(0x58);
    emitByte(0xC0 | instr->src | (8 * instr->dst));
}

void JitCompiler::h_FADD_M(rx_instruction* instr, int i) {
    instr->dst %= RX_REG_FLT_COUNT;
    genAddressReg(instr, true);
    emitByte(0xF3); emitByte(0x44); emitByte(0x0F); emitByte(0xE6); emitByte(0x24); emitByte(0x06);
    emitByte(0x66); emitByte(0x41); emitByte(0x0F); emitByte(0x58);
    emitByte(0xC4 | (8 * instr->dst));
}

void JitCompiler::h_FSUB_R(rx_instruction* instr, int i) {
    instr->dst %= RX_REG_FLT_COUNT;
    instr->src %= RX_REG_FLT_COUNT;
    emitByte(0x66); emitByte(0x41); emitByte(0x0F); emitByte(0x5C);
    emitByte(0xC0 | instr->src | (8 * instr->dst));
}

void JitCompiler::h_FSUB_M(rx_instruction* instr, int i) {
    instr->dst %= RX_REG_FLT_COUNT;
    genAddressReg(instr, true);
    emitByte(0xF3); emitByte(0x44); emitByte(0x0F); emitByte(0xE6); emitByte(0x24); emitByte(0x06);
    emitByte(0x66); emitByte(0x41); emitByte(0x0F); emitByte(0x5C);
    emitByte(0xC4 | (8 * instr->dst));
}

void JitCompiler::h_FSCAL_R(rx_instruction* instr, int i) {
    instr->dst %= RX_REG_FLT_COUNT;
    emitByte(0x41); emitByte(0x0F); emitByte(0x57); emitByte(0xC7 | (8 * instr->dst));
}

void JitCompiler::h_FMUL_R(rx_instruction* instr, int i) {
    instr->dst %= RX_REG_FLT_COUNT;
    instr->src %= RX_REG_FLT_COUNT;
    emitByte(0x66); emitByte(0x41); emitByte(0x0F); emitByte(0x59);
    emitByte(0xE0 | instr->src | (8 * instr->dst));
}

void JitCompiler::h_FDIV_M(rx_instruction* instr, int i) {
    instr->dst %= RX_REG_FLT_COUNT;
    genAddressReg(instr, true);
    emitByte(0xF3); emitByte(0x44); emitByte(0x0F); emitByte(0xE6); emitByte(0x24); emitByte(0x06);
    emitByte(0x45); emitByte(0x0F); emitByte(0x54); emitByte(0xE5);
    emitByte(0x45); emitByte(0x0F); emitByte(0x56); emitByte(0xE6);
    emitByte(0x66); emitByte(0x41); emitByte(0x0F); emitByte(0x5E);
    emitByte(0xE4 | (8 * instr->dst));
}

void JitCompiler::h_FSQRT_R(rx_instruction* instr, int i) {
    instr->dst %= RX_REG_FLT_COUNT;
    emitByte(0x66); emitByte(0x0F); emitByte(0x51); emitByte(0xE4 | (9 * instr->dst));
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
    jit->compiler->code = (uint8_t*)VirtualAlloc(NULL, RX_TOTAL_CODE_SIZE,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!jit->compiler->code) { delete jit->compiler; free(jit); return NULL; }
    return jit;
}

void rx_jit_destroy(rx_jit* jit) {
    if (!jit) return;
    if (jit->compiler->code) VirtualFree(jit->compiler->code, 0, MEM_RELEASE);
    delete jit->compiler;
    free(jit);
}

void rx_jit_generate_program(rx_jit* jit, rx_program* prog, rx_program_config* pcfg) {
    DWORD oldProtect;
    VirtualProtect(jit->compiler->code, RX_TOTAL_CODE_SIZE, PAGE_READWRITE, &oldProtect);
    jit->compiler->cache = nullptr;
    jit->compiler->generateProgram(prog, pcfg);
    VirtualProtect(jit->compiler->code, RX_TOTAL_CODE_SIZE, PAGE_EXECUTE_READ, &oldProtect);
}

void rx_jit_generate_program_light(rx_jit* jit, rx_program* prog, rx_program_config* pcfg,
                                     rx_cache* cache, uint32_t datasetOffset) {
    DWORD oldProtect;
    VirtualProtect(jit->compiler->code, RX_TOTAL_CODE_SIZE, PAGE_READWRITE, &oldProtect);
    jit->compiler->cache = cache;
    jit->compiler->generateSuperscalarHash(cache);
    jit->compiler->generateProgramLight(prog, pcfg, datasetOffset);
    VirtualProtect(jit->compiler->code, RX_TOTAL_CODE_SIZE, PAGE_EXECUTE_READ, &oldProtect);
}

void* rx_jit_get_program_func(rx_jit* jit) {
    return (void*)jit->compiler->code;
}

}
