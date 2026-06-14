#include "randomx_internal.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

extern "C" int g_jit_short_branches;
extern "C" int g_jit_involution_pairs;
extern "C" int g_jit_branch_align;
extern "C" int g_jit_loop_nop;
extern "C" int g_jit_sp_prefetch_hint;
extern "C" int g_jit_bmi2_mulx;
extern "C" int g_jit_cfround_elim;
extern "C" int g_jit_large_pages;
extern "C" int g_jit_jcc_align;
extern "C" int g_jit_near_rcp_pool;
extern "C" int g_jit_double_buffer;
extern "C" int g_jit_inline_rcp_pool;
extern "C" int g_jit_rorx;
extern "C" int g_jit_stack_rcp_pool;
extern "C" int g_jit_cfround_rorx;

#define RX_DATASET_BASE_MASK  (RX_DATASET_BASE_SIZE - 64)
#define RX_CACHE_MASK         ((RX_ARGON_MEMORY * 16) - 1)
#define RX_SCRATCHPAD_MASK    (RX_SCRATCHPAD_L3 - 64)
    #define RX_CODE_ALIGN         32
#define RX_MAX_INSTR_CODE     32
#define RX_SUPER_INSTR_MAX    14
#define RX_SUPER_PROG_HDR     128
#define RX_PROGRAM_CODE_SIZE  16384
#define RX_SUPER_CODE_SIZE    (((RX_CODE_ALIGN + (RX_SUPER_PROG_HDR + RX_SUPER_INSTR_MAX * RX_SUPERSCALAR_MAX_SIZE) * RX_CACHE_ACCESSES - 1) / RX_CODE_ALIGN + 1) * RX_CODE_ALIGN)
#define RX_TOTAL_CODE_SIZE    (RX_PROGRAM_CODE_SIZE + RX_SUPER_CODE_SIZE + 128)
#define RX_SUPER_OFFSET       RX_PROGRAM_CODE_SIZE
#define IMUL_RCP_POOL_SIZE    16
#define IMUL_RCP_POOL_OFFSET  (RX_TOTAL_CODE_SIZE - IMUL_RCP_POOL_SIZE * 8)
#define RX_REGISTER_NEEDS_SIB     4
#define RX_REGISTER_NEEDS_DISP    5
#define RX_CONDITION_OFFSET       8
#define RX_STORE_L3_CONDITION     14

    static const int PROLOGUE_SIZE = 212;
static const int FIRST_LOAD_SIZE = 37;
static const int CONSTANTS_SIZE = 48;
static const int IMUL_RCP_SIZE = 5;
    static const int LOOP_LOAD_SIZE = 120;
static const int PREFETCH_SP_SIZE = 26;
static const int LOOP_STORE_SIZE = 68;
    static const int EPILOGUE_SIZE = 175;
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
    0xff, 0x7f, 0x0f, 0x18, 0x44, 0x38, 0x00, 0x4c, 0x89, 0xc6, 0x49, 0x8b, 0xd9, 0x48, 0x8b, 0xc5, 0x48,
    0xc1, 0xcd, 0x20, 0x4d, 0x33, 0xc0, 0x4d, 0x33, 0xc9, 0x4d, 0x33, 0xd2, 0x4d, 0x33, 0xdb, 0x4d,
    0x33, 0xe4, 0x4d, 0x33, 0xed, 0x4d, 0x33, 0xf6, 0x4d, 0x33, 0xff, 0x48, 0x8d, 0x49, 0x78, 0x66,
    0x44, 0x0f, 0x28, 0x41, 0x48, 0x66, 0x44, 0x0f, 0x28, 0x49, 0x58, 0x66, 0x44, 0x0f, 0x28, 0x51,
    0x68, 0x66, 0x44, 0x0f, 0x28, 0x59, 0x78, 0x66, 0x44, 0x0f, 0x28, 0x2d, 0x00, 0x00, 0x00, 0x00,
    0x66, 0x44, 0x0f, 0x28, 0x35, 0x00, 0x00, 0x00, 0x00, 0x66, 0x44, 0x0f, 0x28, 0x3d, 0x00, 0x00,
    0x00, 0x00,
};

static const uint8_t code_first_load[] = {
    0x48, 0x8b, 0xd0, 0x25, 0xc0, 0xff, 0x1f, 0x00,
    0x48, 0xc1, 0xca, 0x20, 0x81, 0xe2, 0xc0, 0xff,
    0x1f, 0x00, 0x48, 0x81, 0xec, 0x28, 0x00, 0x00,
    0x00, 0xc7, 0x04, 0x24, 0xc0, 0x9f, 0x00, 0x00,
    0xe9, 0x00, 0x00, 0x00, 0x00,
};

static const uint8_t code_constants[] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x80,
};

static const uint8_t code_imul_rcp[] = {
    0xe9, 0x00, 0x00, 0x00, 0x00,
};

static const uint8_t code_loop_load[] = {
    0x48, 0x8d, 0x0c, 0x06, 0x48, 0x89, 0x4c, 0x24, 0x10, 0x4c, 0x33, 0x01, 0x4c, 0x33, 0x49, 0x08,
    0x4c, 0x33, 0x51, 0x10, 0x4c, 0x33, 0x59, 0x18, 0x4c, 0x33, 0x61, 0x20, 0x4c, 0x33, 0x69, 0x28,
    0x4c, 0x33, 0x71, 0x30, 0x4c, 0x33, 0x79, 0x38, 0x48, 0x8d, 0x0c, 0x16, 0x48, 0x89, 0x4c, 0x24,
    0x18, 0xf3, 0x0f, 0xe6, 0x01, 0xf3, 0x0f, 0xe6, 0x49, 0x08, 0xf3, 0x0f, 0xe6, 0x51, 0x10, 0xf3,
    0x0f, 0xe6, 0x59, 0x18, 0xf3, 0x0f, 0xe6, 0x61, 0x20, 0xf3, 0x0f, 0xe6, 0x69, 0x28, 0xf3, 0x0f,
    0xe6, 0x71, 0x30, 0xf3, 0x0f, 0xe6, 0x79, 0x38, 0x41, 0x0f, 0x54, 0xe5, 0x41, 0x0f, 0x54, 0xed,
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
    0x4c, 0x89, 0x79, 0x38, 0x48, 0x8b, 0x4c, 0x24, 0x10, 0x0f, 0x57, 0xc4, 0x0f, 0x57,
    0xcd, 0x0f, 0x57, 0xd6, 0x0f, 0x57, 0xdf, 0x0f, 0x29, 0x01, 0x0f, 0x29,
    0x49, 0x10, 0x0f, 0x29, 0x51, 0x20, 0x0f, 0x29, 0x59, 0x30,
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
    0x48, 0x81, 0xc4, 0xa0, 0x00, 0x00, 0x00,
    0xf3, 0x44, 0x0f, 0x6f, 0x54, 0x24, 0xb0,
    0xf3, 0x44, 0x0f, 0x6f, 0x4c, 0x24, 0xc0,
    0xf3, 0x44, 0x0f, 0x6f, 0x44, 0x24, 0xd0,
    0xf3, 0x0f, 0x6f, 0x7c, 0x24, 0xe0,
    0xf3, 0x0f, 0x6f, 0x74, 0x24, 0xf0,
    0x41, 0x5f, 0x41, 0x5e, 0x41, 0x5d, 0x41, 0x5c, 0x5e, 0x5f, 0x5d, 0x5b,
    0xc3,
};


static const int EPILOGUE_OFFSET = RX_PROGRAM_CODE_SIZE + RX_SUPER_CODE_SIZE - EPILOGUE_SIZE;

static uint64_t randomx_reciprocal_fast_impl(uint32_t divisor);

static inline uint32_t align_up(uint32_t val, uint32_t align) {
    return (val + align - 1) & ~(align - 1);
}

struct JitCompiler {
    uint8_t* code;
    uint8_t* codeSlots[2];
    int activeCodeSlot;
    int32_t pos;
    int32_t instructionOffsets[RX_PROGRAM_SIZE]; int instructionCount;
    int registerUsage[RX_REGISTERS_COUNT];
    rx_cache* cache;
    rx_cache* superscalar_cache;
    rx_cache* superscalarCacheSlots[2];
    uint64_t imul_rcp_pool[IMUL_RCP_POOL_SIZE];
    int imul_rcp_pool_count;
    int activeRcpPoolOffset;
    int activeStackRcpPool;
    int32_t prevFPOperation;
    int32_t prevCFROUND;
    int32_t prevCFROUNDLength;
    int shortBranchCount;
    int generatedCodeSize;
    uint8_t skipInstruction[RX_PROGRAM_SIZE];
    uint8_t branchTarget[RX_PROGRAM_SIZE];

    void emitByte(uint8_t b) { code[pos++] = b; }
    void emit32(uint32_t v) { memcpy(code + pos, &v, 4); pos += 4; }
    void emit64(uint64_t v) { memcpy(code + pos, &v, 8); pos += 8; }
    void emit(const uint8_t* src, int len) { memcpy(code + pos, src, len); pos += len; }
    void emitByteAt(int& at, uint8_t b) { code[at++] = b; }
    void emit32At(int& at, uint32_t v) {
        memcpy(code + at, &v, 4);
        at += 4;
    }
    void emit64At(int& at, uint64_t v) {
        memcpy(code + at, &v, 8);
        at += 8;
    }
    int imulRcpPoolOffset() const {
        if (activeRcpPoolOffset > 0)
            return activeRcpPoolOffset;
        return g_jit_near_rcp_pool ?
            RX_PROGRAM_CODE_SIZE - IMUL_RCP_POOL_SIZE * 8 :
            IMUL_RCP_POOL_OFFSET;
    }

    void emitScratchpadPrefetch() {
        uint8_t prefetch[PREFETCH_SP_SIZE];
        memcpy(prefetch, code_prefetch_sp, sizeof(prefetch));
        int hint = g_jit_sp_prefetch_hint & 3;
        prefetch[10] = (uint8_t)((prefetch[10] & 0xC7) | (hint << 3));
        prefetch[24] = (uint8_t)((prefetch[24] & 0xC7) | (hint << 3));
        emit(prefetch, sizeof(prefetch));
    }

    __forceinline void alignCode(int align) {
        while (pos % align) {
            int n = align - (pos % align);
            if (n > 8) n = 8;
            static const int nopLen[] = {1,2,3,4,5,6,7,8};
            static const uint8_t nopBytes[][8] = {
                {0x90},
                {0x66,0x90},
                {0x0F,0x1F,0x00},
                {0x0F,0x1F,0x40,0x00},
                {0x0F,0x1F,0x44,0x00,0x00},
                {0x66,0x0F,0x1F,0x44,0x00,0x00},
                {0x0F,0x1F,0x80,0x00,0x00,0x00,0x00},
                {0x0F,0x1F,0x84,0x00,0x00,0x00,0x00,0x00},
            };
            int idx = n - 1;
            if (idx >= 8) idx = 7;
            for (int i = 0; i < nopLen[idx] && pos % align; i++)
                emitByte(nopBytes[idx][i]);
        }
    }

    int32_t getImm32(rx_instruction* instr) {
        return (int32_t)(uint32_t)instr->imm32;
    }

    __forceinline int getModShift(rx_instruction* instr) { return (instr->mod >> 2) & 3; }
    __forceinline int getModCond(rx_instruction* instr) { return instr->mod >> 4; }
    __forceinline int getModMem(rx_instruction* instr) { return instr->mod & 3; }

    __forceinline void genSIB(int scale, int index, int base) {
        emitByte((scale << 6) | ((index & 7) << 3) | (base & 7));
    }

    __forceinline void genAddressReg(rx_instruction* instr, bool useRax) {
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

    __forceinline void genAddressRegDst(rx_instruction* instr) {
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

    __forceinline void genAddressImm(rx_instruction* instr) {
        emit32((uint32_t)getImm32(instr) & RX_SPL3_MASK);
    }

    __forceinline void emitMov64RM(int dst_gpr, int src_gpr) {
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

    void analyzeInvolutionPairs(rx_program* prog) {
        int integerUsage[RX_REGISTERS_COUNT];
        int pendingFscal[RX_REG_FLT_COUNT];
        int pendingFswapF[RX_REG_FLT_COUNT];
        int pendingFswapE[RX_REG_FLT_COUNT];
        memset(skipInstruction, 0, sizeof(skipInstruction));
        memset(branchTarget, 0, sizeof(branchTarget));
        if (!g_jit_involution_pairs && g_jit_branch_align <= 1)
            return;
        for (int reg = 0; reg < RX_REGISTERS_COUNT; ++reg)
            integerUsage[reg] = -1;

        for (int i = 0; i < RX_PROGRAM_SIZE; ++i) {
            rx_instruction* instr = &prog->programBuffer[i];
            InstrGen gen = engine[instr->opcode];
            int dst = instr->dst % RX_REGISTERS_COUNT;
            int src = instr->src % RX_REGISTERS_COUNT;

            if (gen == &JitCompiler::h_CBRANCH) {
                int target = integerUsage[dst] + 1;
                if (target >= 0 && target < RX_PROGRAM_SIZE)
                    branchTarget[target] = 1;
                for (int reg = 0; reg < RX_REGISTERS_COUNT; ++reg)
                    integerUsage[reg] = i;
            } else if (gen == &JitCompiler::h_ISWAP_R) {
                if (dst != src) {
                    integerUsage[dst] = i;
                    integerUsage[src] = i;
                }
            } else if (gen == &JitCompiler::h_IADD_RS ||
                       gen == &JitCompiler::h_IADD_M ||
                       gen == &JitCompiler::h_ISUB_R ||
                       gen == &JitCompiler::h_ISUB_M ||
                       gen == &JitCompiler::h_IMUL_R ||
                       gen == &JitCompiler::h_IMUL_M ||
                       gen == &JitCompiler::h_IMULH_R ||
                       gen == &JitCompiler::h_IMULH_M ||
                       gen == &JitCompiler::h_ISMULH_R ||
                       gen == &JitCompiler::h_ISMULH_M ||
                       gen == &JitCompiler::h_INEG_R ||
                       gen == &JitCompiler::h_IXOR_R ||
                       gen == &JitCompiler::h_IXOR_M ||
                       gen == &JitCompiler::h_IROR_R ||
                       gen == &JitCompiler::h_IROL_R) {
                integerUsage[dst] = i;
            } else if (gen == &JitCompiler::h_IMUL_RCP &&
                       !is_zero_or_power_of_2((uint32_t)getImm32(instr))) {
                integerUsage[dst] = i;
            }
        }

        if (!g_jit_involution_pairs)
            return;

        for (int reg = 0; reg < RX_REG_FLT_COUNT; ++reg) {
            pendingFscal[reg] = -1;
            pendingFswapF[reg] = -1;
            pendingFswapE[reg] = -1;
        }

        for (int i = 0; i < RX_PROGRAM_SIZE; ++i) {
            rx_instruction* instr = &prog->programBuffer[i];
            InstrGen gen = engine[instr->opcode];
            if (branchTarget[i] || gen == &JitCompiler::h_CBRANCH) {
                for (int reg = 0; reg < RX_REG_FLT_COUNT; ++reg) {
                    pendingFscal[reg] = -1;
                    pendingFswapF[reg] = -1;
                    pendingFswapE[reg] = -1;
                }
            }

            if (gen == &JitCompiler::h_FSCAL_R) {
                int reg = instr->dst % RX_REG_FLT_COUNT;
                if (pendingFscal[reg] >= 0) {
                    skipInstruction[pendingFscal[reg]] = 1;
                    skipInstruction[i] = 1;
                    pendingFscal[reg] = -1;
                } else {
                    pendingFscal[reg] = i;
                }
                pendingFswapF[reg] = -1;
            } else if (gen == &JitCompiler::h_FSWAP_R) {
                int dst = instr->dst % RX_REGISTERS_COUNT;
                int* pending = dst < RX_REG_FLT_COUNT ?
                    &pendingFswapF[dst] : &pendingFswapE[dst - RX_REG_FLT_COUNT];
                if (*pending >= 0) {
                    skipInstruction[*pending] = 1;
                    skipInstruction[i] = 1;
                    *pending = -1;
                } else {
                    *pending = i;
                }
                if (dst < RX_REG_FLT_COUNT)
                    pendingFscal[dst] = -1;
            } else if (gen == &JitCompiler::h_FADD_R ||
                       gen == &JitCompiler::h_FADD_M ||
                       gen == &JitCompiler::h_FSUB_R ||
                       gen == &JitCompiler::h_FSUB_M) {
                int reg = instr->dst % RX_REG_FLT_COUNT;
                pendingFscal[reg] = -1;
                pendingFswapF[reg] = -1;
            } else if (gen == &JitCompiler::h_FMUL_R ||
                       gen == &JitCompiler::h_FDIV_M ||
                       gen == &JitCompiler::h_FSQRT_R) {
                pendingFswapE[instr->dst % RX_REG_FLT_COUNT] = -1;
            }
        }
    }

    void generateCode(rx_instruction* instr, int i) {
        if (g_jit_branch_align > 1 && branchTarget[i])
            alignCode(g_jit_branch_align);
        instructionOffsets[instructionCount++] = pos;
        if (skipInstruction[i])
            return;
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
        for (unsigned i = 0; i < RX_PROGRAM_SIZE; i++) {
            prog->programBuffer[i].src %= RX_REGISTERS_COUNT;
            prog->programBuffer[i].dst %= RX_REGISTERS_COUNT;
        }
        instructionCount = 0;
        for (int i = 0; i < RX_REGISTERS_COUNT; i++) registerUsage[i] = -1;
        imul_rcp_pool_count = 0;
        prevFPOperation = -1;
        prevCFROUND = -1;
        prevCFROUNDLength = 0;
        shortBranchCount = 0;
        analyzeInvolutionPairs(prog);

        memcpy(code + pos, code_loop_load, LOOP_LOAD_SIZE);
        pos += LOOP_LOAD_SIZE;

        for (unsigned i = 0; i < RX_PROGRAM_SIZE; i++) {
            rx_instruction* instr = &prog->programBuffer[i];
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
        emitByte(0x0F); emitByte(0x18); emitByte(0x44); emitByte(0x38); emitByte(0x00);

        emitByte(0x49); emitByte(0x8B); emitByte(0xC0 + pcfg->readReg0);
        emitByte(0x49); emitByte(0x33); emitByte(0xC0 + pcfg->readReg1);
        emitScratchpadPrefetch();

        memcpy(code + pos, code_loop_store, LOOP_STORE_SIZE);
        pos += LOOP_STORE_SIZE;

        emitByte(0xFF); emitByte(0xCB);
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
        activeRcpPoolOffset = 0;
        activeStackRcpPool = g_jit_stack_rcp_pool;

        memcpy(code + pos, code_prologue, PROLOGUE_SIZE);
        pos += PROLOGUE_SIZE;

        code[pos++] = 0x89; code[pos++] = 0xC2;
        code[pos++] = 0x81; code[pos++] = 0xE2;
        code[pos++] = 0xC0; code[pos++] = 0xFF; code[pos++] = 0xFF; code[pos++] = 0x7F;
        code[pos++] = 0x0F; code[pos++] = 0x18; code[pos++] = 0x14; code[pos++] = 0x17;

        memcpy(code + pos, code_first_load, FIRST_LOAD_SIZE);
        int firstLoadStart = pos;
        if (activeStackRcpPool)
            code[pos + 21] = 0xA8;
        pos += FIRST_LOAD_SIZE;

        pos = ((pos + 15) & ~15);

        int constantsPos = pos;
        memcpy(code + pos, code_constants, CONSTANTS_SIZE);
        pos += CONSTANTS_SIZE;

        pos = ((pos + 15) & ~15);

        int imulRcpPos = pos;
        if (activeStackRcpPool) {
            pos += 288;
        } else {
            memcpy(code + pos, code_imul_rcp, IMUL_RCP_SIZE);
            pos += IMUL_RCP_SIZE;
        }
        if (!activeStackRcpPool && g_jit_inline_rcp_pool) {
            activeRcpPoolOffset = pos;
            pos += IMUL_RCP_POOL_SIZE * 8;
        }

        pos = ((pos + 15) & ~15);

        int loopBeginPos = pos;
        if (g_jit_loop_nop)
            code[pos++] = 0x90;

        memcpy(code + EPILOGUE_OFFSET, code_epilogue, EPILOGUE_SIZE);
        if (activeStackRcpPool)
            code[EPILOGUE_OFFSET + 3] = 0xA8;

        int movapd13_patch = 190;
        int32_t rel = constantsPos - (movapd13_patch + 4);
        memcpy(code + movapd13_patch, &rel, 4);

        int movapd14_patch = 199;
        rel = (constantsPos + 16) - (movapd14_patch + 4);
        memcpy(code + movapd14_patch, &rel, 4);

        int movapd15_patch = 208;
        rel = (constantsPos + 32) - (movapd15_patch + 4);
        memcpy(code + movapd15_patch, &rel, 4);

        int jmpImulPos = firstLoadStart + FIRST_LOAD_SIZE - 4;
        rel = imulRcpPos - (jmpImulPos + 4);
        memcpy(code + jmpImulPos, &rel, 4);

        if (!activeStackRcpPool) {
            int jmpLoopPos = imulRcpPos + IMUL_RCP_SIZE - 4;
            rel = loopBeginPos - (jmpLoopPos + 4);
            memcpy(code + jmpLoopPos, &rel, 4);
        }

        memcpy(code + constantsPos + EMASK_OFFSET_IN_CONSTANTS, pcfg->eMask, sizeof(pcfg->eMask));

        imul_rcp_pool_count = 0;

        pos = loopBeginPos + (g_jit_loop_nop ? 1 : 0);
        this->pos = pos;
        generateProgramPrologue(prog, pcfg, loopBeginPos);

        generateProgramEpilogue(prog, pcfg, loopBeginPos);

        if (activeStackRcpPool) {
            int init = imulRcpPos;
            emitByteAt(init, 0x48); emitByteAt(init, 0x89);
            emitByteAt(init, 0x84); emitByteAt(init, 0x24);
            emit32At(init, 0xA0);
            for (int j = 0; j < imul_rcp_pool_count; j++) {
                emitByteAt(init, 0x48); emitByteAt(init, 0xB8);
                emit64At(init, imul_rcp_pool[j]);
                int offset = 0x20 + j * 8;
                emitByteAt(init, 0x48); emitByteAt(init, 0x89);
                if (offset <= 0x7F) {
                    emitByteAt(init, 0x44); emitByteAt(init, 0x24);
                    emitByteAt(init, (uint8_t)offset);
                } else {
                    emitByteAt(init, 0x84); emitByteAt(init, 0x24);
                    emit32At(init, offset);
                }
            }
            emitByteAt(init, 0x48); emitByteAt(init, 0x8B);
            emitByteAt(init, 0x84); emitByteAt(init, 0x24);
            emit32At(init, 0xA0);
            emitByteAt(init, 0xE9);
            emit32At(init, loopBeginPos - (init + 4));
        } else {
            for (int j = 0; j < imul_rcp_pool_count; j++) {
                memcpy(code + imulRcpPoolOffset() + j * 8,
                       &imul_rcp_pool[j], 8);
            }
        }

        generatedCodeSize = this->pos;
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
        analyzeInvolutionPairs(prog);

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

        code[pos++] = 0x89; code[pos++] = 0xC2;
        code[pos++] = 0x81; code[pos++] = 0xE2;
        code[pos++] = 0xC0; code[pos++] = 0xFF; code[pos++] = 0xFF; code[pos++] = 0x7F;
        code[pos++] = 0x0F; code[pos++] = 0x18; code[pos++] = 0x14; code[pos++] = 0x17;

        memcpy(code + pos, code_first_load, FIRST_LOAD_SIZE);
        int firstLoadStart = pos;
        pos += FIRST_LOAD_SIZE;

        pos = ((pos + 15) & ~15);

        int constantsPos = pos;
        memcpy(code + pos, code_constants, CONSTANTS_SIZE);
        pos += CONSTANTS_SIZE;

        pos = ((pos + 15) & ~15);

        int imulRcpPos = pos;
        memcpy(code + pos, code_imul_rcp, IMUL_RCP_SIZE);
        pos += IMUL_RCP_SIZE;

        pos = ((pos + 15) & ~15);

        int loopBeginPos = pos;
        if (g_jit_loop_nop)
            code[pos++] = 0x90;

        int movapd13_patch = 190;
        int32_t rel = constantsPos - (movapd13_patch + 4);
        memcpy(code + movapd13_patch, &rel, 4);

        int movapd14_patch = 199;
        rel = (constantsPos + 16) - (movapd14_patch + 4);
        memcpy(code + movapd14_patch, &rel, 4);

        int movapd15_patch = 208;
        rel = (constantsPos + 32) - (movapd15_patch + 4);
        memcpy(code + movapd15_patch, &rel, 4);

        int jmpImulPos = firstLoadStart + FIRST_LOAD_SIZE - 4;
        rel = imulRcpPos - (jmpImulPos + 4);
        memcpy(code + jmpImulPos, &rel, 4);

        int jmpLoopPos = imulRcpPos + IMUL_RCP_SIZE - 4;
        rel = loopBeginPos - (jmpLoopPos + 4);
        memcpy(code + jmpLoopPos, &rel, 4);

        memcpy(code + constantsPos + EMASK_OFFSET_IN_CONSTANTS, pcfg->eMask, sizeof(pcfg->eMask));

        pos = loopBeginPos + (g_jit_loop_nop ? 1 : 0);
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
        emitByte(0x0F); emitByte(0x18); emitByte(0x44); emitByte(0x38); emitByte(0x00);

        emitByte(0x49); emitByte(0x8B); emitByte(0xC0 + pcfg->readReg0);
        emitByte(0x49); emitByte(0x33); emitByte(0xC0 + pcfg->readReg1);
        emitScratchpadPrefetch();

        memcpy(code + pos, code_loop_store, LOOP_STORE_SIZE);
        pos += LOOP_STORE_SIZE;

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

        pos = ((pos + 15) & ~15);

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

        pos = ((pos + 15) & ~15);

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
        emitByte(0x0F); emitByte(0x18); emitByte(0x44); emitByte(0x38); emitByte(0x00);
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
        emitByte(0x0F); emitByte(0x18); emitByte(0x44); emitByte(0x38); emitByte(0x00);
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
        imul_rcp_pool_count = 0;
        prevFPOperation = -1;
        shortBranchCount = 0;
        analyzeInvolutionPairs(prog1);
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
        emitByte(0x0F); emitByte(0x18); emitByte(0x44); emitByte(0x38); emitByte(0x00);
        emitByte(0x49); emitByte(0x8B); emitByte(0xC0 + pcfg1->readReg0);
        emitByte(0x49); emitByte(0x33); emitByte(0xC0 + pcfg1->readReg1);
        emitScratchpadPrefetch();

        memcpy(code + pos, code_loop_store, LOOP_STORE_SIZE);
        pos += LOOP_STORE_SIZE;

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
        prevFPOperation = -1;
        analyzeInvolutionPairs(prog2);
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
        emitByte(0x0F); emitByte(0x18); emitByte(0x44); emitByte(0x38); emitByte(0x00);
        emitByte(0x49); emitByte(0x8B); emitByte(0xC0 + pcfg2->readReg0);
        emitByte(0x49); emitByte(0x33); emitByte(0xC0 + pcfg2->readReg1);
        emitScratchpadPrefetch();

        memcpy(code + pos, code_loop_store, LOOP_STORE_SIZE);
        pos += LOOP_STORE_SIZE;

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
        for (int i = 0; i < imul_rcp_pool_count; i++) {
            memcpy(code + imulRcpPoolOffset() + i * 8, &imul_rcp_pool[i], 8);
        }
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
    if (g_jit_bmi2_mulx) {
        *(uint32_t*)(code + pos) = 0xC4D08B49 + (instr->dst << 16);
        *(uint32_t*)(code + pos + 4) =
            0xC0F6FB42 + (instr->dst << 27) + (instr->src << 24);
        pos += 8;
        return;
    }
    *(uint32_t*)(code + pos) = 0xC08B49 + (instr->dst << 16);
    *(uint32_t*)(code + pos + 3) = 0xE0F749 + (instr->src << 16);
    *(uint32_t*)(code + pos + 6) = 0xC28B4C + ((instr->dst & 7) << 19);
    pos += 9;
}

void JitCompiler::h_IMULH_M(rx_instruction* instr, int i) {
    registerUsage[instr->dst] = i;
    if (g_jit_bmi2_mulx) {
        if (instr->src != instr->dst) {
            genAddressReg(instr, false);
            *(uint32_t*)(code + pos) = 0xC4D08B49 + (instr->dst << 16);
            *(uint64_t*)(code + pos + 4) =
                0x0E04F6FB62ULL + ((uint64_t)instr->dst << 27);
            pos += 9;
        } else {
            *(uint64_t*)(code + pos) =
                0x86F6FB62C4D08B49ULL +
                ((uint64_t)instr->dst << 16) +
                ((uint64_t)instr->dst << 59);
            *(uint32_t*)(code + pos + 8) =
                (uint32_t)getImm32(instr) & RX_SPL3_MASK;
            pos += 12;
        }
        return;
    }
    if (instr->src != instr->dst) {
        genAddressReg(instr, false);
        *(uint64_t*)(code + pos) = 0x0E24F748C08B49ULL + ((uint64_t)instr->dst << 16);
        pos += 7;
    } else {
        *(uint64_t*)(code + pos) = 0xA6F748C08B49ULL + ((uint64_t)instr->dst << 16);
        pos += 6;
        genAddressImm(instr);
    }
    emitByte(0x4C); emitByte(0x8B); emitByte(0xC2 | (8 * instr->dst));
}

void JitCompiler::h_ISMULH_R(rx_instruction* instr, int i) {
    registerUsage[instr->dst] = i;
    *(uint64_t*)(code + pos) = 0x8B4CE8F749C08B49ULL + ((uint64_t)instr->dst << 16) + ((uint64_t)instr->src << 40);
    pos += 8;
    emitByte(0xC2 | (8 * instr->dst));
}

void JitCompiler::h_ISMULH_M(rx_instruction* instr, int i) {
    registerUsage[instr->dst] = i;
    if (instr->src != instr->dst) {
        genAddressReg(instr, false);
        *(uint64_t*)(code + pos) = 0x0E2CF748C08B49ULL + ((uint64_t)instr->dst << 16);
        pos += 7;
    } else {
        *(uint64_t*)(code + pos) = 0xAEF748C08B49ULL + ((uint64_t)instr->dst << 16);
        pos += 6;
        genAddressImm(instr);
    }
    emitByte(0x4C); emitByte(0x8B); emitByte(0xC2 | (8 * instr->dst));
}

void JitCompiler::h_IMUL_RCP(rx_instruction* instr, int i) {
    uint32_t divisor = (uint32_t)getImm32(instr);
    if (!is_zero_or_power_of_2(divisor)) {
        registerUsage[instr->dst] = i;
        uint64_t rcp = rx_reciprocal(divisor);
        if (imul_rcp_pool_count < IMUL_RCP_POOL_SIZE) {
            imul_rcp_pool[imul_rcp_pool_count] = rcp;
            emitByte(0x4C); emitByte(0x0F); emitByte(0xAF);
            if (activeStackRcpPool) {
                int offset = 0x20 + imul_rcp_pool_count * 8;
                if (offset <= 0x7F) {
                    emitByte(0x44 | ((instr->dst & 7) << 3));
                    emitByte(0x24);
                    emitByte((uint8_t)offset);
                } else {
                    emitByte(0x84 | ((instr->dst & 7) << 3));
                    emitByte(0x24);
                    emit32(offset);
                }
            } else {
                emitByte(0x05 | ((instr->dst & 7) << 3));
                int32_t disp =
                    (imulRcpPoolOffset() + imul_rcp_pool_count * 8) -
                    (pos + 4);
                emit32(disp);
            }
            imul_rcp_pool_count++;
        } else {
            emitByte(0x48); emitByte(0xB8); emit64(rcp);
            emitByte(0x4C); emitByte(0x0F); emitByte(0xAF);
            emitByte(0xC0 | (8 * instr->dst));
        }
    }
}

void JitCompiler::h_INEG_R(rx_instruction* instr, int i) {
    registerUsage[instr->dst] = i;
    *(uint32_t*)(code + pos) = 0xD8F749 + (instr->dst << 16);
    pos += 3;
}

void JitCompiler::h_IXOR_R(rx_instruction* instr, int i) {
    registerUsage[instr->dst] = i;
    if (instr->src != instr->dst) {
        emitByte(0x4D); emitByte(0x33); emitByte(0xC0 | (8 * instr->dst + instr->src));
    } else {
        uint64_t imm = (uint64_t)(uint32_t)getImm32(instr);
        *(uint64_t*)(code + pos) = (imm << 24) + 0xF08149ULL + (instr->dst << 16);
        pos += 7;
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
        int rotate = getImm32(instr) & 63;
        if (rotate != 0) {
            if (g_jit_rorx) {
                emitByte(0xC4); emitByte(0x43); emitByte(0xFB);
                emitByte(0xF0);
                emitByte(0xC0 | instr->dst | (instr->dst << 3));
                emitByte(rotate);
            } else {
                emitByte(0x49); emitByte(0xC1);
                emitByte(0xC8 | instr->dst); emitByte(rotate);
            }
        }
    }
}

void JitCompiler::h_IROL_R(rx_instruction* instr, int i) {
    registerUsage[instr->dst] = i;
    if (instr->src != instr->dst) {
        emitByte(0x41); emitByte(0x8B); emitByte(0xC8 | instr->src);
        emitByte(0x49); emitByte(0xD3); emitByte(0xC0 | instr->dst);
    } else {
        int rotate = getImm32(instr) & 63;
        if (rotate != 0) {
            if (g_jit_rorx) {
                emitByte(0xC4); emitByte(0x43); emitByte(0xFB);
                emitByte(0xF0);
                emitByte(0xC0 | instr->dst | (instr->dst << 3));
                emitByte((64 - rotate) & 63);
            } else {
                emitByte(0x49); emitByte(0xC1);
                emitByte(0xC0 | instr->dst); emitByte(rotate);
            }
        }
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
    emitByte(0x66); emitByte(0x0F); emitByte(0xC6);
    emitByte(0xC0 | (9 * instr->dst));
    emitByte(1);
}

void JitCompiler::h_FADD_R(rx_instruction* instr, int i) {
    prevFPOperation = pos;
    instr->dst %= RX_REG_FLT_COUNT;
    instr->src %= RX_REG_FLT_COUNT;
    *(uint32_t*)(code + pos) = 0x580F4166;
    pos += 4;
    code[pos++] = 0xC0 | (instr->dst << 3) | instr->src;
}

void JitCompiler::h_FADD_M(rx_instruction* instr, int i) {
    prevFPOperation = pos;
    instr->dst %= RX_REG_FLT_COUNT;
    genAddressReg(instr, true);
    emitByte(0xF3); emitByte(0x44); emitByte(0x0F); emitByte(0xE6); emitByte(0x24); emitByte(0x06);
    emitByte(0x66); emitByte(0x41); emitByte(0x0F); emitByte(0x58);
    emitByte(0xC4 | (instr->dst << 3));
}

void JitCompiler::h_FSUB_R(rx_instruction* instr, int i) {
    prevFPOperation = pos;
    instr->dst %= RX_REG_FLT_COUNT;
    instr->src %= RX_REG_FLT_COUNT;
    *(uint32_t*)(code + pos) = 0x5C0F4166;
    pos += 4;
    code[pos++] = 0xC0 | (instr->dst << 3) | instr->src;
}

void JitCompiler::h_FSUB_M(rx_instruction* instr, int i) {
    prevFPOperation = pos;
    instr->dst %= RX_REG_FLT_COUNT;
    genAddressReg(instr, true);
    emitByte(0xF3); emitByte(0x44); emitByte(0x0F); emitByte(0xE6); emitByte(0x24); emitByte(0x06);
    emitByte(0x66); emitByte(0x41); emitByte(0x0F); emitByte(0x5C);
    emitByte(0xC4 | (instr->dst << 3));
}

void JitCompiler::h_FSCAL_R(rx_instruction* instr, int i) {
    instr->dst %= RX_REG_FLT_COUNT;
    uint8_t modrm = 0xC7 | (instr->dst << 3);
    *(uint32_t*)(code + pos) = 0x00570F41 | ((uint32_t)modrm << 24);
    pos += 4;
}

void JitCompiler::h_FMUL_R(rx_instruction* instr, int i) {
    prevFPOperation = pos;
    instr->dst %= RX_REG_FLT_COUNT;
    instr->src %= RX_REG_FLT_COUNT;
    *(uint32_t*)(code + pos) = 0x590F4166;
    pos += 4;
    code[pos++] = 0xE0 | (instr->dst << 3) | instr->src;
}

void JitCompiler::h_FDIV_M(rx_instruction* instr, int i) {
    prevFPOperation = pos;
    instr->dst %= RX_REG_FLT_COUNT;
    genAddressReg(instr, true);
    emitByte(0xF3); emitByte(0x44); emitByte(0x0F); emitByte(0xE6); emitByte(0x24); emitByte(0x06);
    emitByte(0x45); emitByte(0x0F); emitByte(0x54); emitByte(0xE5);
    emitByte(0x45); emitByte(0x0F); emitByte(0x56); emitByte(0xE6);
    emitByte(0x66); emitByte(0x41); emitByte(0x0F); emitByte(0x5E);
    emitByte(0xE4 | (instr->dst << 3));
}

void JitCompiler::h_FSQRT_R(rx_instruction* instr, int i) {
    prevFPOperation = pos;
    instr->dst %= RX_REG_FLT_COUNT;
    uint8_t modrm = 0xE4 | (9 * instr->dst);
    *(uint32_t*)(code + pos) = 0x00510F66 | ((uint32_t)modrm << 24);
    pos += 4;
}

void JitCompiler::h_CFROUND(rx_instruction* instr, int i) {
    if (g_jit_cfround_elim && prevCFROUND > prevFPOperation) {
        memset(code + prevCFROUND, 0x90, (size_t)prevCFROUNDLength);
    }
    int start = pos;
    int rotate = (13 - (getImm32(instr) & 63)) & 63;
    if (g_jit_cfround_rorx) {
        emitByte(0xC4); emitByte(0xC3); emitByte(0xFB);
        emitByte(0xF0); emitByte(0xC0 | instr->src);
        emitByte((64 - rotate) & 63);
    } else {
        emitMov64RM(0, instr->src);
        if (rotate != 0) {
            emitByte(0x48); emitByte(0xC1); emitByte(0xC0); emitByte(rotate);
        }
    }
    if (prevFPOperation >= 0 && (pos - prevFPOperation) < 12) {
        emitByte(0x66); emitByte(0x90);
    }
    *(uint64_t*)(code + pos) = 0x9FC00D0000600025ULL;
    pos += 8;
    *(uint16_t*)(code + pos) = 0x0000;
    pos += 2;
    *(uint64_t*)(code + pos) = 0x002414AE0F240489ULL;
    pos += 7;
    prevCFROUND = start;
    prevCFROUNDLength = pos - start;
}

void JitCompiler::h_CBRANCH(rx_instruction* instr, int i) {
    if (g_jit_jcc_align) {
        int branchBegin = pos + 7;
        int branchEnd = branchBegin + 13;
        if ((branchBegin ^ branchEnd) >= 32)
            alignCode(32);
    }
    int reg = instr->dst;
    int target = registerUsage[reg] + 1;
    if (instructionOffsets[target] <= prevFPOperation)
        prevFPOperation = pos;
    emitByte(0x49); emitByte(0x81); emitByte(0xC0 | reg);
    int shift = getModCond(instr) + RX_CONDITION_OFFSET;
    uint32_t imm = (uint32_t)getImm32(instr) | (1UL << shift);
    if (RX_CONDITION_OFFSET > 0 || shift > 0)
        imm &= ~(1UL << (shift - 1));
    emit32(imm);
    emitByte(0x49); emitByte(0xF7); emitByte(0xC0 | reg);
    emit32(RX_CONDITION_MASK << shift);

    int32_t shortOffset = instructionOffsets[target] - (pos + 2);
    if (g_jit_short_branches && shortOffset >= -128 && shortOffset <= 127) {
        emitByte(0x74);
        emitByte((uint8_t)(int8_t)shortOffset);
        shortBranchCount++;
    } else {
        emitByte(0x0F);
        emitByte(0x84);
        emit32(instructionOffsets[target] - (pos + 4));
    }

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

int g_jit_epilogue_skip_mask = 0;
int g_jit_short_branches = 0;
int g_jit_involution_pairs = 0;
int g_jit_branch_align = 0;
int g_jit_loop_nop = 1;
int g_jit_sp_prefetch_hint = 0;
int g_jit_bmi2_mulx = 0;
int g_jit_cfround_elim = 0;
int g_jit_large_pages = 0;
int g_jit_jcc_align = 0;
int g_jit_near_rcp_pool = 1;
int g_jit_double_buffer = 0;
int g_jit_inline_rcp_pool = 0;
int g_jit_rorx = 0;
int g_jit_stack_rcp_pool = 0;
int g_jit_cfround_rorx = 0;

struct rx_jit {
    JitCompiler* compiler;
};

rx_jit* rx_jit_create(void) {
    init_engine();
    rx_jit* jit = (rx_jit*)calloc(1, sizeof(rx_jit));
    jit->compiler = new JitCompiler();
    jit->compiler->superscalar_cache = NULL;
    jit->compiler->superscalarCacheSlots[0] = NULL;
    jit->compiler->superscalarCacheSlots[1] = NULL;
    jit->compiler->codeSlots[0] = NULL;
    jit->compiler->codeSlots[1] = NULL;
    jit->compiler->activeCodeSlot = 0;

    jit->compiler->code = NULL;
    if (g_jit_large_pages) {
        SIZE_T largePage = GetLargePageMinimum();
        if (largePage != 0) {
            SIZE_T allocSize =
                (RX_TOTAL_CODE_SIZE + largePage - 1) / largePage * largePage;
            jit->compiler->code = (uint8_t*)VirtualAlloc(
                NULL, allocSize, MEM_RESERVE | MEM_COMMIT | MEM_LARGE_PAGES,
                PAGE_EXECUTE_READWRITE);
        }
    }
    if (!jit->compiler->code) {
        jit->compiler->code = (uint8_t*)VirtualAlloc(NULL, RX_TOTAL_CODE_SIZE,
            MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    }
    if (!jit->compiler->code) { delete jit->compiler; free(jit); return NULL; }
    jit->compiler->codeSlots[0] = jit->compiler->code;
    if (g_jit_double_buffer) {
        jit->compiler->codeSlots[1] = (uint8_t*)VirtualAlloc(
            NULL, RX_TOTAL_CODE_SIZE, MEM_RESERVE | MEM_COMMIT,
            PAGE_EXECUTE_READWRITE);
        if (!jit->compiler->codeSlots[1]) {
            VirtualFree(jit->compiler->codeSlots[0], 0, MEM_RELEASE);
            delete jit->compiler;
            free(jit);
            return NULL;
        }
    }
    return jit;
}

void rx_jit_destroy(rx_jit* jit) {
    if (!jit) return;
    if (jit->compiler->codeSlots[0])
        VirtualFree(jit->compiler->codeSlots[0], 0, MEM_RELEASE);
    if (jit->compiler->codeSlots[1])
        VirtualFree(jit->compiler->codeSlots[1], 0, MEM_RELEASE);
    delete jit->compiler;
    free(jit);
}

void rx_jit_generate_program(rx_jit* jit, rx_program* prog, rx_program_config* pcfg, rx_cache* cache) {
    if (jit->compiler->codeSlots[1]) {
        jit->compiler->activeCodeSlot ^= 1;
        jit->compiler->code =
            jit->compiler->codeSlots[jit->compiler->activeCodeSlot];
        jit->compiler->superscalar_cache =
            jit->compiler->superscalarCacheSlots[jit->compiler->activeCodeSlot];
    }
    jit->compiler->cache = cache;
    jit->compiler->generateProgram(prog, pcfg);
    if (cache && cache != jit->compiler->superscalar_cache) {
        jit->compiler->superscalar_cache = cache;
        jit->compiler->superscalarCacheSlots[
            jit->compiler->activeCodeSlot] = cache;
        jit->compiler->generateSuperscalarHash(cache);
    }
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

int rx_jit_get_short_branch_count(rx_jit* jit) {
    return jit && jit->compiler ? jit->compiler->shortBranchCount : 0;
}

int rx_jit_get_generated_code_size(rx_jit* jit) {
    return jit && jit->compiler ? jit->compiler->generatedCodeSize : 0;
}

void rx_jit_dump_code(rx_jit* jit) {
    if (!jit || !jit->compiler || !jit->compiler->code) return;
    FILE* f = fopen("jit_dump.bin", "wb");
    if (!f) return;
    fwrite(jit->compiler->code, 1, RX_TOTAL_CODE_SIZE, f);
    fclose(f);
}

}

extern "C" {
void rx_jit_generate_program_single_iter(rx_jit* jit, rx_program* prog, rx_program_config* pcfg, rx_cache* cache) {
    jit->compiler->cache = cache;
    jit->compiler->generateProgramSingleIter(prog, pcfg);
    if (cache) {
        jit->compiler->generateSuperscalarHash(cache);
    }
}

void rx_jit_generate_program_dual_interleaved(rx_jit* jit, rx_program* prog1, rx_program_config* pcfg1,
                                                rx_program* prog2, rx_program_config* pcfg2, rx_cache* cache) {
    jit->compiler->cache = cache;
    jit->compiler->generateProgramDualInterleaved(prog1, pcfg1, prog2, pcfg2);
    if (cache) {
        jit->compiler->generateSuperscalarHash(cache);
    }
}
}
