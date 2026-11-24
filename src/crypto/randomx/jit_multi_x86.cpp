/*
 * Multi-lane ("software SMT") RandomX JIT for x86-64.
 *
 * A single RandomX program is latency bound: every iteration starts with
 * scratchpad loads whose address depends on the end of the previous
 * iteration, so consecutive iterations cannot overlap and a modern core
 * retires only ~0.5 instructions per cycle. This generator emits ONE loop
 * that executes the programs of K independent hashes ("lanes"), interleaved
 * in segments, so the out-of-order engine can overlap the dependency chains
 * of different hashes.
 *
 * Interleaving rules
 *  - A lane's program is cut into segments at legal cut points where no
 *    subsequent CBRANCH jumps before the cut (always legal after a CBRANCH,
 *    and also at any earlier instruction outside the next CBRANCH's target
 *    range — including right before CFROUND).
 *  - Integer registers r0..r7 live in r8..r15 for whichever lane is running;
 *    a lane switch spills/fills them to per-lane stack slots (with lane 1
 *    pinning r0..r2 in rbx/rbp/rdi when K==2).
 *  - FP registers:
 *      * AVX-512VL/DQ: banked (lane 0: xmm0..15, lane 1: xmm16..31; or 3
 *        lanes with f/e in xmm0..23).
 *      * AVX2, K==2 (fpBank2): lane 0 keeps f0..3,e0..3 in xmm0..7, lane 1
 *        keeps f0..3,e0..2 in xmm8..14, mantMask/scaleMask are micro-fused
 *        L1 stack operands, and only e3 (xmm7/xmm15) swaps at lane switches
 *        (2 vector ops per switch instead of 16).
 *      * AVX2, K>=3 (or forced fpSpill): f/e in xmm0..7 spilled per switch.
 *  - MXCSR (rounding mode) is per lane with static/lazy elimination:
 *      * Constant-mode chains (no CFROUND, matching initial MXCSR) emit
 *        zero LDMXCSR in the loop.
 *      * Segments with no rounding-sensitive FP ops or starting with CFROUND
 *        skip switch-in LDMXCSR.
 *      * Dead CFROUND loads (no rounding-sensitive FP op reachable in the
 *        segment) store SL_MXCSR without executing LDMXCSR.
 *  - Phase-staggered schedule (optional): offsets lane L's phase by L*256/K
 *    so Head/Tail L3 & DRAM misses of one lane overlap mid-program compute
 *    of another lane instead of stalling in lockstep.
 *
 * Calling convention: Win64 (RX_JIT_ABI), one argument: rx_multi_params *.
 */
#include "randomx_internal.h"
#include "common/vmem.h"

#include <string.h>
#include <stdlib.h>

extern "C" int cpu_has_bmi2(void);

#define MJ_CODE_SIZE   (512 * 1024)
#define MJ_POOL_MAX    1024

extern "C" {
int g_mjit_granularity = 256;      /* target RandomX instructions per segment */
int g_mjit_mxcsr_skip = 0;         /* skip LDMXCSR when lanes share the mode */
int g_mjit_rcp_pool = 1;           /* IMUL_RCP: RIP-relative constant pool */
int g_mjit_prefetch_mode = 1;      /* scratchpad prefetch at iteration end: 0 none, 1 t0 */
int g_mjit_pinned_regs = 1;        /* lane 1 keeps r0..r2 in rbx/rbp/rdi (5-reg swaps) */
/* DIAGNOSTIC ONLY (produces wrong hashes): bit0 = scratchpad L3 accesses use
   the L2 mask, bit1 = dataset reads confined to 64 KB, bit2 = no LDMXCSR,
   bit3 = 20 extra NOP uops per lane switch (sensitivity to uop count). */
int g_mjit_diag = 0;
int g_mjit_ds_prefetch = 0;        /* dataset prefetch hint: 0 nta, 1 t0, 2 t1, 3 t2 */
/* FP banking: 0 = auto (EVEX banks when AVX-512VL/DQ is available, else
   AVX2 K==2 banking or full spill), 1 = always full spill (portable, AVX2). */
int g_mjit_fp_spill = 0;
int g_mjit_fp_bank2 = 1;           /* AVX2 K==2: bank 15/16 FP regs in xmm0..14 */
int g_mjit_stagger = 0;            /* phase-staggered lane schedule */
int g_mjit_smart_cuts = 1;         /* expanded legal cut points + CFROUND-aligned cuts */
int g_mjit_smart_mxcsr = 1;        /* static/lazy LDMXCSR & dead CFROUND load elimination */
int g_mjit_bmi2 = 1;               /* BMI2 MULX (IMULH) + RORX (IROR/IROL/CFROUND) */
int g_mjit_refresh_dspf = 0;       /* refresh dataset prefetcht0 at start of last segment */
int g_mjit_tail_order = 1;         /* issue next dataset & scratchpad prefetches earlier in tail */
int g_mjit_mxguard = 0;            /* dynamic [rsp+FR_HWMXCSR] guard before LDMXCSR */
int rx_cpu_has_avx512_lanes(void);
}

namespace {

enum { RAX = 0, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8, R9, R10, R11, R12, R13, R14, R15 };

/* Stack frame (relative to rsp after the prologue; rsp is 16-byte aligned) */
static const int FR_PARAMS = 0;       /* 8 bytes */
static const int FR_COUNT = 8;        /* 4 bytes */
static const int FR_HWMXCSR = 12;     /* 4 bytes: last hardware MXCSR (for mxguard) */
static const int FR_MANTMASK = 16;    /* 16 bytes (16-aligned): mantMask for fpBank2 */
static const int FR_SCALEMASK = 32;   /* 16 bytes (16-aligned): scaleMask for fpBank2 */
static const int FR_FIRST = 48;       /* 4 bytes: 1 on pass 0, 0 afterwards (stagger) */
static const int FR_LANE0 = 64;
static const int FR_LANE_SIZE = 336;
/* per-lane slot offsets (FR_LANE0 + L * FR_LANE_SIZE is 16-byte aligned) */
static const int SL_R = 0;        /* 8 qwords */
static const int SL_SP0 = 64;     /* pointer to spAddr0 line */
static const int SL_SP1 = 72;     /* pointer to spAddr1 line */
static const int SL_MXMA = 80;    /* rotated mx/ma (low32 = ma) */
static const int SL_DS = 88;      /* dataset base (+datasetOffset) */
static const int SL_SPB = 96;     /* scratchpad base */
static const int SL_MXCSR = 104;  /* dword */
static const int SL_A = 128;      /* 4 x 16 bytes: a registers (lanes >= 3 / spill / bank2) */
static const int SL_EMASK = 192;  /* 16 bytes: eMask */
static const int SL_FE = 208;     /* 8 x 16 bytes: f0-3, e0-3 (FP spill / bank2 e3 at +112) */

static int cached_has_bmi2() {
    static volatile int cached = -1;
    int v = cached;
    if (v < 0) { v = cpu_has_bmi2() ? 1 : 0; cached = v; }
    return v;
}

static inline bool isRoundingSensitiveFP(int op) {
    /* FADD_R, FADD_M, FSUB_R, FSUB_M, FMUL_R, FDIV_M, FSQRT_R depend on MXCSR.RC.
       FSWAP_R (shuffle) and FSCAL_R (bitwise xor) do NOT depend on MXCSR.RC. */
    if (op >= RX_CEIL_RX_FSWAP_R && op < RX_CEIL_RX_FSUB_M) return true;
    if (op >= RX_CEIL_RX_FSCAL_R && op < RX_CEIL_RX_FSQRT_R) return true;
    return false;
}

static inline bool isCbranchOp(int op) {
    return op >= RX_CEIL_RX_FSQRT_R && op < RX_CEIL_RX_CBRANCH;
}

static inline bool isCfroundOp(int op) {
    return op >= RX_CEIL_RX_CBRANCH && op < RX_CEIL_RX_CFROUND;
}

static uint8_t g_op_lut[256];
static int g_op_lut_ready = 0;

static void init_op_lut() {
    if (g_op_lut_ready) return;
    static const int ceils[RX_OP_COUNT] = {
        RX_CEIL_RX_IADD_RS, RX_CEIL_RX_IADD_M, RX_CEIL_RX_ISUB_R, RX_CEIL_RX_ISUB_M,
        RX_CEIL_RX_IMUL_R, RX_CEIL_RX_IMUL_M, RX_CEIL_RX_IMULH_R, RX_CEIL_RX_IMULH_M,
        RX_CEIL_RX_ISMULH_R, RX_CEIL_RX_ISMULH_M, RX_CEIL_RX_IMUL_RCP, RX_CEIL_RX_INEG_R,
        RX_CEIL_RX_IXOR_R, RX_CEIL_RX_IXOR_M, RX_CEIL_RX_IROR_R, RX_CEIL_RX_IROL_R,
        RX_CEIL_RX_ISWAP_R, RX_CEIL_RX_FSWAP_R, RX_CEIL_RX_FADD_R, RX_CEIL_RX_FADD_M,
        RX_CEIL_RX_FSUB_R, RX_CEIL_RX_FSUB_M, RX_CEIL_RX_FSCAL_R, RX_CEIL_RX_FMUL_R,
        RX_CEIL_RX_FDIV_M, RX_CEIL_RX_FSQRT_R, RX_CEIL_RX_CBRANCH, RX_CEIL_RX_CFROUND,
        RX_CEIL_RX_ISTORE, RX_CEIL_RX_NOP
    };
    int k = 0;
    for (int op = 0; op < 256; op++) {
        while (k < RX_OP_COUNT - 1 && op >= ceils[k]) k++;
        g_op_lut[op] = (uint8_t)k;
    }
    g_op_lut_ready = 1;
}

struct Mem {
    int base;   /* -1: none */
    int index;  /* -1: none */
    int scale;  /* log2 */
    int32_t disp;
};

static inline Mem M(int base, int32_t disp = 0) { Mem m = { base, -1, 0, disp }; return m; }
static inline Mem MI(int base, int index, int scale = 0, int32_t disp = 0) {
    Mem m = { base, index, scale, disp }; return m;
}

struct LaneRegs {
    int f[4], e[4], a[4];
    int tmp, emask;
    int aMem; /* a/eMask are memory operands in the lane slots */
};

struct LaneState {
    rx_program *prog;
    rx_program_config *cfg;
    int32_t instrOffset[RX_PROGRAM_MAX_SIZE];
    int regUsage[RX_REGISTERS_COUNT];
    int segStart[RX_PROGRAM_SIZE + 1];
    int nseg;
    uint8_t segHasRoundFP[RX_PROGRAM_SIZE + 1];
    uint8_t segFirstRoundIsCfround[RX_PROGRAM_SIZE + 1];
    uint8_t segHasDeferredCfround[RX_PROGRAM_SIZE + 1];
    uint8_t segHasLoadedCfround[RX_PROGRAM_SIZE + 1];
    uint8_t cfroundNeedsLoad[RX_PROGRAM_SIZE];
    int brTarget[RX_PROGRAM_SIZE];
    int hasCfround;
    int anyRoundFP;
    LaneRegs x;
    int slot; /* rsp offset of this lane's slots */
    int map[8];      /* RandomX register -> GPR */
    int swapped[8];  /* 1 if the GPR is shared with another lane */
};

struct PoolFixup { int patchPos; int index; };

struct MultiJit {
    uint8_t *code;
    int pos;
    int K;
    int fpSpill;
    int fpBank2;
    int useBmi2;
    int mantMask, scaleMask;
    LaneState lane[RX_MULTI_MAX_LANES];
    uint64_t pool[MJ_POOL_MAX];
    int poolCount;
    PoolFixup fix[MJ_POOL_MAX];
    int fixCount;

    /* ------------------------------------------------------------------
     * Encoder. Every instruction is assembled in a local buffer (IB) and
     * copied with one memcpy: emitting byte by byte through code[pos++]
     * made the compiler reload this->pos after every (char-typed, hence
     * potentially aliasing) store, which cost ~15 cycles per code byte.
     * ------------------------------------------------------------------ */
    struct IB {
        uint8_t v[32];
        int n;
        IB() : n(0) {}
        void u8(uint8_t x) { v[n++] = x; }
        void u32(uint32_t x) { memcpy(v + n, &x, 4); n += 4; }
        void u64(uint64_t x) { memcpy(v + n, &x, 8); n += 8; }
    };
    void put(const IB &I) { memcpy(code + pos, I.v, 16); pos += I.n; }

    void b(uint8_t v) { code[pos++] = v; }
    void d32(uint32_t v) { memcpy(code + pos, &v, 4); pos += 4; }
    void q64(uint64_t v) { memcpy(code + pos, &v, 8); pos += 8; }

    static void rexI(IB &I, int w, int reg, int index, int base, bool force = false) {
        uint8_t r = (uint8_t)(0x40 | (w << 3) | (((reg >> 3) & 1) << 2) |
                              (((index >> 3) & 1) << 1) | ((base >> 3) & 1));
        if (r != 0x40 || force) I.u8(r);
    }
    static void modrmRRI(IB &I, int reg, int rm) { I.u8((uint8_t)(0xC0 | ((reg & 7) << 3) | (rm & 7))); }

    /* ModRM + SIB + displacement for a memory operand. forceDisp32 is used by
       EVEX encodings to avoid compressed disp8*N semantics. */
    static void modrmMemI(IB &I, int reg, const Mem &m, bool forceDisp32 = false) {
        int r = (reg & 7) << 3;
        if (m.base < 0) {
            /* [index*s + disp32] or [disp32] */
            I.u8((uint8_t)(0x04 | r));
            int idx = m.index < 0 ? 4 : (m.index & 7);
            I.u8((uint8_t)((m.scale << 6) | (idx << 3) | 5));
            I.u32((uint32_t)m.disp);
            return;
        }
        int mod;
        if (m.disp == 0 && (m.base & 7) != 5) mod = 0;
        else if (!forceDisp32 && m.disp >= -128 && m.disp <= 127) mod = 1;
        else mod = 2;
        bool sib = m.index >= 0 || (m.base & 7) == 4;
        if (sib) {
            I.u8((uint8_t)((mod << 6) | r | 4));
            int idx = m.index < 0 ? 4 : (m.index & 7);
            I.u8((uint8_t)((m.scale << 6) | (idx << 3) | (m.base & 7)));
        } else {
            I.u8((uint8_t)((mod << 6) | r | (m.base & 7)));
        }
        if (mod == 1) I.u8((uint8_t)(int8_t)m.disp);
        else if (mod == 2) I.u32((uint32_t)m.disp);
    }
    static int mIdx(const Mem &m) { return m.index < 0 ? 0 : m.index; }
    static int mBase(const Mem &m) { return m.base < 0 ? 0 : m.base; }

    void rex(int w, int reg, int index, int base, bool force = false) { IB I; rexI(I, w, reg, index, base, force); put(I); }
    void modrmRR(int reg, int rm) { IB I; modrmRRI(I, reg, rm); put(I); }
    void modrmMem(int reg, const Mem &m, bool forceDisp32 = false) { IB I; modrmMemI(I, reg, m, forceDisp32); put(I); }

    /* opcode with reg + r/m register */
    void opRR(int w, uint8_t op, int reg, int rm) { IB I; rexI(I, w, reg, 0, rm); I.u8(op); modrmRRI(I, reg, rm); put(I); }
    void opRR0F(int w, uint8_t op, int reg, int rm) { IB I; rexI(I, w, reg, 0, rm); I.u8(0x0F); I.u8(op); modrmRRI(I, reg, rm); put(I); }
    void opRM(int w, uint8_t op, int reg, const Mem &m) {
        IB I; rexI(I, w, reg, mIdx(m), mBase(m)); I.u8(op); modrmMemI(I, reg, m); put(I);
    }
    void opRM0F(int w, uint8_t op, int reg, const Mem &m) {
        IB I; rexI(I, w, reg, mIdx(m), mBase(m)); I.u8(0x0F); I.u8(op); modrmMemI(I, reg, m); put(I);
    }

    /* integer helpers (64-bit unless noted) */
    void mov(int dst, int src) { opRR(1, 0x8B, dst, src); }
    void mov32(int dst, int src) { opRR(0, 0x8B, dst, src); }
    void load(int dst, const Mem &m) { opRM(1, 0x8B, dst, m); }
    void load32(int dst, const Mem &m) { opRM(0, 0x8B, dst, m); }
    void store(const Mem &m, int src) { opRM(1, 0x89, src, m); }
    void store32(const Mem &m, int src) { opRM(0, 0x89, src, m); }
    void storeImm32(const Mem &m, int32_t imm, int w = 1) {
        IB I; rexI(I, w, 0, mIdx(m), mBase(m)); I.u8(0xC7); modrmMemI(I, 0, m); I.u32((uint32_t)imm); put(I);
    }
    void cmpMemImm8_32(const Mem &m, int8_t imm) {
        IB I; rexI(I, 0, 0, mIdx(m), mBase(m)); I.u8(0x83); modrmMemI(I, 7, m); I.u8((uint8_t)imm); put(I);
    }
    void cmpRegMem32(int r, const Mem &m) { opRM(0, 0x3B, r, m); }
    void lea(int dst, const Mem &m) { opRM(1, 0x8D, dst, m); }
    void lea32(int dst, const Mem &m) { opRM(0, 0x8D, dst, m); }
    void aluRR(uint8_t op, int dst, int src) { opRR(1, op, dst, src); }   /* 03 add, 2B sub, 33 xor, 23 and */
    void aluRM(uint8_t op, int dst, const Mem &m) { opRM(1, op, dst, m); }
    void aluRI(int ext, int dst, int32_t imm, int w = 1) {
        IB I; rexI(I, w, 0, 0, dst); I.u8(0x81); modrmRRI(I, ext, dst); I.u32((uint32_t)imm); put(I);
    }
    void imulRR(int dst, int src) { opRR0F(1, 0xAF, dst, src); }
    void imulRM(int dst, const Mem &m) { opRM0F(1, 0xAF, dst, m); }
    void imulRRI(int dst, int src, int32_t imm) {
        IB I; rexI(I, 1, dst, 0, src); I.u8(0x69); modrmRRI(I, dst, src); I.u32((uint32_t)imm); put(I);
    }
    void unaryR(int ext, int r) { IB I; rexI(I, 1, 0, 0, r); I.u8(0xF7); modrmRRI(I, ext, r); put(I); } /* /3 neg /4 mul /5 imul */
    void unaryM(int ext, const Mem &m) { opRM(1, 0xF7, ext, m); }
    void shiftCl(int ext, int r) { IB I; rexI(I, 1, 0, 0, r); I.u8(0xD3); modrmRRI(I, ext, r); put(I); } /* /0 rol /1 ror */
    void shiftI(int ext, int r, int imm) {
        IB I; rexI(I, 1, 0, 0, r); I.u8(0xC1); modrmRRI(I, ext, r); I.u8((uint8_t)imm); put(I);
    } /* /5 shr */
    void xchg(int a, int c) { opRR(1, 0x87, a, c); }
    void testRI(int r, int32_t imm) { IB I; rexI(I, 1, 0, 0, r); I.u8(0xF7); modrmRRI(I, 0, r); I.u32((uint32_t)imm); put(I); }
    void movImm64(int r, uint64_t imm) { IB I; rexI(I, 1, 0, 0, r, true); I.u8((uint8_t)(0xB8 + (r & 7))); I.u64(imm); put(I); }
    void prefetch(int hint, const Mem &m) { opRM0F(0, 0x18, hint, m); } /* 0 nta, 1 t0, 2 t1 */
    void ldmxcsrRaw(const Mem &m) { vexOrEvex(0xAE, 0, 0, 2, -1, false, 0, &m); } /* VLDMXCSR */
    void push(int r) { if (r >= 8) b(0x41); b((uint8_t)(0x50 + (r & 7))); }
    void pop(int r) { if (r >= 8) b(0x41); b((uint8_t)(0x58 + (r & 7))); }

    /* ---------------- 3-byte VEX for BMI2 (MULX / RORX) ---------------- */
    void vex3(uint8_t mmmmm, int w, int pp, uint8_t op, int reg, int vvvv, bool rmIsReg, int rm, const Mem *m, int imm = -1) {
        IB I;
        int R = (reg >> 3) & 1;
        int X = 0, B = 0;
        if (rmIsReg) B = (rm >> 3) & 1;
        else { X = m->index >= 0 ? (m->index >> 3) & 1 : 0; B = m->base >= 0 ? (m->base >> 3) & 1 : 0; }
        int vv = vvvv < 0 ? 0 : vvvv;
        I.u8(0xC4);
        I.u8((uint8_t)(((~R & 1) << 7) | ((~X & 1) << 6) | ((~B & 1) << 5) | (mmmmm & 31)));
        I.u8((uint8_t)((w << 7) | ((~vv & 15) << 3) | (pp & 3)));
        I.u8(op);
        if (rmIsReg) modrmRRI(I, reg, rm);
        else modrmMemI(I, reg, *m);
        if (imm >= 0) I.u8((uint8_t)imm);
        put(I);
    }
    void mulxRR(int hi, int lo, int src) { vex3(2, 1, 3, 0xF6, hi, lo, true, src, NULL); }
    void mulxRM(int hi, int lo, const Mem &m) { vex3(2, 1, 3, 0xF6, hi, lo, false, 0, &m); }
    void rorx(int dst, int src, int imm) { vex3(3, 1, 3, 0xF0, dst, 0, true, src, NULL, imm & 63); }

    /* ---------------- VEX / EVEX (map 0F, 128-bit) ---------------- */
    /* pp: 0 none, 1 66, 2 F3, 3 F2.  rmIsReg: rm is an xmm register index. */
    static void vexI(IB &I, uint8_t op, int pp, int wEvex, int reg, int vvvv, bool rmIsReg, int rm, const Mem *m) {
        bool needEvex = reg >= 16 || vvvv >= 16 || (rmIsReg && rm >= 16);
        int R = (reg >> 3) & 1;
        int vv = vvvv < 0 ? 0 : vvvv;
        if (!needEvex) {
            int X = 0, B = 0;
            if (rmIsReg) B = (rm >> 3) & 1;
            else { X = m->index >= 0 ? (m->index >> 3) & 1 : 0; B = m->base >= 0 ? (m->base >> 3) & 1 : 0; }
            if (!X && !B) {
                I.u8(0xC5);
                I.u8((uint8_t)(((~R & 1) << 7) | ((~vv & 15) << 3) | pp));
            } else {
                I.u8(0xC4);
                I.u8((uint8_t)(((~R & 1) << 7) | ((~X & 1) << 6) | ((~B & 1) << 5) | 1));
                I.u8((uint8_t)(((~vv & 15) << 3) | pp));
            }
            I.u8(op);
            if (rmIsReg) modrmRRI(I, reg, rm);
            else modrmMemI(I, reg, *m);
        } else {
            int Rp = (reg >> 4) & 1;
            int X, B;
            if (rmIsReg) { B = (rm >> 3) & 1; X = (rm >> 4) & 1; }
            else { X = m->index >= 0 ? (m->index >> 3) & 1 : 0; B = m->base >= 0 ? (m->base >> 3) & 1 : 0; }
            int Vp = (vv >> 4) & 1;
            I.u8(0x62);
            I.u8((uint8_t)(((~R & 1) << 7) | ((~X & 1) << 6) | ((~B & 1) << 5) | ((~Rp & 1) << 4) | 1));
            I.u8((uint8_t)((wEvex << 7) | ((~vv & 15) << 3) | 4 | pp));
            I.u8((uint8_t)(((~Vp & 1) << 3)));
            I.u8(op);
            if (rmIsReg) modrmRRI(I, reg, rm);
            else modrmMemI(I, reg, *m, true);
        }
    }
    void vexOrEvex(uint8_t op, int pp, int wEvex, int reg, int vvvv, bool rmIsReg, int rm, const Mem *m) {
        IB I; vexI(I, op, pp, wEvex, reg, vvvv, rmIsReg, rm, m); put(I);
    }
    void vpdRR(uint8_t op, int dst, int src1, int src2) { vexOrEvex(op, 1, 1, dst, src1, true, src2, NULL); }
    void vaddpd(int d, int s1, int s2) { vpdRR(0x58, d, s1, s2); }
    void vsubpd(int d, int s1, int s2) { vpdRR(0x5C, d, s1, s2); }
    void vmulpd(int d, int s1, int s2) { vpdRR(0x59, d, s1, s2); }
    void vdivpd(int d, int s1, int s2) { vpdRR(0x5E, d, s1, s2); }
    void vandpd(int d, int s1, int s2) { vpdRR(0x54, d, s1, s2); }
    void vorpd(int d, int s1, int s2) { vpdRR(0x56, d, s1, s2); }
    void vxorpd(int d, int s1, int s2) { vpdRR(0x57, d, s1, s2); }
    void vsqrtpd(int d, int s) { vexOrEvex(0x51, 1, 1, d, -1, true, s, NULL); }
    void vshufpd(int d, int s1, int s2, int imm) {
        IB I; vexI(I, 0xC6, 1, 1, d, s1, true, s2, NULL); I.u8((uint8_t)imm); put(I);
    }
    void vcvtdq2pdM(int d, const Mem &m) { vexOrEvex(0xE6, 2, 0, d, -1, false, 0, &m); }
    void vmovupdLoad(int d, const Mem &m) { vexOrEvex(0x10, 1, 1, d, -1, false, 0, &m); }
    void vmovupdStore(const Mem &m, int s) { vexOrEvex(0x11, 1, 1, s, -1, false, 0, &m); }
    void vmovapdLoad(int d, const Mem &m) { vexOrEvex(0x28, 1, 1, d, -1, false, 0, &m); }
    void vmovapdStore(const Mem &m, int s) { vexOrEvex(0x29, 1, 1, s, -1, false, 0, &m); }
    void vpdM(uint8_t op, int d, int s1, const Mem &m) { vexOrEvex(op, 1, 1, d, s1, false, 0, &m); }
    /* d = d op a[src] for lane L (register or memory operand) */
    void fpA(uint8_t op, int L, int d, int asrc) {
        const LaneRegs &x = lane[L].x;
        if (x.aMem) vpdM(op, d, d, M(RSP, slot(L, SL_A + 16 * asrc)));
        else vpdRR(op, d, d, x.a[asrc]);
    }
    void orEmask(int L, int d) {
        const LaneRegs &x = lane[L].x;
        if (x.aMem) vpdM(0x56, d, d, M(RSP, slot(L, SL_EMASK)));
        else vorpd(d, d, x.emask);
    }
    void andMant(int d) {
        if (fpBank2) vpdM(0x54, d, d, M(RSP, FR_MANTMASK));
        else vandpd(d, d, mantMask);
    }
    void xorScale(int d) {
        if (fpBank2) vpdM(0x57, d, d, M(RSP, FR_SCALEMASK));
        else vxorpd(d, d, scaleMask);
    }

    /* Emit LDMXCSR (optionally guarded by [rsp + FR_HWMXCSR]). Clobbers RAX when guarded. */
    void emitLdmxcsrFromSlot(int L, bool regEaxReady = false) {
        if (g_mjit_diag & 4) return;
        if (g_mjit_mxguard) {
            if (!regEaxReady) load32(RAX, M(RSP, slot(L, SL_MXCSR)));
            cmpRegMem32(RAX, M(RSP, FR_HWMXCSR));
            b(0x74); int patch = pos; b(0);
            store32(M(RSP, FR_HWMXCSR), RAX);
            ldmxcsrRaw(M(RSP, slot(L, SL_MXCSR)));
            code[patch] = (uint8_t)(pos - (patch + 1));
        } else {
            if (g_mjit_mxcsr_skip) {
                if (!regEaxReady) load32(RAX, M(RSP, slot(L, SL_MXCSR)));
                store32(M(RSP, FR_HWMXCSR), RAX);
            }
            ldmxcsrRaw(M(RSP, slot(L, SL_MXCSR)));
        }
    }

    /* ---------------------------------------------------------------- */
    int curLane;
    int gpr(int r) const { return lane[curLane].map[r & 7]; }
    int slot(int L, int off) const { return lane[L].slot + off; }

    void addrReg(rx_instruction *instr, int tmp, uint32_t mask) {
        lea32(tmp, M(gpr(instr->src), (int32_t)instr->imm32));
        aluRI(4, tmp, (int32_t)mask, 0); /* and r32, imm32 */
    }
    uint32_t memMask(rx_instruction *instr) const {
        return (instr->mod & 3) ? RX_SPL1_MASK : RX_SPL2_MASK;
    }
    /* memory operand for *_M integer instructions; may clobber rax */
    Mem intMemOperand(rx_instruction *instr, int tmp = RAX) {
        if ((instr->src & 7) != (instr->dst & 7)) {
            addrReg(instr, tmp, memMask(instr));
            return MI(RSI, tmp);
        }
        return M(RSI, (int32_t)(instr->imm32 & l3mask()));
    }
    uint32_t l3mask() const { return (g_mjit_diag & 1) ? RX_SPL2_MASK : RX_SPL3_MASK; }
    uint32_t l3mask64() const { return (g_mjit_diag & 1) ? (RX_SPL2_MASK & ~63u) : RX_SPL3_MASK64; }
    int32_t dsmask() const { return (g_mjit_diag & 2) ? 0xFFC0 : 0x7FFFFFC0; }

    void emitInstr(int L, int i) {
        curLane = L;
        LaneState &ls = lane[L];
        rx_instruction *instr = &ls.prog->programBuffer[i];
        int op = instr->opcode;
        int dst = instr->dst & 7, src = instr->src & 7;
        int rd = gpr(dst), rs = gpr(src);
        const LaneRegs &x = ls.x;
        ls.instrOffset[i] = pos;

        switch (g_op_lut[op & 255]) {
        case RX_OP_IADD_RS: {
            ls.regUsage[dst] = i;
            Mem m = MI(rd, rs, (instr->mod >> 2) & 3, 0);
            if (dst == 5) { m.disp = (int32_t)instr->imm32; lea(rd, m); }
            else lea(rd, m);
            break;
        }
        case RX_OP_IADD_M:
            ls.regUsage[dst] = i;
            aluRM(0x03, rd, intMemOperand(instr));
            break;
        case RX_OP_ISUB_R:
            ls.regUsage[dst] = i;
            if (src != dst) aluRR(0x2B, rd, rs);
            else aluRI(5, rd, (int32_t)instr->imm32);
            break;
        case RX_OP_ISUB_M:
            ls.regUsage[dst] = i;
            aluRM(0x2B, rd, intMemOperand(instr));
            break;
        case RX_OP_IMUL_R:
            ls.regUsage[dst] = i;
            if (src != dst) imulRR(rd, rs);
            else imulRRI(rd, rd, (int32_t)instr->imm32);
            break;
        case RX_OP_IMUL_M:
            ls.regUsage[dst] = i;
            imulRM(rd, intMemOperand(instr));
            break;
        case RX_OP_IMULH_R:
            ls.regUsage[dst] = i;
            if (useBmi2) { mov(RDX, rd); mulxRR(rd, RAX, rs); }
            else { mov(RAX, rd); unaryR(4, rs); mov(rd, RDX); }
            break;
        case RX_OP_IMULH_M: {
            ls.regUsage[dst] = i;
            Mem m = intMemOperand(instr, RCX);
            if (useBmi2) { mov(RDX, rd); mulxRM(rd, RAX, m); }
            else { mov(RAX, rd); unaryM(4, m); mov(rd, RDX); }
            break;
        }
        case RX_OP_ISMULH_R:
            ls.regUsage[dst] = i;
            mov(RAX, rd); unaryR(5, rs); mov(rd, RDX);
            break;
        case RX_OP_ISMULH_M: {
            ls.regUsage[dst] = i;
            Mem m = intMemOperand(instr, RCX);
            mov(RAX, rd); unaryM(5, m); mov(rd, RDX);
            break;
        }
        case RX_OP_IMUL_RCP: {
            uint32_t divisor = instr->imm32;
            if (!is_zero_or_power_of_2(divisor)) {
                ls.regUsage[dst] = i;
                uint64_t rcp = rx_reciprocal(divisor);
                if (g_mjit_rcp_pool && poolCount < MJ_POOL_MAX) {
                    IB I; rexI(I, 1, rd, 0, 0); I.u8(0x0F); I.u8(0xAF); I.u8((uint8_t)(0x05 | ((rd & 7) << 3)));
                    fix[fixCount].patchPos = pos + I.n; fix[fixCount].index = poolCount; fixCount++;
                    pool[poolCount++] = rcp;
                    I.u32(0);
                    put(I);
                } else {
                    movImm64(RAX, rcp); imulRR(rd, RAX);
                }
            }
            break;
        }
        case RX_OP_INEG_R:
            ls.regUsage[dst] = i;
            unaryR(3, rd);
            break;
        case RX_OP_IXOR_R:
            ls.regUsage[dst] = i;
            if (src != dst) aluRR(0x33, rd, rs);
            else aluRI(6, rd, (int32_t)instr->imm32);
            break;
        case RX_OP_IXOR_M:
            ls.regUsage[dst] = i;
            aluRM(0x33, rd, intMemOperand(instr));
            break;
        case RX_OP_IROR_R:
            ls.regUsage[dst] = i;
            if (src != dst) { mov32(RCX, rs); shiftCl(1, rd); }
            else {
                int r = instr->imm32 & 63;
                if (r) { if (useBmi2) rorx(rd, rd, r); else shiftI(1, rd, r); }
            }
            break;
        case RX_OP_IROL_R:
            ls.regUsage[dst] = i;
            if (src != dst) { mov32(RCX, rs); shiftCl(0, rd); }
            else {
                int r = instr->imm32 & 63;
                if (r) { if (useBmi2) rorx(rd, rd, (64 - r) & 63); else shiftI(0, rd, r); }
            }
            break;
        case RX_OP_ISWAP_R:
            if (src != dst) {
                ls.regUsage[dst] = i;
                ls.regUsage[src] = i;
                /* 3x mov-eliminated MOVs via scratch RAX avoid microcoded XCHG */
                mov(RAX, rd);
                mov(rd, rs);
                mov(rs, RAX);
            }
            break;
        case RX_OP_FSWAP_R: {
            int r = (instr->dst & 7) < 4 ? x.f[instr->dst & 3] : x.e[instr->dst & 3];
            vshufpd(r, r, r, 1);
            break;
        }
        case RX_OP_FADD_R:
            fpA(0x58, L, x.f[instr->dst & 3], instr->src & 3);
            break;
        case RX_OP_FADD_M:
            addrReg(instr, RAX, memMask(instr));
            vcvtdq2pdM(x.tmp, MI(RSI, RAX));
            vaddpd(x.f[instr->dst & 3], x.f[instr->dst & 3], x.tmp);
            break;
        case RX_OP_FSUB_R:
            fpA(0x5C, L, x.f[instr->dst & 3], instr->src & 3);
            break;
        case RX_OP_FSUB_M:
            addrReg(instr, RAX, memMask(instr));
            vcvtdq2pdM(x.tmp, MI(RSI, RAX));
            vsubpd(x.f[instr->dst & 3], x.f[instr->dst & 3], x.tmp);
            break;
        case RX_OP_FSCAL_R:
            xorScale(x.f[instr->dst & 3]);
            break;
        case RX_OP_FMUL_R:
            fpA(0x59, L, x.e[instr->dst & 3], instr->src & 3);
            break;
        case RX_OP_FDIV_M:
            addrReg(instr, RAX, memMask(instr));
            vcvtdq2pdM(x.tmp, MI(RSI, RAX));
            andMant(x.tmp);
            orEmask(L, x.tmp);
            vdivpd(x.e[instr->dst & 3], x.e[instr->dst & 3], x.tmp);
            break;
        case RX_OP_FSQRT_R:
            vsqrtpd(x.e[instr->dst & 3], x.e[instr->dst & 3]);
            break;
        case RX_OP_CBRANCH: {
            int target = ls.brTarget[i];
            int shift = (instr->mod >> 4) + RX_JUMP_OFFSET;
            uint32_t imm = instr->imm32 | (1u << shift);
            imm &= ~(1u << (shift - 1));
            aluRI(0, rd, (int32_t)imm);
            testRI(rd, (int32_t)(RX_CONDITION_MASK << shift));
            int32_t rel8 = ls.instrOffset[target] - (pos + 2);
            IB J;
            if (rel8 >= -128) {
                J.u8(0x74); J.u8((uint8_t)(int8_t)rel8);
            } else {
                J.u8(0x0F); J.u8(0x84); J.u32((uint32_t)(ls.instrOffset[target] - (pos + 6)));
            }
            put(J);
            for (int j = 0; j < RX_REGISTERS_COUNT; j++) ls.regUsage[j] = i;
            break;
        }
        case RX_OP_CFROUND: {
            int rot = (13 - (instr->imm32 & 63)) & 63;
            if (useBmi2 && rot) {
                rorx(RAX, rs, (64 - rot) & 63);
            } else {
                mov(RAX, rs);
                if (rot) shiftI(0, RAX, rot);
            }
            aluRI(4, RAX, 0x6000, 0);
            aluRI(1, RAX, RX_MXCSR_DEFAULT, 0);
            store32(M(RSP, slot(L, SL_MXCSR)), RAX);
            if (!g_mjit_smart_mxcsr || ls.cfroundNeedsLoad[i]) {
                emitLdmxcsrFromSlot(L, true);
            }
            break;
        }
        case RX_OP_ISTORE: {
            uint32_t mask = ((instr->mod >> 4) < RX_STORE_L3_COND) ? memMask(instr) : l3mask();
            lea32(RAX, M(rd, (int32_t)instr->imm32));
            aluRI(4, RAX, (int32_t)mask, 0);
            store(MI(RSI, RAX), rs);
            break;
        }
        default:
            break;
        }
    }

    void emitHead(int L) {
        LaneState &ls = lane[L];
        const LaneRegs &x = ls.x;
        load(RCX, M(RSP, slot(L, SL_SP0)));
        for (int i = 0; i < 8; i++) aluRM(0x33, ls.map[i], M(RCX, 8 * i));
        load(RCX, M(RSP, slot(L, SL_SP1)));
        for (int i = 0; i < 4; i++) vcvtdq2pdM(x.f[i], M(RCX, 8 * i));
        for (int i = 0; i < 4; i++) vcvtdq2pdM(x.e[i], M(RCX, 32 + 8 * i));
        for (int i = 0; i < 4; i++) andMant(x.e[i]);
        for (int i = 0; i < 4; i++) orEmask(L, x.e[i]);
    }

    /* uses only rax, rcx, rdx (+ rsi = scratchpad base) as temporaries */
    void emitTail(int L) {
        LaneState &ls = lane[L];
        const LaneRegs &x = ls.x;
        rx_program_config *cfg = ls.cfg;
        const int *mp = ls.map;
        if (g_mjit_tail_order) {
            /* Compute next_ma and issue dataset prefetch BEFORE the 8 dataset XOR loads */
            mov(RAX, mp[cfg->readReg2]);
            aluRR(0x33, RAX, mp[cfg->readReg3]);
            mov32(RAX, RAX);                              /* zero-extend low 32 */
            load(RDX, M(RSP, slot(L, SL_MXMA)));          /* low 32 = ma */
            mov32(RCX, RDX);
            aluRI(4, RCX, dsmask(), 0);
            aluRM(0x03, RCX, M(RSP, slot(L, SL_DS)));     /* rcx = &dataset[ma] */
            shiftI(1, RDX, 32);                           /* ror: low 32 = mx */
            aluRR(0x33, RDX, RAX);                        /* mx ^= (uint32_t)(r2 ^ r3) */
            store(M(RSP, slot(L, SL_MXMA)), RDX);
            mov32(RAX, RDX);
            aluRI(4, RAX, dsmask(), 0);
            aluRM(0x03, RAX, M(RSP, slot(L, SL_DS)));
            prefetch(g_mjit_ds_prefetch & 3, M(RAX));

            /* Dataset XORs into r0..r7 */
            for (int i = 0; i < 8; i++) aluRM(0x33, mp[i], M(RCX, 8 * i));

            /* Compute next sp0/sp1 and issue scratchpad prefetches BEFORE the 12 tail stores */
            mov(RAX, mp[cfg->readReg0]);
            aluRR(0x33, RAX, mp[cfg->readReg1]);
            mov(RDX, RAX);
            shiftI(1, RDX, 32);
            aluRI(4, RAX, (int32_t)l3mask64(), 0);
            aluRI(4, RDX, (int32_t)l3mask64(), 0);
            aluRR(0x03, RAX, RSI);
            aluRR(0x03, RDX, RSI);
            if (g_mjit_prefetch_mode) {
                prefetch(1, M(RAX));
                prefetch(1, M(RDX));
            }
            /* Store r0..r7 to old sp1 and f^e to old sp0 (RAX/RDX preserved) */
            load(RCX, M(RSP, slot(L, SL_SP1)));
            for (int i = 0; i < 8; i++) store(M(RCX, 8 * i), mp[i]);
            load(RCX, M(RSP, slot(L, SL_SP0)));
            for (int i = 0; i < 4; i++) vxorpd(x.f[i], x.f[i], x.e[i]);
            for (int i = 0; i < 4; i++) vmovapdStore(M(RCX, 16 * i), x.f[i]);
            store(M(RSP, slot(L, SL_SP0)), RAX);
            store(M(RSP, slot(L, SL_SP1)), RDX);
            return;
        }
        mov(RAX, mp[cfg->readReg2]);
        aluRR(0x33, RAX, mp[cfg->readReg3]);
        load(RDX, M(RSP, slot(L, SL_MXMA)));          /* low 32 = ma */
        mov32(RCX, RDX);
        aluRI(4, RCX, dsmask(), 0);
        aluRM(0x03, RCX, M(RSP, slot(L, SL_DS)));     /* rcx = &dataset[ma] */
        for (int i = 0; i < 8; i++) aluRM(0x33, mp[i], M(RCX, 8 * i));
        shiftI(1, RDX, 32);                           /* ror: low 32 = mx */
        mov32(RCX, RAX);
        aluRR(0x33, RDX, RCX);                        /* mx ^= r2 ^ r3 */
        store(M(RSP, slot(L, SL_MXMA)), RDX);
        mov32(RAX, RDX);
        aluRI(4, RAX, dsmask(), 0);
        aluRM(0x03, RAX, M(RSP, slot(L, SL_DS)));
        prefetch(g_mjit_ds_prefetch & 3, M(RAX));
        load(RCX, M(RSP, slot(L, SL_SP1)));
        for (int i = 0; i < 8; i++) store(M(RCX, 8 * i), mp[i]);
        load(RCX, M(RSP, slot(L, SL_SP0)));
        for (int i = 0; i < 4; i++) vxorpd(x.f[i], x.f[i], x.e[i]);
        for (int i = 0; i < 4; i++) vmovapdStore(M(RCX, 16 * i), x.f[i]);
        mov(RAX, mp[cfg->readReg0]);
        aluRR(0x33, RAX, mp[cfg->readReg1]);
        mov(RDX, RAX);
        shiftI(1, RDX, 32);
        aluRI(4, RAX, (int32_t)l3mask64(), 0);
        aluRI(4, RDX, (int32_t)l3mask64(), 0);
        aluRR(0x03, RAX, RSI);
        aluRR(0x03, RDX, RSI);
        if (g_mjit_prefetch_mode) {
            prefetch(1, M(RAX));
            prefetch(1, M(RDX));
        }
        store(M(RSP, slot(L, SL_SP0)), RAX);
        store(M(RSP, slot(L, SL_SP1)), RDX);
    }

    /* Switch GPRs, FP state and scratchpad base from `from` to `to`.
       MXCSR loading is emitted separately (after any stagger guard). */
    void emitSwitchRegs(int from, int to, int toSeg, bool isStagger) {
        if (from == to) return;
        if (g_mjit_diag & 8) for (int i = 0; i < 20; i++) b(0x90); /* diag: extra uops */
        if (fpBank2) {
            vmovapdStore(M(RSP, slot(from, SL_FE + 112)), lane[from].x.e[3]);
            if (isStagger || toSeg != 0) {
                vmovapdLoad(lane[to].x.e[3], M(RSP, slot(to, SL_FE + 112)));
            }
        } else if (fpSpill) {
            const LaneRegs &xf = lane[from].x, &xt = lane[to].x;
            for (int i = 0; i < 4; i++) vmovupdStore(M(RSP, slot(from, SL_FE + 16 * i)), xf.f[i]);
            for (int i = 0; i < 4; i++) vmovupdStore(M(RSP, slot(from, SL_FE + 64 + 16 * i)), xf.e[i]);
            if (isStagger || toSeg != 0) {
                for (int i = 0; i < 4; i++) vmovupdLoad(xt.f[i], M(RSP, slot(to, SL_FE + 16 * i)));
                for (int i = 0; i < 4; i++) vmovupdLoad(xt.e[i], M(RSP, slot(to, SL_FE + 64 + 16 * i)));
            }
        }
        for (int i = 0; i < 8; i++)
            if (lane[from].swapped[i]) store(M(RSP, slot(from, SL_R + 8 * i)), lane[from].map[i]);
        for (int i = 0; i < 8; i++)
            if (lane[to].swapped[i]) load(lane[to].map[i], M(RSP, slot(to, SL_R + 8 * i)));
        load(RSI, M(RSP, slot(to, SL_SPB)));
    }

    void emitSwitchMxcsr(int from, int to) {
        if (g_mjit_diag & 4) return;
        if (g_mjit_mxguard || g_mjit_mxcsr_skip) {
            load32(RAX, M(RSP, slot(to, SL_MXCSR)));
            cmpRegMem32(RAX, M(RSP, FR_HWMXCSR));
            b(0x74); int patch = pos; b(0);
            store32(M(RSP, FR_HWMXCSR), RAX);
            ldmxcsrRaw(M(RSP, slot(to, SL_MXCSR)));
            code[patch] = (uint8_t)(pos - (patch + 1));
        } else {
            (void)from;
            ldmxcsrRaw(M(RSP, slot(to, SL_MXCSR)));
        }
    }

    /* Precompute CBRANCH targets and legal cut points, then split into segments. */
    void analyzeAndSplit(int L, int G) {
        LaneState &ls = lane[L];
        int simUsage[RX_REGISTERS_COUNT];
        for (int r = 0; r < RX_REGISTERS_COUNT; r++) simUsage[r] = -1;

        uint8_t legalCut[RX_PROGRAM_SIZE];
        memset(legalCut, 1, sizeof(legalCut));
        legalCut[0] = 0;

        ls.hasCfround = 0;
        ls.anyRoundFP = 0;

        for (int i = 0; i < RX_PROGRAM_SIZE; i++) {
            rx_instruction *instr = &ls.prog->programBuffer[i];
            int op = instr->opcode;
            int dst = instr->dst & 7, src = instr->src & 7;
            ls.brTarget[i] = -1;

            if (op < RX_CEIL_RX_IMUL_RCP) {
                if (op >= RX_CEIL_RX_ISMULH_M) {
                    if (!is_zero_or_power_of_2(instr->imm32)) simUsage[dst] = i;
                } else {
                    simUsage[dst] = i;
                }
            } else if (op < RX_CEIL_RX_ISWAP_R) {
                if (op >= RX_CEIL_RX_IROL_R) {
                    if (src != dst) { simUsage[dst] = i; simUsage[src] = i; }
                } else {
                    simUsage[dst] = i;
                }
            } else if (isCbranchOp(op)) {
                int target = simUsage[dst] + 1;
                ls.brTarget[i] = target;
                /* Cannot cut inside (target, i]: that would split the branch from its target */
                for (int p = target + 1; p <= i; p++) legalCut[p] = 0;
                for (int r = 0; r < RX_REGISTERS_COUNT; r++) simUsage[r] = i;
            } else if (isCfroundOp(op)) {
                ls.hasCfround = 1;
            } else if (isRoundingSensitiveFP(op)) {
                ls.anyRoundFP = 1;
            }
        }

        ls.nseg = 0;
        int start = 0;
        ls.segStart[ls.nseg++] = 0;
        if (!g_mjit_smart_cuts) {
            for (int i = 0; i < RX_PROGRAM_SIZE; i++) {
                int op = ls.prog->programBuffer[i].opcode;
                if (isCbranchOp(op) && i + 1 < RX_PROGRAM_SIZE && (i + 1 - start) >= G) {
                    start = i + 1;
                    ls.segStart[ls.nseg++] = start;
                }
            }
        } else {
            /* Cut at legalCut[p] once (p - start) >= G; also prefer cutting right
               before a legal CFROUND once (p - start) >= G/2 so the new segment
               starts with CFROUND and skips switch-in LDMXCSR. */
            int halfG = G > 2 ? (G * 3) / 4 : G;
            for (int p = 1; p < RX_PROGRAM_SIZE; p++) {
                if (!legalCut[p]) continue;
                int dist = p - start;
                int opAtP = ls.prog->programBuffer[p].opcode;
                bool cutForCfround = (G < RX_PROGRAM_SIZE) && isCfroundOp(opAtP) && dist >= halfG && (RX_PROGRAM_SIZE - p) >= 8;
                if (dist >= G || cutForCfround) {
                    start = p;
                    ls.segStart[ls.nseg++] = start;
                }
            }
        }
        ls.segStart[ls.nseg] = RX_PROGRAM_SIZE;

        /* Per-segment rounding analysis & dead CFROUND load analysis */
        for (int s = 0; s < ls.nseg; s++) {
            int a = ls.segStart[s], bEnd = ls.segStart[s + 1];
            uint8_t hasFP = 0;
            uint8_t firstIsCf = 0;
            uint8_t seenRoundOrBranch = 0;
            uint8_t hasDefCf = 0, hasLoadCf = 0;

            for (int i = a; i < bEnd; i++) {
                int op = ls.prog->programBuffer[i].opcode;
                if (isRoundingSensitiveFP(op)) {
                    hasFP = 1;
                    seenRoundOrBranch = 1;
                } else if (isCbranchOp(op)) {
                    seenRoundOrBranch = 1;
                } else if (isCfroundOp(op)) {
                    if (!seenRoundOrBranch) {
                        firstIsCf = 1;
                        seenRoundOrBranch = 1;
                    }
                    /* Determine if this CFROUND needs an immediate LDMXCSR within this segment */
                    uint8_t needs = 0;
                    for (int j = i + 1; j < bEnd; j++) {
                        int op2 = ls.prog->programBuffer[j].opcode;
                        if (isRoundingSensitiveFP(op2)) { needs = 1; break; }
                        if (isCfroundOp(op2)) { break; } /* overwritten before any FP/branch */
                        if (isCbranchOp(op2)) {
                            int t = ls.brTarget[j];
                            if (t <= i) {
                                /* Backward jump past i: check if [t, i) has any rounding-sensitive FP */
                                for (int k = t; k < i; k++) {
                                    if (isRoundingSensitiveFP(ls.prog->programBuffer[k].opcode)) {
                                        needs = 1; break;
                                    }
                                }
                                if (needs) break;
                            }
                        }
                    }
                    ls.cfroundNeedsLoad[i] = needs;
                    if (needs) hasLoadCf = 1;
                    else hasDefCf = 1;
                }
            }
            ls.segHasRoundFP[s] = hasFP;
            ls.segFirstRoundIsCfround[s] = firstIsCf;
            ls.segHasDeferredCfround[s] = hasDefCf;
            ls.segHasLoadedCfround[s] = hasLoadCf;
        }
    }

    void setupLaneRegs(int L) {
        LaneRegs &x = lane[L].x;
        if (fpBank2) {
            if (L == 0) {
                for (int i = 0; i < 4; i++) { x.f[i] = i; x.e[i] = 4 + i; x.a[i] = -1; }
                x.tmp = 15;
            } else {
                for (int i = 0; i < 4; i++) { x.f[i] = 8 + i; x.e[i] = 12 + i; x.a[i] = -1; }
                x.tmp = 7;
            }
            x.emask = -1;
            x.aMem = 1;
        } else if (fpSpill) {
            /* every lane uses xmm0-7 for f/e, spilled at lane switches */
            for (int i = 0; i < 4; i++) {
                x.f[i] = i;
                x.e[i] = 4 + i;
                x.a[i] = -1;
            }
            x.tmp = 12;
            x.emask = -1;
            x.aMem = 1;
        } else if (K <= 2) {
            int base = L == 0 ? 0 : 16;
            for (int i = 0; i < 4; i++) {
                x.f[i] = base + i;
                x.e[i] = base + 4 + i;
                x.a[i] = base + 8 + i;
            }
            x.tmp = base + 12;
            x.emask = base + 14;
            x.aMem = 0;
        } else {
            /* 3 lanes: f/e resident (24 regs), shared tmp, a/eMask in memory */
            for (int i = 0; i < 4; i++) {
                x.f[i] = 8 * L + i;
                x.e[i] = 8 * L + 4 + i;
                x.a[i] = -1;
            }
            x.tmp = 24;
            x.emask = -1;
            x.aMem = 1;
        }
        lane[L].slot = FR_LANE0 + L * FR_LANE_SIZE;
        static const int pinned1[3] = { RBX, RBP, RDI };
        for (int i = 0; i < 8; i++) {
            lane[L].map[i] = R8 + i;
            lane[L].swapped[i] = K > 1;
        }
        if (K == 2 && g_mjit_pinned_regs) {
            for (int i = 0; i < 3; i++) {
                lane[L].swapped[i] = 0;
                if (L == 1) lane[L].map[i] = pinned1[i];
            }
        }
    }

    int generate(int K_, rx_program **progs, rx_program_config **cfgs, const uint32_t *initMxcsr) {
        init_op_lut();
        K = K_;
        pos = 0;
        poolCount = 0;
        fixCount = 0;
        useBmi2 = g_mjit_bmi2 && cached_has_bmi2();
        bool hasAvx512 = rx_cpu_has_avx512_lanes() != 0;
        fpBank2 = (K == 2 && !hasAvx512 && !g_mjit_fp_spill && g_mjit_fp_bank2) ? 1 : 0;
        fpSpill = (K > 1 && !fpBank2 && (g_mjit_fp_spill || K > 3 || !hasAvx512)) ? 1 : 0;
        mantMask = (fpSpill || K <= 2) ? 13 : 25;
        scaleMask = (fpSpill || K <= 2) ? 15 : 26;

        int effGran = g_mjit_granularity < 1 ? 1 : g_mjit_granularity;
        for (int L = 0; L < K; L++) {
            lane[L].prog = progs[L];
            lane[L].cfg = cfgs[L];
            for (int r = 0; r < RX_REGISTERS_COUNT; r++) lane[L].regUsage[r] = -1;
            setupLaneRegs(L);
            analyzeAndSplit(L, effGran);
        }

        /* Determine if all lanes share a single constant MXCSR across all iterations */
        bool allStaticSameMxcsr = false;
        int firstConstLane = 0;
        if (g_mjit_smart_mxcsr && initMxcsr != NULL) {
            bool ok = true;
            uint32_t common = 0;
            bool haveCommon = false;
            for (int L = 0; L < K; L++) {
                if (lane[L].hasCfround) { ok = false; break; }
                if (!lane[L].anyRoundFP) continue;
                if (!haveCommon) { common = initMxcsr[L]; firstConstLane = L; haveCommon = true; }
                else if (initMxcsr[L] != common) { ok = false; break; }
            }
            if (ok) allStaticSameMxcsr = true;
        }

        const int frame = FR_LANE0 + K * FR_LANE_SIZE;
        const int xmmSave = 160;
        const int frameTotal = ((frame + xmmSave + 15) & ~15) + 8; /* keep rsp 16-aligned */

        /* ---- prologue (Win64 ABI: rcx = params) ---- */
        push(RBX); push(RBP); push(RDI); push(RSI);
        push(R12); push(R13); push(R14); push(R15);
        aluRI(5, RSP, frameTotal);
        const int xmmBase = frameTotal - xmmSave;
        for (int i = 0; i < 10; i++) vmovupdStore(M(RSP, xmmBase + 16 * i), 6 + i);
        b(0xC5); b(0xF8); b(0x77); /* vzeroupper */
        store(M(RSP, FR_PARAMS), RCX);

        if (fpBank2) {
            vmovupdLoad(0, M(RCX, offsetof(rx_multi_params, mantMask)));
            vmovapdStore(M(RSP, FR_MANTMASK), 0);
            vmovupdLoad(0, M(RCX, offsetof(rx_multi_params, scaleMask)));
            vmovapdStore(M(RSP, FR_SCALEMASK), 0);
        } else {
            vmovupdLoad(mantMask, M(RCX, offsetof(rx_multi_params, mantMask)));
            vmovupdLoad(scaleMask, M(RCX, offsetof(rx_multi_params, scaleMask)));
        }
        for (int L = 0; L < K; L++) {
            const LaneRegs &x = lane[L].x;
            int lp = (int)(offsetof(rx_multi_params, lane) + L * sizeof(rx_lane_params));
            load(RDX, M(RCX, lp + (int)offsetof(rx_lane_params, reg)));
            if (!x.aMem) {
                for (int i = 0; i < 4; i++) vmovupdLoad(x.a[i], M(RDX, (int)offsetof(rx_register_file, a) + 16 * i));
                vmovupdLoad(x.emask, M(RCX, lp + (int)offsetof(rx_lane_params, eMask)));
            } else {
                int stmp = fpBank2 ? 0 : x.tmp;
                for (int i = 0; i < 4; i++) {
                    vmovupdLoad(stmp, M(RDX, (int)offsetof(rx_register_file, a) + 16 * i));
                    vmovupdStore(M(RSP, slot(L, SL_A + 16 * i)), stmp);
                }
                vmovupdLoad(stmp, M(RCX, lp + (int)offsetof(rx_lane_params, eMask)));
                vmovupdStore(M(RSP, slot(L, SL_EMASK)), stmp);
            }
            load(RAX, M(RCX, lp + (int)offsetof(rx_lane_params, mx_ma)));
            mov(RBP, RAX);
            shiftI(1, RBP, 32);
            store(M(RSP, slot(L, SL_MXMA)), RBP);
            load(RDI, M(RCX, lp + (int)offsetof(rx_lane_params, ds)));
            store(M(RSP, slot(L, SL_DS)), RDI);
            load(RSI, M(RCX, lp + (int)offsetof(rx_lane_params, sp)));
            store(M(RSP, slot(L, SL_SPB)), RSI);
            /* prefetch first dataset line (ma) */
            mov32(RDX, RBP);
            aluRI(4, RDX, dsmask(), 0);
            prefetch(0, MI(RDI, RDX));
            /* spAddr0 = mx, spAddr1 = ma */
            mov(RDX, RAX);
            shiftI(5, RDX, 32);          /* shr rdx, 32 */
            aluRI(4, RAX, (int32_t)l3mask64(), 0);
            aluRI(4, RDX, (int32_t)l3mask64(), 0);
            aluRR(0x03, RAX, RSI);
            aluRR(0x03, RDX, RSI);
            store(M(RSP, slot(L, SL_SP0)), RAX);
            store(M(RSP, slot(L, SL_SP1)), RDX);
            load32(RAX, M(RCX, lp + (int)offsetof(rx_lane_params, mxcsr)));
            store32(M(RSP, slot(L, SL_MXCSR)), RAX);
            for (int i = 0; i < 8; i++) storeImm32(M(RSP, slot(L, SL_R + 8 * i)), 0);
        }

        /* ---- schedule: lockstep or phase-staggered ---- */
        struct SchedItem { int L; int s; int phase; int wrapped; };
        SchedItem sched[RX_MULTI_MAX_LANES * (RX_PROGRAM_SIZE + 1)];
        int nsched = 0;
        bool activeStagger = false;

        if (g_mjit_stagger && K >= 2) {
            int anyWrapped = 0;
            for (int L = 0; L < K; L++) {
                int q = (L * RX_PROGRAM_SIZE) / K;
                for (int s = 0; s < lane[L].nseg; s++) {
                    int raw = lane[L].segStart[s] + q;
                    int wr = (raw >= RX_PROGRAM_SIZE) ? 1 : 0;
                    if (wr) anyWrapped = 1;
                    sched[nsched].L = L;
                    sched[nsched].s = s;
                    sched[nsched].phase = raw % RX_PROGRAM_SIZE;
                    sched[nsched].wrapped = wr;
                    nsched++;
                }
            }
            if (anyWrapped) {
                activeStagger = true;
                /* Stable insertion sort by phase */
                for (int i = 1; i < nsched; i++) {
                    SchedItem key = sched[i];
                    int j = i - 1;
                    while (j >= 0 && sched[j].phase > key.phase) {
                        sched[j + 1] = sched[j];
                        j--;
                    }
                    sched[j + 1] = key;
                }
            } else {
                nsched = 0;
            }
        }
        if (!activeStagger) {
            int maxSeg = 0;
            for (int L = 0; L < K; L++) if (lane[L].nseg > maxSeg) maxSeg = lane[L].nseg;
            for (int s = 0; s < maxSeg; s++)
                for (int L = 0; L < K; L++)
                    if (s < lane[L].nseg) {
                        sched[nsched].L = L;
                        sched[nsched].s = s;
                        sched[nsched].phase = lane[L].segStart[s];
                        sched[nsched].wrapped = 0;
                        nsched++;
                    }
        }

        load32(RAX, M(RCX, offsetof(rx_multi_params, iterations)));
        if (activeStagger) {
            aluRI(0, RAX, 1, 0); /* add eax, 1 */
            storeImm32(M(RSP, FR_FIRST), 1, 0);
        }
        store32(M(RSP, FR_COUNT), RAX);
        for (int i = 0; i < 8; i++) aluRR(0x33, R8 + i, R8 + i);
        for (int L = 0; L < K; L++)
            for (int i = 0; i < 8; i++)
                if (lane[L].map[i] < R8) aluRR(0x33, lane[L].map[i], lane[L].map[i]);

        int lastLane = sched[nsched - 1].L;
        /* entering the loop: registers hold zeros = "lastLane" state */
        load(RSI, M(RSP, slot(lastLane, SL_SPB)));
        int initLoadLane = allStaticSameMxcsr ? firstConstLane : lastLane;
        if (!(g_mjit_diag & 4)) {
            load32(RAX, M(RSP, slot(initLoadLane, SL_MXCSR)));
            store32(M(RSP, FR_HWMXCSR), RAX);
            ldmxcsrRaw(M(RSP, slot(initLoadLane, SL_MXCSR)));
        }

        /* Precompute which scheduled entries need a switch-in LDMXCSR */
        uint8_t needSwitchMxcsr[RX_MULTI_MAX_LANES * (RX_PROGRAM_SIZE + 1)];
        memset(needSwitchMxcsr, 0, (size_t)nsched);
        if (!allStaticSameMxcsr && !(g_mjit_diag & 4)) {
            if (g_mjit_smart_mxcsr) {
                /* First pass: any segment with rounding FP that doesn't start with CFROUND needs MXCSR */
                for (int n = 0; n < nsched; n++) {
                    int L = sched[n].L, s = sched[n].s;
                    if (lane[L].segHasRoundFP[s] && !lane[L].segFirstRoundIsCfround[s]) {
                        needSwitchMxcsr[n] = 1;
                    }
                }
                /* Second pass (lockstep only, where every segment runs every pass):
                   if the previous cyclic segment that loaded MXCSR belongs to the SAME lane L
                   (or another constant-mode lane with identical initMxcsr) AND lane L had no
                   deferred CFROUND in between, we can drop needSwitchMxcsr[n]. */
                if (!activeStagger) {
                    /* Ensure initial prologue state matches cyclic steady state before dropping:
                       check steady state over 2 passes of the cycle. */
                    int hwOwner = initLoadLane;
                    uint8_t laneDirty[RX_MULTI_MAX_LANES] = {0};
                    /* First check steady-state entry owner at n=0 after 1 full pass */
                    for (int pass = 0; pass < 2; pass++) {
                        for (int n = 0; n < nsched; n++) {
                            int L = sched[n].L, s = sched[n].s;
                            if (needSwitchMxcsr[n]) {
                                bool sameConst = (hwOwner >= 0 && hwOwner != L && initMxcsr != NULL &&
                                                  !lane[L].hasCfround && !lane[hwOwner].hasCfround &&
                                                  initMxcsr[L] == initMxcsr[hwOwner]);
                                if (pass == 1) {
                                    /* Only drop if BOTH pass 0 (from initLoadLane) AND pass 1 (steady state) agree! */
                                }
                                if ((hwOwner == L && !laneDirty[L]) || sameConst) {
                                    /* Can potentially skip; verified conservatively below */
                                } else {
                                    hwOwner = L;
                                    laneDirty[L] = 0;
                                }
                            }
                            if (lane[L].segHasLoadedCfround[s]) {
                                hwOwner = L;
                                laneDirty[L] = 0;
                            }
                            if (lane[L].segHasDeferredCfround[s]) {
                                laneDirty[L] = 1;
                            }
                        }
                    }
                    /* Now apply skipping only when BOTH entry from initLoadLane AND cyclic wrap-around agree */
                    int steadyOwner = hwOwner;
                    uint8_t steadyDirty[RX_MULTI_MAX_LANES];
                    memcpy(steadyDirty, laneDirty, sizeof(steadyDirty));
                    int o0 = initLoadLane, o1 = steadyOwner;
                    uint8_t d0[RX_MULTI_MAX_LANES] = {0}, d1[RX_MULTI_MAX_LANES];
                    memcpy(d1, steadyDirty, sizeof(d1));
                    for (int n = 0; n < nsched; n++) {
                        int L = sched[n].L, s = sched[n].s;
                        if (needSwitchMxcsr[n]) {
                            bool ok0 = (o0 == L && !d0[L]) ||
                                       (o0 >= 0 && initMxcsr != NULL && !lane[L].hasCfround && !lane[o0].hasCfround && initMxcsr[L] == initMxcsr[o0]);
                            bool ok1 = (o1 == L && !d1[L]) ||
                                       (o1 >= 0 && initMxcsr != NULL && !lane[L].hasCfround && !lane[o1].hasCfround && initMxcsr[L] == initMxcsr[o1]);
                            if (ok0 && ok1) {
                                needSwitchMxcsr[n] = 0;
                            } else {
                                o0 = L; d0[L] = 0;
                                o1 = L; d1[L] = 0;
                            }
                        }
                        if (lane[L].segHasLoadedCfround[s]) { o0 = L; d0[L] = 0; o1 = L; d1[L] = 0; }
                        if (lane[L].segHasDeferredCfround[s]) { d0[L] = 1; d1[L] = 1; }
                    }
                }
            } else {
                int c = lastLane;
                for (int n = 0; n < nsched; n++) {
                    if (activeStagger || sched[n].L != c) needSwitchMxcsr[n] = 1;
                    c = sched[n].L;
                }
            }
        }

        /* align loop start */
        while (pos & 15) b(0x90);
        int loopStart = pos;
        int cur = lastLane;
        for (int n = 0; n < nsched; n++) {
            int L = sched[n].L, s = sched[n].s;
            int prevLane = cur;
            emitSwitchRegs(cur, L, s, activeStagger);
            cur = L;

            int skipPatch = -1;
            if (activeStagger) {
                if (sched[n].wrapped) {
                    /* skip on pass 0 (FR_FIRST != 0) */
                    cmpMemImm8_32(M(RSP, FR_FIRST), 0);
                    b(0x0F); b(0x85); skipPatch = pos; d32(0);
                } else {
                    /* skip on last pass (FR_COUNT == 1) */
                    cmpMemImm8_32(M(RSP, FR_COUNT), 1);
                    b(0x0F); b(0x84); skipPatch = pos; d32(0);
                }
            }

            if (needSwitchMxcsr[n]) {
                emitSwitchMxcsr(prevLane, L);
            }
            if (g_mjit_refresh_dspf && s == lane[L].nseg - 1 && lane[L].nseg >= 2) {
                load32(RAX, M(RSP, slot(L, SL_MXMA)));
                aluRI(4, RAX, dsmask(), 0);
                aluRM(0x03, RAX, M(RSP, slot(L, SL_DS)));
                prefetch(1, M(RAX)); /* prefetcht0 */
            }
            if (s == 0) emitHead(L);
            for (int i = lane[L].segStart[s]; i < lane[L].segStart[s + 1]; i++)
                emitInstr(L, i);
            if (s == lane[L].nseg - 1) emitTail(L);

            if (skipPatch >= 0) {
                int32_t rel = pos - (skipPatch + 4);
                memcpy(code + skipPatch, &rel, 4);
            }
        }
        if (activeStagger) {
            storeImm32(M(RSP, FR_FIRST), 0, 0);
        }
        /* dec dword [rsp+FR_COUNT]; jnz loopStart */
        b(0xFF); modrmMem(1, M(RSP, FR_COUNT));
        b(0x0F); b(0x85); d32((uint32_t)(loopStart - (pos + 4)));

        /* ---- epilogue ---- */
        if (fpBank2) {
            vmovapdStore(M(RSP, slot(cur, SL_FE + 112)), lane[cur].x.e[3]);
        }
        for (int L = 0; L < K; L++)
            for (int i = 0; i < 8; i++)
                if (L == cur || !lane[L].swapped[i])
                    store(M(RSP, slot(L, SL_R + 8 * i)), lane[L].map[i]);
        load(RCX, M(RSP, FR_PARAMS));
        for (int L = 0; L < K; L++) {
            const LaneRegs &x = lane[L].x;
            int lp = (int)(offsetof(rx_multi_params, lane) + L * sizeof(rx_lane_params));
            load(RDX, M(RCX, lp + (int)offsetof(rx_lane_params, reg)));
            for (int i = 0; i < 8; i++) {
                load(RAX, M(RSP, slot(L, SL_R + 8 * i)));
                store(M(RDX, 8 * i), RAX);
            }
            if (fpBank2) {
                for (int i = 0; i < 4; i++) vmovupdStore(M(RDX, (int)offsetof(rx_register_file, f) + 16 * i), x.f[i]);
                for (int i = 0; i < 3; i++) vmovupdStore(M(RDX, (int)offsetof(rx_register_file, e) + 16 * i), x.e[i]);
                vmovapdLoad(7, M(RSP, slot(L, SL_FE + 112)));
                vmovupdStore(M(RDX, (int)offsetof(rx_register_file, e) + 48), 7);
            } else if (fpSpill && L != cur) {
                for (int i = 0; i < 8; i++) {
                    vmovupdLoad(x.tmp, M(RSP, slot(L, SL_FE + 16 * i)));
                    vmovupdStore(M(RDX, (int)offsetof(rx_register_file, f) + 16 * i), x.tmp);
                }
            } else {
                for (int i = 0; i < 4; i++) vmovupdStore(M(RDX, (int)offsetof(rx_register_file, f) + 16 * i), x.f[i]);
                for (int i = 0; i < 4; i++) vmovupdStore(M(RDX, (int)offsetof(rx_register_file, e) + 16 * i), x.e[i]);
            }
            load(RAX, M(RSP, slot(L, SL_MXMA)));
            store(M(RCX, lp + (int)offsetof(rx_lane_params, mx_ma)), RAX);
            load32(RAX, M(RSP, slot(L, SL_MXCSR)));
            store32(M(RCX, lp + (int)offsetof(rx_lane_params, mxcsr)), RAX);
        }
        for (int i = 0; i < 10; i++) vmovupdLoad(6 + i, M(RSP, xmmBase + 16 * i));
        aluRI(0, RSP, frameTotal);
        pop(R15); pop(R14); pop(R13); pop(R12);
        pop(RSI); pop(RDI); pop(RBP); pop(RBX);
        b(0xC3);

        /* ---- constant pool ---- */
        while (pos & 7) b(0xCC);
        int poolPos = pos;
        for (int i = 0; i < poolCount; i++) q64(pool[i]);
        for (int i = 0; i < fixCount; i++) {
            int32_t rel = (poolPos + 8 * fix[i].index) - (fix[i].patchPos + 4);
            memcpy(code + fix[i].patchPos, &rel, 4);
        }
        return pos;
    }
};

} /* namespace */

extern "C" {

struct rx_mjit {
    MultiJit *j;
};

rx_mjit *rx_mjit_create(void) {
    rx_mjit *m = (rx_mjit *)calloc(1, sizeof(rx_mjit));
    if (!m) return NULL;
    m->j = new MultiJit();
    m->j->code = (uint8_t *)vmem_alloc(MJ_CODE_SIZE, VMEM_EXEC, NULL);
    if (!m->j->code) { delete m->j; free(m); return NULL; }
    return m;
}

void rx_mjit_destroy(rx_mjit *m) {
    if (!m) return;
    vmem_free(m->j->code);
    delete m->j;
    free(m);
}

int rx_mjit_generate_ex(rx_mjit *m, int K, rx_program **progs, rx_program_config **cfgs, const uint32_t *initMxcsr) {
    if (K < 1 || K > RX_MULTI_MAX_LANES) return -1;
    return m->j->generate(K, progs, cfgs, initMxcsr);
}

int rx_mjit_generate(rx_mjit *m, int K, rx_program **progs, rx_program_config **cfgs) {
    return rx_mjit_generate_ex(m, K, progs, cfgs, NULL);
}

void *rx_mjit_code(rx_mjit *m) { return m->j->code; }

}
