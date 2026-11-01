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
 *  - A lane's program is cut into segments only right after a CBRANCH.
 *    RandomX branch targets are always > the previous CBRANCH of the same
 *    program, so a taken branch never leaves its segment.
 *  - Integer registers r0..r7 live in r8..r15 for whichever lane is running;
 *    a lane switch spills/fills them to per-lane stack slots.
 *  - FP registers are banked per lane: lane 0 uses xmm0..xmm15 (VEX),
 *    lane 1 uses xmm16..xmm31 (EVEX, AVX-512VL/DQ), so FP state is never
 *    spilled. Lanes >= 2 (if requested) are not supported by this banking.
 *  - MXCSR (rounding mode) is per lane and reloaded at every lane switch.
 *
 * Calling convention: Win64 (RX_JIT_ABI), one argument: rx_multi_params *.
 */
#include "randomx_internal.h"
#include "common/vmem.h"

#include <string.h>
#include <stdlib.h>

#define MJ_CODE_SIZE   (128 * 1024)
#define MJ_POOL_MAX    1024

extern "C" {
int g_mjit_granularity = 256;      /* target RandomX instructions per segment */
int g_mjit_mxcsr_skip = 0;         /* skip LDMXCSR when lanes share the mode */
int g_mjit_rcp_pool = 1;           /* IMUL_RCP: RIP-relative constant pool */
int g_mjit_prefetch_mode = 1;      /* scratchpad prefetch at iteration end: 0 none, 1 t0 */
}

namespace {

enum { RAX = 0, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8, R9, R10, R11, R12, R13, R14, R15 };

/* Stack frame (relative to rsp after the prologue) */
static const int FR_PARAMS = 0;
static const int FR_LANE0 = 64;
static const int FR_LANE_SIZE = 128;
/* per-lane slot offsets */
static const int SL_R = 0;        /* 8 qwords */
static const int SL_SP0 = 64;     /* pointer to spAddr0 line */
static const int SL_SP1 = 72;     /* pointer to spAddr1 line */
static const int SL_MXMA = 80;    /* rotated mx/ma (low32 = ma) */
static const int SL_DS = 88;      /* dataset base (+datasetOffset) */
static const int SL_SPB = 96;     /* scratchpad base */
static const int SL_MXCSR = 104;  /* dword */

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
};

struct LaneState {
    rx_program *prog;
    rx_program_config *cfg;
    int32_t instrOffset[RX_PROGRAM_MAX_SIZE];
    int regUsage[RX_REGISTERS_COUNT];
    int segStart[RX_PROGRAM_SIZE + 1];
    int nseg;
    LaneRegs x;
    int slot; /* rsp offset of this lane's slots */
};

struct PoolFixup { int patchPos; int index; };

struct MultiJit {
    uint8_t *code;
    int pos;
    int K;
    int mantMask, scaleMask;
    LaneState lane[RX_MULTI_MAX_LANES];
    uint64_t pool[MJ_POOL_MAX];
    int poolCount;
    PoolFixup fix[MJ_POOL_MAX];
    int fixCount;

    /* ------------------------------------------------------------------ */
    void b(uint8_t v) { code[pos++] = v; }
    void d32(uint32_t v) { memcpy(code + pos, &v, 4); pos += 4; }
    void q64(uint64_t v) { memcpy(code + pos, &v, 8); pos += 8; }

    void rex(int w, int reg, int index, int base, bool force = false) {
        uint8_t r = (uint8_t)(0x40 | (w << 3) | (((reg >> 3) & 1) << 2) |
                              (((index >> 3) & 1) << 1) | ((base >> 3) & 1));
        if (r != 0x40 || force) b(r);
    }

    void modrmRR(int reg, int rm) { b((uint8_t)(0xC0 | ((reg & 7) << 3) | (rm & 7))); }

    /* ModRM + SIB + displacement for a memory operand. forceDisp32 is used by
       EVEX encodings to avoid compressed disp8*N semantics. */
    void modrmMem(int reg, const Mem &m, bool forceDisp32 = false) {
        int r = (reg & 7) << 3;
        if (m.base < 0) {
            /* [index*s + disp32] or [disp32] */
            b((uint8_t)(0x04 | r));
            int idx = m.index < 0 ? 4 : (m.index & 7);
            b((uint8_t)((m.scale << 6) | (idx << 3) | 5));
            d32((uint32_t)m.disp);
            return;
        }
        int mod;
        if (m.disp == 0 && (m.base & 7) != 5) mod = 0;
        else if (!forceDisp32 && m.disp >= -128 && m.disp <= 127) mod = 1;
        else mod = 2;
        bool sib = m.index >= 0 || (m.base & 7) == 4;
        if (sib) {
            b((uint8_t)((mod << 6) | r | 4));
            int idx = m.index < 0 ? 4 : (m.index & 7);
            b((uint8_t)((m.scale << 6) | (idx << 3) | (m.base & 7)));
        } else {
            b((uint8_t)((mod << 6) | r | (m.base & 7)));
        }
        if (mod == 1) b((uint8_t)(int8_t)m.disp);
        else if (mod == 2) d32((uint32_t)m.disp);
    }

    /* opcode with reg + r/m register */
    void opRR(int w, uint8_t op, int reg, int rm) { rex(w, reg, 0, rm); b(op); modrmRR(reg, rm); }
    void opRR0F(int w, uint8_t op, int reg, int rm) { rex(w, reg, 0, rm); b(0x0F); b(op); modrmRR(reg, rm); }
    void opRM(int w, uint8_t op, int reg, const Mem &m) {
        rex(w, reg, m.index < 0 ? 0 : m.index, m.base < 0 ? 0 : m.base); b(op); modrmMem(reg, m);
    }
    void opRM0F(int w, uint8_t op, int reg, const Mem &m) {
        rex(w, reg, m.index < 0 ? 0 : m.index, m.base < 0 ? 0 : m.base); b(0x0F); b(op); modrmMem(reg, m);
    }

    /* integer helpers (64-bit unless noted) */
    void mov(int dst, int src) { opRR(1, 0x8B, dst, src); }
    void mov32(int dst, int src) { opRR(0, 0x8B, dst, src); }
    void load(int dst, const Mem &m) { opRM(1, 0x8B, dst, m); }
    void load32(int dst, const Mem &m) { opRM(0, 0x8B, dst, m); }
    void store(const Mem &m, int src) { opRM(1, 0x89, src, m); }
    void store32(const Mem &m, int src) { opRM(0, 0x89, src, m); }
    void storeImm32(const Mem &m, int32_t imm, int w = 1) { opRM(w, 0xC7, 0, m); d32((uint32_t)imm); }
    void lea(int dst, const Mem &m) { opRM(1, 0x8D, dst, m); }
    void lea32(int dst, const Mem &m) { opRM(0, 0x8D, dst, m); }
    void aluRR(uint8_t op, int dst, int src) { opRR(1, op, dst, src); }   /* 03 add, 2B sub, 33 xor, 23 and */
    void aluRM(uint8_t op, int dst, const Mem &m) { opRM(1, op, dst, m); }
    void aluRI(int ext, int dst, int32_t imm, int w = 1) { rex(w, 0, 0, dst); b(0x81); modrmRR(ext, dst); d32((uint32_t)imm); }
    void imulRR(int dst, int src) { opRR0F(1, 0xAF, dst, src); }
    void imulRM(int dst, const Mem &m) { opRM0F(1, 0xAF, dst, m); }
    void imulRRI(int dst, int src, int32_t imm) { opRR(1, 0x69, dst, src); d32((uint32_t)imm); }
    void unaryR(int ext, int r) { rex(1, 0, 0, r); b(0xF7); modrmRR(ext, r); }        /* /3 neg /4 mul /5 imul */
    void unaryM(int ext, const Mem &m) { opRM(1, 0xF7, ext, m); }
    void shiftCl(int ext, int r) { rex(1, 0, 0, r); b(0xD3); modrmRR(ext, r); }       /* /0 rol /1 ror */
    void shiftI(int ext, int r, int imm) { rex(1, 0, 0, r); b(0xC1); modrmRR(ext, r); b((uint8_t)imm); } /* /5 shr */
    void xchg(int a, int c) { opRR(1, 0x87, a, c); }
    void testRI(int r, int32_t imm) { rex(1, 0, 0, r); b(0xF7); modrmRR(0, r); d32((uint32_t)imm); }
    void movImm64(int r, uint64_t imm) { rex(1, 0, 0, r, true); b((uint8_t)(0xB8 + (r & 7))); q64(imm); }
    void prefetch(int hint, const Mem &m) { opRM0F(0, 0x18, hint, m); } /* 0 nta, 1 t0, 2 t1 */
    void ldmxcsr(const Mem &m) { opRM0F(0, 0xAE, 2, m); }
    void push(int r) { if (r >= 8) b(0x41); b((uint8_t)(0x50 + (r & 7))); }
    void pop(int r) { if (r >= 8) b(0x41); b((uint8_t)(0x58 + (r & 7))); }

    /* ---------------- VEX / EVEX (map 0F, 128-bit) ---------------- */
    /* pp: 0 none, 1 66, 2 F3, 3 F2.  rmIsReg: rm is an xmm register index. */
    void vexOrEvex(uint8_t op, int pp, int wEvex, int reg, int vvvv, bool rmIsReg, int rm, const Mem *m) {
        bool needEvex = reg >= 16 || vvvv >= 16 || (rmIsReg && rm >= 16);
        int R = (reg >> 3) & 1;
        int vv = vvvv < 0 ? 0 : vvvv;
        if (!needEvex) {
            int X = 0, B = 0;
            if (rmIsReg) B = (rm >> 3) & 1;
            else { X = m->index >= 0 ? (m->index >> 3) & 1 : 0; B = m->base >= 0 ? (m->base >> 3) & 1 : 0; }
            if (!X && !B) {
                b(0xC5);
                b((uint8_t)(((~R & 1) << 7) | ((~vv & 15) << 3) | pp));
            } else {
                b(0xC4);
                b((uint8_t)(((~R & 1) << 7) | ((~X & 1) << 6) | ((~B & 1) << 5) | 1));
                b((uint8_t)(((~vv & 15) << 3) | pp));
            }
            b(op);
            if (rmIsReg) modrmRR(reg, rm);
            else modrmMem(reg, *m);
        } else {
            int Rp = (reg >> 4) & 1;
            int X, B;
            if (rmIsReg) { B = (rm >> 3) & 1; X = (rm >> 4) & 1; }
            else { X = m->index >= 0 ? (m->index >> 3) & 1 : 0; B = m->base >= 0 ? (m->base >> 3) & 1 : 0; }
            int Vp = (vv >> 4) & 1;
            b(0x62);
            b((uint8_t)(((~R & 1) << 7) | ((~X & 1) << 6) | ((~B & 1) << 5) | ((~Rp & 1) << 4) | 1));
            b((uint8_t)((wEvex << 7) | ((~vv & 15) << 3) | 4 | pp));
            b((uint8_t)(((~Vp & 1) << 3)));
            b(op);
            if (rmIsReg) modrmRR(reg, rm);
            else modrmMem(reg, *m, true);
        }
    }
    void vpdRR(uint8_t op, int dst, int src1, int src2) { vexOrEvex(op, 1, 1, dst, src1, true, src2, NULL); }
    void vpdRM(uint8_t op, int dst, int src1, const Mem &m, bool evex) {
        /* force EVEX if any xmm >= 16 */
        (void)evex;
        vexOrEvex(op, 1, 1, dst, src1, false, 0, &m);
    }
    void vaddpd(int d, int s1, int s2) { vpdRR(0x58, d, s1, s2); }
    void vsubpd(int d, int s1, int s2) { vpdRR(0x5C, d, s1, s2); }
    void vmulpd(int d, int s1, int s2) { vpdRR(0x59, d, s1, s2); }
    void vdivpd(int d, int s1, int s2) { vpdRR(0x5E, d, s1, s2); }
    void vandpd(int d, int s1, int s2) { vpdRR(0x54, d, s1, s2); }
    void vorpd(int d, int s1, int s2) { vpdRR(0x56, d, s1, s2); }
    void vxorpd(int d, int s1, int s2) { vpdRR(0x57, d, s1, s2); }
    void vsqrtpd(int d, int s) { vexOrEvex(0x51, 1, 1, d, -1, true, s, NULL); }
    void vshufpd(int d, int s1, int s2, int imm) { vpdRR(0xC6, d, s1, s2); b((uint8_t)imm); }
    void vcvtdq2pdM(int d, const Mem &m) { vexOrEvex(0xE6, 2, 0, d, -1, false, 0, &m); }
    void vmovupdLoad(int d, const Mem &m) { vexOrEvex(0x10, 1, 1, d, -1, false, 0, &m); }
    void vmovupdStore(const Mem &m, int s) { vexOrEvex(0x11, 1, 1, s, -1, false, 0, &m); }
    void vmovapdStore(const Mem &m, int s) { vexOrEvex(0x29, 1, 1, s, -1, false, 0, &m); }

    /* ---------------------------------------------------------------- */
    static int gpr(int r) { return R8 + (r & 7); }
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
        return M(RSI, (int32_t)(instr->imm32 & RX_SPL3_MASK));
    }

    void emitInstr(int L, int i) {
        LaneState &ls = lane[L];
        rx_instruction *instr = &ls.prog->programBuffer[i];
        int op = instr->opcode;
        int dst = instr->dst & 7, src = instr->src & 7;
        int rd = gpr(dst), rs = gpr(src);
        const LaneRegs &x = ls.x;
        ls.instrOffset[i] = pos;

        if (op < RX_CEIL_RX_IADD_RS) {
            ls.regUsage[dst] = i;
            Mem m = MI(rd, rs, (instr->mod >> 2) & 3, 0);
            if (dst == 5) { m.disp = (int32_t)instr->imm32; lea(rd, m); }
            else lea(rd, m);
            /* lea with base r13 and disp 0 is encoded with disp8 automatically */
        } else if (op < RX_CEIL_RX_IADD_M) {
            ls.regUsage[dst] = i;
            aluRM(0x03, rd, intMemOperand(instr));
        } else if (op < RX_CEIL_RX_ISUB_R) {
            ls.regUsage[dst] = i;
            if (src != dst) aluRR(0x2B, rd, rs);
            else aluRI(5, rd, (int32_t)instr->imm32);
        } else if (op < RX_CEIL_RX_ISUB_M) {
            ls.regUsage[dst] = i;
            aluRM(0x2B, rd, intMemOperand(instr));
        } else if (op < RX_CEIL_RX_IMUL_R) {
            ls.regUsage[dst] = i;
            if (src != dst) imulRR(rd, rs);
            else imulRRI(rd, rd, (int32_t)instr->imm32);
        } else if (op < RX_CEIL_RX_IMUL_M) {
            ls.regUsage[dst] = i;
            imulRM(rd, intMemOperand(instr));
        } else if (op < RX_CEIL_RX_IMULH_R) {
            ls.regUsage[dst] = i;
            mov(RAX, rd); unaryR(4, rs); mov(rd, RDX);
        } else if (op < RX_CEIL_RX_IMULH_M) {
            ls.regUsage[dst] = i;
            Mem m = intMemOperand(instr, RCX);
            mov(RAX, rd); unaryM(4, m); mov(rd, RDX);
        } else if (op < RX_CEIL_RX_ISMULH_R) {
            ls.regUsage[dst] = i;
            mov(RAX, rd); unaryR(5, rs); mov(rd, RDX);
        } else if (op < RX_CEIL_RX_ISMULH_M) {
            ls.regUsage[dst] = i;
            Mem m = intMemOperand(instr, RCX);
            mov(RAX, rd); unaryM(5, m); mov(rd, RDX);
        } else if (op < RX_CEIL_RX_IMUL_RCP) {
            uint32_t divisor = instr->imm32;
            if (!is_zero_or_power_of_2(divisor)) {
                ls.regUsage[dst] = i;
                uint64_t rcp = rx_reciprocal(divisor);
                if (g_mjit_rcp_pool && poolCount < MJ_POOL_MAX) {
                    /* imul rd, [rip + disp32] */
                    rex(1, rd, 0, 0); b(0x0F); b(0xAF); b((uint8_t)(0x05 | ((rd & 7) << 3)));
                    fix[fixCount].patchPos = pos; fix[fixCount].index = poolCount; fixCount++;
                    pool[poolCount++] = rcp;
                    d32(0);
                } else {
                    movImm64(RAX, rcp); imulRR(rd, RAX);
                }
            }
        } else if (op < RX_CEIL_RX_INEG_R) {
            ls.regUsage[dst] = i;
            unaryR(3, rd);
        } else if (op < RX_CEIL_RX_IXOR_R) {
            ls.regUsage[dst] = i;
            if (src != dst) aluRR(0x33, rd, rs);
            else aluRI(6, rd, (int32_t)instr->imm32);
        } else if (op < RX_CEIL_RX_IXOR_M) {
            ls.regUsage[dst] = i;
            aluRM(0x33, rd, intMemOperand(instr));
        } else if (op < RX_CEIL_RX_IROR_R) {
            ls.regUsage[dst] = i;
            if (src != dst) { mov32(RCX, rs); shiftCl(1, rd); }
            else { int r = instr->imm32 & 63; if (r) shiftI(1, rd, r); }
        } else if (op < RX_CEIL_RX_IROL_R) {
            ls.regUsage[dst] = i;
            if (src != dst) { mov32(RCX, rs); shiftCl(0, rd); }
            else { int r = instr->imm32 & 63; if (r) shiftI(0, rd, r); }
        } else if (op < RX_CEIL_RX_ISWAP_R) {
            if (src != dst) {
                ls.regUsage[dst] = i;
                ls.regUsage[src] = i;
                xchg(rd, rs);
            }
        } else if (op < RX_CEIL_RX_FSWAP_R) {
            int r = (instr->dst & 7) < 4 ? x.f[instr->dst & 3] : x.e[instr->dst & 3];
            vshufpd(r, r, r, 1);
        } else if (op < RX_CEIL_RX_FADD_R) {
            vaddpd(x.f[instr->dst & 3], x.f[instr->dst & 3], x.a[instr->src & 3]);
        } else if (op < RX_CEIL_RX_FADD_M) {
            addrReg(instr, RAX, memMask(instr));
            vcvtdq2pdM(x.tmp, MI(RSI, RAX));
            vaddpd(x.f[instr->dst & 3], x.f[instr->dst & 3], x.tmp);
        } else if (op < RX_CEIL_RX_FSUB_R) {
            vsubpd(x.f[instr->dst & 3], x.f[instr->dst & 3], x.a[instr->src & 3]);
        } else if (op < RX_CEIL_RX_FSUB_M) {
            addrReg(instr, RAX, memMask(instr));
            vcvtdq2pdM(x.tmp, MI(RSI, RAX));
            vsubpd(x.f[instr->dst & 3], x.f[instr->dst & 3], x.tmp);
        } else if (op < RX_CEIL_RX_FSCAL_R) {
            int r = x.f[instr->dst & 3];
            vxorpd(r, r, scaleMask);
        } else if (op < RX_CEIL_RX_FMUL_R) {
            vmulpd(x.e[instr->dst & 3], x.e[instr->dst & 3], x.a[instr->src & 3]);
        } else if (op < RX_CEIL_RX_FDIV_M) {
            addrReg(instr, RAX, memMask(instr));
            vcvtdq2pdM(x.tmp, MI(RSI, RAX));
            vandpd(x.tmp, x.tmp, mantMask);
            vorpd(x.tmp, x.tmp, x.emask);
            vdivpd(x.e[instr->dst & 3], x.e[instr->dst & 3], x.tmp);
        } else if (op < RX_CEIL_RX_FSQRT_R) {
            int r = x.e[instr->dst & 3];
            vsqrtpd(r, r);
        } else if (op < RX_CEIL_RX_CBRANCH) {
            int reg = dst;
            int target = ls.regUsage[reg] + 1;
            int shift = (instr->mod >> 4) + RX_JUMP_OFFSET;
            uint32_t imm = instr->imm32 | (1u << shift);
            imm &= ~(1u << (shift - 1));
            aluRI(0, rd, (int32_t)imm);
            testRI(rd, (int32_t)(RX_CONDITION_MASK << shift));
            int32_t rel8 = ls.instrOffset[target] - (pos + 2);
            if (rel8 >= -128) {
                b(0x74); b((uint8_t)(int8_t)rel8);
            } else {
                b(0x0F); b(0x84); d32((uint32_t)(ls.instrOffset[target] - (pos + 4)));
            }
            for (int j = 0; j < RX_REGISTERS_COUNT; j++) ls.regUsage[j] = i;
        } else if (op < RX_CEIL_RX_CFROUND) {
            int rot = (13 - (instr->imm32 & 63)) & 63;
            mov(RAX, rs);
            if (rot) shiftI(0, RAX, rot); /* rol rax, rot */
            aluRI(4, RAX, 0x6000, 0);
            aluRI(1, RAX, RX_MXCSR_DEFAULT, 0); /* or eax */
            store32(M(RSP, slot(L, SL_MXCSR)), RAX);
            ldmxcsr(M(RSP, slot(L, SL_MXCSR)));
        } else if (op < RX_CEIL_RX_ISTORE) {
            uint32_t mask = ((instr->mod >> 4) < RX_STORE_L3_COND) ? memMask(instr) : RX_SPL3_MASK;
            lea32(RAX, M(rd, (int32_t)instr->imm32));
            aluRI(4, RAX, (int32_t)mask, 0);
            store(MI(RSI, RAX), rs);
        } else {
            /* NOP */
        }
    }

    void emitHead(int L) {
        LaneState &ls = lane[L];
        const LaneRegs &x = ls.x;
        load(RCX, M(RSP, slot(L, SL_SP0)));
        for (int i = 0; i < 8; i++) aluRM(0x33, R8 + i, M(RCX, 8 * i));
        load(RCX, M(RSP, slot(L, SL_SP1)));
        for (int i = 0; i < 4; i++) vcvtdq2pdM(x.f[i], M(RCX, 8 * i));
        for (int i = 0; i < 4; i++) vcvtdq2pdM(x.e[i], M(RCX, 32 + 8 * i));
        for (int i = 0; i < 4; i++) vandpd(x.e[i], x.e[i], mantMask);
        for (int i = 0; i < 4; i++) vorpd(x.e[i], x.e[i], x.emask);
    }

    void emitTail(int L) {
        LaneState &ls = lane[L];
        const LaneRegs &x = ls.x;
        rx_program_config *cfg = ls.cfg;
        /* rax = r[readReg2] ^ r[readReg3] */
        mov(RAX, gpr(cfg->readReg2));
        aluRR(0x33, RAX, gpr(cfg->readReg3));
        load(RBP, M(RSP, slot(L, SL_MXMA)));
        load(RDI, M(RSP, slot(L, SL_DS)));
        /* dataset read at ma (low 32 bits of rbp) */
        mov32(RCX, RBP);
        aluRI(4, RCX, 0x7FFFFFC0, 0);
        for (int i = 0; i < 8; i++) aluRM(0x33, R8 + i, MI(RDI, RCX, 0, 8 * i));
        /* mx ^= rax; prefetch dataset[mx]; swap */
        mov32(RCX, RAX);
        shiftI(1, RBP, 32);            /* ror rbp, 32 */
        aluRR(0x33, RBP, RCX);
        mov32(RAX, RBP);
        aluRI(4, RAX, 0x7FFFFFC0, 0);
        prefetch(0, MI(RDI, RAX));
        store(M(RSP, slot(L, SL_MXMA)), RBP);
        /* store integer registers to spAddr1 */
        load(RCX, M(RSP, slot(L, SL_SP1)));
        for (int i = 0; i < 8; i++) store(M(RCX, 8 * i), R8 + i);
        /* f ^= e; store to spAddr0 */
        load(RCX, M(RSP, slot(L, SL_SP0)));
        for (int i = 0; i < 4; i++) vxorpd(x.f[i], x.f[i], x.e[i]);
        for (int i = 0; i < 4; i++) vmovapdStore(M(RCX, 16 * i), x.f[i]);
        /* next iteration's scratchpad addresses */
        mov(RAX, gpr(cfg->readReg0));
        aluRR(0x33, RAX, gpr(cfg->readReg1));
        mov(RDX, RAX);
        shiftI(1, RDX, 32);            /* ror rdx, 32 */
        aluRI(4, RAX, RX_SPL3_MASK64, 0);
        aluRI(4, RDX, RX_SPL3_MASK64, 0);
        aluRR(0x03, RAX, RSI);
        aluRR(0x03, RDX, RSI);
        if (g_mjit_prefetch_mode) {
            prefetch(1, M(RAX));
            prefetch(1, M(RDX));
        }
        store(M(RSP, slot(L, SL_SP0)), RAX);
        store(M(RSP, slot(L, SL_SP1)), RDX);
    }

    void emitSwitch(int from, int to) {
        if (from == to) return;
        for (int i = 0; i < 8; i++) store(M(RSP, slot(from, SL_R + 8 * i)), R8 + i);
        for (int i = 0; i < 8; i++) load(R8 + i, M(RSP, slot(to, SL_R + 8 * i)));
        load(RSI, M(RSP, slot(to, SL_SPB)));
        if (g_mjit_mxcsr_skip) {
            load32(RAX, M(RSP, slot(to, SL_MXCSR)));
            rex(0, RAX, 0, RSP); b(0x3B); modrmMem(RAX, M(RSP, slot(from, SL_MXCSR))); /* cmp eax, [from] */
            b(0x74); int patch = pos; b(0);
            ldmxcsr(M(RSP, slot(to, SL_MXCSR)));
            code[patch] = (uint8_t)(pos - (patch + 1));
        } else {
            ldmxcsr(M(RSP, slot(to, SL_MXCSR)));
        }
    }

    void splitSegments(int L, int G) {
        LaneState &ls = lane[L];
        ls.nseg = 0;
        int start = 0;
        ls.segStart[ls.nseg++] = 0;
        for (int i = 0; i < RX_PROGRAM_SIZE; i++) {
            int op = ls.prog->programBuffer[i].opcode;
            bool isBranch = op >= RX_CEIL_RX_FSQRT_R && op < RX_CEIL_RX_CBRANCH;
            if (isBranch && i + 1 < RX_PROGRAM_SIZE && (i + 1 - start) >= G) {
                start = i + 1;
                ls.segStart[ls.nseg++] = start;
            }
        }
        ls.segStart[ls.nseg] = RX_PROGRAM_SIZE;
    }

    void setupLaneRegs(int L) {
        LaneRegs &x = lane[L].x;
        int base = L == 0 ? 0 : 16;
        for (int i = 0; i < 4; i++) {
            x.f[i] = base + i;
            x.e[i] = base + 4 + i;
            x.a[i] = base + 8 + i;
        }
        x.tmp = base + 12;
        x.emask = base + 14;
        lane[L].slot = FR_LANE0 + L * FR_LANE_SIZE;
    }

    int generate(int K_, rx_program **progs, rx_program_config **cfgs) {
        K = K_;
        pos = 0;
        poolCount = 0;
        fixCount = 0;
        mantMask = 13;
        scaleMask = 15;
        for (int L = 0; L < K; L++) {
            lane[L].prog = progs[L];
            lane[L].cfg = cfgs[L];
            for (int r = 0; r < RX_REGISTERS_COUNT; r++) lane[L].regUsage[r] = -1;
            setupLaneRegs(L);
            splitSegments(L, g_mjit_granularity < 1 ? 1 : g_mjit_granularity);
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

        vmovupdLoad(mantMask, M(RCX, offsetof(rx_multi_params, mantMask)));
        vmovupdLoad(scaleMask, M(RCX, offsetof(rx_multi_params, scaleMask)));
        for (int L = 0; L < K; L++) {
            const LaneRegs &x = lane[L].x;
            int lp = (int)(offsetof(rx_multi_params, lane) + L * sizeof(rx_lane_params));
            load(RDX, M(RCX, lp + (int)offsetof(rx_lane_params, reg)));
            for (int i = 0; i < 4; i++) vmovupdLoad(x.a[i], M(RDX, (int)offsetof(rx_register_file, a) + 16 * i));
            vmovupdLoad(x.emask, M(RCX, lp + (int)offsetof(rx_lane_params, eMask)));
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
            aluRI(4, RDX, 0x7FFFFFC0, 0);
            prefetch(0, MI(RDI, RDX));
            /* spAddr0 = mx, spAddr1 = ma */
            mov(RDX, RAX);
            shiftI(5, RDX, 32);          /* shr rdx, 32 */
            aluRI(4, RAX, RX_SPL3_MASK64, 0);
            aluRI(4, RDX, RX_SPL3_MASK64, 0);
            aluRR(0x03, RAX, RSI);
            aluRR(0x03, RDX, RSI);
            store(M(RSP, slot(L, SL_SP0)), RAX);
            store(M(RSP, slot(L, SL_SP1)), RDX);
            load32(RAX, M(RCX, lp + (int)offsetof(rx_lane_params, mxcsr)));
            store32(M(RSP, slot(L, SL_MXCSR)), RAX);
            for (int i = 0; i < 8; i++) storeImm32(M(RSP, slot(L, SL_R + 8 * i)), 0);
        }
        load32(RBX, M(RCX, offsetof(rx_multi_params, iterations)));
        for (int i = 0; i < 8; i++) aluRR(0x33, R8 + i, R8 + i);

        /* ---- schedule: round-robin over segments ---- */
        int schedLane[RX_MULTI_MAX_LANES * (RX_PROGRAM_SIZE + 1)];
        int schedSeg[RX_MULTI_MAX_LANES * (RX_PROGRAM_SIZE + 1)];
        int nsched = 0;
        int maxSeg = 0;
        for (int L = 0; L < K; L++) if (lane[L].nseg > maxSeg) maxSeg = lane[L].nseg;
        for (int s = 0; s < maxSeg; s++)
            for (int L = 0; L < K; L++)
                if (s < lane[L].nseg) { schedLane[nsched] = L; schedSeg[nsched] = s; nsched++; }
        int lastLane = schedLane[nsched - 1];
        /* entering the loop: registers hold zeros = "lastLane" state */
        load(RSI, M(RSP, slot(lastLane, SL_SPB)));
        ldmxcsr(M(RSP, slot(lastLane, SL_MXCSR)));

        /* align loop start */
        while (pos & 15) b(0x90);
        int loopStart = pos;
        int cur = lastLane;
        for (int n = 0; n < nsched; n++) {
            int L = schedLane[n], s = schedSeg[n];
            emitSwitch(cur, L);
            cur = L;
            if (s == 0) emitHead(L);
            for (int i = lane[L].segStart[s]; i < lane[L].segStart[s + 1]; i++)
                emitInstr(L, i);
            if (s == lane[L].nseg - 1) emitTail(L);
        }
        /* dec ebx; jnz loopStart */
        rex(0, 0, 0, RBX); b(0xFF); modrmRR(1, RBX);
        b(0x0F); b(0x85); d32((uint32_t)(loopStart - (pos + 4)));

        /* ---- epilogue ---- */
        for (int i = 0; i < 8; i++) store(M(RSP, slot(cur, SL_R + 8 * i)), R8 + i);
        load(RCX, M(RSP, FR_PARAMS));
        for (int L = 0; L < K; L++) {
            const LaneRegs &x = lane[L].x;
            int lp = (int)(offsetof(rx_multi_params, lane) + L * sizeof(rx_lane_params));
            load(RDX, M(RCX, lp + (int)offsetof(rx_lane_params, reg)));
            for (int i = 0; i < 8; i++) {
                load(RAX, M(RSP, slot(L, SL_R + 8 * i)));
                store(M(RDX, 8 * i), RAX);
            }
            for (int i = 0; i < 4; i++) vmovupdStore(M(RDX, (int)offsetof(rx_register_file, f) + 16 * i), x.f[i]);
            for (int i = 0; i < 4; i++) vmovupdStore(M(RDX, (int)offsetof(rx_register_file, e) + 16 * i), x.e[i]);
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

int rx_mjit_generate(rx_mjit *m, int K, rx_program **progs, rx_program_config **cfgs) {
    if (K < 1 || K > 2) return -1;
    return m->j->generate(K, progs, cfgs);
}

void *rx_mjit_code(rx_mjit *m) { return m->j->code; }

}
