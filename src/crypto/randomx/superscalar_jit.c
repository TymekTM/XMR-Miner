#include "randomx_internal.h"
#include <string.h>
#include <stdlib.h>
#include "common/vmem.h"

#define SSJIT_CODE_SIZE 8192

#define REG_RAX  0
#define REG_RCX  1
#define REG_RDX  2
#define REG_RBX  3
#define REG_RSP  4
#define REG_RBP  5
#define REG_RDI  7
#define REG_R8   8
#define REG_R9   9
#define REG_R10  10
#define REG_R11  11
#define REG_R12  12

static const int REG_MAP[8] = {
    REG_RAX, REG_RCX, REG_R8, REG_R9,
    REG_R10, REG_R11, REG_R12, REG_RBX
};

typedef struct {
    uint8_t *code;
    size_t pos;
} ssjit_emitter;

static void eb(ssjit_emitter *e, uint8_t b) { e->code[e->pos++] = b; }
static void eu32(ssjit_emitter *e, uint32_t v) { memcpy(e->code + e->pos, &v, 4); e->pos += 4; }
static void eu64(ssjit_emitter *e, uint64_t v) { memcpy(e->code + e->pos, &v, 8); e->pos += 8; }

static void erex(ssjit_emitter *e, int w, int r, int x, int b) {
    eb(e, (uint8_t)(0x40 | (w ? 8 : 0) | (r ? 4 : 0) | (x ? 2 : 0) | (b ? 1 : 0)));
}

static void erex_rb(ssjit_emitter *e, int reg, int rm) {
    erex(e, 1, (reg >> 3) & 1, 0, (rm >> 3) & 1);
}

static void emodrm(ssjit_emitter *e, int reg, int rm) {
    eb(e, (uint8_t)(0xC0 | ((reg & 7) << 3) | (rm & 7)));
}

static void epush(ssjit_emitter *e, int r) {
    if (r >= 8) eb(e, 0x41);
    eb(e, (uint8_t)(0x50 + (r & 7)));
}

static void epop(ssjit_emitter *e, int r) {
    if (r >= 8) eb(e, 0x41);
    eb(e, (uint8_t)(0x58 + (r & 7)));
}

static void emov_rr(ssjit_emitter *e, int d, int s) {
    erex_rb(e, s, d);
    eb(e, 0x89);
    emodrm(e, s, d);
}

static void emov_ri64(ssjit_emitter *e, int reg, uint64_t imm) {
    erex(e, 1, (reg >> 3) & 1, 0, (reg >> 3) & 1);
    eb(e, (uint8_t)(0xB8 + (reg & 7)));
    eu64(e, imm);
}

static void emov_rm(ssjit_emitter *e, int reg, int base, int disp) {
    erex_rb(e, reg, base);
    eb(e, 0x8B);
    if (disp == 0 && (base & 7) != 5) {
        eb(e, (uint8_t)(((reg & 7) << 3) | (base & 7)));
    } else if (disp >= -128 && disp <= 127) {
        eb(e, (uint8_t)(0x40 | ((reg & 7) << 3) | (base & 7)));
        eb(e, (uint8_t)(int8_t)disp);
    } else {
        eb(e, (uint8_t)(0x80 | ((reg & 7) << 3) | (base & 7)));
        eu32(e, (uint32_t)disp);
    }
}

static void emov_mr(ssjit_emitter *e, int base, int disp, int reg) {
    erex_rb(e, reg, base);
    eb(e, 0x89);
    if (disp == 0 && (base & 7) != 5) {
        eb(e, (uint8_t)(((reg & 7) << 3) | (base & 7)));
    } else if (disp >= -128 && disp <= 127) {
        eb(e, (uint8_t)(0x40 | ((reg & 7) << 3) | (base & 7)));
        eb(e, (uint8_t)(int8_t)disp);
    } else {
        eb(e, (uint8_t)(0x80 | ((reg & 7) << 3) | (base & 7)));
        eu32(e, (uint32_t)disp);
    }
}

static void eadd_rr(ssjit_emitter *e, int d, int s) {
    erex_rb(e, s, d); eb(e, 0x01); emodrm(e, s, d);
}

static void esub_rr(ssjit_emitter *e, int d, int s) {
    erex_rb(e, s, d); eb(e, 0x29); emodrm(e, s, d);
}

static void exor_rr(ssjit_emitter *e, int d, int s) {
    erex_rb(e, s, d); eb(e, 0x31); emodrm(e, s, d);
}

static void eimul_rr(ssjit_emitter *e, int d, int s) {
    erex_rb(e, d, s); eb(e, 0x0F); eb(e, 0xAF); emodrm(e, d, s);
}

static void eror_ri(ssjit_emitter *e, int d, uint8_t imm) {
    erex_rb(e, 0, d); eb(e, 0xC1); emodrm(e, 1, d); eb(e, imm);
}

static void eadd_ri32(ssjit_emitter *e, int d, int32_t imm) {
    erex_rb(e, 0, d); eb(e, 0x81); emodrm(e, 0, d); eu32(e, (uint32_t)imm);
}

static void exor_ri32(ssjit_emitter *e, int d, int32_t imm) {
    erex_rb(e, 0, d); eb(e, 0x81); emodrm(e, 6, d); eu32(e, (uint32_t)imm);
}

static void elea_sib(ssjit_emitter *e, int dst, int src, int shift) {
    erex(e, 1, (dst >> 3) & 1, (src >> 3) & 1, (dst >> 3) & 1);
    eb(e, 0x8D);
    eb(e, (uint8_t)(0x04 | ((dst & 7) << 3)));
    eb(e, (uint8_t)(((shift & 3) << 6) | ((src & 7) << 3) | (dst & 7)));
}

static void eprologue(ssjit_emitter *e) {
    epush(e, REG_RBP);
    epush(e, REG_RDI);
    epush(e, REG_RBX);
    epush(e, REG_R12);
    emov_rr(e, REG_RBP, REG_RCX);
    emov_rm(e, REG_RAX, REG_RBP, 0);
    emov_rm(e, REG_RCX, REG_RBP, 8);
    emov_rm(e, REG_R8,  REG_RBP, 16);
    emov_rm(e, REG_R9,  REG_RBP, 24);
    emov_rm(e, REG_R10, REG_RBP, 32);
    emov_rm(e, REG_R11, REG_RBP, 40);
    emov_rm(e, REG_R12, REG_RBP, 48);
    emov_rm(e, REG_RBX, REG_RBP, 56);
}

static void eepilogue(ssjit_emitter *e) {
    emov_mr(e, REG_RBP, 0,  REG_RAX);
    emov_mr(e, REG_RBP, 8,  REG_RCX);
    emov_mr(e, REG_RBP, 16, REG_R8);
    emov_mr(e, REG_RBP, 24, REG_R9);
    emov_mr(e, REG_RBP, 32, REG_R10);
    emov_mr(e, REG_RBP, 40, REG_R11);
    emov_mr(e, REG_RBP, 48, REG_R12);
    emov_mr(e, REG_RBP, 56, REG_RBX);
    epop(e, REG_R12);
    epop(e, REG_RBX);
    epop(e, REG_RDI);
    epop(e, REG_RBP);
    eb(e, 0xC3);
}

static void eimulh_r(ssjit_emitter *e, int dst, int src) {
    int rd = REG_MAP[dst];
    int rs = REG_MAP[src];

    if (rd == REG_RAX) {
        erex_rb(e, 0, rs); eb(e, 0xF7); emodrm(e, 4, rs);
        emov_rr(e, REG_RAX, REG_RDX);
    } else {
        epush(e, REG_RAX);
        emov_rr(e, REG_RAX, rd);
        if (rs == REG_RAX) {
            erex(e, 1, 0, 0, 0);
            eb(e, 0xF7);
            eb(e, 0x64);
            eb(e, 0x24);
            eb(e, 0x00);
        } else {
            erex_rb(e, 0, rs); eb(e, 0xF7); emodrm(e, 4, rs);
        }
        emov_rr(e, rd, REG_RDX);
        epop(e, REG_RAX);
    }
}

static void eismulh_r(ssjit_emitter *e, int dst, int src) {
    int rd = REG_MAP[dst];
    int rs = REG_MAP[src];
    if (rd == REG_RAX) {
        erex_rb(e, 0, rs);
        eb(e, 0xF7);
        emodrm(e, 5, rs);
        emov_rr(e, REG_RAX, REG_RDX);
    } else {
        epush(e, REG_RAX);
        emov_rr(e, REG_RAX, rd);
        if (rs == REG_RAX) {
            erex_rb(e, 0, REG_RSP);
            eb(e, 0xF7);
            eb(e, 0x6C);
            eb(e, 0x24);
            eb(e, 0x00);
        } else {
            erex_rb(e, 0, rs);
            eb(e, 0xF7);
            emodrm(e, 5, rs);
        }
        emov_rr(e, rd, REG_RDX);
        epop(e, REG_RAX);
    }
}

static void emit_instruction(ssjit_emitter *e, const rx_instruction *instr, const uint64_t *reciprocals) {
    int dst = instr->dst % 8;
    int src = instr->src % 8;
    int rd = REG_MAP[dst];
    int rs = REG_MAP[src];

    switch (instr->opcode) {
    case RX_SS_ISUB_R:
        esub_rr(e, rd, rs);
        break;
    case RX_SS_IXOR_R:
        exor_rr(e, rd, rs);
        break;
    case RX_SS_IADD_RS: {
        uint32_t shift = (instr->mod >> 2) & 3;
        if (shift == 0) {
            eadd_rr(e, rd, rs);
        } else {
            elea_sib(e, rd, rs, shift);
        }
        break;
    }
    case RX_SS_IMUL_R:
        eimul_rr(e, rd, rs);
        break;
    case RX_SS_IROR_C:
        eror_ri(e, rd, (uint8_t)instr->imm32);
        break;
    case RX_SS_IADD_C7:
    case RX_SS_IADD_C8:
    case RX_SS_IADD_C9:
        eadd_ri32(e, rd, (int32_t)instr->imm32);
        break;
    case RX_SS_IXOR_C7:
    case RX_SS_IXOR_C8:
    case RX_SS_IXOR_C9:
        exor_ri32(e, rd, (int32_t)instr->imm32);
        break;
    case RX_SS_IMULH_R:
        eimulh_r(e, dst, src);
        break;
    case RX_SS_ISMULH_R:
        eismulh_r(e, dst, src);
        break;
    case RX_SS_IMUL_RCP: {
        uint32_t idx = instr->imm32;
        uint64_t rcp = reciprocals ? reciprocals[idx] : 0;
        emov_ri64(e, REG_RDX, rcp);
        eimul_rr(e, rd, REG_RDX);
        break;
    }
    }
}

void ss_jit_compile(rx_superscalar_program *prog, const uint64_t *reciprocals) {
    uint8_t *code = (uint8_t *)vmem_alloc(SSJIT_CODE_SIZE, VMEM_EXEC, NULL);
    if (!code) return;

    ssjit_emitter em;
    em.code = code;
    em.pos = 0;

    eprologue(&em);

    for (uint32_t i = 0; i < prog->size; i++) {
        emit_instruction(&em, &prog->buffer[i], reciprocals);
    }

    eepilogue(&em);

    vmem_protect_rx(code, SSJIT_CODE_SIZE);

    prog->code = code;
    prog->fn = (void (RX_JIT_ABI *)(uint64_t *))code;
}

void ss_jit_free(rx_superscalar_program *prog) {
    if (prog->code) {
        vmem_free(prog->code);
        prog->code = NULL;
        prog->fn = NULL;
    }
}
