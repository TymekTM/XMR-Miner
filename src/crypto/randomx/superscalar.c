#include "randomx_internal.h"
#include "crypto/blake2/blake2_generator.h"
#include <string.h>
#include <stdlib.h>

#define SS_ISUB_R    0
#define SS_IXOR_R    1
#define SS_IADD_RS   2
#define SS_IMUL_R    3
#define SS_IROR_C    4
#define SS_IADD_C7   5
#define SS_IXOR_C7   6
#define SS_IADD_C8   7
#define SS_IXOR_C8   8
#define SS_IADD_C9   9
#define SS_IXOR_C9   10
#define SS_IMULH_R   11
#define SS_ISMULH_R  12
#define SS_IMUL_RCP  13
#define SS_COUNT     14

#define EP_NULL  0
#define EP_P0    1
#define EP_P1    2
#define EP_P5    4
#define EP_P01   (EP_P0 | EP_P1)
#define EP_P05   (EP_P0 | EP_P5)
#define EP_P015  (EP_P0 | EP_P1 | EP_P5)

#define CYCLE_MAP_SIZE    (RX_SUPERSCALAR_LATENCY + 4)
#define LOOK_FORWARD       4
#define MAX_THROWAWAY      256
#define NUM_REGISTERS     8

typedef struct {
    int size;
    int latency;
    int uop1;
    int uop2;
    int dep;
} ss_macroop;

static const ss_macroop mop_add_rr   = {3, 1, EP_P015, EP_NULL, 0};
static const ss_macroop mop_sub_rr   = {3, 1, EP_P015, EP_NULL, 0};
static const ss_macroop mop_xor_rr   = {3, 1, EP_P015, EP_NULL, 0};
static const ss_macroop mop_imul_rr  = {4, 3, EP_P1, EP_NULL, 0};
static const ss_macroop mop_lea_sib  = {4, 1, EP_P01, EP_NULL, 0};
static const ss_macroop mop_ror_ri  = {4, 1, EP_P05, EP_NULL, 0};
static const ss_macroop mop_add_ri   = {7, 1, EP_P015, EP_NULL, 0};
static const ss_macroop mop_xor_ri   = {7, 1, EP_P015, EP_NULL, 0};
static const ss_macroop mop_mov_ri64 = {10, 1, EP_P015, EP_NULL, 0};
static const ss_macroop mop_mov_rr   = {3, 0, EP_NULL, EP_NULL, 0};
static const ss_macroop mop_mul_r    = {3, 4, EP_P1, EP_P5, 0};

static const ss_macroop imulh_ops[3] = {{3, 0, EP_NULL, EP_NULL, 0}, {3, 4, EP_P1, EP_P5, 0}, {3, 0, EP_NULL, EP_NULL, 0}};
static const ss_macroop ismulh_ops[3] = {{3, 0, EP_NULL, EP_NULL, 0}, {3, 4, EP_P1, EP_P5, 0}, {3, 0, EP_NULL, EP_NULL, 0}};
static const ss_macroop imulrcp_ops[2] = {{10, 1, EP_P015, EP_NULL, 0}, {4, 3, EP_P1, EP_NULL, 1}};

typedef struct {
    int type;
    int size;
    int latency;
    int resultOp;
    int dstOp;
    int srcOp;
    const ss_macroop *ops;
    int numOps;
} ss_instr_info;

static const ss_instr_info info_isub_r  = {SS_ISUB_R,  3, 1, 0, 0, 0, &mop_sub_rr, 1};
static const ss_instr_info info_ixor_r  = {SS_IXOR_R,  3, 1, 0, 0, 0, &mop_xor_rr, 1};
static const ss_instr_info info_iadd_rs = {SS_IADD_RS, 4, 1, 0, 0, 0, &mop_lea_sib, 1};
static const ss_instr_info info_imul_r  = {SS_IMUL_R,  4, 3, 0, 0, 0, &mop_imul_rr, 1};
static const ss_instr_info info_ror_c   = {SS_IROR_C,  4, 1, 0, 0, -1, &mop_ror_ri, 1};
static const ss_instr_info info_iadd_c7 = {SS_IADD_C7, 7, 1, 0, 0, -1, &mop_add_ri, 1};
static const ss_instr_info info_ixor_c7 = {SS_IXOR_C7, 7, 1, 0, 0, -1, &mop_xor_ri, 1};
static const ss_instr_info info_iadd_c8 = {SS_IADD_C8, 8, 1, 0, 0, -1, &mop_add_ri, 1};
static const ss_instr_info info_ixor_c8 = {SS_IXOR_C8, 8, 1, 0, 0, -1, &mop_xor_ri, 1};
static const ss_instr_info info_iadd_c9 = {SS_IADD_C9, 9, 1, 0, 0, -1, &mop_add_ri, 1};
static const ss_instr_info info_ixor_c9 = {SS_IXOR_C9, 9, 1, 0, 0, -1, &mop_xor_ri, 1};
static const ss_instr_info info_imulh_r  = {SS_IMULH_R,  9, 3, 1, 0, 1, imulh_ops, 3};
static const ss_instr_info info_ismulh_r = {SS_ISMULH_R, 9, 3, 1, 0, 1, ismulh_ops, 3};
static const ss_instr_info info_imul_rcp = {SS_IMUL_RCP, 14, 4, 1, 1, -1, imulrcp_ops, 2};

static const ss_instr_info info_nop = {-1, 0, 0, -1, -1, -1, NULL, 0};

static const ss_instr_info *slot3[]  = { &info_isub_r, &info_ixor_r };
static const ss_instr_info *slot3L[] = { &info_isub_r, &info_ixor_r, &info_imulh_r, &info_ismulh_r };
static const ss_instr_info *slot4[]  = { &info_ror_c, &info_iadd_rs };
static const ss_instr_info *slot7[]  = { &info_ixor_c7, &info_iadd_c7 };
static const ss_instr_info *slot8[]  = { &info_ixor_c8, &info_iadd_c8 };
static const ss_instr_info *slot9[]  = { &info_ixor_c9, &info_iadd_c9 };
static const ss_instr_info *slot10 = &info_imul_rcp;

static int is_mul(int type) {
    return type == SS_IMUL_R || type == SS_IMULH_R || type == SS_ISMULH_R || type == SS_IMUL_RCP;
}

typedef struct {
    int counts[4];
    int size;
    int index;
} ss_decode_buffer;

static const ss_decode_buffer db_484  = {{4, 8, 4}, 3, 0};
static const ss_decode_buffer db_7333 = {{7, 3, 3, 3}, 4, 1};
static const ss_decode_buffer db_3733 = {{3, 7, 3, 3}, 4, 2};
static const ss_decode_buffer db_493  = {{4, 9, 3}, 3, 3};
static const ss_decode_buffer db_4444 = {{4, 4, 4, 4}, 4, 4};
static const ss_decode_buffer db_3310 = {{3, 3, 10}, 3, 5};

static const ss_decode_buffer *default_buffers[] = { &db_484, &db_7333, &db_3733, &db_493 };

static const ss_decode_buffer *fetch_next(const ss_decode_buffer *cur, int instrType, int cycle, int mulCount, blake2_gen *gen) {
    if (instrType == SS_IMULH_R || instrType == SS_ISMULH_R)
        return &db_3310;
    if (mulCount < cycle + 1)
        return &db_4444;
    if (instrType == SS_IMUL_RCP)
        return (gen_get_byte(gen) & 1) ? &db_484 : &db_493;
    return default_buffers[gen_get_byte(gen) & 3];
}

typedef struct {
    int latency;
    int lastOpGroup;
    int lastOpPar;
    int value;
} ss_reg_info;

typedef struct {
    int type;
    int src;
    int dst;
    int mod;
    uint32_t imm32;
    int opGroup;
    int opGroupPar;
    int canReuse;
    int groupParIsSource;
    const ss_instr_info *info;
} ss_instruction;

static void ss_instr_reset(ss_instruction *instr) {
    instr->src = -1;
    instr->dst = -1;
    instr->canReuse = 0;
    instr->groupParIsSource = 0;
}

static void ss_instr_create(ss_instruction *instr, const ss_instr_info *info, blake2_gen *gen) {
    instr->info = info;
    ss_instr_reset(instr);
    instr->type = -1;
    instr->mod = 0;
    instr->imm32 = 0;
    instr->opGroup = -1;
    instr->opGroupPar = -1;
    instr->canReuse = 0;
    instr->groupParIsSource = 0;

    switch (info->type) {
    case SS_ISUB_R:
        instr->opGroup = SS_IADD_RS;
        instr->groupParIsSource = 1;
        break;
    case SS_IXOR_R:
        instr->opGroup = SS_IXOR_R;
        instr->groupParIsSource = 1;
        break;
    case SS_IADD_RS:
        instr->mod = gen_get_byte(gen);
        instr->opGroup = SS_IADD_RS;
        instr->groupParIsSource = 1;
        break;
    case SS_IMUL_R:
        instr->opGroup = SS_IMUL_R;
        instr->groupParIsSource = 1;
        break;
    case SS_IROR_C:
        do { instr->imm32 = gen_get_byte(gen) & 63; } while (instr->imm32 == 0);
        instr->opGroup = SS_IROR_C;
        instr->opGroupPar = -1;
        break;
    case SS_IADD_C7:
    case SS_IADD_C8:
    case SS_IADD_C9:
        instr->imm32 = gen_get_uint32(gen);
        instr->opGroup = SS_IADD_C7;
        instr->opGroupPar = -1;
        break;
    case SS_IXOR_C7:
    case SS_IXOR_C8:
    case SS_IXOR_C9:
        instr->imm32 = gen_get_uint32(gen);
        instr->opGroup = SS_IXOR_C7;
        instr->opGroupPar = -1;
        break;
    case SS_IMULH_R:
        instr->canReuse = 1;
        instr->opGroupPar = gen_get_uint32(gen);
        instr->opGroup = SS_IMULH_R;
        break;
    case SS_ISMULH_R:
        instr->canReuse = 1;
        instr->opGroupPar = gen_get_uint32(gen);
        instr->opGroup = SS_ISMULH_R;
        break;
    case SS_IMUL_RCP:
        do { instr->imm32 = gen_get_uint32(gen); } while (is_zero_or_power_of_2(instr->imm32));
        instr->opGroup = SS_IMUL_RCP;
        instr->opGroupPar = -1;
        break;
    }
    instr->type = info->type;
}

static void ss_instr_create_for_slot(ss_instruction *instr, blake2_gen *gen, int slotSize, int fetchType, int isLast, int isFirst) {
    switch (slotSize) {
    case 3:
        if (isLast)
            ss_instr_create(instr, slot3L[gen_get_byte(gen) & 3], gen);
        else
            ss_instr_create(instr, slot3[gen_get_byte(gen) & 1], gen);
        break;
    case 4:
        if (fetchType == 4 && !isLast)
            ss_instr_create(instr, &info_imul_r, gen);
        else
            ss_instr_create(instr, slot4[gen_get_byte(gen) & 1], gen);
        break;
    case 7:
        ss_instr_create(instr, slot7[gen_get_byte(gen) & 1], gen);
        break;
    case 8:
        ss_instr_create(instr, slot8[gen_get_byte(gen) & 1], gen);
        break;
    case 9:
        ss_instr_create(instr, slot9[gen_get_byte(gen) & 1], gen);
        break;
    case 10:
        ss_instr_create(instr, slot10, gen);
        break;
    }
}

static int ss_select_dst(ss_instruction *instr, int cycle, int allowChainedMul, ss_reg_info *regs, blake2_gen *gen) {
    int avail[8];
    int numAvail = 0;
    for (int i = 0; i < NUM_REGISTERS; i++) {
        if (regs[i].latency <= cycle &&
            (instr->canReuse || i != instr->src) &&
            (allowChainedMul || instr->opGroup != SS_IMUL_R || regs[i].lastOpGroup != SS_IMUL_R) &&
            (regs[i].lastOpGroup != instr->opGroup || regs[i].lastOpPar != instr->opGroupPar) &&
            (instr->type != SS_IADD_RS || i != 5))
            avail[numAvail++] = i;
    }
    if (numAvail == 0) return 0;
    if (numAvail == 1) { instr->dst = avail[0]; return 1; }
    instr->dst = avail[gen_get_uint32(gen) % numAvail];
    return 1;
}

static int ss_select_src(ss_instruction *instr, int cycle, ss_reg_info *regs, blake2_gen *gen) {
    int avail[8];
    int numAvail = 0;
    for (int i = 0; i < NUM_REGISTERS; i++) {
        if (regs[i].latency <= cycle)
            avail[numAvail++] = i;
    }
    if (numAvail == 2 && instr->info->type == SS_IADD_RS) {
        if (avail[0] == 5 || avail[1] == 5) {
            instr->opGroupPar = instr->src = 5;
            return 1;
        }
    }
    if (numAvail == 0) return 0;
    if (numAvail == 1) { instr->src = avail[0]; if (instr->groupParIsSource) instr->opGroupPar = instr->src; return 1; }
    instr->src = avail[gen_get_uint32(gen) % numAvail];
    if (instr->groupParIsSource) instr->opGroupPar = instr->src;
    return 1;
}

static void ss_instr_to_native(const ss_instruction *instr, rx_instruction *out) {
    out->opcode = (u8)instr->type;
    out->dst = (u8)instr->dst;
    out->src = (u8)(instr->src >= 0 ? instr->src : instr->dst);
    out->mod = (u8)instr->mod;
    write_u32_le((u8 *)&out->imm32, instr->imm32);
}

static int schedule_uop(int commit, int uop, int portBusy[CYCLE_MAP_SIZE][3], int cycle) {
    for (; cycle < CYCLE_MAP_SIZE; ++cycle) {
        if ((uop & EP_P5) && !portBusy[cycle][2]) {
            if (commit) portBusy[cycle][2] = uop;
            return cycle;
        }
        if ((uop & EP_P0) && !portBusy[cycle][0]) {
            if (commit) portBusy[cycle][0] = uop;
            return cycle;
        }
        if ((uop & EP_P1) && !portBusy[cycle][1]) {
            if (commit) portBusy[cycle][1] = uop;
            return cycle;
        }
    }
    return -1;
}

static int schedule_mop(int commit, const ss_macroop *mop, int portBusy[CYCLE_MAP_SIZE][3], int cycle, int depCycle) {
    if (mop->dep) {
        if (depCycle > cycle)
            cycle = depCycle;
    }
    if (mop->uop2 != EP_NULL) {
        for (; cycle < CYCLE_MAP_SIZE; ++cycle) {
            int c1 = schedule_uop(0, mop->uop1, portBusy, cycle);
            int c2 = schedule_uop(0, mop->uop2, portBusy, cycle);
            if (c1 >= 0 && c1 == c2) {
                if (commit) {
                    schedule_uop(1, mop->uop1, portBusy, c1);
                    schedule_uop(1, mop->uop2, portBusy, c2);
                }
                return c1;
            }
        }
        return -1;
    }
    if (mop->uop1 != EP_NULL)
        return schedule_uop(commit, mop->uop1, portBusy, cycle);
    return cycle;
}

void generate_superscalar(rx_superscalar_program *prog, blake2_gen *gen) {
    int portBusy[CYCLE_MAP_SIZE][3];
    memset(portBusy, 0, sizeof(portBusy));
    ss_reg_info regs[NUM_REGISTERS];
    memset(regs, 0, sizeof(regs));

    const ss_decode_buffer *db = &db_484;
    ss_instruction cur;
    memset(&cur, 0, sizeof(cur));
    cur.info = &info_nop;
    int mopIdx = 0;
    int codeSize = 0;
    int macroOpCount = 0;
    int cycle = 0;
    int depCycle = 0;
    int retireCycle = 0;
    int portsSaturated = 0;
    int programSize = 0;
    int mulCount = 0;
    int decodeCycle;
    int throwAwayCount = 0;

    for (decodeCycle = 0; decodeCycle < RX_SUPERSCALAR_LATENCY && !portsSaturated && programSize < RX_SUPERSCALAR_MAX_SIZE; ++decodeCycle) {
        db = fetch_next(db, cur.type, decodeCycle, mulCount, gen);

        int bufIdx = 0;
        while (bufIdx < db->size) {
            int topCycle = cycle;

            if (mopIdx >= cur.info->numOps) {
                if (portsSaturated || programSize >= RX_SUPERSCALAR_MAX_SIZE)
                    break;
                ss_instr_create_for_slot(&cur, gen, db->counts[bufIdx], db->index, db->size == bufIdx + 1, bufIdx == 0);
                mopIdx = 0;
            }

            const ss_macroop *mop = &cur.info->ops[mopIdx];
            int scheduleCycle = schedule_mop(0, mop, portBusy, cycle, depCycle);
            if (scheduleCycle < 0) {
                portsSaturated = 1;
                break;
            }

            if (mopIdx == cur.info->srcOp) {
                int forward;
                for (forward = 0; forward < LOOK_FORWARD && !ss_select_src(&cur, scheduleCycle, regs, gen); ++forward) {
                    ++scheduleCycle;
                    ++cycle;
                }
                if (forward == LOOK_FORWARD) {
                    if (throwAwayCount < MAX_THROWAWAY) {
                        throwAwayCount++;
                        mopIdx = cur.info->numOps;
                        continue;
                    }
                    cur.info = &info_nop;
                    mopIdx = 1;
                    break;
                }
            }

            if (mopIdx == cur.info->dstOp) {
                int forward;
                for (forward = 0; forward < LOOK_FORWARD && !ss_select_dst(&cur, scheduleCycle, throwAwayCount > 0, regs, gen); ++forward) {
                    ++scheduleCycle;
                    ++cycle;
                }
                if (forward == LOOK_FORWARD) {
                    if (throwAwayCount < MAX_THROWAWAY) {
                        throwAwayCount++;
                        mopIdx = cur.info->numOps;
                        continue;
                    }
                    cur.info = &info_nop;
                    mopIdx = 1;
                    break;
                }
            }

            throwAwayCount = 0;

            scheduleCycle = schedule_mop(1, mop, portBusy, scheduleCycle, scheduleCycle);
            if (scheduleCycle < 0) {
                portsSaturated = 1;
                break;
            }

            depCycle = scheduleCycle + mop->latency;

            if (mopIdx == cur.info->resultOp) {
                int dst = cur.dst;
                regs[dst].latency = depCycle;
                retireCycle = depCycle;
                regs[dst].lastOpGroup = cur.opGroup;
                regs[dst].lastOpPar = cur.opGroupPar;
            }

            codeSize += mop->size;
            bufIdx++;
            mopIdx++;
            macroOpCount++;

            if (scheduleCycle >= RX_SUPERSCALAR_LATENCY) {
                portsSaturated = 1;
            }
            cycle = topCycle;

            if (mopIdx >= cur.info->numOps) {
                ss_instr_to_native(&cur, &prog->buffer[programSize++]);
                mulCount += is_mul(cur.type);
            }
        }
        ++cycle;
    }

    int asicLatencies[8];
    memset(asicLatencies, 0, sizeof(asicLatencies));
    for (int i = 0; i < programSize; ++i) {
        rx_instruction *instr = &prog->buffer[i];
        int d = instr->dst;
        int s = instr->src;
        if (d < 0 || d >= 8 || s < 0 || s >= 8) {
            /* should never happen */
        }
        int latDst = asicLatencies[d] + 1;
        int latSrc = (d != s) ? asicLatencies[s] + 1 : 0;
        asicLatencies[d] = latDst > latSrc ? latDst : latSrc;
    }

    int asicLatencyMax = 0;
    int addressReg = 0;
    for (int i = 0; i < NUM_REGISTERS; i++) {
        if (asicLatencies[i] > asicLatencyMax) {
            asicLatencyMax = asicLatencies[i];
            addressReg = i;
        }
    }

    prog->size = (uint32_t)programSize;
    prog->addrReg = addressReg;
}
