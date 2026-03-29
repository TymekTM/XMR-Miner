#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <windows.h>

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

typedef struct { uint8_t *code; size_t pos; } emitter;
static void eb(emitter *e, uint8_t b) { e->code[e->pos++] = b; }
static void eu32(emitter *e, uint32_t v) { memcpy(e->code + e->pos, &v, 4); e->pos += 4; }
static void eu64(emitter *e, uint64_t v) { memcpy(e->code + e->pos, &v, 8); e->pos += 8; }

static void erex(emitter *e, int w, int r, int x, int b) {
    eb(e, 0x40 | (w?8:0) | (r?4:0) | (x?2:0) | (b?1:0));
}
static void erex_rb(emitter *e, int reg, int rm) { erex(e, 1, reg>>3, 0, rm>>3); }
static void emodrm(emitter *e, int reg, int rm) { eb(e, 0xC0 | ((reg&7)<<3) | (rm&7)); }

static void epush(emitter *e, int r) { if(r>=8) eb(e,0x41); eb(e,0x50+(r&7)); }
static void epop(emitter *e, int r) { if(r>=8) eb(e,0x41); eb(e,0x58+(r&7)); }
static void emov_rr(emitter *e, int d, int s) { erex_rb(e,s,d); eb(e,0x89); emodrm(e,s,d); }

static void emov_rm(emitter *e, int reg, int base, int disp) {
    erex_rb(e, reg, base);
    eb(e, 0x8B);
    if (disp == 0 && (base & 7) != 5) {
        eb(e, ((reg&7)<<3) | (base&7));
    } else if (disp >= -128 && disp <= 127) {
        eb(e, 0x40 | ((reg&7)<<3) | (base&7));
        eb(e, (int8_t)disp);
    } else {
        eb(e, 0x80 | ((reg&7)<<3) | (base&7));
        eu32(e, (uint32_t)disp);
    }
}

static void emov_mr(emitter *e, int base, int disp, int reg) {
    erex_rb(e, reg, base);
    eb(e, 0x89);
    if (disp == 0 && (base & 7) != 5) {
        eb(e, ((reg&7)<<3) | (base&7));
    } else if (disp >= -128 && disp <= 127) {
        eb(e, 0x40 | ((reg&7)<<3) | (base&7));
        eb(e, (int8_t)disp);
    } else {
        eb(e, 0x80 | ((reg&7)<<3) | (base&7));
        eu32(e, (uint32_t)disp);
    }
}

static void esub(emitter *e, int d, int s) { erex_rb(e,s,d); eb(e,0x29); emodrm(e,s,d); }
static void exor(emitter *e, int d, int s) { erex_rb(e,s,d); eb(e,0x31); emodrm(e,s,d); }
static void eadd(emitter *e, int d, int s) { erex_rb(e,s,d); eb(e,0x01); emodrm(e,s,d); }

static void dump_code(uint8_t *code, size_t len) {
    printf("    ");
    for (size_t i = 0; i < len; i++) {
        printf("%02X ", code[i]);
        if ((i+1) % 20 == 0) printf("\n    ");
    }
    printf("\n");
}

int main() {
    uint8_t *code = VirtualAlloc(NULL, 4096, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    emitter em = {code, 0};

    epush(&em, REG_RBP);
    epush(&em, REG_RDI);
    epush(&em, REG_RBX);
    epush(&em, REG_R12);
    emov_rr(&em, REG_RBP, REG_RCX);

    emov_rm(&em, REG_RAX, REG_RBP, 0);
    emov_rm(&em, REG_RCX, REG_RBP, 8);
    emov_rm(&em, REG_R8,  REG_RBP, 16);
    emov_rm(&em, REG_R9,  REG_RBP, 24);
    emov_rm(&em, REG_R10, REG_RBP, 32);
    emov_rm(&em, REG_R11, REG_RBP, 40);
    emov_rm(&em, REG_R12, REG_RBP, 48);
    emov_rm(&em, REG_RBX, REG_RBP, 56);

    // Test ISUB_R: r[0] -= r[1] -> sub rax, rcx
    esub(&em, REG_MAP[0], REG_MAP[1]);

    // Test IXOR_R: r[2] ^= r[3] -> xor r8, r9
    exor(&em, REG_MAP[2], REG_MAP[3]);

    // Test IADD_RS: r[4] += r[5] << 0 -> add r10, r11
    eadd(&em, REG_MAP[4], REG_MAP[5]);

    // Store back
    emov_mr(&em, REG_RBP, 0,  REG_RAX);
    emov_mr(&em, REG_RBP, 8,  REG_RCX);
    emov_mr(&em, REG_RBP, 16, REG_R8);
    emov_mr(&em, REG_RBP, 24, REG_R9);
    emov_mr(&em, REG_RBP, 32, REG_R10);
    emov_mr(&em, REG_RBP, 40, REG_R11);
    emov_mr(&em, REG_RBP, 48, REG_R12);
    emov_mr(&em, REG_RBP, 56, REG_RBX);

    epop(&em, REG_R12);
    epop(&em, REG_RBX);
    epop(&em, REG_RDI);
    epop(&em, REG_RBP);
    eb(&em, 0xC3);

    printf("[I] Generated %zu bytes\n", em.pos);
    dump_code(code, em.pos);

    DWORD op;
    VirtualProtect(code, 4096, PAGE_EXECUTE_READ, &op);

    typedef void (*fn_t)(uint64_t*);
    fn_t fn = (fn_t)code;

    uint64_t r[8] = {
        1000, 200, 0xAABB, 0x1122, 5000, 100, 0, 0
    };

    printf("[I] Before: r0=%llu r1=%llu r2=%#llx r3=%#llx r4=%llu r5=%llu\n",
        (unsigned long long)r[0], (unsigned long long)r[1],
        (unsigned long long)r[2], (unsigned long long)r[3],
        (unsigned long long)r[4], (unsigned long long)r[5]);

    fn(r);

    printf("[I] After:  r0=%llu r1=%llu r2=%#llx r3=%#llx r4=%llu r5=%llu\n",
        (unsigned long long)r[0], (unsigned long long)r[1],
        (unsigned long long)r[2], (unsigned long long)r[3],
        (unsigned long long)r[4], (unsigned long long)r[5]);

    int ok = 1;
    if (r[0] != 800) { printf("[FAIL] r0 expected 800 got %llu\n", (unsigned long long)r[0]); ok = 0; }
    if (r[2] != (0xAABB ^ 0x1122)) { printf("[FAIL] r2 expected %llx got %llx\n", (unsigned long long)(0xAABB^0x1122), (unsigned long long)r[2]); ok = 0; }
    if (r[4] != 5100) { printf("[FAIL] r4 expected 5100 got %llu\n", (unsigned long long)r[4]); ok = 0; }
    if (ok) printf("[PASS] All checks passed\n");

    VirtualFree(code, 0, MEM_RELEASE);
    return ok ? 0 : 1;
}
