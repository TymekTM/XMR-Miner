#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <windows.h>

typedef void (*ss_fn)(uint64_t *);

int main() {
    printf("[TEST] Minimal JIT smoke test\n");
    fflush(stdout);

    uint8_t *code = (uint8_t *)VirtualAlloc(NULL, 4096,
        MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!code) { printf("[FAIL] VirtualAlloc\n"); return 1; }

    size_t pos = 0;

    // Prologue: push rbp, rdi, rbx, r12
    // push rbp
    code[pos++] = 0x55;
    // push rdi
    code[pos++] = 0x57;
    // push rbx
    code[pos++] = 0x53;
    // push r12
    code[pos++] = 0x41; code[pos++] = 0x54;

    // mov rbp, rcx  (rcx = first arg = pointer to r[8])
    code[pos++] = 0x48; code[pos++] = 0x89; code[pos++] = 0xCD;

    // Load r[0..7] into RAX,RCX,R8,R9,R10,R11,R12,RBX from [rb+0..56]
    // mov rax, [rbp+0]
    code[pos++] = 0x48; code[pos++] = 0x8B; code[pos++] = 0x45; code[pos++] = 0x00;
    // mov rcx, [rbp+8]
    code[pos++] = 0x48; code[pos++] = 0x8B; code[pos++] = 0x4D; code[pos++] = 0x08;
    // mov r8, [rbp+16]
    code[pos++] = 0x4C; code[pos++] = 0x8B; code[pos++] = 0x45; code[pos++] = 0x10;
    // mov r9, [rbp+24]
    code[pos++] = 0x4C; code[pos++] = 0x8B; code[pos++] = 0x4D; code[pos++] = 0x18;
    // mov r10, [rbp+32]
    code[pos++] = 0x4C; code[pos++] = 0x8B; code[pos++] = 0x55; code[pos++] = 0x20;
    // mov r11, [rbp+40]
    code[pos++] = 0x4C; code[pos++] = 0x8B; code[pos++] = 0x5D; code[pos++] = 0x28;
    // mov r12, [rbp+48]
    code[pos++] = 0x4C; code[pos++] = 0x8B; code[pos++] = 0x65; code[pos++] = 0x30;
    // mov rbx, [rbp+56]
    code[pos++] = 0x48; code[pos++] = 0x8B; code[pos++] = 0x5D; code[pos++] = 0x38;

    // XOR rax, rcx (ISUB_R: r[0] -= r[1] -> sub rax, rcx)
    code[pos++] = 0x48; code[pos++] = 0x29; code[pos++] = 0xC8;

    // Store back
    // mov [rbp+0], rax
    code[pos++] = 0x48; code[pos++] = 0x89; code[pos++] = 0x45; code[pos++] = 0x00;
    // mov [rbp+8], rcx
    code[pos++] = 0x48; code[pos++] = 0x89; code[pos++] = 0x4D; code[pos++] = 0x08;
    // mov [rbp+16], r8
    code[pos++] = 0x4C; code[pos++] = 0x89; code[pos++] = 0x45; code[pos++] = 0x10;
    // mov [rbp+24], r9
    code[pos++] = 0x4C; code[pos++] = 0x89; code[pos++] = 0x4D; code[pos++] = 0x18;
    // mov [rbp+32], r10
    code[pos++] = 0x4C; code[pos++] = 0x89; code[pos++] = 0x55; code[pos++] = 0x20;
    // mov [rbp+40], r11
    code[pos++] = 0x4C; code[pos++] = 0x89; code[pos++] = 0x5D; code[pos++] = 0x28;
    // mov [rbp+48], r12
    code[pos++] = 0x4C; code[pos++] = 0x89; code[pos++] = 0x65; code[pos++] = 0x30;
    // mov [rbp+56], rbx
    code[pos++] = 0x48; code[pos++] = 0x89; code[pos++] = 0x5D; code[pos++] = 0x38;

    // Epilogue
    // pop r12
    code[pos++] = 0x41; code[pos++] = 0x5C;
    // pop rbx
    code[pos++] = 0x5B;
    // pop rdi
    code[pos++] = 0x5F;
    // pop rbp
    code[pos++] = 0x5D;
    // ret
    code[pos++] = 0xC3;

    printf("[I] Generated %zu bytes of code\n", pos);
    printf("[I] Code bytes:");
    for (size_t i = 0; i < pos; i++) {
        if (i % 16 == 0) printf("\n    ");
        printf("%02X ", code[i]);
    }
    printf("\n");
    fflush(stdout);

    DWORD old_protect;
    VirtualProtect(code, 4096, PAGE_EXECUTE_READ, &old_protect);

    ss_fn fn = (ss_fn)code;

    uint64_t r[8];
    r[0] = 0x1111111111111111ULL;
    r[1] = 0x2222222222222222ULL;
    r[2] = 0x3333333333333333ULL;
    r[3] = 0x4444444444444444ULL;
    r[4] = 0x5555555555555555ULL;
    r[5] = 0x6666666666666666ULL;
    r[6] = 0x7777777777777777ULL;
    r[7] = 0x8888888888888888ULL;

    printf("[I] Before: r[0]=%016llx r[1]=%016llx\n",
        (unsigned long long)r[0], (unsigned long long)r[1]);
    fflush(stdout);

    printf("[I] Calling JIT function...\n");
    fflush(stdout);

    fn(r);

    printf("[I] After:  r[0]=%016llx r[1]=%016llx\n",
        (unsigned long long)r[0], (unsigned long long)r[1]);
    fflush(stdout);

    uint64_t expected = 0x1111111111111111ULL - 0x2222222222222222ULL;
    printf("[%s] r[0] = %016llx (expected %016llx)\n",
        r[0] == expected ? "PASS" : "FAIL",
        (unsigned long long)r[0], (unsigned long long)expected);

    VirtualFree(code, 0, MEM_RELEASE);
    return 0;
}
