#include <stdio.h>
#include <stdint.h>

/*
Test if simple JIT function works and identify crash point
*/
int main(void) {
    // Allocate executable memory
    uint8_t *code = (uint8_t *)malloc(4096);
    if (!code) return 1;

    // Write a simple x86-64 function that just returns
    // mov rax, 0x12345678
    // ret
    code[0] = 0x48; code[1] = 0xb8;  // mov rax, imm64
    code[2] = 0x78; code[3] = 0x56; code[4] = 0x34; code[5] = 0x12;
    code[6] = 0x00; code[7] = 0x00; code[8] = 0x00; code[9] = 0x00;
    code[10] = 0xc3;  // ret

    // Make page executable
    // MPROTECT equivalent for Windows: VirtualProtect

    typedef int64_t (*JitFunc)(void);
    JitFunc func = (JitFunc)code;

    printf("[TEST] Calling simple JIT function...\n");
    int64_t result = func();
    printf("[OK] Result: 0x%llx\n", result);

    free(code);
    return 0;
}
