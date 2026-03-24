#include "crypto/randomx/randomx.h"
#include <stdio.h>
#include <string.h>
#include <windows.h>

int main(void) {
    printf("[TEST] Minimal JIT function\n");

    // Allocate executable memory
    uint8_t *code = (uint8_t*)VirtualAlloc(NULL, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!code) {
        printf("[FAIL] Code allocation\n");
        return 1;
    }

    // Clear with NOPs
    memset(code, 0x90, 4096);

    // Write minimal prologue + epilogue
    uint8_t* p = code;

    // sub rsp, 0x10 (allocate 16 bytes for stack)
    *p++ = 0x48; *p++ = 0x81; *p++ = 0xEC;
    *p++ = 0x10; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;

    // mov rax, rbx (just copy rbx to rax)
    *p++ = 0x48; *p++ = 0x89; *p++ = 0xD8;

    // add rsp, 0x10 (deallocate)
    *p++ = 0x48; *p++ = 0x81; *p++ = 0xC4;
    *p++ = 0x10; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;

    // ret
    *p++ = 0xC3;

    printf("[TEST] Generated code at %p\n", code);
    printf("[TEST] First 20 bytes: ");
    for (int i = 0; i < 20; i++) printf("%02x ", code[i]);
    printf("\n");

    // Try calling it
    typedef void (*MinimalFunc)(void);
    MinimalFunc func = (MinimalFunc)code;

    __try {
        printf("[TEST] Calling function...\n");
        func();
        printf("[TEST] Function returned OK\n");
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        printf("[ERROR] Exception: 0x%08lx\n", GetExceptionCode());
    }

    VirtualFree(code, 0, MEM_RELEASE);
    return 0;
}
