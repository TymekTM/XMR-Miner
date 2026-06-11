#include <stdio.h>
#include <string.h>
#include <windows.h>

#define __BMI2__
#include <intrin.h>

int main() {
    printf("=== BMI2 intrinsics availability ===\n\n");

    void *mem = VirtualAlloc(NULL, 4096, MEM_RESERVE | MEM_COMMIT,
                              PAGE_EXECUTE_READWRITE);
    unsigned char *code = (unsigned char *)mem;

    typedef unsigned long long (*fn_t)(unsigned long long);

    unsigned long long val = 0x0123456789ABCDEFULL;

    #ifdef _rorx_u64
        printf("_rorx_u64 AVAILABLE!\n");
        printf("_rorx_u64(0x%llX, 5) = 0x%llX\n", val, _rorx_u64(val, 5));
        printf("_rorx_u64(0x%llX, 13) = 0x%llX\n", val, _rorx_u64(val, 13));

        static unsigned long long (*p_rorx)(unsigned long long, unsigned int) = _rorx_u64;
        unsigned char *ptr = (unsigned char*)p_rorx;
        printf("\n_rorx_u64 first 20 bytes:\n");
        for (int i = 0; i < 20; i++) {
            printf("%02X ", ptr[i]);
            if ((i+1) % 10 == 0) printf("\n");
        }
        printf("\n");

        memcpy(code, ptr, 20);
        code[20] = 0xC3;
        FlushInstructionCache(GetCurrentProcess(), code, 21);

        fn_t f = (fn_t)code;
        unsigned long long r = f(val);
        printf("Executed copied bytes: rorx(0x%llX, 5) = 0x%llX\n", val, r);

        /* Compare with ROL */
        unsigned long long rol_val = _rotl64(val, 59);
        printf("rol64(val, 59) = 0x%llX (should match rorx)\n", rol_val);

        /* Now test: use the EXACT byte sequence from _rorx_u64 in our JIT context */
        /* The key question: what VEX encoding does MSVC generate? */
        printf("\n--- Testing exact MSVC RORX encoding in JIT context ---\n");
        /* Build: MOV rax, [rcx]; RORX rax,rax,5; RET */
        /* We'll extract just the RORX part from ptr and prepend MOV + append RET */
        unsigned char jit_code[32];
        int pos = 0;
        /* MOV rax, rcx = 48 89 C8 */
        jit_code[pos++] = 0x48; jit_code[pos++] = 0x89; jit_code[pos++] = 0xC8;
        /* Copy RORX instruction bytes (skip any prologue/epilogue) */
        /* ptr points to _rorx_u64 which starts with prologue, need to find the actual RORX */
        /* Let's search for C4 or F0 pattern in the bytes */
        for (int i = 0; i < 18; i++) {
            if (ptr[i] == 0xC4 || ptr[i] == 0xF0) {
                printf("Found potential RORX at offset %d: ", i);
                for (int j = i; j < i+6 && j < 20; j++) printf("%02X ", ptr[j]);
                printf("\n");
            }
        }
    #else
        printf("_rorx_u64 NOT available even with #define __BMI2__\n");
        
        printf("\nTesting other BMI2 intrinsics:\n");
        #ifdef _bextr_u64
            printf("bextr(0x%llX, 8, 16) = 0x%llX\n", val, _bextr_u64(val, 8, 16));
        #endif
        #ifdef _bzhi_u64
            printf("bzhi(0x%llX, 16) = 0x%llX\n", val, _bzhi_u64(val, 16));
        #endif
        #ifdef _pext_u64
            printf("pext available\n");
        #endif
        #ifdef _pdep_u64
            printf("pdep available\n");
        #endif
    #endif

    VirtualFree(mem, 0, MEM_RELEASE);
    return 0;
}
