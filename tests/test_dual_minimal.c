#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#define SCRATCHPAD_SIZE RX_SCRATCHPAD_L3
#include "crypto/randomx/randomx_internal.h"
#include "common/cpu.h"
#include "common/log.h"

static LONG WINAPI veh(PEXCEPTION_POINTERS ep) {
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    printf("VEH: code=0x%08lX rip=%p\n", code, ep->ContextRecord->Rip);
    printf("  rcx=%p r8=%llx r9=%llx r10=%llx r11=%llx\n",
        (void*)ep->ContextRecord->Rcx,
        (unsigned long long)ep->ContextRecord->R8,
        (unsigned long long)ep->ContextRecord->R9,
        (unsigned long long)ep->ContextRecord->R10,
        (unsigned long long)ep->ContextRecord->R11);
    printf("  r12=%llx r13=%llx r14=%llx r15=%llx\n",
        (unsigned long long)ep->ContextRecord->R12,
        (unsigned long long)ep->ContextRecord->R13,
        (unsigned long long)ep->ContextRecord->R14,
        (unsigned long long)ep->ContextRecord->R15);
    fflush(stdout);
    if (code == 0x80000003) {
        ep->ContextRecord->Rip += 1;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static void enable_huge_pages() {
    TOKEN_PRIVILEGES tp = {0};
    LUID luid;
    HANDLE token;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        if (LookupPrivilegeValueA(NULL, "SeLockMemoryPrivilege", &luid)) {
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL);
        }
        CloseHandle(token);
    }
}

typedef void (*ProgramFunc)(rx_register_file*, rx_memory_regs*, uint8_t*, uint32_t);
typedef void (*DualFunc)(RxDualParams*);

extern void vm_initialize(rx_vm*);
extern void rx_jit_generate_program(rx_jit*, rx_program*, rx_program_config*, rx_cache*);
extern void rx_jit_generate_program_dual_interleaved(rx_jit*, rx_program*, rx_program_config*, rx_program*, rx_program_config*, rx_cache*);
extern void* rx_jit_get_program_func(rx_jit*);

static int run_single_jit(rx_vm* vm, uint8_t* seed, uint32_t iterations) {
    rx_fill_aes4rx4(seed, sizeof(rx_program), &vm->program);
    vm_initialize(vm);
    rx_jit_generate_program(vm->jit, &vm->program, &vm->config, vm->cachePtr);
    ProgramFunc func = (ProgramFunc)rx_jit_get_program_func(vm->jit);
    if (!func) return -1;

    rx_memory_regs memRegs;
    memRegs.mx_ma = vm->mem.mx_ma;
    memRegs.memory = vm->mem.memory + vm->datasetOffset;
    func(&vm->reg, &memRegs, vm->scratchpad, iterations);
    vm->mem.mx_ma = memRegs.mx_ma;
    return 0;
}

static void dump_reg_file(const char* label, rx_register_file* reg) {
    printf("  %s r:", label);
    for (int i = 0; i < 8; i++) printf(" %016llx", (unsigned long long)reg->r[i]);
    printf("\n");
    printf("  %s mx_ma: (not in reg file)\n", label);
}

static int compare_vm_state(const char* label, rx_vm* ref, rx_vm* dual, uint8_t* sp_ref, uint8_t* sp_dual, int sp_size) {
    int mismatches = 0;

    for (int i = 0; i < 8; i++) {
        if (ref->reg.r[i] != dual->reg.r[i]) {
            printf("  %s MISMATCH r[%d]: ref=%016llx dual=%016llx\n",
                label, i, (unsigned long long)ref->reg.r[i], (unsigned long long)dual->reg.r[i]);
            mismatches++;
        }
    }
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 2; j++) {
            uint64_t ref_bits, dual_bits;
            memcpy(&ref_bits, &ref->reg.f[i][j], 8);
            memcpy(&dual_bits, &dual->reg.f[i][j], 8);
            if (ref_bits != dual_bits) {
                printf("  %s MISMATCH f[%d][%d]: ref=%016llx dual=%016llx\n",
                    label, i, j, (unsigned long long)ref_bits, (unsigned long long)dual_bits);
                mismatches++;
            }
            memcpy(&ref_bits, &ref->reg.e[i][j], 8);
            memcpy(&dual_bits, &dual->reg.e[i][j], 8);
            if (ref_bits != dual_bits) {
                printf("  %s MISMATCH e[%d][%d]: ref=%016llx dual=%016llx\n",
                    label, i, j, (unsigned long long)ref_bits, (unsigned long long)dual_bits);
                mismatches++;
            }
            memcpy(&ref_bits, &ref->reg.a[i][j], 8);
            memcpy(&dual_bits, &dual->reg.a[i][j], 8);
            if (ref_bits != dual_bits) {
                printf("  %s MISMATCH a[%d][%d]: ref=%016llx dual=%016llx\n",
                    label, i, j, (unsigned long long)ref_bits, (unsigned long long)dual_bits);
                mismatches++;
            }
        }
    }
    if (ref->mem.mx_ma != dual->mem.mx_ma) {
        printf("  %s MISMATCH mx_ma: ref=%016llx dual=%016llx\n",
            label, (unsigned long long)ref->mem.mx_ma, (unsigned long long)dual->mem.mx_ma);
        mismatches++;
    }
    int sp_diffs = 0;
    int first_sp_idx[8];
    uint64_t first_sp_ref[8];
    uint64_t first_sp_dual[8];
    for (int k = 0; k < 8; k++) first_sp_idx[k] = -1;
    for (int i = 0; i < sp_size; i += 8) {
        uint64_t v1, v2;
        memcpy(&v1, sp_ref + i, 8);
        memcpy(&v2, sp_dual + i, 8);
        if (v1 != v2) {
            if (sp_diffs < 8) {
                first_sp_idx[sp_diffs] = i;
                first_sp_ref[sp_diffs] = v1;
                first_sp_dual[sp_diffs] = v2;
            }
            sp_diffs++;
        }
    }
    if (sp_diffs > 0) {
        printf("  %s MISMATCH scratchpad: %d/%d qwords differ\n", label, sp_diffs, sp_size / 8);
        for (int k = 0; k < 8 && first_sp_idx[k] >= 0; k++) {
            printf("  %s scratch[%d]: ref=%016llx dual=%016llx\n",
                label,
                first_sp_idx[k],
                (unsigned long long)first_sp_ref[k],
                (unsigned long long)first_sp_dual[k]);
        }
        mismatches += sp_diffs;
    }
    return mismatches;
}

int main() {
    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
    AddVectoredExceptionHandler(1, veh);
    enable_huge_pages();

    rx_cache* cache = rx_alloc_cache(1);
    uint8_t key[] = "test_key_123456";
    rx_init_cache(cache, key, sizeof(key));

    rx_dataset* dataset = rx_alloc_dataset(1);
    rx_init_dataset_cached(dataset, cache, 0, RX_DATASET_ITEMS, 8, 8);

    uint8_t seed1[32] = {0xAA, 0xBB, 0xCC, 0xDD};
    uint8_t seed2[32] = {0x11, 0x22, 0x33, 0x44};

    uint32_t test_iterations[] = {1, 4, 16, 64, 256};
    int num_tests = sizeof(test_iterations) / sizeof(test_iterations[0]);
    int total_pass = 0;

    for (int t = 0; t < num_tests; t++) {
        uint32_t iters = test_iterations[t];
        printf("\n=== Test with %u iterations ===\n", iters); fflush(stdout);

        rx_vm* ref1 = rx_create_vm(1, 1, 1, cache, dataset);
        rx_vm* ref2 = rx_create_vm(1, 1, 1, cache, dataset);
        rx_vm* dual1 = rx_create_vm(1, 1, 1, cache, dataset);
        rx_vm* dual2 = rx_create_vm(1, 1, 1, cache, dataset);

        int r1 = run_single_jit(ref1, seed1, iters);
        int r2 = run_single_jit(ref2, seed2, iters);
        if (r1 < 0 || r2 < 0) {
            printf("  SKIP: single JIT failed\n"); fflush(stdout);
            rx_destroy_vm(ref1); rx_destroy_vm(ref2);
            rx_destroy_vm(dual1); rx_destroy_vm(dual2);
            continue;
        }

        uint8_t* sp1_ref = malloc(SCRATCHPAD_SIZE);
        uint8_t* sp2_ref = malloc(SCRATCHPAD_SIZE);
        memcpy(sp1_ref, ref1->scratchpad, SCRATCHPAD_SIZE);
        memcpy(sp2_ref, ref2->scratchpad, SCRATCHPAD_SIZE);

        rx_fill_aes4rx4(seed1, sizeof(rx_program), &dual1->program);
        rx_fill_aes4rx4(seed2, sizeof(rx_program), &dual2->program);
        vm_initialize(dual1);
        vm_initialize(dual2);

        rx_jit_generate_program_dual_interleaved(dual1->jit, &dual1->program, &dual1->config,
                                                   &dual2->program, &dual2->config, dual1->cachePtr);
        DualFunc dfunc = (DualFunc)rx_jit_get_program_func(dual1->jit);

        RxDualParams params;
        memset(&params, 0, sizeof(params));
        params.reg1 = &dual1->reg;
        params.reg2 = &dual2->reg;
        params.mx_ma1 = dual1->mem.mx_ma;
        params.mx_ma2 = dual2->mem.mx_ma;
        params.sp1 = dual1->scratchpad;
        params.sp2 = dual2->scratchpad;
        params.dataset1 = dual1->mem.memory + dual1->datasetOffset;
        params.dataset2 = dual2->mem.memory + dual2->datasetOffset;
        params.iterations = iters;
        params.mxcsr1 = RX_MXCSR_DEFAULT;
        params.mxcsr2 = RX_MXCSR_DEFAULT;

        DWORD oldMode = SetErrorMode(SEM_NOGPFAULTERRORBOX);
        __try {
            dfunc(&params);
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            printf("  CRASH in dual JIT!\n"); fflush(stdout);
            SetErrorMode(oldMode);
            free(sp1_ref); free(sp2_ref);
            rx_destroy_vm(ref1); rx_destroy_vm(ref2);
            rx_destroy_vm(dual1); rx_destroy_vm(dual2);
            continue;
        }
        SetErrorMode(oldMode);

        dual1->mem.mx_ma = params.mx_ma1;
        dual2->mem.mx_ma = params.mx_ma2;

        printf("  dual1 reg.r: ");
        for (int i = 0; i < 8; i++) printf("%016llx ", (unsigned long long)dual1->reg.r[i]);
        printf("\n");
        printf("  dual2 reg.r: ");
        for (int i = 0; i < 8; i++) printf("%016llx ", (unsigned long long)dual2->reg.r[i]);
        printf("\n"); fflush(stdout);

        int m1 = compare_vm_state("VM1", ref1, dual1, sp1_ref, dual1->scratchpad, SCRATCHPAD_SIZE);
        int m2 = compare_vm_state("VM2", ref2, dual2, sp2_ref, dual2->scratchpad, SCRATCHPAD_SIZE);

        if (m1 == 0 && m2 == 0) {
            printf("  PASS: All outputs match!\n"); fflush(stdout);
            total_pass++;
        } else {
            printf("  FAIL: VM1=%d mismatches, VM2=%d mismatches\n", m1, m2); fflush(stdout);
            dump_reg_file("VM1 ref:", &ref1->reg);
            dump_reg_file("VM1 dual:", &dual1->reg);
            dump_reg_file("VM2 ref:", &ref2->reg);
            dump_reg_file("VM2 dual:", &dual2->reg);
        }

        free(sp1_ref); free(sp2_ref);
        rx_destroy_vm(ref1); rx_destroy_vm(ref2);
        rx_destroy_vm(dual1); rx_destroy_vm(dual2);
    }

    printf("\n=== RESULTS: %d/%d tests passed ===\n", total_pass, num_tests);
    fflush(stdout);

    rx_free_dataset(dataset);
    rx_free_cache(cache);
    return total_pass == num_tests ? 0 : 1;
}
