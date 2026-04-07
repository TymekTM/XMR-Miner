#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <windows.h>
#include "crypto/randomx/randomx_internal.h"

extern int g_jit_epilogue_skip_mask;

#define JIT_SKIP_XOR_CHAIN     0x01
#define JIT_SKIP_RBP_UPDATE    0x02
#define JIT_SKIP_DS_PREFETCH   0x04
#define JIT_SKIP_REGFILE_READ  0x08
#define JIT_SKIP_SP_PREFETCH   0x10
#define JIT_SKIP_LOOP_STORE    0x20

static const char* phase_name(int mask) {
    if (mask & JIT_SKIP_XOR_CHAIN) return "XOR_CHAIN";
    if (mask & JIT_SKIP_RBP_UPDATE) return "RBP_UPDATE";
    if (mask & JIT_SKIP_DS_PREFETCH) return "DS_PREFETCH";
    if (mask & JIT_SKIP_REGFILE_READ) return "REGFILE_READ";
    if (mask & JIT_SKIP_SP_PREFETCH) return "SP_PREFETCH";
    if (mask & JIT_SKIP_LOOP_STORE) return "LOOP_STORE";
    return "?";
}

int main(int argc, char **argv) {
    printf("=== JIT Epilogue Phase Skip Analysis (NOP-patch) ===\n\n");

    rx_cache *cache = rx_alloc_cache(1);
    rx_dataset *dataset = rx_alloc_dataset(1);
    if (!cache || !dataset) { printf("[FAIL] Alloc failed\n"); return 1; }

    uint8_t seed[32];
    for (int i = 0; i < 32; i++) seed[i] = (uint8_t)(i * 37 + 13);
    rx_init_cache(cache, seed, 32);
    rx_init_dataset_cached(dataset, cache, 0, RX_DATASET_ITEMS, 8, 8);

    struct { int mask; const char *name; } tests[] = {
        { 0, "FULL (reference)" },
        { JIT_SKIP_XOR_CHAIN, "SKIP XOR_CHAIN" },
        { JIT_SKIP_RBP_UPDATE, "SKIP RBP_UPDATE" },
        { JIT_SKIP_DS_PREFETCH, "SKIP DS_PREFETCH" },
        { JIT_SKIP_REGFILE_READ, "SKIP REGFILE_READ" },
        { JIT_SKIP_SP_PREFETCH, "SKIP SP_PREFETCH" },
        { JIT_SKIP_LOOP_STORE, "SKIP LOOP_STORE" },
        { JIT_SKIP_XOR_CHAIN | JIT_SKIP_RBP_UPDATE, "SKIP XOR+RBP" },
        { JIT_SKIP_DS_PREFETCH | JIT_SKIP_SP_PREFETCH, "SKIP both PREFETCHes" },
        { JIT_SKIP_XOR_CHAIN | JIT_SKIP_RBP_UPDATE | JIT_SKIP_DS_PREFETCH,
          "SKIP XOR+RBP+DS_PF" },
        { JIT_SKIP_SP_PREFETCH | JIT_SKIP_DS_PREFETCH, "SKIP ALL PREFETCH" },
        { JIT_SKIP_REGFILE_READ | JIT_SKIP_DS_PREFETCH, "SKIP REGFILE+DS_PF" },
    };

    int num_tests = sizeof(tests) / sizeof(tests[0]);

    uint8_t ref_hash[32] = {0};

    g_jit_epilogue_skip_mask = 0;
    {
        rx_vm *vm_ref = rx_create_vm(RX_FLAG_JIT | RX_FLAG_DEFAULT, cache, dataset);
        uint8_t input[76];
        for (int i = 0; i < 76; i++) input[i] = (uint8_t)i;
        rx_calculate_hash(vm_ref, input, 76, ref_hash);
        rx_destroy_vm(vm_ref);
        printf("[REF] Full JIT hash: ");
        for (int i = 0; i < 8; i++) printf("%02x", ref_hash[i]);
        printf("...\n\n");
        fflush(stdout);
    }

    int pass = 0;
    for (int t = 0; t < num_tests; t++) {
        g_jit_epilogue_skip_mask = tests[t].mask;
        printf("[%d/%d] Testing: %s (mask=0x%02X)...", t+1, num_tests, tests[t].name, tests[t].mask);
        fflush(stdout);

        rx_vm *vm = rx_create_vm(RX_FLAG_JIT | RX_FLAG_DEFAULT, cache, dataset);
        if (!vm) { printf(" [ERR] VM create failed\n"); fflush(stdout); continue; }
        printf(" VM OK, hashing...");
        fflush(stdout);

        uint8_t input[76];
        for (int i = 0; i < 76; i++) input[i] = (uint8_t)i;

        uint8_t test_hash[32];
        rx_calculate_hash(vm, input, 76, test_hash);

        int match = (memcmp(test_hash, ref_hash, 32) == 0);
        printf("[%s] %-40s mask=0x%02X",
               match ? "OK " : "DIFF", tests[t].name, tests[t].mask);
        if (!match) {
            printf(" -> ");
            for (int i = 0; i < 6; i++) printf("%02x", test_hash[i]);
        }
        printf("\n");
        fflush(stdout);
        if (match) pass++;

        rx_destroy_vm(vm);
    }

    g_jit_epilogue_skip_mask = 0;
    printf("\n=== %d/%d passed ===\n", pass, num_tests);
    rx_free_dataset(dataset);
    rx_free_cache(cache);
    return (pass == num_tests) ? 0 : 1;
}
