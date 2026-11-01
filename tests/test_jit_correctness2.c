#include "crypto/randomx/randomx.h"
#include "crypto/randomx/randomx_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#endif
#include <immintrin.h>

extern int g_jit_bmi2_mulx;
extern int g_jit_cfround_elim;
extern int g_jit_large_pages;
extern int g_jit_jcc_align;
extern int g_jit_near_rcp_pool;
extern int g_aes_hash_fill_prefetch;
extern int g_jit_double_buffer;
extern int g_jit_inline_rcp_pool;
extern int g_jit_rorx;
extern int g_jit_stack_rcp_pool;
extern int g_jit_cfround_rorx;
extern int g_aes_hash_fill_upstream;

int main(int argc, char **argv) {
    g_jit_bmi2_mulx = argc > 1 ? atoi(argv[1]) : 0;
    g_jit_cfround_elim = argc > 2 ? atoi(argv[2]) : 0;
    g_jit_large_pages = argc > 3 ? atoi(argv[3]) : 0;
    g_jit_jcc_align = argc > 4 ? atoi(argv[4]) : 0;
    g_jit_near_rcp_pool = argc > 5 ? atoi(argv[5]) : 0;
    g_aes_hash_fill_prefetch = argc > 6 ? atoi(argv[6]) : 0;
    g_jit_double_buffer = argc > 7 ? atoi(argv[7]) : 0;
    g_jit_inline_rcp_pool = argc > 8 ? atoi(argv[8]) : 0;
    g_jit_rorx = argc > 9 ? atoi(argv[9]) : 0;
    g_jit_stack_rcp_pool = argc > 10 ? atoi(argv[10]) : 0;
    g_jit_cfround_rorx = argc > 11 ? atoi(argv[11]) : 0;
    g_aes_hash_fill_upstream = argc > 12 ? atoi(argv[12]) : 0;
    const char *key = "test key 000";
    rx_cache *cache = rx_alloc_cache(0);
    rx_init_cache(cache, key, strlen(key));

    rx_dataset *dataset = rx_alloc_dataset(0);
    rx_init_dataset(dataset, cache, 0, RX_DATASET_ITEMS + RX_DATASET_EXTRA_ITEMS, 8, 8);

    rx_vm *vm_j = rx_create_vm(RX_FLAG_JIT, cache, dataset);
    rx_vm *vm_i = rx_create_vm(RX_FLAG_DEFAULT, cache, dataset);

    int total = 0, pass = 0, fail = 0;
    for (int trial = 0; trial < 100; trial++) {
        char input[80];
        snprintf(input, sizeof(input), "test input number %d for trial %d", trial * 7, trial);

        uint8_t hash_j[32], hash_i[32];
        rx_calculate_hash(vm_j, input, strlen(input), hash_j);
        rx_calculate_hash(vm_i, input, strlen(input), hash_i);
        total++;
        if (memcmp(hash_j, hash_i, 32) == 0) pass++;
        else {
            fail++;
            printf("FAIL trial %d input='%s'\n", trial, input);
            printf("  JIT:  "); for (int i=0;i<32;i++) printf("%02x",hash_j[i]); printf("\n");
            printf("  Int:  "); for (int i=0;i<32;i++) printf("%02x",hash_i[i]); printf("\n");
        }
    }

    printf("\nrx_calculate_hash: %d/%d passed, %d failed\n", pass, total, fail);

    pass = 0; fail = 0; total = 0;
    for (int trial = 0; trial < 100; trial++) {
        char blob1[76] = {0};
        char blob2[76] = {0};
        snprintf((char*)blob1, sizeof(blob1), "blob1 trial %d padding padding", trial);
        snprintf((char*)blob2, sizeof(blob2), "blob2 trial %d padding padding", trial);

        uint8_t h1_j[32], h2_j[32], h1_i[32], h2_i[32];
        rx_calculate_hash_first(vm_j, blob1, 76);
        rx_calculate_hash_first(vm_i, blob1, 76);
        rx_calculate_hash_next(vm_j, blob2, 76, h2_j);
        rx_calculate_hash_next(vm_i, blob2, 76, h2_i);
        rx_calculate_hash_last(vm_j, h1_j);
        rx_calculate_hash_last(vm_i, h1_i);
        total++;
        if (memcmp(h1_j, h1_i, 32) == 0 && memcmp(h2_j, h2_i, 32) == 0) pass++;
        else {
            fail++;
            printf("FAIL batch trial %d\n", trial);
            printf("  JIT h1:  "); for (int i=0;i<32;i++) printf("%02x",h1_j[i]); printf("\n");
            printf("  Int h1:  "); for (int i=0;i<32;i++) printf("%02x",h1_i[i]); printf("\n");
            printf("  JIT h2:  "); for (int i=0;i<32;i++) printf("%02x",h2_j[i]); printf("\n");
            printf("  Int h2:  "); for (int i=0;i<32;i++) printf("%02x",h2_i[i]); printf("\n");
        }
    }

    printf("Batch API: %d/%d passed, %d failed\n", pass, total, fail);

    rx_destroy_vm(vm_j);
    rx_destroy_vm(vm_i);
    rx_free_dataset(dataset);
    rx_free_cache(cache);
    return (fail > 0) ? 1 : 0;
}
