#include "crypto/randomx/randomx.h"
#include "crypto/randomx/randomx_internal.h"
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <immintrin.h>

int main(void) {
    const char *key = "test key 000";
    rx_cache *cache = rx_alloc_cache(0);
    rx_init_cache(cache, key, strlen(key));

    rx_dataset *dataset = rx_alloc_dataset(0);
    rx_init_dataset(dataset, cache, 0, RX_DATASET_ITEMS + RX_DATASET_EXTRA_ITEMS, 8, 8);

    const char *input = "This is a test";
    uint8_t tempHash[64];
    blake2b(tempHash, 64, input, strlen(input), NULL, 0);

    rx_vm *vm_j = rx_create_vm(RX_FLAG_JIT, cache, dataset);
    rx_vm *vm_i = rx_create_vm(RX_FLAG_DEFAULT, cache, dataset);

    uint8_t seed_j[64], seed_i[64];
    memcpy(seed_j, tempHash, 64);
    memcpy(seed_i, tempHash, 64);

    rx_vm_run(vm_i, seed_i);
    rx_vm_run(vm_j, seed_j);

    printf("After rx_vm_run (same seed):\n");
    int all_match = 1;
    for (int i = 0; i < 8; i++) {
        int m = (vm_j->reg.r[i] == vm_i->reg.r[i]);
        printf("  R%d: JIT=0x%016llx  Int=0x%016llx  %s\n", i,
            (unsigned long long)vm_j->reg.r[i],
            (unsigned long long)vm_i->reg.r[i],
            m ? "OK" : "MISMATCH");
        if (!m) all_match = 0;
    }

    uint64_t mx_j = (uint32_t)(vm_j->mem.mx_ma >> 32);
    uint64_t ma_j = (uint32_t)(vm_j->mem.mx_ma & 0xFFFFFFFF);
    uint64_t mx_i = (uint32_t)(vm_i->mem.mx_ma >> 32);
    uint64_t ma_i = (uint32_t)(vm_i->mem.mx_ma & 0xFFFFFFFF);
    printf("  mx: JIT=%llu Int=%llu %s\n", (unsigned long long)mx_j, (unsigned long long)mx_i, mx_j == mx_i ? "OK" : "MISMATCH");
    printf("  ma: JIT=%llu Int=%llu %s\n", (unsigned long long)ma_j, (unsigned long long)ma_i, ma_j == ma_i ? "OK" : "MISMATCH");

    int fp_match = 1;
    for (int i = 0; i < 4; i++) {
        __m128d j_vec = _mm_loadu_pd(vm_j->reg.a[i]);
        __m128d i_vec = _mm_loadu_pd(vm_i->reg.a[i]);
        __m128i j_iv = _mm_castpd_si128(j_vec);
        __m128i i_iv = _mm_castpd_si128(i_vec);
        uint64_t j0 = (uint64_t)_mm_extract_epi64(j_iv, 0), j1 = (uint64_t)_mm_extract_epi64(j_iv, 1);
        uint64_t i0 = (uint64_t)_mm_extract_epi64(i_iv, 0), i1 = (uint64_t)_mm_extract_epi64(i_iv, 1);
        if (j0 != i0 || j1 != i1) {
            fp_match = 0;
            printf("  FP%d MISMATCH: JIT=[%llx,%llx] Int=[%llx,%llx]\n", i,
                (unsigned long long)j0, (unsigned long long)j1,
                (unsigned long long)i0, (unsigned long long)i1);
        }
    }
    printf("  FP regs: %s\n", fp_match ? "OK" : "MISMATCH");

    printf("\nScratchpad first 32 bytes: %s\n",
        memcmp(vm_j->scratchpad, vm_i->scratchpad, 32) == 0 ? "MATCH" : "MISMATCH");

    printf("\nNow testing rx_calculate_hash:\n");
    uint8_t hash_j[32], hash_i[32];
    memcpy(seed_j, tempHash, 64);
    memcpy(seed_i, tempHash, 64);
    rx_calculate_hash(vm_j, input, strlen(input), hash_j);
    rx_calculate_hash(vm_i, input, strlen(input), hash_i);
    printf("  JIT hash:  "); for (int i=0;i<32;i++) printf("%02x",hash_j[i]); printf("\n");
    printf("  Int hash:  "); for (int i=0;i<32;i++) printf("%02x",hash_i[i]); printf("\n");
    printf("  Hash match: %s\n", memcmp(hash_j, hash_i, 32) == 0 ? "YES" : "NO");

    printf("\nNow testing batch API (hash_first + hash_next):\n");
    memcpy(seed_j, tempHash, 64);
    memcpy(seed_i, tempHash, 64);
    uint8_t blob1[64] = {0};
    memcpy(blob1, "nonce0001", 9);
    uint8_t blob2[64] = {0};
    memcpy(blob2, "nonce0002", 9);

    uint8_t batch_j1[32], batch_j2[32], batch_i1[32], batch_i2[32];
    rx_calculate_hash_first(vm_j, blob1, 64);
    rx_calculate_hash_first(vm_i, blob1, 64);
    rx_calculate_hash_next(vm_j, blob2, 64, batch_j2);
    rx_calculate_hash_next(vm_i, blob2, 64, batch_i2);
    rx_calculate_hash_last(vm_j, batch_j1);
    rx_calculate_hash_last(vm_i, batch_i1);

    printf("  JIT batch hash1:  "); for (int i=0;i<32;i++) printf("%02x",batch_j1[i]); printf("\n");
    printf("  Int batch hash1:  "); for (int i=0;i<32;i++) printf("%02x",batch_i1[i]); printf("\n");
    printf("  Batch hash1 match: %s\n", memcmp(batch_j1, batch_i1, 32) == 0 ? "YES" : "NO");
    printf("  JIT batch hash2:  "); for (int i=0;i<32;i++) printf("%02x",batch_j2[i]); printf("\n");
    printf("  Int batch hash2:  "); for (int i=0;i<32;i++) printf("%02x",batch_i2[i]); printf("\n");
    printf("  Batch hash2 match: %s\n", memcmp(batch_j2, batch_i2, 32) == 0 ? "YES" : "NO");

    rx_destroy_vm(vm_j);
    rx_destroy_vm(vm_i);
    rx_free_dataset(dataset);
    rx_free_cache(cache);
    return 0;
}
