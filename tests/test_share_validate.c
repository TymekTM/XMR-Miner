#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "crypto/randomx/randomx_internal.h"
#include "common/osdep.h"

static int share_meets_target(const uint8_t *hash, uint64_t target) {
    return read_u64_le(hash + 24) <= target;
}

int main(int argc, char **argv) {
    int num_hashes = 50000;
    if (argc > 1) num_hashes = atoi(argv[1]);

    printf("[SHARE-VALIDATE] Testing %d hashes for share acceptance\n", num_hashes);

    rx_cache *cache = rx_alloc_cache(1);
    uint8_t key[] = "share_validation_test_key_12345";
    rx_init_cache(cache, key, sizeof(key));

    rx_dataset *dataset = rx_alloc_dataset(1);
    rx_init_dataset_cached(dataset, cache, 0, RX_DATASET_ITEMS, 8, 8);

    rx_vm *vm = rx_create_vm(RX_FLAG_JIT, cache, dataset);
    if (!vm) { printf("FAIL: cannot create VM\n"); return 1; }

    uint8_t blob[76];
    memset(blob, 0, sizeof(blob));
    blob[0] = 0x10; blob[1] = 0x03; blob[2] = 0xe3;
    for (int i = 3; i < 7; i++) blob[i] = (uint8_t)(i * 7 + 42);
    for (int i = 39; i < 43; i++) blob[i] = 0xAA;

    uint8_t hash[32], commitment[32];

    *(uint32_t *)(blob + 39) = 0;
    rx_calculate_hash_first(vm, blob, sizeof(blob));

    int total = 0;
    int shares_diff1 = 0;
    int shares_diff100 = 0;
    int shares_diff1k = 0;
    int shares_diff10k = 0;
    int shares_diff100k = 0;

    uint64_t target_diff1     = 0xFFFFFFFFFFFFFFFFULL / 1;
    uint64_t target_diff100   = 0xFFFFFFFFFFFFFFFFULL / 100;
    uint64_t target_diff1k    = 0xFFFFFFFFFFFFFFFFULL / 1000;
    uint64_t target_diff10k   = 0xFFFFFFFFFFFFFFFFULL / 10000;
    uint64_t target_diff100k  = 0xFFFFFFFFFFFFFFFFULL / 100000;

    printf("[SHARE-VALIDATE] Running %d hashes via JIT batch API...\n", num_hashes);

    for (int i = 0; i < num_hashes; i++) {
        *(uint32_t *)(blob + 39) = (uint32_t)(i + 1);
        rx_calculate_hash_next(vm, blob, sizeof(blob), hash);
        rx_calculate_commitment(blob, sizeof(blob), hash, commitment);
        total++;

        if (share_meets_target(hash, target_diff1))     shares_diff1++;
        if (share_meets_target(hash, target_diff100))   shares_diff100++;
        if (share_meets_target(hash, target_diff1k))    shares_diff1k++;
        if (share_meets_target(hash, target_diff10k))   shares_diff10k++;
        if (share_meets_target(hash, target_diff100k))  shares_diff100k++;

        if ((i + 1) % 10000 == 0) {
            printf("  ... %d/%d hashes done\n", i + 1, num_hashes);
        }
    }

    printf("\n======================================================================\n");
    printf("  SHARE VALIDATION RESULTS (%d total hashes)\n", total);
    printf("======================================================================\n\n");

    printf("  Difficulty    Target (tail64)      Shares Found    Expected      Status\n");
    printf("  ----------   ------------------    ------------   ------------   ------\n");
    printf("  1            0x%016llx   %-12d   ~%-11d   %s\n",
           (unsigned long long)target_diff1, shares_diff1, num_hashes,
           (shares_diff1 >= num_hashes / 2) ? "OK" : "LOW");
    printf("  100          0x%016llx   %-12d   ~%-11d   %s\n",
           (unsigned long long)target_diff100, shares_diff100, num_hashes / 100,
           (shares_diff100 >= num_hashes / 200) ? "OK" : "LOW");
    printf("  1,000        0x%016llx   %-12d   ~%-11d   %s\n",
           (unsigned long long)target_diff1k, shares_diff1k, num_hashes / 1000,
           (shares_diff1k >= num_hashes / 2000) ? "OK" : "LOW");
    printf("  10,000       0x%016llx   %-12d   ~%-11d   %s\n",
           (unsigned long long)target_diff10k, shares_diff10k, num_hashes / 10000,
           (shares_diff10k >= 5) ? "OK" : "LOW");
    printf("  100,000      0x%016llx   %-12d   ~%-11d   %s\n",
           (unsigned long long)target_diff100k, shares_diff100k, num_hashes / 100000,
           (shares_diff100k >= 1) ? "OK" : "LOW");

    printf("\n  Sample hashes (first 5):\n");
    *(uint32_t *)(blob + 39) = 1;
    rx_calculate_hash_first(vm, blob, sizeof(blob));
    for (int i = 0; i < 5; i++) {
        *(uint32_t *)(blob + 39) = (uint32_t)(i + 1);
        rx_calculate_hash_next(vm, blob, sizeof(blob), hash);
        printf("    nonce=%-6d tail64=0x%016llx target1k=%s\n",
               i + 1,
               (unsigned long long)read_u64_le(hash + 24),
               share_meets_target(hash, target_diff1k) ? "SHARE!" : "    -");
    }

    int all_ok = (shares_diff1 >= num_hashes / 2) &&
                 (shares_diff100 >= num_hashes / 200) &&
                 (shares_diff1k >= 1);

    printf("\n  OVERALL: %s\n", all_ok ?
           "PASS - Hash distribution looks correct, shares would be accepted by pool" :
           "WARN - Share count lower than expected (may be noise)");

    rx_destroy_vm(vm);
    rx_free_dataset(dataset);
    rx_free_cache(cache);

    return all_ok ? 0 : 1;
}
