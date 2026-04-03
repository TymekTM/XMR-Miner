#include "crypto/randomx/randomx.h"
#include "crypto/randomx/randomx_internal.h"
#include <stdio.h>
#include <string.h>
#include <windows.h>

static void hex_dump(const char *label, const uint8_t *data, int len) {
    printf("  %s: ", label);
    for (int i = 0; i < len; i++) printf("%02x", data[i]);
    printf("\n");
}

int main(void) {
    const char *key = "test key 000";
    size_t key_len = strlen(key);

    rx_cache *cache = rx_alloc_cache(0);
    rx_init_cache(cache, key, key_len);

    rx_dataset *dataset = rx_alloc_dataset(0);
    rx_init_dataset(dataset, cache, 0, RX_DATASET_ITEMS + RX_DATASET_EXTRA_ITEMS, 8, 8);

    const char *input = "This is a test";

    printf("[TEST] rx_vm_run then check: does JIT modify vm->reg?\n"); fflush(stdout);
    {
        uint8_t tempHash[64];
        blake2b(tempHash, 64, input, strlen(input), NULL, 0);

        rx_vm *vm_j = rx_create_vm(RX_FLAG_JIT, cache, dataset);

        rx_vm_init_scratchpad(vm_j, tempHash);

        uint8_t reg_before[256];
        memset(reg_before, 0, sizeof(reg_before));
        memcpy(reg_before, &vm_j->reg, sizeof(rx_register_file));

        printf("  Before vm_run: R0=0x%016llx mx_ma=0x%016llx\n",
               (unsigned long long)vm_j->reg.r[0],
               (unsigned long long)vm_j->mem.mx_ma);

        rx_vm_run(vm_j, tempHash);

        printf("  After vm_run:  R0=0x%016llx mx_ma=0x%016llx\n",
               (unsigned long long)vm_j->reg.r[0],
               (unsigned long long)vm_j->mem.mx_ma);

        int changed = (memcmp(reg_before, &vm_j->reg, sizeof(rx_register_file)) != 0);
        printf("  Registers changed by JIT: %s\n", changed ? "YES" : "NO");

        uint8_t hash_after[32];
        rx_hash_aes1rx4(vm_j->scratchpad, RX_SCRATCHPAD_L3, &vm_j->reg.a);
        blake2b(hash_after, 32, &vm_j->reg, sizeof(rx_register_file), NULL, 0);
        hex_dump("  hash_after_vm_run", hash_after, 32);

        rx_destroy_vm(vm_j);
    }

    printf("\n[TEST] rx_calculate_hash with JIT\n"); fflush(stdout);
    {
        rx_vm *vm_j = rx_create_vm(RX_FLAG_JIT, cache, dataset);

        uint8_t hash[32];
        rx_calculate_hash(vm_j, input, strlen(input), hash);
        hex_dump("  hash_calc", hash, 32);

        printf("  R0=0x%016llx mx_ma=0x%016llx\n",
               (unsigned long long)vm_j->reg.r[0],
               (unsigned long long)vm_j->mem.mx_ma);

        rx_destroy_vm(vm_j);
    }

    printf("\n[TEST] Manual chain simulation with JIT\n"); fflush(stdout);
    {
        uint8_t tempHash[64];
        blake2b(tempHash, 64, input, strlen(input), NULL, 0);

        rx_vm *vm_j = rx_create_vm(RX_FLAG_JIT, cache, dataset);

        rx_vm_init_scratchpad(vm_j, tempHash);

        printf("  Running chain 0 (rx_vm_run)...\n"); fflush(stdout);
        rx_vm_run(vm_j, tempHash);

        printf("  After chain 0: R0=0x%016llx mx_ma=0x%016llx\n",
               (unsigned long long)vm_j->reg.r[0],
               (unsigned long long)vm_j->mem.mx_ma);

        blake2b(tempHash, 64, &vm_j->reg, sizeof(rx_register_file), NULL, 0);
        printf("  tempHash after chain 0: "); for (int i=0;i<8;i++) printf("%02x",tempHash[i]); printf("...\n");

        printf("  Running chain 1 (rx_vm_run)...\n"); fflush(stdout);
        rx_vm_run(vm_j, tempHash);

        printf("  After chain 1: R0=0x%016llx mx_ma=0x%016llx\n",
               (unsigned long long)vm_j->reg.r[0],
               (unsigned long long)vm_j->mem.mx_ma);

        rx_vm_run(vm_j, tempHash);
        printf("  After chain 2 (final): R0=0x%016llx mx_ma=0x%016llx\n",
               (unsigned long long)vm_j->reg.r[0],
               (unsigned long long)vm_j->mem.mx_ma);

        uint8_t hash[32];
        rx_hash_aes1rx4(vm_j->scratchpad, RX_SCRATCHPAD_L3, &vm_j->reg.a);
        blake2b(hash, 32, &vm_j->reg, sizeof(rx_register_file), NULL, 0);
        hex_dump("  manual_final_hash", hash, 32);

        rx_destroy_vm(vm_j);
    }

    rx_free_dataset(dataset);
    rx_free_cache(cache);
    return 0;
}
