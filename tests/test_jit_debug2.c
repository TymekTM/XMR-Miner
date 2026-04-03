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

    printf("[TEST1] rx_calculate_hash: interpreter vs JIT\n"); fflush(stdout);
    {
        rx_vm *vm_i = rx_create_vm(RX_FLAG_DEFAULT, cache, dataset);
        rx_vm *vm_j = rx_create_vm(RX_FLAG_JIT, cache, dataset);

        uint8_t hash_i[32], hash_j[32];
        rx_calculate_hash(vm_i, input, strlen(input), hash_i);
        rx_calculate_hash(vm_j, input, strlen(input), hash_j);

        printf("  interp: "); for (int i=0;i<32;i++) printf("%02x",hash_i[i]); printf("\n");
        printf("  jit:   "); for (int i=0;i<32;i++) printf("%02x",hash_j[i]); printf("\n");
        printf("  match: %s\n", memcmp(hash_i, hash_j, 32) == 0 ? "YES" : "NO");

        rx_destroy_vm(vm_i);
        rx_destroy_vm(vm_j);
    }

    printf("\n[TEST2] Single rx_vm_run: interpreter vs JIT register compare\n"); fflush(stdout);
    {
        uint8_t seed[64];
        blake2b(seed, 64, input, strlen(input), NULL, 0);

        rx_vm *vm_i = rx_create_vm(RX_FLAG_DEFAULT, cache, dataset);
        rx_vm *vm_j = rx_create_vm(RX_FLAG_JIT, cache, dataset);

        rx_fill_aes4rx4(seed, sizeof(rx_program), &vm_i->program);
        rx_fill_aes4rx4(seed, sizeof(rx_program), &vm_j->program);
        vm_initialize(vm_i);
        vm_initialize(vm_j);

        rx_vm_init_scratchpad(vm_i, seed);
        rx_vm_init_scratchpad(vm_j, seed);

        printf("  Before: mx_ma interp=0x%016llx jit=0x%016llx\n",
               (unsigned long long)vm_i->mem.mx_ma, (unsigned long long)vm_j->mem.mx_ma);

        rx_vm_run(vm_i, seed);
        rx_vm_run(vm_j, seed);

        printf("  After vm_run:\n");
        int ok = 1;
        for (int i = 0; i < 8; i++) {
            if (vm_i->reg.r[i] != vm_j->reg.r[i]) {
                printf("    R%d: interp=0x%016llx jit=0x%016llx\n", i,
                       (unsigned long long)vm_i->reg.r[i], (unsigned long long)vm_j->reg.r[i]);
                ok = 0;
            }
        }
        printf("    mx_ma: interp=0x%016llx jit=0x%016llx\n",
               (unsigned long long)vm_i->mem.mx_ma, (unsigned long long)vm_j->mem.mx_ma);
        printf("  regs match: %s\n", ok ? "YES" : "NO");

        uint8_t hash_i[32], hash_j[32];
        rx_hash_aes1rx4(vm_i->scratchpad, RX_SCRATCHPAD_L3, &vm_i->reg.a);
        blake2b(hash_i, 32, &vm_i->reg, sizeof(rx_register_file), NULL, 0);
        rx_hash_aes1rx4(vm_j->scratchpad, RX_SCRATCHPAD_L3, &vm_j->reg.a);
        blake2b(hash_j, 32, &vm_j->reg, sizeof(rx_register_file), NULL, 0);
        printf("  single-chain hash match: %s\n", memcmp(hash_i, hash_j, 32) == 0 ? "YES" : "NO");
        if (memcmp(hash_i, hash_j, 32) != 0) {
            hex_dump("    interp", hash_i, 32);
            hex_dump("    jit", hash_j, 32);
        }

        rx_destroy_vm(vm_i);
        rx_destroy_vm(vm_j);
    }

    rx_free_dataset(dataset);
    rx_free_cache(cache);
    return 0;
}
