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

    uint8_t blob[76];
    memset(blob, 0, sizeof(blob));
    blob[0] = 0x10; blob[1] = 0x03; blob[2] = 0xe3;

    printf("[DEBUG] Comparing interpreter vs JIT after rx_vm_run (single chain)\n"); fflush(stdout);

    for (int iter_test = 0; iter_test < 3; iter_test++) {
        uint8_t seed[64];
        blake2b(seed, 64, blob, sizeof(blob), NULL, 0);

        rx_vm *vm_i = rx_create_vm(RX_FLAG_DEFAULT, cache, dataset);
        rx_vm *vm_j = rx_create_vm(RX_FLAG_JIT, cache, dataset);

        rx_fill_aes4rx4(seed, sizeof(rx_program), &vm_i->program);
        rx_fill_aes4rx4(seed, sizeof(rx_program), &vm_j->program);
        vm_initialize(vm_i);
        vm_initialize(vm_j);

        printf("[DEBUG] Test %d: mx_ma=0x%016llx datasetOffset=%u\n", iter_test,
               (unsigned long long)vm_i->mem.mx_ma, (unsigned)vm_i->datasetOffset);
        printf("[DEBUG]   readReg0=%d readReg1=%d readReg2=%d readReg3=%d\n",
               vm_i->config.readReg0, vm_i->config.readReg1, vm_i->config.readReg2, vm_i->config.readReg3);

        rx_vm_init_scratchpad(vm_i, seed);
        rx_vm_init_scratchpad(vm_j, seed);

        rx_vm_run(vm_i, seed);
        rx_vm_run(vm_j, seed);

        int regs_match = 1;
        for (int i = 0; i < 8; i++) {
            if (vm_i->reg.r[i] != vm_j->reg.r[i]) {
                printf("[DEBUG]   R%d MISMATCH: interp=0x%016llx jit=0x%016llx\n",
                       i, (unsigned long long)vm_i->reg.r[i], (unsigned long long)vm_j->reg.r[i]);
                regs_match = 0;
            }
        }
        int fp_match = 1;
        for (int i = 0; i < 4; i++) {
            uint64_t ia = *(uint64_t*)&vm_i->reg.a[i][0];
            uint64_t ja = *(uint64_t*)&vm_j->reg.a[i][0];
            if (ia != ja) {
                printf("[DEBUG]   a[%d] MISMATCH: interp=0x%016llx jit=0x%016llx\n",
                       i, (unsigned long long)ia, (unsigned long long)ja);
                fp_match = 0;
            }
        }
        int mx_match = (vm_i->mem.mx_ma == vm_j->mem.mx_ma);
        if (!mx_match) {
            printf("[DEBUG]   mx_ma MISMATCH: interp=0x%016llx jit=0x%016llx\n",
                   (unsigned long long)vm_i->mem.mx_ma, (unsigned long long)vm_j->mem.mx_ma);
        }

        printf("[DEBUG] Test %d: regs=%s fp=%s mx=%s\n", iter_test,
               regs_match ? "OK" : "FAIL", fp_match ? "OK" : "FAIL", mx_match ? "OK" : "FAIL");

        rx_destroy_vm(vm_i);
        rx_destroy_vm(vm_j);

        blob[39] += 1;
    }

    rx_free_dataset(dataset);
    rx_free_cache(cache);
    printf("[DEBUG] Done\n");
    return 0;
}
