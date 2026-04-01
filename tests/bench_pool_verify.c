#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "crypto/randomx/randomx_internal.h"
#include "common/log.h"

static void hex_decode(const char *hex, uint8_t *out, int max_bytes) {
    int len = (int)strlen(hex);
    for (int i = 0; i < len / 2 && i < max_bytes; i++) {
        char h[3] = { hex[i*2], hex[i*2+1], 0 };
        out[i] = (uint8_t)strtoul(h, NULL, 16);
    }
}

static void print_hash(const char *label, const uint8_t *h) {
    printf("%s: ", label);
    for (int i = 0; i < 32; i++) printf("%02x", h[i]);
    printf("\n");
}

int main() {
    const char *blob_hex = "10109394b4ce061a688af228cdb3ea09b36d48d6661c7d74b7a95a072dfaf689763517537d0aa900000000f8a236f991ec21f849a26d30929765a1aef399ab1b49c39c9079a8cb772c8da018";
    const char *seed_hex = "091af5b650b0b6a2ef6f203aa1d2fdda78f854a9ea7340d714a344be09848e17";

    uint8_t blob[76];
    uint8_t seed[32];
    hex_decode(blob_hex, blob, 76);
    hex_decode(seed_hex, seed, 32);

    int blob_len = 76;
    printf("Blob len: %d\n", blob_len);
    printf("Nonce (LE at offset 39): %02x %02x %02x %02x = %u\n",
           blob[39], blob[40], blob[41], blob[42], *(uint32_t*)(blob+39));

    *(uint32_t*)(blob + 39) = 0x000064de;
    printf("Set nonce to 0x000064de\n");

    rx_cache *cache = rx_alloc_cache(0);
    rx_init_cache(cache, seed, 32);
    printf("Cache initialized\n");

    rx_dataset *dataset = rx_alloc_dataset(0);
    rx_init_dataset_cached(dataset, cache, 0, RX_DATASET_ITEMS, 1, 1);
    printf("Dataset initialized\n");

    rx_vm *vm_interp = rx_create_vm(1, 0, 0, cache, dataset);
    rx_vm *vm_jit = rx_create_vm(1, 1, 0, cache, dataset);

    uint8_t hash_interp[32], hash_jit[32];

    rx_calculate_hash(vm_interp, blob, blob_len, hash_interp);
    rx_calculate_hash(vm_jit, blob, blob_len, hash_jit);

    print_hash("Interp ", hash_interp);
    print_hash("JIT    ", hash_jit);

    int match = memcmp(hash_interp, hash_jit, 32) == 0;
    printf("Match: %s\n", match ? "YES" : "NO");

    uint32_t hv_interp = hash_interp[0] | (hash_interp[1]<<8) | (hash_interp[2]<<16) | (hash_interp[3]<<24);
    uint32_t hv_jit = hash_jit[0] | (hash_jit[1]<<8) | (hash_jit[2]<<16) | (hash_jit[3]<<24);
    printf("hash_val interp: %08x\n", hv_interp);
    printf("hash_val jit:    %08x\n", hv_jit);
    printf("target:          %08x\n", 0x0000e904);

    rx_destroy_vm(vm_interp);
    rx_destroy_vm(vm_jit);
    rx_free_dataset(dataset);
    rx_free_cache(cache);

    return 0;
}
