#include "crypto/randomx/randomx.h"
#include "crypto/randomx/randomx_internal.h"
#include "crypto/blake2/blake2b.h"
#include <stdio.h>
#include <string.h>
#include <windows.h>

static void print_hash(const char *label, const uint8_t *hash, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) printf("%02x", hash[i]);
    printf("\n");
    fflush(stdout);
}

int main(void) {
    const char *key = "test key 000";
    size_t key_len = strlen(key);

    printf("=== Debug RandomX Interpreter ===\n\n");
    fflush(stdout);

    rx_cache *cache = rx_alloc_cache(0);
    if (!cache) { printf("[FAIL] cache\n"); return 1; }

    printf("Init cache...\n"); fflush(stdout);
    rx_init_cache(cache, key, key_len);
    printf("Cache ready\n"); fflush(stdout);

    rx_vm *vm = rx_create_vm(0, 0, 0, cache, NULL);
    if (!vm) { printf("[FAIL] vm\n"); return 1; }

    const char *input = "This is a test";
    size_t input_len = strlen(input);

    uint8_t tempHash[64];
    memset(tempHash, 0, sizeof(tempHash));
    blake2b(tempHash, 64, input, input_len, NULL, 0);
    print_hash("blake2b(input)", tempHash, 64);

    rx_vm_init_scratchpad(vm, tempHash);
    print_hash("scratchpad[0:64]", vm->scratchpad, 64);
    print_hash("scratchpad[64:128]", vm->scratchpad + 64, 64);

    rx_fill_aes4rx4(tempHash, sizeof(rx_program), &vm->program);
    print_hash("program.entropy[0:64]", (uint8_t*)vm->program.entropyBuffer, 64);
    print_hash("program.instr[0:64]", (uint8_t*)vm->program.programBuffer, 64);

    rx_reset_float_state();
    for (int chain = 0; chain < RX_PROGRAM_COUNT - 1; chain++) {
        rx_vm_run(vm, tempHash);
        blake2b(tempHash, 64, &vm->reg, sizeof(rx_register_file), NULL, 0);
        printf("After chain %d:\n", chain);
        print_hash("  tempHash", tempHash, 64);
        printf("  reg.r[0]=%016llx\n", (unsigned long long)vm->reg.r[0]);
        printf("  reg.r[1]=%016llx\n", (unsigned long long)vm->reg.r[1]);
    }
    rx_vm_run(vm, tempHash);

    uint8_t final_hash[32];
    rx_vm_get_final_result(vm, final_hash);
    print_hash("final hash", final_hash, 32);

    printf("\nExpected: 639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f\n");

    rx_destroy_vm(vm);
    rx_free_cache(cache);
    return 0;
}
