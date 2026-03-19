#include "crypto/randomx/randomx.h"
#include "crypto/randomx/randomx_internal.h"
#include "crypto/blake2/blake2b.h"
#include "crypto/blake2/blake2_generator.h"
#include "crypto/keccak/keccak.h"
#include "common/log.h"
#include "common/osdep.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <excpt.h>

static int check_u64(const char *label, uint64_t actual, uint64_t expected) {
    if (actual == expected) {
        printf("[PASS] %s\n", label);
        return 0;
    }
    printf("[FAIL] %s\n", label);
    printf("  expected: %016llx\n", (unsigned long long)expected);
    printf("  got:      %016llx\n", (unsigned long long)actual);
    return 1;
}

static int check_hex(const char *label, const uint8_t *actual, size_t len, const char *expected_hex) {
    uint8_t expected[64];
    int exp_len = (int)strlen(expected_hex) / 2;
    if (exp_len < 0 || (size_t)exp_len != len) {
        printf("[FAIL] %s - invalid expected hex\n", label);
        return 1;
    }
    for (int i = 0; i < exp_len; i++) {
        unsigned int byte;
        sscanf(expected_hex + 2 * i, "%2x", &byte);
        expected[i] = (uint8_t)byte;
    }
    if (memcmp(actual, expected, len) == 0) {
        printf("[PASS] %s\n", label);
        return 0;
    }
    printf("[FAIL] %s\n", label);
    printf("  expected: %s\n", expected_hex);
    printf("  got:      ");
    for (size_t i = 0; i < len; i++) printf("%02x", actual[i]);
    printf("\n");
    return 1;
}

int main(void) {
    int failures = 0;

    printf("[I] === RandomX Tests ===\n");

    const char *ss_references[10] = {
        "d3a4a6623738756f77e6104469102f082eff2a3e60be7ad696285ef7dfc72a61",
        "f5e7e0bbc7e93c609003d6359208688070afb4a77165a552ff7be63b38dfbc86",
        "85ed8b11734de5b3e9836641413a8f36e99e89694f419c8cd25c3f3f16c40c5a",
        "5dd956292cf5d5704ad99e362d70098b2777b2a1730520be52f772ca48cd3bc0",
        "6f14018ca7d519e9b48d91af094c0f2d7e12e93af0228782671a8640092af9e5",
        "134be097c92e2c45a92f23208cacd89e4ce51f1009a0b900dbe83b38de11d791",
        "268f9392c20c6e31371a5131f82bd7713d3910075f2f0468baafaa1abd2f3187",
        "c668a05fd909714ed4a91e8d96d67b17e44329e88bc71e0672b529a3fc16be47",
        "99739351315840963011e4c5d8e90ad0bfed3facdcb713fe8f7138fbf01c4c94",
        "14ab53d61880471f66e80183968d97effd5492b406876060e595fcf9682f9295",
    };

    printf("[I] SuperscalarHash generator test...\n");
    fflush(stdout);
    {
        blake2_gen gen;
        blake2_gen_init(&gen, "test key 000", 12);
        rx_superscalar_program prog0;
        memset(&prog0, 0, sizeof(prog0));
        generate_superscalar(&prog0, &gen);
        printf("[I] Program 0: size=%u addrReg=%d\n", prog0.size, prog0.addrReg);
        fflush(stdout);
        uint8_t sprogHash[32];
        blake2b(sprogHash, 32, prog0.buffer, sizeof(rx_instruction) * prog0.size, NULL, 0);
        failures += check_hex("SuperscalarHash program 0", sprogHash, 32, ss_references[0]);
        for (int i = 1; i < 10; i++) {
            rx_superscalar_program prog;
            memset(&prog, 0, sizeof(prog));
            generate_superscalar(&prog, &gen);
            uint8_t sprogHash2[32];
            blake2b(sprogHash2, 32, prog.buffer, sizeof(rx_instruction) * prog.size, NULL, 0);
            char label[64];
            sprintf(label, "SuperscalarHash program %d", i);
            failures += check_hex(label, sprogHash2, 32, ss_references[i]);
        }
    }

    rx_cache *cache = rx_alloc_cache(0);
    if (!cache) {
        printf("[FAIL] Failed to allocate cache (256 MB)\n");
        return 1;
    }
    printf("[I] Cache allocated (%d MB)\n", (int)(RX_CACHE_SIZE / (1024 * 1024)));

    const char *key = "test key 000";
    size_t key_len = strlen(key);

    printf("[I] Initializing cache (Argon2d 262144 KiB, this takes ~30 seconds)...\n");
    fflush(stdout);
    rx_init_cache(cache, key, key_len);
    fflush(stdout);
    printf("[I] Cache initialized\n");
    fflush(stdout);

    uint8_t *cacheMem = (uint8_t *)rx_get_cache_memory(cache);

    uint64_t val0;
    memcpy(&val0, cacheMem, 8);
    failures += check_u64("Cache offset 0", val0, 0x191e0e1d23c02186ULL);

    uint64_t val1568413;
    memcpy(&val1568413, cacheMem + 1568413 * 8, 8);
    failures += check_u64("Cache offset 1568413", val1568413, 0xf1b62fe6210bf8b1ULL);

    uint64_t val33554431;
    memcpy(&val33554431, cacheMem + 33554431 * 8, 8);
    failures += check_u64("Cache offset 33554431", val33554431, 0x1f47f056d05cd99bULL);

    rx_vm *vm = rx_create_vm(0, 0, 0, cache, NULL);
    if (!vm) {
        printf("[FAIL] Failed to create VM\n");
        rx_free_cache(cache);
        return 1;
    }
    printf("[I] VM created (light mode)\n");

    const char *input1 = "This is a test";
    size_t input1_len = strlen(input1);
    uint8_t hash1[32];
    printf("[I] Calculating hash for 'This is a test' (light mode, ~30 seconds)...\n");
    fflush(stdout);
    rx_calculate_hash(vm, input1, input1_len, hash1);
    fflush(stdout);
    failures += check_hex("Hash 'This is a test'",
        hash1, 32,
        "639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f");

    const char *input2 = "Lorem ipsum dolor sit amet";
    size_t input2_len = strlen(input2);
    uint8_t hash2[32];
    printf("[I] Calculating hash for 'Lorem ipsum dolor sit amet'...\n");
    fflush(stdout);
    rx_calculate_hash(vm, input2, input2_len, hash2);
    fflush(stdout);
    failures += check_hex("Hash 'Lorem ipsum dolor sit amet'",
        hash2, 32,
        "300a0adb47603dedb42228ccb2b211104f4da45af709cd7547cd049e9489c969");

    rx_destroy_vm(vm);
    rx_free_cache(cache);

    printf("[I] === JIT Compilation Test ===\n");
    fflush(stdout);
    {
        uint8_t test_seed[32] = {0x01};
        rx_cache *jit_cache = rx_alloc_cache(0);
        if (!jit_cache) { printf("[FAIL] JIT test: cache alloc failed\n"); }
        else {
            rx_init_cache(jit_cache, test_seed, 32);
            rx_vm *jit_vm = rx_create_vm(1, 1, 0, jit_cache, NULL);
            if (!jit_vm) { printf("[FAIL] JIT test: VM alloc failed\n"); }
            else {
                printf("[I] Testing JIT compilation only (no dataset for execution)...\n");
                fflush(stdout);
                __try {
                    extern void rx_jit_generate_program(rx_jit*, rx_program*, rx_program_config*);
                    extern rx_jit *rx_jit_create(void);
                    extern void rx_jit_destroy(rx_jit *jit);
                    rx_jit *jit = rx_jit_create();
                    if (jit) {
                        rx_jit_generate_program(jit, &jit_vm->program, &jit_vm->config);
                        printf("[PASS] JIT compilation succeeded\n");
                        rx_jit_destroy(jit);
                    } else {
                        printf("[FAIL] JIT alloc failed\n");
                    }
                } __except(EXCEPTION_EXECUTE_HANDLER) {
                    printf("[FAIL] JIT crashed with exception 0x%08lx\n", GetExceptionCode());
                }
                fflush(stdout);
                rx_destroy_vm(jit_vm);
            }
            rx_free_cache(jit_cache);
        }
    }

    printf("[I] === Keccak-256 Tests ===\n");
    fflush(stdout);

    uint8_t keccak_hash[32];

    keccak256((const uint8_t *)"", 0, keccak_hash);
    failures += check_hex("keccak256('')", keccak_hash, 32,
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");

    keccak256((const uint8_t *)"abc", 3, keccak_hash);
    failures += check_hex("keccak256('abc')", keccak_hash, 32,
        "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");

    keccak256((const uint8_t *)"\x00", 1, keccak_hash);
    failures += check_hex("keccak256(0x00)", keccak_hash, 32,
        "bc36789e7a1e281436464229828f817d6612f7b477d66591ff96a9e064bcc98a");

    printf("[I] === Results: %d failures ===\n", failures);
    return failures;
}
