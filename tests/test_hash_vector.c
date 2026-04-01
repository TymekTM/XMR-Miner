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

static int hex_match(const uint8_t *a, const uint8_t *b, int len) {
    return memcmp(a, b, len) == 0;
}

int main(void) {
    const char *key = "test key 000";
    size_t key_len = strlen(key);

    printf("[TEST] Key: \"%s\" (%d bytes)\n", key, (int)key_len);

    printf("[TEST] Allocating cache...\n"); fflush(stdout);
    rx_cache *cache = rx_alloc_cache(0);
    if (!cache) { printf("[FAIL] cache alloc\n"); return 1; }

    printf("[TEST] Initializing cache...\n"); fflush(stdout);
    rx_init_cache(cache, key, key_len);

    printf("[TEST] Allocating dataset...\n"); fflush(stdout);
    rx_dataset *dataset = rx_alloc_dataset(0);
    if (!dataset) { printf("[FAIL] dataset alloc\n"); return 1; }

    printf("[TEST] Initializing dataset (this takes ~60s)...\n"); fflush(stdout);
    rx_init_dataset(dataset, cache, 0, RX_DATASET_ITEMS + RX_DATASET_EXTRA_ITEMS, 8, 8);

    int pass = 1;

    printf("[TEST] === V1 (interpreter, light) ===\n"); fflush(stdout);
    {
        rx_vm *vm = rx_create_vm(RX_FLAG_DEFAULT, cache, NULL);
        if (!vm) { printf("[FAIL] VM alloc\n"); return 1; }

        uint8_t hash[32];
        const char *input1 = "This is a test";
        rx_calculate_hash(vm, input1, strlen(input1), hash);
        hex_dump("hash1", hash, 32);

        uint8_t expected1[] = {
            0x63, 0x91, 0x83, 0xaa, 0xe1, 0xbf, 0x4c, 0x9a,
            0x35, 0x88, 0x4c, 0xb4, 0x6b, 0x09, 0xca, 0xd9,
            0x17, 0x5f, 0x04, 0xef, 0xd7, 0x68, 0x4e, 0x72,
            0x62, 0xa0, 0xac, 0x1c, 0x2f, 0x0b, 0x4e, 0x3f,
        };
        printf("  expected: ");
        for (int i = 0; i < 32; i++) printf("%02x", expected1[i]);
        printf("\n  match: %s\n", hex_match(hash, expected1, 32) ? "YES" : "NO");
        if (!hex_match(hash, expected1, 32)) pass = 0;

        const char *input2 = "Lorem ipsum dolor sit amet";
        rx_calculate_hash(vm, input2, strlen(input2), hash);
        hex_dump("hash2", hash, 32);

        uint8_t expected2[] = {
            0x30, 0x0a, 0x0a, 0xdb, 0x47, 0x60, 0x3d, 0xed,
            0xb4, 0x22, 0x28, 0xcc, 0xb2, 0xb2, 0x11, 0x10,
            0x4f, 0x4d, 0xa4, 0x5a, 0xf7, 0x09, 0xcd, 0x75,
            0x47, 0xcd, 0x04, 0x9e, 0x94, 0x89, 0xc9, 0x69,
        };
        printf("  expected: ");
        for (int i = 0; i < 32; i++) printf("%02x", expected2[i]);
        printf("\n  match: %s\n", hex_match(hash, expected2, 32) ? "YES" : "NO");
        if (!hex_match(hash, expected2, 32)) pass = 0;

        rx_destroy_vm(vm);
    }

    printf("\n[TEST] === Dataset integrity check ===\n"); fflush(stdout);
    {
        uint8_t itemBuf[64] = {0};
        int dsPass = 1;
        for (uint64_t itemNum = 0; itemNum < 20; itemNum++) {
            rx_init_dataset_item(cache, itemBuf, itemNum);
            uint8_t *dsMem = (uint8_t *)rx_get_dataset_memory(dataset) + itemNum * 64;
            if (memcmp(itemBuf, dsMem, 64) != 0) {
                printf("  MISMATCH at item %llu:\n", (unsigned long long)itemNum);
                hex_dump("  init_item", itemBuf, 64);
                hex_dump("  ds_memory", dsMem, 64);
                dsPass = 0;
                break;
            }
        }
        if (dsPass) printf("  First 20 items match: YES\n");
        if (!dsPass) pass = 0;

        uint64_t total_items = (RX_DATASET_BASE_SIZE + 33554368ULL) / 64;
        printf("  Total dataset items: %llu\n", (unsigned long long)total_items);
        printf("  Dataset memory size: %llu MB\n", (unsigned long long)((RX_DATASET_BASE_SIZE + 33554368ULL) / (1024*1024)));
        printf("  RX_DATASET_BASE_SIZE: %llu\n", (unsigned long long)RX_DATASET_BASE_SIZE);
        printf("  RX_DATASET_EXTRA_SIZE: %llu\n", (unsigned long long)33554368ULL);
        printf("  RX_CACHE_LINE_ALIGN_MASK: 0x%08x\n", (unsigned int)((RX_DATASET_BASE_SIZE - 1) & ~(64 - 1)));
    }

    printf("\n[TEST] === Full VM vs Light VM first iteration debug ===\n"); fflush(stdout);
    {
        const char *input = "This is a test";
        uint8_t tempHash[64];
        blake2b(tempHash, 64, input, strlen(input), NULL, 0);

        rx_vm *vm_light = rx_create_vm(RX_FLAG_DEFAULT, cache, NULL);
        rx_vm *vm_full = rx_create_vm(RX_FLAG_DEFAULT, cache, dataset);

        rx_fill_aes4rx4(tempHash, sizeof(rx_program), &vm_light->program);
        rx_fill_aes4rx4(tempHash, sizeof(rx_program), &vm_full->program);

        vm_initialize(vm_light);
        vm_initialize(vm_full);

        printf("  light mem.mx_ma: 0x%016llx\n", (unsigned long long)vm_light->mem.mx_ma);
        printf("  full  mem.mx_ma: 0x%016llx\n", (unsigned long long)vm_full->mem.mx_ma);
        printf("  light datasetOffset: %u\n", (unsigned)vm_light->datasetOffset);
        printf("  full  datasetOffset: %u\n", (unsigned)vm_full->datasetOffset);
        printf("  light lightClient: %d\n", vm_light->lightClient);
        printf("  full  lightClient: %d\n", vm_full->lightClient);
        printf("  light fullMem: %d\n", vm_light->fullMem);
        printf("  full  fullMem: %d\n", vm_full->fullMem);
        printf("  light flagV2: %d\n", vm_light->flagV2);
        printf("  full  flagV2: %d\n", vm_full->flagV2);

        for (int i = 0; i < 8; i++) {
            int rv = -1;
            if (i == vm_light->config.readReg0) rv = 0;
            else if (i == vm_light->config.readReg1) rv = 1;
            else if (i == vm_light->config.readReg2) rv = 2;
            else if (i == vm_light->config.readReg3) rv = 3;
            printf("  reg%d: light_readReg=%d full_readReg=%d\n", i, rv, rv);
        }

        printf("  light prog size: %d\n", vm_light->flagV2 ? 384 : 256);
        printf("  full  prog size: %d\n", vm_full->flagV2 ? 384 : 256);

        printf("  Program entropy (first 16): ");
        for (int i = 0; i < 16; i++) printf("%016llx ", (unsigned long long)vm_light->program.entropyBuffer[i]);
        printf("\n");
        printf("  Full   entropy (first 16): ");
        for (int i = 0; i < 16; i++) printf("%016llx ", (unsigned long long)vm_full->program.entropyBuffer[i]);
        printf("\n");

        int entropyMatch = 1;
        for (int i = 0; i < 256; i++) {
            if (vm_light->program.entropyBuffer[i] != vm_full->program.entropyBuffer[i]) {
                printf("  Entropy MISMATCH at index %d: light=%016llx full=%016llx\n",
                    i, (unsigned long long)vm_light->program.entropyBuffer[i], (unsigned long long)vm_full->program.entropyBuffer[i]);
                entropyMatch = 0;
                break;
            }
        }
        if (entropyMatch) printf("  Entropy buffers match: YES\n");

        rx_destroy_vm(vm_light);
        rx_destroy_vm(vm_full);
    }

    printf("\n[TEST] === V1 (interpreter, full VM) ===\n"); fflush(stdout);
    {
        rx_vm *vm = rx_create_vm(RX_FLAG_DEFAULT, cache, dataset);
        if (!vm) { printf("[FAIL] VM alloc\n"); return 1; }

        uint8_t hash[32];
        const char *input1 = "This is a test";
        rx_calculate_hash(vm, input1, strlen(input1), hash);
        hex_dump("hash1", hash, 32);

        uint8_t expected1[] = {
            0x63, 0x91, 0x83, 0xaa, 0xe1, 0xbf, 0x4c, 0x9a,
            0x35, 0x88, 0x4c, 0xb4, 0x6b, 0x09, 0xca, 0xd9,
            0x17, 0x5f, 0x04, 0xef, 0xd7, 0x68, 0x4e, 0x72,
            0x62, 0xa0, 0xac, 0x1c, 0x2f, 0x0b, 0x4e, 0x3f,
        };
        printf("  expected: ");
        for (int i = 0; i < 32; i++) printf("%02x", expected1[i]);
        printf("\n  match: %s\n", hex_match(hash, expected1, 32) ? "YES" : "NO");
        if (!hex_match(hash, expected1, 32)) pass = 0;

        const char *input2 = "Lorem ipsum dolor sit amet";
        rx_calculate_hash(vm, input2, strlen(input2), hash);
        hex_dump("hash2", hash, 32);

        uint8_t expected2[] = {
            0x30, 0x0a, 0x0a, 0xdb, 0x47, 0x60, 0x3d, 0xed,
            0xb4, 0x22, 0x28, 0xcc, 0xb2, 0xb2, 0x11, 0x10,
            0x4f, 0x4d, 0xa4, 0x5a, 0xf7, 0x09, 0xcd, 0x75,
            0x47, 0xcd, 0x04, 0x9e, 0x94, 0x89, 0xc9, 0x69,
        };
        printf("  expected: ");
        for (int i = 0; i < 32; i++) printf("%02x", expected2[i]);
        printf("\n  match: %s\n", hex_match(hash, expected2, 32) ? "YES" : "NO");
        if (!hex_match(hash, expected2, 32)) pass = 0;

        rx_destroy_vm(vm);
    }

    printf("\n[TEST] === V2 (interpreter, light) ===\n"); fflush(stdout);
    {
        rx_vm *vm = rx_create_vm(RX_FLAG_V2, cache, NULL);
        if (!vm) { printf("[FAIL] VM alloc\n"); return 1; }

        uint8_t hash[32];
        const char *input1 = "This is a test";
        rx_calculate_hash(vm, input1, strlen(input1), hash);
        hex_dump("hash1", hash, 32);

        uint8_t expected1[] = {
            0x22, 0xec, 0x6b, 0x86, 0x1b, 0x3e, 0xb2, 0x36,
            0x86, 0xb2, 0xef, 0xba, 0xd6, 0x95, 0x13, 0xc9,
            0x67, 0xec, 0xfc, 0xe8, 0x09, 0x83, 0xdf, 0x66,
            0xc9, 0xc5, 0xb4, 0xfb, 0xfb, 0x4c, 0xdb, 0x6f,
        };
        printf("  expected: ");
        for (int i = 0; i < 32; i++) printf("%02x", expected1[i]);
        printf("\n  match: %s\n", hex_match(hash, expected1, 32) ? "YES" : "NO");
        if (!hex_match(hash, expected1, 32)) pass = 0;

        const char *input2 = "Lorem ipsum dolor sit amet";
        rx_calculate_hash(vm, input2, strlen(input2), hash);
        hex_dump("hash2", hash, 32);

        uint8_t expected2[] = {
            0x9e, 0x2c, 0x77, 0x2c, 0x12, 0xfd, 0x48, 0xf9,
            0x3c, 0x14, 0xc9, 0x7f, 0xdc, 0x89, 0xd5, 0x56,
            0x26, 0x4d, 0x91, 0x00, 0x59, 0x70, 0x23, 0xf4,
            0x4d, 0x91, 0x63, 0xe2, 0x79, 0x01, 0x2e, 0xcf,
        };
        printf("  expected: ");
        for (int i = 0; i < 32; i++) printf("%02x", expected2[i]);
        printf("\n  match: %s\n", hex_match(hash, expected2, 32) ? "YES" : "NO");
        if (!hex_match(hash, expected2, 32)) pass = 0;

        rx_destroy_vm(vm);
    }

    printf("\n[TEST] === V2 (interpreter, full VM) ===\n"); fflush(stdout);
    {
        rx_vm *vm = rx_create_vm(RX_FLAG_V2, cache, dataset);
        if (!vm) { printf("[FAIL] VM alloc\n"); return 1; }

        uint8_t hash[32];
        const char *input1 = "This is a test";
        rx_calculate_hash(vm, input1, strlen(input1), hash);
        hex_dump("hash1", hash, 32);

        uint8_t expected1[] = {
            0x22, 0xec, 0x6b, 0x86, 0x1b, 0x3e, 0xb2, 0x36,
            0x86, 0xb2, 0xef, 0xba, 0xd6, 0x95, 0x13, 0xc9,
            0x67, 0xec, 0xfc, 0xe8, 0x09, 0x83, 0xdf, 0x66,
            0xc9, 0xc5, 0xb4, 0xfb, 0xfb, 0x4c, 0xdb, 0x6f,
        };
        printf("  expected: ");
        for (int i = 0; i < 32; i++) printf("%02x", expected1[i]);
        printf("\n  match: %s\n", hex_match(hash, expected1, 32) ? "YES" : "NO");
        if (!hex_match(hash, expected1, 32)) pass = 0;

        rx_destroy_vm(vm);
    }

    printf("\n[TEST] === Commitment test ===\n"); fflush(stdout);
    {
        rx_vm *vm = rx_create_vm(RX_FLAG_V2, cache, NULL);
        if (!vm) { printf("[FAIL] VM alloc\n"); return 1; }

        uint8_t hash[32], commitment[32];
        const char *input = "This is a test";
        rx_calculate_hash(vm, input, strlen(input), hash);
        rx_calculate_commitment(input, strlen(input), hash, commitment);
        hex_dump("commitment", commitment, 32);

        uint8_t expected[] = {
            0x13, 0x3b, 0xe7, 0x17, 0x39, 0x90, 0x46, 0xb0,
            0x3a, 0xe8, 0x2c, 0xe8, 0xdd, 0xd9, 0xd1, 0xee,
            0x4d, 0x3e, 0xa7, 0xfc, 0xa0, 0x3a, 0x50, 0xde,
            0xc0, 0x9b, 0x68, 0x48, 0xcb, 0xb9, 0x8e, 0x18,
        };
        printf("  expected: ");
        for (int i = 0; i < 32; i++) printf("%02x", expected[i]);
        printf("\n  match: %s\n", hex_match(commitment, expected, 32) ? "YES" : "NO");
        if (!hex_match(commitment, expected, 32)) pass = 0;

        rx_destroy_vm(vm);
    }

    rx_destroy_vm(NULL);
    rx_free_dataset(dataset);
    rx_free_cache(cache);

    printf("\n[TEST] Overall: %s\n", pass ? "PASS" : "FAIL");
    return pass ? 0 : 1;
}
