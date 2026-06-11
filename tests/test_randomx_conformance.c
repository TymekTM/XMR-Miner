#include "crypto/randomx/randomx.h"

#include <immintrin.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HASH_SIZE 32
#define GUARD_SIZE 16
#define MAX_INPUT_SIZE 1024

typedef struct {
    uint8_t guard_before[GUARD_SIZE];
    uint8_t hash[HASH_SIZE];
    uint8_t guard_after[GUARD_SIZE];
} guarded_hash;

static int checks = 0;
static int failures = 0;

static void print_hex(const uint8_t *data, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        printf("%02x", data[i]);
    }
}

static void fail_hash(const char *label, const uint8_t *expected, const uint8_t *actual) {
    ++failures;
    printf("[FAIL] %s\n  expected: ", label);
    print_hex(expected, HASH_SIZE);
    printf("\n  actual:   ");
    print_hex(actual, HASH_SIZE);
    printf("\n");
}

static void check_true(int condition, const char *label) {
    ++checks;
    if (!condition) {
        ++failures;
        printf("[FAIL] %s\n", label);
    }
}

static void check_hash(const uint8_t *expected, const uint8_t *actual, const char *label) {
    ++checks;
    if (memcmp(expected, actual, HASH_SIZE) != 0) {
        fail_hash(label, expected, actual);
    }
}

static uint64_t splitmix64(uint64_t *state) {
    uint64_t z;
    *state += UINT64_C(0x9e3779b97f4a7c15);
    z = *state;
    z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
    return z ^ (z >> 31);
}

static void fill_random(uint8_t *data, size_t size, uint64_t seed) {
    size_t offset = 0;
    while (offset < size) {
        uint64_t value = splitmix64(&seed);
        size_t copy = size - offset < sizeof(value) ? size - offset : sizeof(value);
        memcpy(data + offset, &value, copy);
        offset += copy;
    }
}

static int guards_ok(const guarded_hash *output) {
    for (size_t i = 0; i < GUARD_SIZE; ++i) {
        if (output->guard_before[i] != 0xa5 || output->guard_after[i] != 0x5a) {
            return 0;
        }
    }
    return 1;
}

static void init_guarded_hash(guarded_hash *output) {
    memset(output->guard_before, 0xa5, sizeof(output->guard_before));
    memset(output->hash, 0xcc, sizeof(output->hash));
    memset(output->guard_after, 0x5a, sizeof(output->guard_after));
}

static int create_vms(int version_flag, rx_cache *cache, rx_dataset *dataset,
                      rx_vm **interp, rx_vm **jit, rx_vm **light,
                      rx_vm **dual1, rx_vm **dual2) {
    *interp = rx_create_vm(version_flag, cache, dataset);
    *jit = rx_create_vm(version_flag | RX_FLAG_JIT, cache, dataset);
    *light = rx_create_vm(version_flag, cache, NULL);
    *dual1 = rx_create_vm(version_flag | RX_FLAG_JIT, cache, dataset);
    *dual2 = rx_create_vm(version_flag | RX_FLAG_JIT, cache, dataset);
    return *interp && *jit && *light && *dual1 && *dual2;
}

static void destroy_vms(rx_vm *interp, rx_vm *jit, rx_vm *light,
                        rx_vm *dual1, rx_vm *dual2) {
    rx_destroy_vm(interp);
    rx_destroy_vm(jit);
    rx_destroy_vm(light);
    rx_destroy_vm(dual1);
    rx_destroy_vm(dual2);
}

static void test_known_vector(rx_vm *interp, rx_vm *jit, rx_vm *light,
                              const uint8_t expected[HASH_SIZE], const char *version) {
    static const char input[] = "This is a test";
    uint8_t hi[HASH_SIZE], hj[HASH_SIZE], hl[HASH_SIZE];
    char label[96];

    rx_calculate_hash(interp, input, sizeof(input) - 1, hi);
    rx_calculate_hash(jit, input, sizeof(input) - 1, hj);
    rx_calculate_hash(light, input, sizeof(input) - 1, hl);

    snprintf(label, sizeof(label), "%s official vector: interpreter", version);
    check_hash(expected, hi, label);
    snprintf(label, sizeof(label), "%s official vector: JIT", version);
    check_hash(expected, hj, label);
    snprintf(label, sizeof(label), "%s official vector: light", version);
    check_hash(expected, hl, label);
}

static void test_random_differential(int version_flag, rx_vm *interp, rx_vm *jit,
                                     rx_vm *light, rx_vm *dual1, rx_vm *dual2) {
    static const size_t lengths[] = {
        0, 1, 7, 8, 15, 16, 31, 32, 63, 64, 65, 76, 127, 128, 255, 256, 511, 1024
    };
    uint8_t input1[MAX_INPUT_SIZE], input2[MAX_INPUT_SIZE];
    uint8_t input_copy[MAX_INPUT_SIZE];
    uint8_t ref1[HASH_SIZE], ref2[HASH_SIZE], jit1[HASH_SIZE], jit2[HASH_SIZE];
    uint8_t light_hash[HASH_SIZE], dual_hash1[HASH_SIZE], dual_hash2[HASH_SIZE];
    char label[128];

    for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); ++i) {
        size_t len1 = lengths[i];
        size_t len2 = lengths[(i * 7 + 5) % (sizeof(lengths) / sizeof(lengths[0]))];
        fill_random(input1, len1, UINT64_C(0x1234000000000000) + i + version_flag);
        fill_random(input2, len2, UINT64_C(0x9876000000000000) + i + version_flag);
        memcpy(input_copy, input1, len1);

        rx_calculate_hash(interp, input1, len1, ref1);
        rx_calculate_hash(interp, input2, len2, ref2);
        rx_calculate_hash(jit, input1, len1, jit1);
        rx_calculate_hash(jit, input2, len2, jit2);
        rx_calculate_hash_dual(dual1, dual2, input1, len1, input2, len2,
                               dual_hash1, dual_hash2);

        snprintf(label, sizeof(label), "V%d JIT differential length %zu",
                 version_flag ? 2 : 1, len1);
        check_hash(ref1, jit1, label);
        snprintf(label, sizeof(label), "V%d JIT differential second lane length %zu",
                 version_flag ? 2 : 1, len2);
        check_hash(ref2, jit2, label);
        snprintf(label, sizeof(label), "V%d dual lane 1 length %zu",
                 version_flag ? 2 : 1, len1);
        check_hash(ref1, dual_hash1, label);
        snprintf(label, sizeof(label), "V%d dual lane 2 length %zu",
                 version_flag ? 2 : 1, len2);
        check_hash(ref2, dual_hash2, label);

        if (i < 4 || i == 11 || i + 1 == sizeof(lengths) / sizeof(lengths[0])) {
            rx_calculate_hash(light, input1, len1, light_hash);
            snprintf(label, sizeof(label), "V%d light/full length %zu",
                     version_flag ? 2 : 1, len1);
            check_hash(ref1, light_hash, label);
        }

        snprintf(label, sizeof(label), "V%d input immutability length %zu",
                 version_flag ? 2 : 1, len1);
        check_true(memcmp(input1, input_copy, len1) == 0, label);
    }
}

static void test_pipeline(int version_flag, rx_cache *cache, rx_dataset *dataset) {
    uint8_t inputs[5][160];
    size_t lengths[] = { 0, 1, 76, 79, 160 };
    uint8_t expected[5][HASH_SIZE], actual[5][HASH_SIZE];
    rx_vm *reference = rx_create_vm(version_flag, cache, dataset);
    rx_vm *pipeline = rx_create_vm(version_flag | RX_FLAG_JIT, cache, dataset);
    char label[96];

    check_true(reference != NULL && pipeline != NULL, "pipeline VM allocation");
    if (!reference || !pipeline) {
        rx_destroy_vm(reference);
        rx_destroy_vm(pipeline);
        return;
    }

    for (size_t i = 0; i < 5; ++i) {
        fill_random(inputs[i], lengths[i], UINT64_C(0xa110000000000000) + i + version_flag);
        rx_calculate_hash(reference, inputs[i], lengths[i], expected[i]);
    }

    rx_calculate_hash_first(pipeline, inputs[0], lengths[0]);
    for (size_t i = 1; i < 5; ++i) {
        rx_calculate_hash_next(pipeline, inputs[i], lengths[i], actual[i - 1]);
    }
    rx_calculate_hash_last(pipeline, actual[4]);

    for (size_t i = 0; i < 5; ++i) {
        snprintf(label, sizeof(label), "V%d pipeline item %zu",
                 version_flag ? 2 : 1, i);
        check_hash(expected[i], actual[i], label);
    }

    rx_destroy_vm(reference);
    rx_destroy_vm(pipeline);
}

static void test_reuse_and_guards(int version_flag, rx_vm *jit) {
    uint8_t input[76], first[HASH_SIZE];
    guarded_hash guarded;
    char label[96];

    fill_random(input, sizeof(input), UINT64_C(0x55aa123456780000) + version_flag);
    rx_calculate_hash(jit, input, sizeof(input), first);

    for (int i = 0; i < 4; ++i) {
        init_guarded_hash(&guarded);
        rx_calculate_hash(jit, input, sizeof(input), guarded.hash);
        snprintf(label, sizeof(label), "V%d deterministic VM reuse %d",
                 version_flag ? 2 : 1, i);
        check_hash(first, guarded.hash, label);
        snprintf(label, sizeof(label), "V%d output guards %d",
                 version_flag ? 2 : 1, i);
        check_true(guards_ok(&guarded), label);
    }
}

static void test_mxcsr_restore(int version_flag, rx_vm *jit) {
    uint8_t input[76], output[HASH_SIZE];
    uint32_t original = _mm_getcsr();
    uint32_t custom = (original & ~0x6000u) | 0x4000u;
    char label[96];

    fill_random(input, sizeof(input), UINT64_C(0xf00d123456780000) + version_flag);
    _mm_setcsr(custom);
    rx_calculate_hash(jit, input, sizeof(input), output);
    snprintf(label, sizeof(label), "V%d full hash restores MXCSR", version_flag ? 2 : 1);
    check_true(_mm_getcsr() == custom, label);

    rx_calculate_hash_first(jit, input, sizeof(input));
    snprintf(label, sizeof(label), "V%d hash_first restores MXCSR", version_flag ? 2 : 1);
    check_true(_mm_getcsr() == custom, label);
    rx_calculate_hash_last(jit, output);
    snprintf(label, sizeof(label), "V%d hash_last restores MXCSR", version_flag ? 2 : 1);
    check_true(_mm_getcsr() == custom, label);
    _mm_setcsr(original);
}

static void test_dataset_samples(rx_cache *cache, rx_dataset *dataset) {
    static const uint64_t items[] = {
        0, 1, 17, 1024, RX_DATASET_ITEMS - 1,
        RX_DATASET_ITEMS, RX_DATASET_ITEMS + RX_DATASET_EXTRA_ITEMS - 1
    };
    uint8_t generated[RX_DATASET_ITEM_SIZE];
    uint8_t *memory = (uint8_t *)rx_get_dataset_memory(dataset);
    char label[96];

    for (size_t i = 0; i < sizeof(items) / sizeof(items[0]); ++i) {
        rx_init_dataset_item(cache, generated, items[i]);
        snprintf(label, sizeof(label), "dataset item %llu",
                 (unsigned long long)items[i]);
        check_true(memcmp(generated, memory + items[i] * RX_DATASET_ITEM_SIZE,
                          RX_DATASET_ITEM_SIZE) == 0, label);
    }
}

int main(void) {
    static const uint8_t expected_v1[HASH_SIZE] = {
        0x63, 0x91, 0x83, 0xaa, 0xe1, 0xbf, 0x4c, 0x9a,
        0x35, 0x88, 0x4c, 0xb4, 0x6b, 0x09, 0xca, 0xd9,
        0x17, 0x5f, 0x04, 0xef, 0xd7, 0x68, 0x4e, 0x72,
        0x62, 0xa0, 0xac, 0x1c, 0x2f, 0x0b, 0x4e, 0x3f
    };
    static const uint8_t expected_v2[HASH_SIZE] = {
        0x22, 0xec, 0x6b, 0x86, 0x1b, 0x3e, 0xb2, 0x36,
        0x86, 0xb2, 0xef, 0xba, 0xd6, 0x95, 0x13, 0xc9,
        0x67, 0xec, 0xfc, 0xe8, 0x09, 0x83, 0xdf, 0x66,
        0xc9, 0xc5, 0xb4, 0xfb, 0xfb, 0x4c, 0xdb, 0x6f
    };
    static const char key[] = "test key 000";
    rx_cache *cache = NULL;
    rx_dataset *dataset = NULL;

    printf("RandomX conformance test\n");
    printf("Initializing cache and full dataset...\n");

    cache = rx_alloc_cache(0);
    check_true(cache != NULL, "cache allocation");
    if (!cache) {
        return 1;
    }
    rx_init_cache(cache, key, sizeof(key) - 1);

    dataset = rx_alloc_dataset(0);
    check_true(dataset != NULL, "dataset allocation");
    if (!dataset) {
        rx_free_cache(cache);
        return 1;
    }
    rx_init_dataset_cached(dataset, cache, 0,
                           RX_DATASET_ITEMS + RX_DATASET_EXTRA_ITEMS, 8, 8);
    test_dataset_samples(cache, dataset);

    for (int version = 0; version < 2; ++version) {
        int version_flag = version ? RX_FLAG_V2 : RX_FLAG_DEFAULT;
        rx_vm *interp = NULL, *jit = NULL, *light = NULL;
        rx_vm *dual1 = NULL, *dual2 = NULL;

        printf("Testing V%d...\n", version + 1);
        check_true(create_vms(version_flag, cache, dataset, &interp, &jit, &light,
                              &dual1, &dual2), "VM allocation");
        if (!interp || !jit || !light || !dual1 || !dual2) {
            destroy_vms(interp, jit, light, dual1, dual2);
            continue;
        }

        test_known_vector(interp, jit, light, version ? expected_v2 : expected_v1,
                          version ? "V2" : "V1");
        test_random_differential(version_flag, interp, jit, light, dual1, dual2);
        test_pipeline(version_flag, cache, dataset);
        test_reuse_and_guards(version_flag, jit);
        test_mxcsr_restore(version_flag, jit);
        destroy_vms(interp, jit, light, dual1, dual2);
    }

    rx_free_dataset(dataset);
    rx_free_cache(cache);

    printf("%s: %d checks, %d failures\n",
           failures == 0 ? "[PASS]" : "[FAIL]", checks, failures);
    return failures == 0 ? 0 : 1;
}
