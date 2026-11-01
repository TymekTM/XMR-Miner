/*
 * Differential test for the multi-lane JIT (rx_vm_group).
 *
 * For several interleaving granularities and option combinations, hashes
 * produced by a 2-lane group (single-shot and batch pipeline) are compared
 * with the single-lane JIT and, for a subset, the interpreter. The official
 * RandomX test vector is checked on every lane.
 *
 *   test_multilane [--dump file]   (--dump writes one generated program)
 */
#include "crypto/randomx/randomx.h"
#include "crypto/randomx/randomx_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int checks = 0, failures = 0;

static void check(int ok, const char *label) {
    checks++;
    if (!ok) { failures++; printf("[FAIL] %s\n", label); }
}

static uint64_t splitmix64(uint64_t *s) {
    uint64_t z = (*s += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

static void fill(uint8_t *d, size_t n, uint64_t seed) {
    for (size_t i = 0; i < n; i++) {
        if ((i & 7) == 0) seed = splitmix64(&seed);
        d[i] = (uint8_t)(seed >> (8 * (i & 7)));
    }
}

int main(int argc, char **argv) {
    static const uint8_t expected[32] = {
        0x63, 0x91, 0x83, 0xaa, 0xe1, 0xbf, 0x4c, 0x9a,
        0x35, 0x88, 0x4c, 0xb4, 0x6b, 0x09, 0xca, 0xd9,
        0x17, 0x5f, 0x04, 0xef, 0xd7, 0x68, 0x4e, 0x72,
        0x62, 0xa0, 0xac, 0x1c, 0x2f, 0x0b, 0x4e, 0x3f
    };
    const char *dump = NULL;
    int rounds = 6;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--dump") && i + 1 < argc) dump = argv[++i];
        else if (!strcmp(argv[i], "--rounds") && i + 1 < argc) rounds = atoi(argv[++i]);
    }

    const char key[] = "test key 000";
    rx_cache *cache = rx_alloc_cache(1);
    rx_init_cache(cache, key, sizeof(key) - 1);
    rx_dataset *ds = rx_alloc_dataset(1);
    rx_init_dataset_cached(ds, cache, 0, RX_DATASET_ITEMS + RX_DATASET_EXTRA_ITEMS, 4, 4);

    rx_vm *ref = rx_create_vm(RX_FLAG_JIT, cache, ds);
    rx_vm *interp = rx_create_vm(RX_FLAG_DEFAULT, cache, ds);

    if (!rx_cpu_has_avx512_lanes()) {
        printf("[SKIP] CPU lacks AVX-512F/VL/DQ: 2-lane group unavailable\n");
    }

    static const int grans[] = { 256, 128, 64, 32, 16, 8, 1 };
    for (int cfg = 0; cfg < 7; cfg++) {
        /* lanes 1..4 auto banking, then lanes 2..4 forced FP spill */
        int lanes = cfg < 4 ? cfg + 1 : cfg - 2;
        int spill = cfg >= 4;
        g_mjit_fp_spill = spill;
        rx_vm_group *g = rx_create_vm_group(lanes, RX_FLAG_DEFAULT, cache, ds);
        if (!g) { printf("[SKIP] lanes=%d group unavailable\n", lanes); continue; }
        for (size_t gi = 0; gi < sizeof(grans) / sizeof(grans[0]); gi++) {
            for (int opt = 0; opt < 4; opt++) {
                g_mjit_granularity = grans[gi];
                g_mjit_mxcsr_skip = opt & 1;
                g_mjit_rcp_pool = (opt & 2) ? 0 : 1;
                char label[160];

                /* official vector on every lane */
                const char *tv = "This is a test";
                const void *in[4] = { tv, tv, tv, tv };
                size_t sz[4] = { strlen(tv), strlen(tv), strlen(tv), strlen(tv) };
                uint8_t out[4][32];
                void *outs[4] = { out[0], out[1], out[2], out[3] };
                rx_group_hash(g, in, sz, outs);
                for (int l = 0; l < lanes; l++) {
                    snprintf(label, sizeof(label), "lanes=%d spill=%d gran=%d opt=%d official vector lane %d",
                             lanes, spill, grans[gi], opt, l);
                    check(memcmp(out[l], expected, 32) == 0, label);
                }

                /* batch pipeline with distinct inputs per lane */
                uint8_t blobs[4][8][200];
                size_t lens[8] = { 76, 76, 77, 43, 76, 128, 129, 200 };
                int nb = rounds < 8 ? rounds : 8;
                for (int l = 0; l < 4; l++)
                    for (int k = 0; k < nb; k++)
                        fill(blobs[l][k], lens[k], (uint64_t)(l * 1000 + k * 17 + gi * 7 + opt + lanes * 100000));
                const void *first[4] = { blobs[0][0], blobs[1][0], blobs[2][0], blobs[3][0] };
                size_t fsz[4] = { lens[0], lens[0], lens[0], lens[0] };
                rx_group_hash_first(g, first, fsz);
                for (int k = 1; k <= nb; k++) {
                    uint8_t got[4][32];
                    void *gouts[4] = { got[0], got[1], got[2], got[3] };
                    if (k < nb) {
                        const void *nx[4] = { blobs[0][k], blobs[1][k], blobs[2][k], blobs[3][k] };
                        size_t nsz[4] = { lens[k], lens[k], lens[k], lens[k] };
                        rx_group_hash_next(g, nx, nsz, gouts);
                    } else {
                        rx_group_hash_last(g, gouts);
                    }
                    for (int l = 0; l < lanes; l++) {
                        uint8_t want[32];
                        rx_calculate_hash(ref, blobs[l][k - 1], lens[k - 1], want);
                        snprintf(label, sizeof(label), "lanes=%d spill=%d gran=%d opt=%d batch item %d lane %d",
                                 lanes, spill, grans[gi], opt, k - 1, l);
                        check(memcmp(got[l], want, 32) == 0, label);
                        if (gi == 0 && opt == 0 && k == 1 && !spill) {
                            uint8_t w2[32];
                            rx_calculate_hash(interp, blobs[l][0], lens[0], w2);
                            snprintf(label, sizeof(label), "lanes=%d interpreter cross-check lane %d", lanes, l);
                            check(memcmp(got[l], w2, 32) == 0, label);
                        }
                    }
                }
            }
        }
        if (dump && lanes == 2 && !spill) {
            rx_program *progs[2] = { &rx_vm_group_vm(g, 0)->program, &rx_vm_group_vm(g, 1)->program };
            rx_program_config *cfgs[2] = { &rx_vm_group_vm(g, 0)->config, &rx_vm_group_vm(g, 1)->config };
            extern rx_mjit *rx_vm_group_mjit(rx_vm_group *);
            g_mjit_granularity = 32;
            rx_mjit *mj = rx_vm_group_mjit(g);
            int n = rx_mjit_generate(mj, 2, progs, cfgs);
            FILE *f = fopen(dump, "wb");
            if (f) { fwrite(rx_mjit_code(mj), 1, (size_t)n, f); fclose(f); }
            printf("dumped %d bytes of 2-lane code to %s\n", n, dump);
        }
        rx_destroy_vm_group(g);
    }

    rx_destroy_vm(ref);
    rx_destroy_vm(interp);
    rx_free_dataset(ds);
    rx_free_cache(cache);
    printf("%s: %d checks, %d failures\n", failures ? "[FAIL]" : "[PASS]", checks, failures);
    return failures ? 1 : 0;
}
