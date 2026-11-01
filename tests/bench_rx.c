#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/*
 * bench_rx - portable (POSIX + Windows) RandomX hashrate benchmark.
 *
 *   bench_rx [-t threads] [-n hashes/thread] [-r repeats] [-p pages]
 *            [--no-pin] [--full] [--no-check] [-c cpu_list]
 *
 *   pages: 0 = 4 KB, 1 = 2 MB huge pages, 2 = 1 GB pages (default; falls back to 2 MB)
 *
 * Before measuring it verifies the official RandomX test vector
 * (key "test key 000", input "This is a test") with the JIT VM, and that
 * the batch pipeline (hash_first/hash_next) matches rx_calculate_hash.
 * Hashrate is reported as the median of the repeats; every repeat runs all
 * threads concurrently and is timed from a common start barrier.
 */
#include "crypto/randomx/randomx.h"
#include "crypto/randomx/randomx_internal.h"
#include "common/vmem.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#include <sched.h>
#include <time.h>
#include <unistd.h>
#endif

#define MAX_THREADS 256

static double now_sec(void) {
#ifdef _WIN32
    LARGE_INTEGER f, c;
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&c);
    return (double)c.QuadPart / (double)f.QuadPart;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + ts.tv_nsec * 1e-9;
#endif
}

static int num_cpus(void) {
#ifdef _WIN32
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return (int)si.dwNumberOfProcessors;
#else
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    return n > 0 ? (int)n : 1;
#endif
}

static void pin_self(int cpu) {
#ifdef _WIN32
    SetThreadAffinityMask(GetCurrentThread(), (DWORD_PTR)1 << cpu);
#else
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    pthread_setaffinity_np(pthread_self(), sizeof(set), &set);
#endif
}

/* ---- simple spinning barrier (portable) ---- */
static volatile int g_barrier_count = 0;
static volatile int g_barrier_gen = 0;
static int g_barrier_total = 0;

static void barrier_wait(void) {
    int gen = g_barrier_gen;
    if (__atomic_add_fetch(&g_barrier_count, 1, __ATOMIC_SEQ_CST) == g_barrier_total) {
        g_barrier_count = 0;
        __atomic_add_fetch(&g_barrier_gen, 1, __ATOMIC_SEQ_CST);
    } else {
        while (__atomic_load_n(&g_barrier_gen, __ATOMIC_SEQ_CST) == gen) {
#if defined(__x86_64__) || defined(_M_X64)
            _mm_pause();
#endif
        }
    }
}

typedef struct {
    int tid;
    int cpu;
    int hashes;
    int repeats;
    int full_mode; /* 0 batch, 1 full, 2 dual, 3 group (multi-lane batch) */
    int lanes;
    rx_cache *cache;
    rx_dataset *dataset;
    double *seconds; /* [repeats] */
    uint8_t last_hash[32];
    int sp_kind;
} worker_t;

static int g_pin = 1;

/* ---- A/B experiment support ---- */
typedef struct { int lanes; char knobs[256]; } ab_config;
static ab_config g_ab[2];
static int g_ab_mode = 0;
static double *g_ab_time[2]; /* [round * threads + tid] */
static int g_ab_rounds = 0;

static int apply_knobs(const char *spec) {
    /* every config starts from the defaults so A and B differ only in spec */
    g_mjit_granularity = 256;
    g_mjit_mxcsr_skip = 0;
    g_mjit_rcp_pool = 1;
    g_mjit_prefetch_mode = 1;
    g_mjit_pinned_regs = 1;
    g_mjit_diag = 0;
    g_mjit_ds_prefetch = 0;
    g_mjit_fp_spill = 0;
    char buf[256];
    snprintf(buf, sizeof(buf), "%s", spec);
    char *save = NULL;
    for (char *t = strtok_r(buf, ",", &save); t; t = strtok_r(NULL, ",", &save)) {
        char name[64]; int val;
        if (sscanf(t, "%63[^=]=%d", name, &val) != 2) continue;
        if (!strcmp(name, "gran")) g_mjit_granularity = val;
        else if (!strcmp(name, "mxskip")) g_mjit_mxcsr_skip = val;
        else if (!strcmp(name, "rcp_pool")) g_mjit_rcp_pool = val;
        else if (!strcmp(name, "prefetch")) g_mjit_prefetch_mode = val;
        else if (!strcmp(name, "pinned")) g_mjit_pinned_regs = val;
        else if (!strcmp(name, "diag")) g_mjit_diag = val;
        else if (!strcmp(name, "dspf")) g_mjit_ds_prefetch = val;
        else if (!strcmp(name, "spill")) g_mjit_fp_spill = val;
        else if (!strcmp(name, "lanes")) {}
        else { printf("unknown knob %s\n", name); return 0; }
    }
    return 1;
}

static int knob_lanes(const char *spec) {
    const char *p = strstr(spec, "lanes=");
    return p ? atoi(p + 6) : 1;
}

#ifdef _WIN32
static DWORD WINAPI worker_main(LPVOID p)
#else
static void *worker_main(void *p)
#endif
{
    worker_t *w = (worker_t *)p;
    if (g_pin && w->cpu >= 0) pin_self(w->cpu);

    if (g_ab_mode) {
        rx_vm_group *grp[2];
        int K[2];
        uint8_t blobs[RX_MULTI_MAX_LANES][76];
        uint8_t outs_[RX_MULTI_MAX_LANES][32];
        const void *in[RX_MULTI_MAX_LANES];
        void *out[RX_MULTI_MAX_LANES];
        size_t sz[RX_MULTI_MAX_LANES];
        uint32_t gn = 0;
        for (int l = 0; l < RX_MULTI_MAX_LANES; l++) {
            memset(blobs[l], 0, 76);
            blobs[l][0] = 0x10; blobs[l][3] = (uint8_t)w->tid; blobs[l][4] = (uint8_t)l;
            in[l] = blobs[l]; out[l] = outs_[l]; sz[l] = 76;
        }
        for (int c = 0; c < 2; c++) {
            K[c] = g_ab[c].lanes;
            grp[c] = rx_create_vm_group(K[c], RX_FLAG_DEFAULT, w->cache, w->dataset);
            if (!grp[c]) { fprintf(stderr, "group alloc failed\n"); exit(3); }
            rx_group_hash_first(grp[c], in, sz);
        }
        for (int r = 0; r < g_ab_rounds; r++) {
            for (int k = 0; k < 2; k++) {
                int c = (r & 1) ? 1 - k : k;   /* ABBA ordering */
                barrier_wait();
                if (w->tid == 0) apply_knobs(g_ab[c].knobs);
                barrier_wait();
                /* one warm-up hash per slice (JIT/knob change) */
                gn++; for (int l = 0; l < K[c]; l++) memcpy(blobs[l] + 39, &gn, 4);
                rx_group_hash_next(grp[c], in, sz, out);
                double t0 = now_sec();
                for (int i = 0; i < w->hashes; i += K[c]) {
                    gn++;
                    for (int l = 0; l < K[c]; l++) memcpy(blobs[l] + 39, &gn, 4);
                    rx_group_hash_next(grp[c], in, sz, out);
                }
                double dt = now_sec() - t0;
                int done = ((w->hashes + K[c] - 1) / K[c]) * K[c];
                g_ab_time[c][r * g_barrier_total + w->tid] = dt / done;
            }
        }
        rx_destroy_vm_group(grp[0]);
        rx_destroy_vm_group(grp[1]);
#ifdef _WIN32
        return 0;
#else
        return NULL;
#endif
    }
    if (w->full_mode == 3) {
        rx_vm_group *g = rx_create_vm_group(w->lanes, RX_FLAG_DEFAULT, w->cache, w->dataset);
        if (!g) { fprintf(stderr, "group alloc failed (lanes=%d)\n", w->lanes); exit(3); }
        w->sp_kind = rx_vm_group_vm(g, 0)->sp_page_kind;
        int K = w->lanes;
        uint8_t blobs[RX_MULTI_MAX_LANES][76];
        uint8_t outs_[RX_MULTI_MAX_LANES][32];
        const void *in[RX_MULTI_MAX_LANES];
        void *out[RX_MULTI_MAX_LANES];
        size_t sz[RX_MULTI_MAX_LANES];
        uint32_t gn = 0;
        for (int l = 0; l < K; l++) {
            memset(blobs[l], 0, 76);
            blobs[l][0] = 0x10; blobs[l][1] = 0x03; blobs[l][2] = 0xe3;
            blobs[l][3] = (uint8_t)w->tid; blobs[l][4] = (uint8_t)l;
            in[l] = blobs[l]; out[l] = outs_[l]; sz[l] = 76;
        }
        rx_group_hash_first(g, in, sz);
        for (int i = 0; i < 2; i++) {
            gn++;
            for (int l = 0; l < K; l++) memcpy(blobs[l] + 39, &gn, 4);
            rx_group_hash_next(g, in, sz, out);
        }
        for (int r = 0; r < w->repeats; r++) {
            barrier_wait();
            double t0 = now_sec();
            for (int i = 0; i < w->hashes; i += K) {
                gn++;
                for (int l = 0; l < K; l++) memcpy(blobs[l] + 39, &gn, 4);
                rx_group_hash_next(g, in, sz, out);
            }
            w->seconds[r] = now_sec() - t0;
            barrier_wait();
        }
        rx_destroy_vm_group(g);
#ifdef _WIN32
        return 0;
#else
        return NULL;
#endif
    }
    rx_vm *vm = rx_create_vm(RX_FLAG_JIT, w->cache, w->dataset);
    rx_vm *vm2 = w->full_mode == 2 ? rx_create_vm(RX_FLAG_JIT, w->cache, w->dataset) : NULL;
    if (!vm || (w->full_mode == 2 && !vm2)) { fprintf(stderr, "VM alloc failed\n"); exit(3); }
    w->sp_kind = vm->sp_page_kind;

    uint8_t blob[76];
    memset(blob, 0, sizeof(blob));
    blob[0] = 0x10; blob[1] = 0x03; blob[2] = 0xe3;
    for (int i = 3; i < 7; i++) blob[i] = (uint8_t)(w->tid * 17 + i);
    uint32_t nonce = 0;
    uint8_t hash[32];

    memcpy(blob + 39, &nonce, 4);
    rx_calculate_hash_first(vm, blob, sizeof(blob));
    for (int i = 0; i < 3; i++) { /* warm-up: JIT, TLB, caches */
        nonce++; memcpy(blob + 39, &nonce, 4);
        rx_calculate_hash_next(vm, blob, sizeof(blob), hash);
    }

    for (int r = 0; r < w->repeats; r++) {
        barrier_wait();
        double t0 = now_sec();
        if (w->full_mode == 2) {
            uint8_t blob2[76], hash2[32];
            memcpy(blob2, blob, sizeof(blob2));
            blob2[5] ^= 0x80;
            for (int i = 0; i < w->hashes; i += 2) {
                nonce++; memcpy(blob + 39, &nonce, 4); memcpy(blob2 + 39, &nonce, 4);
                rx_calculate_hash_dual(vm, vm2, blob, sizeof(blob), blob2, sizeof(blob2), hash, hash2);
            }
        } else if (w->full_mode) {
            for (int i = 0; i < w->hashes; i++) {
                nonce++; memcpy(blob + 39, &nonce, 4);
                rx_calculate_hash(vm, blob, sizeof(blob), hash);
            }
        } else {
            for (int i = 0; i < w->hashes; i++) {
                nonce++; memcpy(blob + 39, &nonce, 4);
                rx_calculate_hash_next(vm, blob, sizeof(blob), hash);
            }
        }
        w->seconds[r] = now_sec() - t0;
        barrier_wait();
    }
    memcpy(w->last_hash, hash, 32);
    rx_destroy_vm(vm);
    rx_destroy_vm(vm2);
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

static int cmp_double(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return x < y ? -1 : x > y;
}

static int verify(rx_cache *cache, rx_dataset *dataset) {
    static const uint8_t expected[32] = {
        0x63, 0x91, 0x83, 0xaa, 0xe1, 0xbf, 0x4c, 0x9a,
        0x35, 0x88, 0x4c, 0xb4, 0x6b, 0x09, 0xca, 0xd9,
        0x17, 0x5f, 0x04, 0xef, 0xd7, 0x68, 0x4e, 0x72,
        0x62, 0xa0, 0xac, 0x1c, 0x2f, 0x0b, 0x4e, 0x3f
    };
    int ok = 1;
    rx_vm *jit = rx_create_vm(RX_FLAG_JIT, cache, dataset);
    rx_vm *interp = rx_create_vm(RX_FLAG_DEFAULT, cache, dataset);
    uint8_t h[32], ref[32];
    const char *in = "This is a test";
    rx_calculate_hash(jit, in, strlen(in), h);
    if (memcmp(h, expected, 32) != 0) { printf("  [FAIL] official vector (JIT)\n"); ok = 0; }
    else printf("  [PASS] official test vector (JIT, full dataset)\n");

    /* batch pipeline vs single-shot JIT vs interpreter */
    uint8_t blob[76];
    memset(blob, 0x5c, sizeof(blob));
    uint32_t n = 0;
    memcpy(blob + 39, &n, 4);
    rx_calculate_hash_first(jit, blob, sizeof(blob));
    int batch_ok = 1;
    for (n = 1; n <= 4; n++) {
        uint8_t prev[76];
        memcpy(prev, blob, 76);
        memcpy(blob + 39, &n, 4);
        rx_calculate_hash_next(jit, blob, sizeof(blob), h);
        rx_calculate_hash(interp, prev, sizeof(prev), ref);
        if (memcmp(h, ref, 32) != 0) batch_ok = 0;
    }
    printf("  [%s] batch pipeline == interpreter (4 nonces)\n", batch_ok ? "PASS" : "FAIL");
    ok &= batch_ok;
    rx_destroy_vm(jit);
    rx_destroy_vm(interp);
    return ok;
}

int main(int argc, char **argv) {
    int threads = num_cpus();
    int hashes = 200;
    int repeats = 5;
    int pages = 2;
    int full_mode = 0;
    int lanes = 1;
    int check = 1;
    int cpu_list[MAX_THREADS];
    int cpu_list_n = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-t") && i + 1 < argc) threads = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-n") && i + 1 < argc) hashes = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-r") && i + 1 < argc) repeats = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-p") && i + 1 < argc) pages = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--no-pin")) g_pin = 0;
        else if (!strcmp(argv[i], "--full")) full_mode = 1;
        else if (!strcmp(argv[i], "--dual")) full_mode = 2;
        else if (!strcmp(argv[i], "--lanes") && i + 1 < argc) { lanes = atoi(argv[++i]); full_mode = 3; }
        else if (!strcmp(argv[i], "--gran") && i + 1 < argc) g_mjit_granularity = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--mxskip")) g_mjit_mxcsr_skip = 1;
        else if (!strcmp(argv[i], "--ab") && i + 2 < argc) {
            g_ab_mode = 1;
            snprintf(g_ab[0].knobs, sizeof(g_ab[0].knobs), "%s", argv[++i]);
            snprintf(g_ab[1].knobs, sizeof(g_ab[1].knobs), "%s", argv[++i]);
            g_ab[0].lanes = knob_lanes(g_ab[0].knobs);
            g_ab[1].lanes = knob_lanes(g_ab[1].knobs);
        }
        else if (!strcmp(argv[i], "--set") && i + 1 < argc) {
            /* --set name=value for experiment knobs */
            char name[64]; int val;
            if (sscanf(argv[++i], "%63[^=]=%d", name, &val) == 2) {
                if (!strcmp(name, "rcp_pool")) g_mjit_rcp_pool = val;
                else if (!strcmp(name, "prefetch")) g_mjit_prefetch_mode = val;
                else { printf("unknown knob %s\n", name); return 2; }
            }
        }
        else if (!strcmp(argv[i], "--no-check")) check = 0;
        else if (!strcmp(argv[i], "-c") && i + 1 < argc) {
            char *s = argv[++i];
            while (*s && cpu_list_n < MAX_THREADS) {
                cpu_list[cpu_list_n++] = (int)strtol(s, &s, 10);
                if (*s == ',') s++;
            }
        } else {
            printf("usage: %s [-t threads] [-n hashes] [-r repeats] [-p 0|1|2] "
                   "[--no-pin] [--full] [--no-check] [-c cpu,list]\n", argv[0]);
            return 2;
        }
    }
    if (threads < 1) threads = 1;
    if (threads > MAX_THREADS) threads = MAX_THREADS;
    if (repeats < 1) repeats = 1;

    printf("bench_rx: threads=%d hashes/thread=%d repeats=%d pages=%d lanes=%d gran=%d mode=%s pin=%d\n",
           threads, hashes, repeats, pages, lanes, g_mjit_granularity, full_mode == 3 ? "group" : full_mode == 2 ? "dual" : full_mode ? "full" : "batch", g_pin);

    const char key[] = "test key 000";
    double t0 = now_sec();
    rx_cache *cache = rx_alloc_cache(pages > 0);
    rx_init_cache(cache, key, sizeof(key) - 1);
    rx_dataset *dataset = rx_alloc_dataset(pages);
    if (!cache || !dataset) { printf("allocation failed\n"); return 1; }
    rx_init_dataset_cached(dataset, cache, 0, RX_DATASET_ITEMS + RX_DATASET_EXTRA_ITEMS,
                           num_cpus(), num_cpus());
    printf("  init: %.1f s, dataset pages: %s\n", now_sec() - t0, vmem_kind_name(dataset->page_kind));

    if (check && !verify(cache, dataset)) {
        printf("CORRECTNESS FAILURE - aborting\n");
        return 1;
    }

    if (g_ab_mode) {
        g_ab_rounds = repeats;
        g_ab_time[0] = (double *)calloc((size_t)repeats * threads, sizeof(double));
        g_ab_time[1] = (double *)calloc((size_t)repeats * threads, sizeof(double));
        printf("  A/B: A=\"%s\" (lanes %d)  B=\"%s\" (lanes %d)  rounds=%d\n",
               g_ab[0].knobs, g_ab[0].lanes, g_ab[1].knobs, g_ab[1].lanes, repeats);
    }
    worker_t *w = (worker_t *)calloc(threads, sizeof(worker_t));
    g_barrier_total = threads;
    int ncpu = num_cpus();
    for (int i = 0; i < threads; i++) {
        w[i].tid = i;
        w[i].cpu = cpu_list_n ? cpu_list[i % cpu_list_n] : i % ncpu;
        w[i].hashes = hashes;
        w[i].repeats = repeats;
        w[i].full_mode = full_mode;
        w[i].lanes = lanes;
        w[i].cache = cache;
        w[i].dataset = dataset;
        w[i].seconds = (double *)calloc(repeats, sizeof(double));
    }
#ifdef _WIN32
    HANDLE *th = (HANDLE *)calloc(threads, sizeof(HANDLE));
    for (int i = 0; i < threads; i++) th[i] = CreateThread(NULL, 0, worker_main, &w[i], 0, NULL);
    WaitForMultipleObjects(threads, th, TRUE, INFINITE);
#else
    pthread_t *th = (pthread_t *)calloc(threads, sizeof(pthread_t));
    for (int i = 0; i < threads; i++) pthread_create(&th[i], NULL, worker_main, &w[i]);
    for (int i = 0; i < threads; i++) pthread_join(th[i], NULL);
#endif

    if (g_ab_mode) {
        double *ratio = (double *)calloc(repeats, sizeof(double));
        double *ha = (double *)calloc(repeats, sizeof(double));
        double *hb = (double *)calloc(repeats, sizeof(double));
        for (int r = 0; r < repeats; r++) {
            double ra = 0, rb = 0;
            for (int t = 0; t < threads; t++) {
                ra += 1.0 / g_ab_time[0][r * threads + t];
                rb += 1.0 / g_ab_time[1][r * threads + t];
            }
            ha[r] = ra; hb[r] = rb; ratio[r] = rb / ra;
        }
        qsort(ratio, repeats, sizeof(double), cmp_double);
        qsort(ha, repeats, sizeof(double), cmp_double);
        qsort(hb, repeats, sizeof(double), cmp_double);
        int q1 = repeats / 4, q3 = (3 * repeats) / 4;
        if (q3 >= repeats) q3 = repeats - 1;
        printf("ABRESULT A=%.1f H/s B=%.1f H/s  B/A median=%+.2f%%  IQR=[%+.2f%%, %+.2f%%]\n",
               ha[repeats / 2], hb[repeats / 2], (ratio[repeats / 2] - 1) * 100,
               (ratio[q1] - 1) * 100, (ratio[q3] - 1) * 100);
        return 0;
    }
    printf("  scratchpad pages: %s\n", vmem_kind_name(w[0].sp_kind));
    double *rates = (double *)calloc(repeats, sizeof(double));
    for (int r = 0; r < repeats; r++) {
        double total = 0.0;
        for (int i = 0; i < threads; i++) total += hashes / w[i].seconds[r];
        rates[r] = total;
        printf("  run %d: %9.1f H/s\n", r + 1, total);
    }
    qsort(rates, repeats, sizeof(double), cmp_double);
    double median = rates[repeats / 2];
    double best = rates[repeats - 1];
    printf("RESULT threads=%d median=%.1f H/s best=%.1f H/s per_thread=%.1f H/s\n",
           threads, median, best, median / threads);
    return 0;
}
