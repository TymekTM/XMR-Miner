/*
 * Focused benchmark: time to compute ~1,000,000 hashes on N threads
 * (default: all logical cores). Uses the production batch API
 * (hash_first / hash_next) and JIT, matching real mining load.
 *
 * Reports: wall time, total hashrate, per-thread hashrate, and the
 * derived time for exactly 1 MH. Verifies correctness against a
 * single-threaded reference.
 */
#include "crypto/randomx/randomx.h"
#include "miner/affinity.h"
#include "common/log.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int tid;
    int nthreads;
    int hashes_this_thread;
    rx_vm *vm;
    uint8_t seed[76];
    uint8_t hash[32];
    double elapsed;
    int ok;
    const int *affinity_order;
    int affinity_count;
} thread_arg_t;

static DWORD WINAPI bench_thread(LPVOID arg) {
    thread_arg_t *a = (thread_arg_t *)arg;

    /* Pin to the same core the production miner would use for this tid. */
    if (a->affinity_count > 0) {
        int cpu = a->affinity_order[a->tid % a->affinity_count];
        affinity_pin_current(cpu);
    }
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);

    /* per-thread distinct nonce seed */
    uint32_t base = (uint32_t)a->tid * 0x9E3779B9u;
    memcpy(a->seed + 39, &base, 4);

    LARGE_INTEGER freq, t0, t1;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t0);

    int n = a->hashes_this_thread;
    uint8_t first_hash[32];
    uint8_t last[32];
    rx_calculate_hash_first(a->vm, a->seed, sizeof(a->seed));
    for (int i = 1; i < n; i++) {
        base += (uint32_t)a->nthreads;
        memcpy(a->seed + 39, &base, 4);
        rx_calculate_hash_next(a->vm, a->seed, sizeof(a->seed), i == 1 ? first_hash : last);
    }
    rx_calculate_hash_last(a->vm, last);
    /* expose hash of this thread's starting nonce (nonce = tid*golden) */
    memcpy(a->hash, first_hash, 32);

    QueryPerformanceCounter(&t1);
    a->elapsed = (double)(t1.QuadPart - t0.QuadPart) / (double)freq.QuadPart;
    return 0;
}

int main(int argc, char **argv) {
    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);

    int nthreads = 0;
    if (argc > 1) nthreads = atoi(argv[1]);
    if (nthreads <= 0) {
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        nthreads = (int)si.dwNumberOfProcessors;
    }
    if (nthreads > AFFINITY_MAX_CORES) nthreads = AFFINITY_MAX_CORES;

    /* ~1,000,000 hashes total, split across threads */
    long total_target = 1000000;
    int per_thread = (int)((total_target + nthreads - 1) / nthreads);
    long total_hashes = (long)per_thread * nthreads;

    printf("XMR-Miner 1 MH benchmark\n");
    printf("  threads        : %d\n", nthreads);
    printf("  hashes/thread  : %d\n", per_thread);
    printf("  total hashes   : %ld\n", total_hashes);
    printf("  mode           : JIT batch (hash_first/hash_next)\n");
    fflush(stdout);

    rx_cache *cache = rx_alloc_cache(1);
    if (!cache) { printf("FAIL: cache alloc\n"); return 1; }
    uint8_t key[] = "benchmark_seed_1mh";
    rx_init_cache(cache, key, sizeof(key));

    rx_dataset *dataset = rx_alloc_dataset(1);
    if (!dataset) { printf("FAIL: dataset alloc\n"); return 1; }
    printf("  init dataset   : ..."); fflush(stdout);
    rx_init_dataset_cached(dataset, cache, 0, RX_DATASET_ITEMS, nthreads, nthreads);
    printf(" done\n"); fflush(stdout);

    /* correctness reference */
    uint8_t ref[32], seed0[76] = {0};
    {
        rx_vm *vm = rx_create_vm(RX_FLAG_JIT | RX_FLAG_DEFAULT, cache, dataset);
        rx_calculate_hash(vm, seed0, sizeof(seed0), ref);
        rx_destroy_vm(vm);
    }

    /* Compute the same affinity order the production miner uses. */
    int affinity_order[AFFINITY_MAX_CORES * 2];
    int affinity_count = affinity_detect_and_order(affinity_order, AFFINITY_MAX_CORES * 2);
    if (affinity_count > 0) {
        core_list_t cl;
        affinity_detect_cores(&cl);
        int np = 0;
        for (int i = 0; i < cl.count; i++) if (cl.is_pcore[i]) np++;
        printf("  affinity       : %d cores (%d P, %d E) -> %d slots\n",
               cl.count, np, cl.count - np, affinity_count);
    }

    thread_arg_t *args = calloc(nthreads, sizeof(thread_arg_t));
    HANDLE *threads = calloc(nthreads, sizeof(HANDLE));
    for (int i = 0; i < nthreads; i++) {
        args[i].tid = i;
        args[i].nthreads = nthreads;
        args[i].hashes_this_thread = per_thread;
        args[i].affinity_order = affinity_order;
        args[i].affinity_count = affinity_count;
        memset(args[i].seed, 0, sizeof(args[i].seed));
        args[i].vm = rx_create_vm(RX_FLAG_JIT | RX_FLAG_DEFAULT, cache, dataset);
    }

    printf("\n  running %ld hashes on %d threads ...\n", total_hashes, nthreads);
    fflush(stdout);

    LARGE_INTEGER freq, t0, t1;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t0);

    for (int i = 0; i < nthreads; i++)
        threads[i] = CreateThread(NULL, 0, bench_thread, &args[i], 0, NULL);
    WaitForMultipleObjects((DWORD)nthreads, threads, TRUE, INFINITE);

    QueryPerformanceCounter(&t1);
    double wall = (double)(t1.QuadPart - t0.QuadPart) / (double)freq.QuadPart;

    for (int i = 0; i < nthreads; i++) CloseHandle(threads[i]);

    /* correctness: thread 0 with nonce 0 must match the reference */
    int correct = (memcmp(args[0].hash, ref, 32) == 0);

    double hashrate_total = (double)total_hashes / wall;
    double hashrate_per_thread = hashrate_total / nthreads;
    double time_1mh = 1000000.0 / hashrate_total;

    printf("\n==================== RESULTS ====================\n");
    printf("  wall time            : %.3f s\n", wall);
    printf("  total hashrate       : %.1f H/s  (%.3f kH/s)\n", hashrate_total, hashrate_total / 1000.0);
    printf("  hashrate / thread    : %.1f H/s\n", hashrate_per_thread);
    printf("  time for 1 MH        : %.2f s  (%.1f min)\n", time_1mh, time_1mh / 60.0);
    printf("  correctness (vs ref) : %s\n", correct ? "OK" : "MISMATCH");
    printf("================================================\n");

    for (int i = 0; i < nthreads; i++) rx_destroy_vm(args[i].vm);
    free(args); free(threads);
    rx_free_dataset(dataset);
    rx_free_cache(cache);
    return correct ? 0 : 1;
}
