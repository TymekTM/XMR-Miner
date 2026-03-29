#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <windows.h>
#include "crypto/randomx/randomx_internal.h"

int main() {
    printf("[BENCH] Dataset creation benchmark\n");
    fflush(stdout);

    uint8_t seed[32] = {0};
    rx_cache *cache = rx_alloc_cache(0);
    if (!cache) { printf("[FAIL] alloc cache\n"); return 1; }

    printf("[BENCH] Initializing cache...\n");
    fflush(stdout);
    DWORD t0 = GetTickCount();
    rx_init_cache(cache, seed, 32);
    DWORD t1 = GetTickCount();
    printf("[BENCH] Cache init: %u ms\n", t1 - t0);
    fflush(stdout);

    rx_dataset *ds = rx_alloc_dataset(0);
    if (!ds) { printf("[FAIL] alloc dataset\n"); return 1; }

    printf("[BENCH] Initializing full dataset (33554432 items)...\n");
    fflush(stdout);
    t0 = GetTickCount();
    rx_init_dataset(ds, cache, 0, 33554432, 1, 1);
    t1 = GetTickCount();
    DWORD elapsed = t1 - t0;
    printf("[BENCH] Dataset init: %u ms (%.1f sec, %.0f items/sec)\n",
        elapsed, elapsed / 1000.0, 33554432.0 / (elapsed / 1000.0));
    fflush(stdout);

    rx_free_dataset(ds);
    rx_free_cache(cache);
    printf("[BENCH] Done\n");
    return 0;
}
