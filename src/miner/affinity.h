#pragma once

#include <windows.h>

#define AFFINITY_MAX_CORES 64

typedef struct {
    int count;
    int os_index[AFFINITY_MAX_CORES];   /* OS processor index for each physical core */
    int is_pcore[AFFINITY_MAX_CORES];   /* 1 = P-core (has HT), 0 = E-core */
    int sibling[AFFINITY_MAX_CORES];    /* second logical processor for HT cores (-1 if none) */
} core_list_t;

/* Enumerate physical cores. Returns count, 0 on failure. A core with 2
   logical processors is treated as a P-core (HT), 1 as an E-core. */
int affinity_detect_cores(core_list_t *cores);

/* Sort cores so P-cores come first (stable). */
void affinity_sort_pcore_first(core_list_t *cores);

/* Build a thread placement order: P-core primaries, then P-core HT siblings,
   then E-cores. Returns the number of entries written. */
int affinity_build_order(const core_list_t *cores, int *order, int max_count);

/* Convenience: detect + sort + build in one call. Returns order length. */
int affinity_detect_and_order(int *order, int max_count);

/* Pin the current thread to the given OS CPU index. */
void affinity_pin_current(int os_cpu);
