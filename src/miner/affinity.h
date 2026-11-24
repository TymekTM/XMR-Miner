#pragma once

#include <windows.h>

#define AFFINITY_MAX_CORES 64

typedef struct {
    int count;
    int os_index[AFFINITY_MAX_CORES];   /* OS processor index for each physical core */
    int is_pcore[AFFINITY_MAX_CORES];   /* 1 = P-core, 0 = E-core */
    int sibling[AFFINITY_MAX_CORES];    /* second logical processor for HT cores (-1 if none) */
    int eff_class[AFFINITY_MAX_CORES];  /* Windows EfficiencyClass */
} core_list_t;

typedef struct {
    int os_cpu;
    int is_pcore;
    int is_ht_sibling;
    int core_idx;
} core_slot_t;

/* Enumerate physical cores using EfficiencyClass (fallback to HT count). */
int affinity_detect_cores(core_list_t *cores);

/* Sort cores so P-cores come first (stable). */
void affinity_sort_pcore_first(core_list_t *cores);

/* Build a thread placement order: P-core primaries, then E-cores,
   then P-core HT siblings (physical-first for multi-lane + efficiency). */
int affinity_build_order(const core_list_t *cores, int *order, int max_count);

/* Build detailed worker placement slots (physical-first: P -> E -> P-HT). */
int affinity_build_slots(const core_list_t *cores, core_slot_t *slots, int max_count);

/* Convenience: detect + sort + build in one call. Returns order length. */
int affinity_detect_and_order(int *order, int max_count);

/* Pin the current thread to the given OS CPU index. */
void affinity_pin_current(int os_cpu);
