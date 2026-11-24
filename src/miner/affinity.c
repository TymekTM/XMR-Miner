#include "affinity.h"
#include <stdlib.h>

int affinity_detect_cores(core_list_t *cores) {
    cores->count = 0;

    DWORD len = 0;
    GetLogicalProcessorInformationEx(RelationProcessorCore, NULL, &len);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) return 0;

    SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *buf = (SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *)malloc(len);
    if (!buf) return 0;

    if (!GetLogicalProcessorInformationEx(RelationProcessorCore, buf, &len)) {
        free(buf);
        return 0;
    }

    BYTE *ptr = (BYTE *)buf;
    DWORD remaining = len;
    while (remaining > 0) {
        SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *item = (SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *)ptr;
        if (item->Relationship == RelationProcessorCore) {
            GROUP_AFFINITY mask = item->Processor.GroupMask[0];
            int os_idx = -1;
            int sibling = -1;
            int bits = 0;
            for (int b = 0; b < 64 && b < (int)sizeof(mask.Mask) * 8; b++) {
                if (mask.Mask & (1ULL << b)) {
                    int cpu = b + mask.Group * 64;
                    if (os_idx < 0) os_idx = cpu;
                    else if (sibling < 0) sibling = cpu;
                    bits++;
                }
            }
            if (os_idx >= 0 && cores->count < AFFINITY_MAX_CORES) {
                cores->os_index[cores->count] = os_idx;
                cores->is_pcore[cores->count] = (bits == 2) ? 1 : 0;
                cores->sibling[cores->count] = sibling;
                cores->eff_class[cores->count] = (int)item->Processor.EfficiencyClass;
                cores->count++;
            }
        }
        ptr += item->Size;
        remaining -= item->Size;
    }

    free(buf);
    /* On hybrid CPUs (Intel 12th-14th gen), EfficiencyClass accurately distinguishes
       P-cores from E-cores even when Hyper-Threading is disabled in BIOS. */
    if (cores->count > 0) {
        int min_eff = cores->eff_class[0], max_eff = cores->eff_class[0];
        for (int i = 1; i < cores->count; i++) {
            if (cores->eff_class[i] < min_eff) min_eff = cores->eff_class[i];
            if (cores->eff_class[i] > max_eff) max_eff = cores->eff_class[i];
        }
        if (max_eff > min_eff) {
            for (int i = 0; i < cores->count; i++) {
                cores->is_pcore[i] = (cores->eff_class[i] == max_eff) ? 1 : 0;
            }
        } else {
            /* Homogeneous CPU: all cores are P-cores */
            for (int i = 0; i < cores->count; i++) {
                cores->is_pcore[i] = 1;
            }
        }
    }
    return cores->count;
}

void affinity_sort_pcore_first(core_list_t *cores) {
    /* Stable bubble sort: P-cores first. */
    for (int i = 0; i < cores->count - 1; i++) {
        for (int j = 0; j < cores->count - 1 - i; j++) {
            if (cores->is_pcore[j] < cores->is_pcore[j + 1]) {
                int tmp;
                tmp = cores->os_index[j]; cores->os_index[j] = cores->os_index[j + 1]; cores->os_index[j + 1] = tmp;
                tmp = cores->is_pcore[j]; cores->is_pcore[j] = cores->is_pcore[j + 1]; cores->is_pcore[j + 1] = tmp;
                tmp = cores->sibling[j]; cores->sibling[j] = cores->sibling[j + 1]; cores->sibling[j + 1] = tmp;
                tmp = cores->eff_class[j]; cores->eff_class[j] = cores->eff_class[j + 1]; cores->eff_class[j + 1] = tmp;
            }
        }
    }
}

int affinity_build_slots(const core_list_t *cores, core_slot_t *slots, int max_count) {
    int n = 0;
    /* 1. P-core primaries first */
    for (int i = 0; i < cores->count && n < max_count; i++) {
        if (cores->is_pcore[i]) {
            slots[n].os_cpu = cores->os_index[i];
            slots[n].is_pcore = 1;
            slots[n].is_ht_sibling = 0;
            slots[n].core_idx = i;
            n++;
        }
    }
    /* 2. E-cores second, spread round-robin across L2 clusters (4 E-cores per
       cluster on Intel hybrid CPUs) so partial E-core counts (e.g. -t 12..16)
       maximize dedicated L2 per active E-core. */
    int e_idx[AFFINITY_MAX_CORES];
    int e_count = 0;
    for (int i = 0; i < cores->count && e_count < AFFINITY_MAX_CORES; i++) {
        if (!cores->is_pcore[i]) e_idx[e_count++] = i;
    }
    if (e_count > 0) {
        int cluster_size = (e_count >= 8 && (e_count % 4) == 0) ? 4 : 1;
        int num_clusters = (e_count + cluster_size - 1) / cluster_size;
        for (int pos = 0; pos < cluster_size && n < max_count; pos++) {
            for (int cl = 0; cl < num_clusters && n < max_count; cl++) {
                int idx = cl * cluster_size + pos;
                if (idx >= e_count) continue;
                int ci = e_idx[idx];
                slots[n].os_cpu = cores->os_index[ci];
                slots[n].is_pcore = 0;
                slots[n].is_ht_sibling = 0;
                slots[n].core_idx = ci;
                n++;
            }
        }
    }
    /* 3. P-core HT siblings last */
    for (int i = 0; i < cores->count && n < max_count; i++) {
        if (cores->is_pcore[i] && cores->sibling[i] >= 0) {
            slots[n].os_cpu = cores->sibling[i];
            slots[n].is_pcore = 1;
            slots[n].is_ht_sibling = 1;
            slots[n].core_idx = i;
            n++;
        }
    }
    return n;
}

int affinity_build_order(const core_list_t *cores, int *order, int max_count) {
    core_slot_t slots[AFFINITY_MAX_CORES * 2];
    int cap = max_count < (AFFINITY_MAX_CORES * 2) ? max_count : (AFFINITY_MAX_CORES * 2);
    int n = affinity_build_slots(cores, slots, cap);
    for (int i = 0; i < n; i++) order[i] = slots[i].os_cpu;
    return n;
}

int affinity_detect_and_order(int *order, int max_count) {
    core_list_t cores;
    if (affinity_detect_cores(&cores) <= 0) return 0;
    affinity_sort_pcore_first(&cores);
    return affinity_build_order(&cores, order, max_count);
}

void affinity_pin_current(int os_cpu) {
    GROUP_AFFINITY ga;
    ZeroMemory(&ga, sizeof(ga));
    ga.Group = (WORD)(os_cpu / 64);
    ga.Mask = (KAFFINITY)(1ULL << (os_cpu % 64));
    SetThreadGroupAffinity(GetCurrentThread(), &ga, NULL);
}
