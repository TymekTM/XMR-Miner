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
                cores->count++;
            }
        }
        ptr += item->Size;
        remaining -= item->Size;
    }

    free(buf);
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
            }
        }
    }
}

int affinity_build_order(const core_list_t *cores, int *order, int max_count) {
    int n = 0;
    /* P-core primaries first */
    for (int i = 0; i < cores->count && n < max_count; i++) {
        if (cores->is_pcore[i]) order[n++] = cores->os_index[i];
    }
    /* P-core HT siblings second (measured ~188 H/s, slightly faster than
       E-cores ~176 H/s on 14th gen for RandomX) */
    for (int i = 0; i < cores->count && n < max_count; i++) {
        if (cores->is_pcore[i] && cores->sibling[i] >= 0) order[n++] = cores->sibling[i];
    }
    /* E-cores last */
    for (int i = 0; i < cores->count && n < max_count; i++) {
        if (!cores->is_pcore[i]) order[n++] = cores->os_index[i];
    }
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
