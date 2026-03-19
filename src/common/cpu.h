#pragma once

#include "osdep.h"

typedef struct {
    int has_aes_ni;
    int has_avx2;
    int has_sse2;
    int has_bmi2;
    int has_avx;
    int logical_cores;
    int physical_cores;
    int l3_cache_kb;
    char brand_string[49];
} cpu_info_t;

void cpu_detect(cpu_info_t *info);
void cpu_print_info(const cpu_info_t *info);
int cpu_has_aes_ni(void);
int cpu_has_avx2(void);
int cpu_has_sse2(void);
int cpu_has_bmi2(void);
int cpu_count_logical(void);
