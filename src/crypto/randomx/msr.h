#pragma once

#include <stdint.h>

int msr_init(void);
void msr_destroy(void);
int msr_read_package_energy(double *joules);
int msr_set_package_power_limit(double watts, uint64_t *original);
int msr_restore_package_power_limit(uint64_t original);
int msr_set_prefetch_control(uint64_t value, uint64_t *original);
int msr_restore_prefetch_control(uint64_t original);
