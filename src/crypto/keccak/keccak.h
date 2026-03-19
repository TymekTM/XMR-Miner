#pragma once

#include "common/osdep.h"

void keccak256(const uint8_t *data, size_t len, uint8_t *hash);
void keccak1600(const uint64_t *state);
void keccakf1600(uint64_t *state);
