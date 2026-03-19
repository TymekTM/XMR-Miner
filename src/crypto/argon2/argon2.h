#pragma once

#include "common/osdep.h"

#define ARGON2_OK           0
#define ARGON2_VERIFY_NONE  0
#define ARGON2_VERSION_13   0x13

typedef enum {
    ARGON2_D = 0,
    ARGON2_I = 1,
    ARGON2_ID = 2,
} argon2_type;

int argon2_hash(const argon2_type type,
                u32 t_cost, u32 m_cost, u32 parallelism,
                const void *pwd, size_t pwdlen,
                const void *salt, size_t saltlen,
                const void *secret, size_t secretlen,
                const void *ad, size_t adlen,
                void *hash, size_t hashlen,
                void *external_memory);

void argon2_test_gb(u64 *a, u64 *b, u64 *c, u64 *d);
void argon2_test_P(u64 v[16]);
