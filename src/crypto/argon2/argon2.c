#include "argon2.h"
#include "../blake2/blake2b.h"
#include <string.h>
#include <stdlib.h>
#include <intrin.h>

#define BLOCK_SIZE 1024
#define QWORDS 128
#define SYNC_POINTS 4

static void gb(u64 *a, u64 *b, u64 *c, u64 *d) {
    u64 aa = *a, bb = *b, cc = *c, dd = *d;
    u64 ab = 2ULL * (u32)aa * (u32)bb;
    aa += bb; aa += ab;
    dd ^= aa; dd = (dd >> 32) | (dd << 32);
    u64 cd = 2ULL * (u32)cc * (u32)dd;
    cc += dd; cc += cd;
    bb ^= cc; bb = (bb >> 24) | (bb << 40);
    ab = 2ULL * (u32)aa * (u32)bb;
    aa += bb; aa += ab;
    dd ^= aa; dd = (dd >> 16) | (dd << 48);
    cd = 2ULL * (u32)cc * (u32)dd;
    cc += dd; cc += cd;
    bb ^= cc; bb = (bb >> 63) | (bb << 1);
    *a = aa; *b = bb; *c = cc; *d = dd;
}

static void P(u64 v[16]) {
    gb(&v[0], &v[4], &v[8], &v[12]);
    gb(&v[1], &v[5], &v[9], &v[13]);
    gb(&v[2], &v[6], &v[10], &v[14]);
    gb(&v[3], &v[7], &v[11], &v[15]);
    gb(&v[0], &v[5], &v[10], &v[15]);
    gb(&v[1], &v[6], &v[11], &v[12]);
    gb(&v[2], &v[7], &v[8], &v[13]);
    gb(&v[3], &v[4], &v[9], &v[14]);
}

static void fill_block(const u64 *prev, const u64 *ref, u64 *next, int with_xor) {
    for (int i = 0; i < QWORDS; i += 8) {
        _mm_prefetch((const char *)(prev + i), _MM_HINT_T0);
        _mm_prefetch((const char *)(ref + i), _MM_HINT_T0);
    }
    __declspec(align(64)) u64 R[QWORDS];
    for (int i = 0; i < QWORDS; i++)
        R[i] = prev[i] ^ ref[i];

    u64 tmp[QWORDS];
    for (int i = 0; i < QWORDS; i++)
        tmp[i] = R[i];
    if (with_xor)
        for (int i = 0; i < QWORDS; i++)
            tmp[i] ^= next[i];

    for (int i = 0; i < 8; i++)
        P(R + i * 16);

    u64 col[16];
    for (int i = 0; i < 8; i++) {
        for (int r = 0; r < 8; r++) {
            col[2*r]   = R[2*i + r * 16];
            col[2*r+1] = R[2*i + r * 16 + 1];
        }
        P(col);
        for (int r = 0; r < 8; r++) {
            R[2*i + r * 16]     = col[2*r];
            R[2*i + r * 16 + 1] = col[2*r+1];
        }
    }

    for (int i = 0; i < QWORDS; i++)
        next[i] = tmp[i] ^ R[i];
}

static void H_prime(u8 *out, size_t outlen, const u8 *in, size_t inlen) {
    u8 buf[4];
    write_u32_le(buf, (u32)outlen);
    if (outlen <= 64) {
        blake2b_state st;
        blake2b_init(&st, (u32)outlen);
        blake2b_update(&st, buf, 4);
        blake2b_update(&st, in, inlen);
        blake2b_final(&st, out, (u32)outlen);
        return;
    }
    u32 r = (u32)((outlen + 31) / 32) - 2;
    u8 V[64];
    blake2b_state st;
    blake2b_init(&st, 64);
    blake2b_update(&st, buf, 4);
    blake2b_update(&st, in, inlen);
    blake2b_final(&st, V, 64);
    memcpy(out, V, 32);
    for (u32 i = 2; i <= r; i++) {
        blake2b_init(&st, 64);
        blake2b_update(&st, V, 64);
        blake2b_final(&st, V, 64);
        memcpy(out + (i - 1) * 32, V, 32);
    }
    u32 last_len = (u32)(outlen - 32 * r);
    blake2b_init(&st, last_len);
    blake2b_update(&st, V, 64);
    blake2b_final(&st, V, last_len);
    memcpy(out + r * 32, V, last_len);
}

static void initial_hash(u8 H0[64], u32 t_cost, u32 m_cost, u32 parallelism,
                           const void *pwd, size_t pwdlen,
                           const void *salt, size_t saltlen,
                           argon2_type type,
                           const void *secret, size_t secretlen,
                           const void *ad, size_t adlen,
                           u32 hashlen) {
    blake2b_state st;
    blake2b_init(&st, 64);
    u32 le;
    write_u32_le(&le, parallelism);  blake2b_update(&st, &le, 4);
    write_u32_le(&le, hashlen);     blake2b_update(&st, &le, 4);
    write_u32_le(&le, m_cost);       blake2b_update(&st, &le, 4);
    write_u32_le(&le, t_cost);       blake2b_update(&st, &le, 4);
    write_u32_le(&le, 0x13);         blake2b_update(&st, &le, 4);
    write_u32_le(&le, (u32)type);    blake2b_update(&st, &le, 4);
    write_u32_le(&le, (u32)pwdlen);  blake2b_update(&st, &le, 4);
    if (pwdlen > 0) blake2b_update(&st, pwd, pwdlen);
    write_u32_le(&le, (u32)saltlen); blake2b_update(&st, &le, 4);
    if (saltlen > 0) blake2b_update(&st, salt, saltlen);
    write_u32_le(&le, (u32)secretlen); blake2b_update(&st, &le, 4);
    if (secretlen > 0) blake2b_update(&st, secret, secretlen);
    write_u32_le(&le, (u32)adlen);   blake2b_update(&st, &le, 4);
    if (adlen > 0) blake2b_update(&st, ad, adlen);
    blake2b_final(&st, H0, 64);
}

static u32 index_alpha(u32 pass, u32 slice, u32 index,
                       u32 lane_length, u32 seg_len,
                       u32 pseudo_rand, int same_lane) {
    u32 reference_area_size;
    u64 rel_pos;
    u32 start_pos, abs_pos;

    if (pass == 0) {
        if (slice == 0) {
            reference_area_size = index - 1;
        } else {
            if (same_lane) {
                reference_area_size = slice * seg_len + index - 1;
            } else {
                reference_area_size = slice * seg_len + (u32)((index == 0) ? -1 : 0);
            }
        }
    } else {
        if (same_lane) {
            reference_area_size = lane_length - seg_len + index - 1;
        } else {
            reference_area_size = lane_length - seg_len + (u32)((index == 0) ? -1 : 0);
        }
    }

    rel_pos = pseudo_rand;
    rel_pos = rel_pos * rel_pos >> 32;
    rel_pos = reference_area_size - 1 - (reference_area_size * rel_pos >> 32);

    start_pos = 0;
    if (pass != 0) {
        start_pos = (slice == SYNC_POINTS - 1)
                        ? 0
                        : (slice + 1) * seg_len;
    }

    abs_pos = (start_pos + (u32)rel_pos) % lane_length;
    return abs_pos;
}

int argon2_hash(const argon2_type type,
                u32 t_cost, u32 m_cost, u32 parallelism,
                const void *pwd, size_t pwdlen,
                const void *salt, size_t saltlen,
                const void *secret, size_t secretlen,
                const void *ad, size_t adlen,
                void *hash, size_t hashlen,
                void *external_memory) {
    u32 lane_length = (m_cost / parallelism) & ~3u;
    u32 m_prime = lane_length * parallelism;
    u32 seg_len = lane_length / SYNC_POINTS;
    size_t mem_bytes = (size_t)m_prime * BLOCK_SIZE;
    int own_memory = 0;
    u64 *blocks;
    if (external_memory) {
        blocks = (u64 *)external_memory;
        memset(blocks, 0, mem_bytes);
    } else {
        blocks = (u64 *)calloc(mem_bytes, 1);
        if (!blocks) return -1;
        own_memory = 1;
    }

    u8 H0[64];
    initial_hash(H0, t_cost, m_cost, parallelism, pwd, pwdlen, salt, saltlen,
                  type, secret, secretlen, ad, adlen, (u32)hashlen);

    u8 block_input[64 + 4 + 4];
    memcpy(block_input, H0, 64);

    for (u32 lane = 0; lane < parallelism; lane++) {
        for (u32 j = 0; j < 2; j++) {
            write_u32_le(block_input + 64, j);
            write_u32_le(block_input + 68, lane);
            H_prime((u8 *)(blocks + (size_t)(lane * lane_length + j) * QWORDS),
                    BLOCK_SIZE, block_input, 72);
        }
    }

    for (u32 pass = 0; pass < t_cost; pass++) {
        for (u32 slice = 0; slice < SYNC_POINTS; slice++) {
            for (u32 lane = 0; lane < parallelism; lane++) {
                u32 starting_index = (pass == 0 && slice == 0) ? 2 : 0;
                u32 curr_offset = lane * lane_length + slice * seg_len + starting_index;
                u32 prev_offset;
                u32 pos_in_lane = curr_offset % lane_length;
                if (pos_in_lane == 0)
                    prev_offset = curr_offset + lane_length - 1;
                else
                    prev_offset = curr_offset - 1;
                u32 next_crossing = (pos_in_lane == 0)
                    ? (curr_offset + 1)
                    : (curr_offset + lane_length - pos_in_lane + 1);

                for (u32 index = starting_index; index < seg_len;
                     index++, curr_offset++, prev_offset++) {
                    if (curr_offset == next_crossing) {
                        prev_offset = curr_offset - 1;
                        next_crossing += lane_length;
                    }
                    u64 pseudo_rand = (blocks + (size_t)prev_offset * QWORDS)[0];
                    u32 ref_lane = (u32)((pseudo_rand >> 32) % parallelism);
                    if (pass == 0 && slice == 0) {
                        ref_lane = lane;
                    }
                    u32 ref_index = index_alpha(pass, slice, index,
                                                lane_length, seg_len,
                                                (u32)(pseudo_rand & 0xFFFFFFFF),
                                                ref_lane == lane);
                    u64 *curr = blocks + (size_t)curr_offset * QWORDS;
                    u64 *prev = blocks + (size_t)prev_offset * QWORDS;
                    u64 *ref  = blocks + (size_t)(ref_lane * lane_length + ref_index) * QWORDS;
                    int with_xor = (pass > 0) ? 1 : 0;
                    fill_block(prev, ref, curr, with_xor);
                }
            }
        }
    }

    if (hash && hashlen > 0) {
        u8 C[BLOCK_SIZE];
        memset(C, 0, BLOCK_SIZE);
        for (u32 lane = 0; lane < parallelism; lane++) {
            const u64 *last = blocks + (size_t)(lane * lane_length + lane_length - 1) * QWORDS;
            for (int i = 0; i < QWORDS; i++)
                ((u64 *)C)[i] ^= last[i];
        }
        H_prime(hash, hashlen, C, BLOCK_SIZE);
    }

    if (own_memory) free(blocks);
    return ARGON2_OK;
}

void argon2_test_gb(u64 *a, u64 *b, u64 *c, u64 *d) { gb(a, b, c, d); }
