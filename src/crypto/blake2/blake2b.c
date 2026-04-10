#include "blake2b.h"
#include <string.h>

#define NATIVE_LITTLE_ENDIAN
#include "blake2b-impl.h"

typedef struct {
    u8 digest_length;
    u8 key_length;
    u8 fanout;
    u8 depth;
    u32 leaf_length;
    u32 node_offset;
    u32 xof_length;
    u8 node_depth;
    u8 inner_length;
    u8 reserved[14];
    u8 salt[BLAKE2B_SALTBYTES];
    u8 personal[BLAKE2B_PERSONALBYTES];
} blake2b_param;

static const u64 blake2b_IV[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL,
};

static const u8 blake2b_sigma[12][16] = {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 },
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
};

#define G(r,i,a,b,c,d) do { \
    a = a + b + m[blake2b_sigma[r][2*i+0]]; \
    d = rotr64(d ^ a, 32); \
    c = c + d; \
    b = rotr64(b ^ c, 24); \
    a = a + b + m[blake2b_sigma[r][2*i+1]]; \
    d = rotr64(d ^ a, 16); \
    c = c + d; \
    b = rotr64(b ^ c, 63); \
} while(0)

static __forceinline void blake2b_compress(blake2b_state *S, const u8 block[BLAKE2B_BLOCKBYTES]) {
    u64 m[16];
    u64 v[16];
    int i;

    for (i = 0; i < 16; ++i)
        m[i] = load64(block + i * sizeof(m[i]));

    for (i = 0; i < 8; ++i)
        v[i] = S->h[i];

    v[8]  = blake2b_IV[0];
    v[9]  = blake2b_IV[1];
    v[10] = blake2b_IV[2];
    v[11] = blake2b_IV[3];
    v[12] = blake2b_IV[4] ^ S->t[0];
    v[13] = blake2b_IV[5] ^ S->t[1];
    v[14] = blake2b_IV[6] ^ S->f[0];
    v[15] = blake2b_IV[7] ^ S->f[1];

    for (int r = 0; r < 12; ++r) {
        G(r, 0, v[ 0], v[ 4], v[ 8], v[12]);
        G(r, 1, v[ 1], v[ 5], v[ 9], v[13]);
        G(r, 2, v[ 2], v[ 6], v[10], v[14]);
        G(r, 3, v[ 3], v[ 7], v[11], v[15]);
        G(r, 4, v[ 0], v[ 5], v[10], v[15]);
        G(r, 5, v[ 1], v[ 6], v[11], v[12]);
        G(r, 6, v[ 2], v[ 7], v[ 8], v[13]);
        G(r, 7, v[ 3], v[ 4], v[ 9], v[14]);
    }

    for (i = 0; i < 8; ++i)
        S->h[i] ^= v[i] ^ v[i + 8];
}

#undef G

static int blake2b_is_lastblock(const blake2b_state *S) {
    return S->f[0] != 0;
}

static void blake2b_increment_counter(blake2b_state *S, const u64 inc) {
    S->t[0] += inc;
    S->t[1] += (S->t[0] < inc);
}

static void blake2b_set_lastblock(blake2b_state *S) {
    S->f[0] = (u64)-1;
}

static void blake2b_init0(blake2b_state *S) {
    memset(S, 0, sizeof(blake2b_state));
    for (int i = 0; i < 8; ++i)
        S->h[i] = blake2b_IV[i];
}

static int blake2b_init_param(blake2b_state *S, const blake2b_param *P) {
    const u8 *p = (const u8 *)(P);
    blake2b_init0(S);
    for (int i = 0; i < 8; ++i)
        S->h[i] ^= load64(p + sizeof(S->h[i]) * i);
    S->outlen = P->digest_length;
    return 0;
}

int blake2b_init(blake2b_state *S, size_t outlen) {
    blake2b_param P;
    if (!outlen || outlen > BLAKE2B_OUTBYTES) return -1;
    memset(&P, 0, sizeof(P));
    P.digest_length = (u8)outlen;
    P.fanout = 1;
    P.depth = 1;
    return blake2b_init_param(S, &P);
}

int blake2b_init_key(blake2b_state *S, size_t outlen, const void *key, size_t keylen) {
    blake2b_param P;
    if (!outlen || outlen > BLAKE2B_OUTBYTES) return -1;
    if (!key || !keylen || keylen > BLAKE2B_KEYBYTES) return -1;
    memset(&P, 0, sizeof(P));
    P.digest_length = (u8)outlen;
    P.key_length = (u8)keylen;
    P.fanout = 1;
    P.depth = 1;
    if (blake2b_init_param(S, &P) < 0) return -1;
    {
        u8 block[BLAKE2B_BLOCKBYTES];
        memset(block, 0, BLAKE2B_BLOCKBYTES);
        memcpy(block, key, keylen);
        blake2b_update(S, block, BLAKE2B_BLOCKBYTES);
        secure_zero_memory(block, BLAKE2B_BLOCKBYTES);
    }
    return 0;
}

int blake2b_update(blake2b_state *S, const void *pin, size_t inlen) {
    const u8 *in = (const u8 *)pin;
    if (inlen > 0) {
        size_t left = S->buflen;
        size_t fill = BLAKE2B_BLOCKBYTES - left;
        if (inlen > fill) {
            S->buflen = 0;
            memcpy(S->buf + left, in, fill);
            blake2b_increment_counter(S, BLAKE2B_BLOCKBYTES);
            blake2b_compress(S, S->buf);
            in += fill;
            inlen -= fill;
            while (inlen > BLAKE2B_BLOCKBYTES) {
                blake2b_increment_counter(S, BLAKE2B_BLOCKBYTES);
                blake2b_compress(S, in);
                in += BLAKE2B_BLOCKBYTES;
                inlen -= BLAKE2B_BLOCKBYTES;
            }
        }
        memcpy(S->buf + S->buflen, in, inlen);
        S->buflen += (int)inlen;
    }
    return 0;
}

int blake2b_final(blake2b_state *S, void *out, size_t outlen) {
    u8 buffer[BLAKE2B_OUTBYTES];
    if (!out || outlen < (size_t)S->outlen) return -1;
    if (blake2b_is_lastblock(S)) return -1;
    blake2b_increment_counter(S, S->buflen);
    blake2b_set_lastblock(S);
    memset(S->buf + S->buflen, 0, BLAKE2B_BLOCKBYTES - S->buflen);
    blake2b_compress(S, S->buf);
    for (int i = 0; i < 8; ++i)
        store64(buffer + sizeof(S->h[i]) * i, S->h[i]);
    memcpy(out, buffer, S->outlen);
    secure_zero_memory(buffer, sizeof(buffer));
    return 0;
}

int blake2b(void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen) {
    blake2b_state S;
    if (!in && inlen > 0) return -1;
    if (!out) return -1;
    if (!outlen || outlen > BLAKE2B_OUTBYTES) return -1;
    if (keylen > BLAKE2B_KEYBYTES) return -1;
    if (keylen > 0) {
        if (blake2b_init_key(&S, outlen, key, keylen) < 0) return -1;
    } else {
        if (blake2b_init(&S, outlen) < 0) return -1;
    }
    blake2b_update(&S, in, inlen);
    blake2b_final(&S, out, outlen);
    return 0;
}

static __forceinline void blake2b_compress_fast(u64 h[8], const u8 *block, u64 t0, u64 t1, u64 f0, u64 f1) {
    u64 m[16], v[16];
    int i;
    for (i = 0; i < 16; ++i) m[i] = load64(block + i * 8);
    for (i = 0; i < 8; ++i) v[i] = h[i];
    v[8] = blake2b_IV[0]; v[9] = blake2b_IV[1]; v[10] = blake2b_IV[2]; v[11] = blake2b_IV[3];
    v[12] = blake2b_IV[4] ^ t0; v[13] = blake2b_IV[5] ^ t1;
    v[14] = blake2b_IV[6] ^ f0; v[15] = blake2b_IV[7] ^ f1;
#define G(r,i,a,b,c,d) do { \
    a = a + b + m[blake2b_sigma[r][2*i+0]]; d = rotr64(d ^ a, 32); \
    c = c + d; b = rotr64(b ^ c, 24); \
    a = a + b + m[blake2b_sigma[r][2*i+1]]; d = rotr64(d ^ a, 16); \
    c = c + d; b = rotr64(b ^ c, 63); \
} while(0)
    for (int r = 0; r < 12; ++r) {
        G(r,0,v[0],v[4],v[8],v[12]); G(r,1,v[1],v[5],v[9],v[13]);
        G(r,2,v[2],v[6],v[10],v[14]); G(r,3,v[3],v[7],v[11],v[15]);
        G(r,4,v[0],v[5],v[10],v[15]); G(r,5,v[1],v[6],v[11],v[12]);
        G(r,6,v[2],v[7],v[8],v[13]); G(r,7,v[3],v[4],v[9],v[14]);
    }
#undef G
    for (i = 0; i < 8; ++i) h[i] ^= v[i] ^ v[i+8];
}

void rx_blake2b_regfile(void *out, const void *regfile) {
    u64 h[8];
    const u8 *in = (const u8 *)regfile;
    int i;
    for (i = 0; i < 8; ++i) h[i] = blake2b_IV[i];
    h[0] ^= 0x0000000001010040ULL;
    blake2b_compress_fast(h, in, 128, 0, 0, 0);
    blake2b_compress_fast(h, in + 128, 256, 0, 0, 0);
    {
        u8 buf[128];
        memset(buf, 0, 128);
        blake2b_compress_fast(h, buf, 256, 0, (u64)-1, (u64)-1);
        for (i = 0; i < 8; ++i) store64((u8 *)out + i * 8, h[i]);
    }
}

void rx_blake2b_blob(void *out, const void *input, size_t len) {
    u64 h[8];
    const u8 *in = (const u8 *)input;
    int i;
    for (i = 0; i < 8; ++i) h[i] = blake2b_IV[i];
    h[0] ^= 0x0000000001010040ULL;
    if (len <= BLAKE2B_BLOCKBYTES) {
        u8 buf[BLAKE2B_BLOCKBYTES];
        memset(buf, 0, BLAKE2B_BLOCKBYTES);
        memcpy(buf, in, len);
        blake2b_compress_fast(h, buf, len, 0, (u64)-1, (u64)-1);
    } else {
        blake2b_compress_fast(h, in, BLAKE2B_BLOCKBYTES, 0, 0, 0);
        blake2b_compress_fast(h, in + BLAKE2B_BLOCKBYTES, len, 0, (u64)-1, (u64)-1);
    }
    for (i = 0; i < 8; ++i) store64((u8 *)out + i * 8, h[i]);
}
