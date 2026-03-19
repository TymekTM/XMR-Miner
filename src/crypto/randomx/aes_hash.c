#include "randomx_internal.h"

#define AES_HASH_1R_STATE0 0xd7983aad, 0xcc82db47, 0x9fa856de, 0x92b52c0d
#define AES_HASH_1R_STATE1 0xace78057, 0xf59e125a, 0x15c7b798, 0x338d996e
#define AES_HASH_1R_STATE2 0xe8a07ce4, 0x5079506b, 0xae62c7d0, 0x6a770017
#define AES_HASH_1R_STATE3 0x7e994948, 0x79a10005, 0x07ad828d, 0x630a240c
#define AES_HASH_1R_XKEY0 0x06890201, 0x90dc56bf, 0x8b24949f, 0xf6fa8389
#define AES_HASH_1R_XKEY1 0xed18f99b, 0xee1043c6, 0x51f4e03c, 0x61b263d1

#define AES_GEN_1R_KEY0 0xb4f44917, 0xdbb5552b, 0x62716609, 0x6daca553
#define AES_GEN_1R_KEY1 0x0da1dc4e, 0x1725d378, 0x846a710d, 0x6d7caf07
#define AES_GEN_1R_KEY2 0x3e20e345, 0xf4c0794f, 0x9f947ec6, 0x3f1262f1
#define AES_GEN_1R_KEY3 0x49169154, 0x16314c88, 0xb1ba317c, 0x6aef8135

#define AES_GEN_4R_KEY0 0x99e5d23f, 0x2f546d2b, 0xd1833ddb, 0x6421aadd
#define AES_GEN_4R_KEY1 0xa5dfcde5, 0x06f79d53, 0xb6913f55, 0xb20e3450
#define AES_GEN_4R_KEY2 0x171c02bf, 0x0aa4679f, 0x515e7baf, 0x5c3ed904
#define AES_GEN_4R_KEY3 0xd8ded291, 0xcd673785, 0xe78f5d08, 0x85623763
#define AES_GEN_4R_KEY4 0x229effb4, 0x3d518b6d, 0xe3d6a7a6, 0xb5826f73
#define AES_GEN_4R_KEY5 0xb272b7d2, 0xe9024d4e, 0x9c10b3d9, 0xc7566bf3
#define AES_GEN_4R_KEY6 0xf63befa7, 0x2ba9660a, 0xf765a38b, 0xf273c9e7
#define AES_GEN_4R_KEY7 0xc0b0762d, 0x0c06d1fd, 0x915839de, 0x7a7cd609

void rx_hash_aes1rx4(const void *input, size_t inputSize, void *hash) {
    const uint8_t *inptr = (const uint8_t *)input;
    const uint8_t *inputEnd = inptr + inputSize;

    rx_vec_i128 s0 = rx_set_i128(AES_HASH_1R_STATE0);
    rx_vec_i128 s1 = rx_set_i128(AES_HASH_1R_STATE1);
    rx_vec_i128 s2 = rx_set_i128(AES_HASH_1R_STATE2);
    rx_vec_i128 s3 = rx_set_i128(AES_HASH_1R_STATE3);

    while (inptr < inputEnd) {
        _mm_prefetch((const char *)(inptr + 128), _MM_HINT_T0);
        s0 = rx_aesenc_i128(s0, rx_load_i128((const rx_vec_i128 *)inptr + 0));
        s1 = rx_aesdec_i128(s1, rx_load_i128((const rx_vec_i128 *)inptr + 1));
        s2 = rx_aesenc_i128(s2, rx_load_i128((const rx_vec_i128 *)inptr + 2));
        s3 = rx_aesdec_i128(s3, rx_load_i128((const rx_vec_i128 *)inptr + 3));
        inptr += 64;
    }

    rx_vec_i128 xk0 = rx_set_i128(AES_HASH_1R_XKEY0);
    rx_vec_i128 xk1 = rx_set_i128(AES_HASH_1R_XKEY1);
    s0 = rx_aesenc_i128(s0, xk0);
    s1 = rx_aesdec_i128(s1, xk0);
    s2 = rx_aesenc_i128(s2, xk0);
    s3 = rx_aesdec_i128(s3, xk0);
    s0 = rx_aesenc_i128(s0, xk1);
    s1 = rx_aesdec_i128(s1, xk1);
    s2 = rx_aesenc_i128(s2, xk1);
    s3 = rx_aesdec_i128(s3, xk1);

    rx_store_i128((rx_vec_i128 *)hash + 0, s0);
    rx_store_i128((rx_vec_i128 *)hash + 1, s1);
    rx_store_i128((rx_vec_i128 *)hash + 2, s2);
    rx_store_i128((rx_vec_i128 *)hash + 3, s3);
}

void rx_fill_aes1rx4(void *state, size_t outputSize, void *buffer) {
    uint8_t *outptr = (uint8_t *)buffer;
    const uint8_t *outputEnd = outptr + outputSize;

    rx_vec_i128 k0 = rx_set_i128(AES_GEN_1R_KEY0);
    rx_vec_i128 k1 = rx_set_i128(AES_GEN_1R_KEY1);
    rx_vec_i128 k2 = rx_set_i128(AES_GEN_1R_KEY2);
    rx_vec_i128 k3 = rx_set_i128(AES_GEN_1R_KEY3);

    rx_vec_i128 s0 = rx_load_i128((const rx_vec_i128 *)state + 0);
    rx_vec_i128 s1 = rx_load_i128((const rx_vec_i128 *)state + 1);
    rx_vec_i128 s2 = rx_load_i128((const rx_vec_i128 *)state + 2);
    rx_vec_i128 s3 = rx_load_i128((const rx_vec_i128 *)state + 3);

    while (outptr < outputEnd) {
        _mm_prefetch((const char *)(outptr + 128), _MM_HINT_T0);
        s0 = rx_aesdec_i128(s0, k0);
        s1 = rx_aesenc_i128(s1, k1);
        s2 = rx_aesdec_i128(s2, k2);
        s3 = rx_aesenc_i128(s3, k3);
        _mm_stream_si128((__m128i *)outptr + 0, s0);
        _mm_stream_si128((__m128i *)outptr + 1, s1);
        _mm_stream_si128((__m128i *)outptr + 2, s2);
        _mm_stream_si128((__m128i *)outptr + 3, s3);
        outptr += 64;
    }
    _mm_sfence();

    rx_store_i128((rx_vec_i128 *)state + 0, s0);
    rx_store_i128((rx_vec_i128 *)state + 1, s1);
    rx_store_i128((rx_vec_i128 *)state + 2, s2);
    rx_store_i128((rx_vec_i128 *)state + 3, s3);
}

void rx_fill_aes4rx4(void *state, size_t outputSize, void *buffer) {
    uint8_t *outptr = (uint8_t *)buffer;
    const uint8_t *outputEnd = outptr + outputSize;

    rx_vec_i128 k0 = rx_set_i128(AES_GEN_4R_KEY0);
    rx_vec_i128 k1 = rx_set_i128(AES_GEN_4R_KEY1);
    rx_vec_i128 k2 = rx_set_i128(AES_GEN_4R_KEY2);
    rx_vec_i128 k3 = rx_set_i128(AES_GEN_4R_KEY3);
    rx_vec_i128 k4 = rx_set_i128(AES_GEN_4R_KEY4);
    rx_vec_i128 k5 = rx_set_i128(AES_GEN_4R_KEY5);
    rx_vec_i128 k6 = rx_set_i128(AES_GEN_4R_KEY6);
    rx_vec_i128 k7 = rx_set_i128(AES_GEN_4R_KEY7);

    rx_vec_i128 s0 = rx_load_i128((const rx_vec_i128 *)state + 0);
    rx_vec_i128 s1 = rx_load_i128((const rx_vec_i128 *)state + 1);
    rx_vec_i128 s2 = rx_load_i128((const rx_vec_i128 *)state + 2);
    rx_vec_i128 s3 = rx_load_i128((const rx_vec_i128 *)state + 3);

    while (outptr < outputEnd) {
        _mm_prefetch((const char *)(outptr + 128), _MM_HINT_T0);
        s0 = rx_aesdec_i128(s0, k0); s1 = rx_aesenc_i128(s1, k0);
        s2 = rx_aesdec_i128(s2, k4); s3 = rx_aesenc_i128(s3, k4);
        s0 = rx_aesdec_i128(s0, k1); s1 = rx_aesenc_i128(s1, k1);
        s2 = rx_aesdec_i128(s2, k5); s3 = rx_aesenc_i128(s3, k5);
        s0 = rx_aesdec_i128(s0, k2); s1 = rx_aesenc_i128(s1, k2);
        s2 = rx_aesdec_i128(s2, k6); s3 = rx_aesenc_i128(s3, k6);
        s0 = rx_aesdec_i128(s0, k3); s1 = rx_aesenc_i128(s1, k3);
        s2 = rx_aesdec_i128(s2, k7); s3 = rx_aesenc_i128(s3, k7);
        _mm_stream_si128((__m128i *)outptr + 0, s0);
        _mm_stream_si128((__m128i *)outptr + 1, s1);
        _mm_stream_si128((__m128i *)outptr + 2, s2);
        _mm_stream_si128((__m128i *)outptr + 3, s3);
        outptr += 64;
    }
    _mm_sfence();
}

void rx_hash_and_fill_aes1rx4(void *scratchpad, size_t scratchpadSize, void *hash, void *fill_state) {
    uint8_t *sp = (uint8_t *)scratchpad;
    const uint8_t *spEnd = sp + scratchpadSize;

    rx_vec_i128 hs0 = rx_set_i128(AES_HASH_1R_STATE0);
    rx_vec_i128 hs1 = rx_set_i128(AES_HASH_1R_STATE1);
    rx_vec_i128 hs2 = rx_set_i128(AES_HASH_1R_STATE2);
    rx_vec_i128 hs3 = rx_set_i128(AES_HASH_1R_STATE3);

    const rx_vec_i128 fk0 = rx_set_i128(AES_GEN_1R_KEY0);
    const rx_vec_i128 fk1 = rx_set_i128(AES_GEN_1R_KEY1);
    const rx_vec_i128 fk2 = rx_set_i128(AES_GEN_1R_KEY2);
    const rx_vec_i128 fk3 = rx_set_i128(AES_GEN_1R_KEY3);

    rx_vec_i128 fs0 = rx_load_i128((const rx_vec_i128 *)fill_state + 0);
    rx_vec_i128 fs1 = rx_load_i128((const rx_vec_i128 *)fill_state + 1);
    rx_vec_i128 fs2 = rx_load_i128((const rx_vec_i128 *)fill_state + 2);
    rx_vec_i128 fs3 = rx_load_i128((const rx_vec_i128 *)fill_state + 3);

    while (sp < spEnd) {
        if (sp + 128 < spEnd)
            _mm_prefetch((const char *)(sp + 128), _MM_HINT_T0);
        hs0 = rx_aesenc_i128(hs0, rx_load_i128((const rx_vec_i128 *)sp + 0));
        hs1 = rx_aesdec_i128(hs1, rx_load_i128((const rx_vec_i128 *)sp + 1));
        hs2 = rx_aesenc_i128(hs2, rx_load_i128((const rx_vec_i128 *)sp + 2));
        hs3 = rx_aesdec_i128(hs3, rx_load_i128((const rx_vec_i128 *)sp + 3));
        fs0 = rx_aesdec_i128(fs0, fk0);
        fs1 = rx_aesenc_i128(fs1, fk1);
        fs2 = rx_aesdec_i128(fs2, fk2);
        fs3 = rx_aesenc_i128(fs3, fk3);
        _mm_stream_si128((__m128i *)sp + 0, fs0);
        _mm_stream_si128((__m128i *)sp + 1, fs1);
        _mm_stream_si128((__m128i *)sp + 2, fs2);
        _mm_stream_si128((__m128i *)sp + 3, fs3);
        sp += 64;
    }
    _mm_sfence();

    rx_store_i128((rx_vec_i128 *)fill_state + 0, fs0);
    rx_store_i128((rx_vec_i128 *)fill_state + 1, fs1);
    rx_store_i128((rx_vec_i128 *)fill_state + 2, fs2);
    rx_store_i128((rx_vec_i128 *)fill_state + 3, fs3);

    rx_vec_i128 xk0 = rx_set_i128(AES_HASH_1R_XKEY0);
    rx_vec_i128 xk1 = rx_set_i128(AES_HASH_1R_XKEY1);
    hs0 = rx_aesenc_i128(hs0, xk0); hs1 = rx_aesdec_i128(hs1, xk0);
    hs2 = rx_aesenc_i128(hs2, xk0); hs3 = rx_aesdec_i128(hs3, xk0);
    hs0 = rx_aesenc_i128(hs0, xk1); hs1 = rx_aesdec_i128(hs1, xk1);
    hs2 = rx_aesenc_i128(hs2, xk1); hs3 = rx_aesdec_i128(hs3, xk1);

    rx_store_i128((rx_vec_i128 *)hash + 0, hs0);
    rx_store_i128((rx_vec_i128 *)hash + 1, hs1);
    rx_store_i128((rx_vec_i128 *)hash + 2, hs2);
    rx_store_i128((rx_vec_i128 *)hash + 3, hs3);
}
