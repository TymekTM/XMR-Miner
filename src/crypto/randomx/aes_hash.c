#include "randomx_internal.h"
#include "common/cpu.h"

int g_aes_hash_fill_prefetch = 0;
int g_aes_hash_fill_upstream = 0;
int g_aes_use_vaes = 1;

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

#if defined(_MSC_VER) || defined(__VAES__)
#define RX_HAVE_VAES_CODE 1
#else
#define RX_HAVE_VAES_CODE 0
#endif

void rx_hash_aes1rx4(const void *input, size_t inputSize, void *hash) {
    const uint8_t *inptr = (const uint8_t *)input;
    const uint8_t *inputEnd = inptr + inputSize;

#if RX_HAVE_VAES_CODE
    if (g_aes_use_vaes && cpu_has_vaes()) {
        __m256i s02 = _mm256_set_m128i(rx_set_i128(AES_HASH_1R_STATE2), rx_set_i128(AES_HASH_1R_STATE0));
        __m256i s13 = _mm256_set_m128i(rx_set_i128(AES_HASH_1R_STATE3), rx_set_i128(AES_HASH_1R_STATE1));
        while (inptr < inputEnd) {
            __m256i a0 = _mm256_loadu_si256((const __m256i *)inptr + 0);
            __m256i a1 = _mm256_loadu_si256((const __m256i *)inptr + 1);
            __m256i l02 = _mm256_permute2x128_si256(a0, a1, 0x20);
            __m256i l13 = _mm256_permute2x128_si256(a0, a1, 0x31);
            s02 = _mm256_aesenc_epi128(s02, l02);
            s13 = _mm256_aesdec_epi128(s13, l13);
            inptr += 64;
        }
        __m128i xk0_128 = rx_set_i128(AES_HASH_1R_XKEY0);
        __m128i xk1_128 = rx_set_i128(AES_HASH_1R_XKEY1);
        __m256i xk0 = _mm256_set_m128i(xk0_128, xk0_128);
        __m256i xk1 = _mm256_set_m128i(xk1_128, xk1_128);
        s02 = _mm256_aesenc_epi128(s02, xk0);
        s13 = _mm256_aesdec_epi128(s13, xk0);
        s02 = _mm256_aesenc_epi128(s02, xk1);
        s13 = _mm256_aesdec_epi128(s13, xk1);
        _mm256_storeu_si256((__m256i *)hash + 0, _mm256_permute2x128_si256(s02, s13, 0x20));
        _mm256_storeu_si256((__m256i *)hash + 1, _mm256_permute2x128_si256(s02, s13, 0x31));
        _mm256_zeroupper();
        return;
    }
#endif

    rx_vec_i128 s0 = rx_set_i128(AES_HASH_1R_STATE0);
    rx_vec_i128 s1 = rx_set_i128(AES_HASH_1R_STATE1);
    rx_vec_i128 s2 = rx_set_i128(AES_HASH_1R_STATE2);
    rx_vec_i128 s3 = rx_set_i128(AES_HASH_1R_STATE3);

    while (inptr < inputEnd) {
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

#if RX_HAVE_VAES_CODE
    if (g_aes_use_vaes && cpu_has_vaes()) {
        __m256i k02 = _mm256_set_m128i(rx_set_i128(AES_GEN_1R_KEY2), rx_set_i128(AES_GEN_1R_KEY0));
        __m256i k13 = _mm256_set_m128i(rx_set_i128(AES_GEN_1R_KEY3), rx_set_i128(AES_GEN_1R_KEY1));
        __m256i s02 = _mm256_set_m128i(_mm_loadu_si128((const __m128i *)state + 2),
                                       _mm_loadu_si128((const __m128i *)state + 0));
        __m256i s13 = _mm256_set_m128i(_mm_loadu_si128((const __m128i *)state + 3),
                                       _mm_loadu_si128((const __m128i *)state + 1));
        while (outptr < outputEnd) {
            s02 = _mm256_aesdec_epi128(s02, k02);
            s13 = _mm256_aesenc_epi128(s13, k13);
            _mm256_storeu_si256((__m256i *)outptr + 0, _mm256_permute2x128_si256(s02, s13, 0x20));
            _mm256_storeu_si256((__m256i *)outptr + 1, _mm256_permute2x128_si256(s02, s13, 0x31));
            outptr += 64;
        }
        _mm256_storeu_si256((__m256i *)state + 0, _mm256_permute2x128_si256(s02, s13, 0x20));
        _mm256_storeu_si256((__m256i *)state + 1, _mm256_permute2x128_si256(s02, s13, 0x31));
        _mm256_zeroupper();
        return;
    }
#endif

    rx_vec_i128 k0 = rx_set_i128(AES_GEN_1R_KEY0);
    rx_vec_i128 k1 = rx_set_i128(AES_GEN_1R_KEY1);
    rx_vec_i128 k2 = rx_set_i128(AES_GEN_1R_KEY2);
    rx_vec_i128 k3 = rx_set_i128(AES_GEN_1R_KEY3);

    rx_vec_i128 s0 = rx_load_i128((const rx_vec_i128 *)state + 0);
    rx_vec_i128 s1 = rx_load_i128((const rx_vec_i128 *)state + 1);
    rx_vec_i128 s2 = rx_load_i128((const rx_vec_i128 *)state + 2);
    rx_vec_i128 s3 = rx_load_i128((const rx_vec_i128 *)state + 3);

    while (outptr < outputEnd) {
        s0 = rx_aesdec_i128(s0, k0);
        s1 = rx_aesenc_i128(s1, k1);
        s2 = rx_aesdec_i128(s2, k2);
        s3 = rx_aesenc_i128(s3, k3);
        _mm_store_si128((__m128i *)outptr + 0, s0);
        _mm_store_si128((__m128i *)outptr + 1, s1);
        _mm_store_si128((__m128i *)outptr + 2, s2);
        _mm_store_si128((__m128i *)outptr + 3, s3);
        outptr += 64;
    }

    rx_store_i128((rx_vec_i128 *)state + 0, s0);
    rx_store_i128((rx_vec_i128 *)state + 1, s1);
    rx_store_i128((rx_vec_i128 *)state + 2, s2);
    rx_store_i128((rx_vec_i128 *)state + 3, s3);
}

void rx_fill_aes4rx4(void *state, size_t outputSize, void *buffer) {
    uint8_t *outptr = (uint8_t *)buffer;
    const uint8_t *outputEnd = outptr + outputSize;

#if RX_HAVE_VAES_CODE
    if (g_aes_use_vaes && cpu_has_vaes()) {
        __m256i k04 = _mm256_set_m128i(rx_set_i128(AES_GEN_4R_KEY4), rx_set_i128(AES_GEN_4R_KEY0));
        __m256i k15 = _mm256_set_m128i(rx_set_i128(AES_GEN_4R_KEY5), rx_set_i128(AES_GEN_4R_KEY1));
        __m256i k26 = _mm256_set_m128i(rx_set_i128(AES_GEN_4R_KEY6), rx_set_i128(AES_GEN_4R_KEY2));
        __m256i k37 = _mm256_set_m128i(rx_set_i128(AES_GEN_4R_KEY7), rx_set_i128(AES_GEN_4R_KEY3));
        __m256i s02 = _mm256_set_m128i(_mm_loadu_si128((const __m128i *)state + 2),
                                       _mm_loadu_si128((const __m128i *)state + 0));
        __m256i s13 = _mm256_set_m128i(_mm_loadu_si128((const __m128i *)state + 3),
                                       _mm_loadu_si128((const __m128i *)state + 1));
        while (outptr < outputEnd) {
            s02 = _mm256_aesdec_epi128(s02, k04); s13 = _mm256_aesenc_epi128(s13, k04);
            s02 = _mm256_aesdec_epi128(s02, k15); s13 = _mm256_aesenc_epi128(s13, k15);
            s02 = _mm256_aesdec_epi128(s02, k26); s13 = _mm256_aesenc_epi128(s13, k26);
            s02 = _mm256_aesdec_epi128(s02, k37); s13 = _mm256_aesenc_epi128(s13, k37);
            _mm256_storeu_si256((__m256i *)outptr + 0, _mm256_permute2x128_si256(s02, s13, 0x20));
            _mm256_storeu_si256((__m256i *)outptr + 1, _mm256_permute2x128_si256(s02, s13, 0x31));
            outptr += 64;
        }
        _mm256_zeroupper();
        return;
    }
#endif

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
        s0 = rx_aesdec_i128(s0, k0); s1 = rx_aesenc_i128(s1, k0);
        s2 = rx_aesdec_i128(s2, k4); s3 = rx_aesenc_i128(s3, k4);
        s0 = rx_aesdec_i128(s0, k1); s1 = rx_aesenc_i128(s1, k1);
        s2 = rx_aesdec_i128(s2, k5); s3 = rx_aesenc_i128(s3, k5);
        s0 = rx_aesdec_i128(s0, k2); s1 = rx_aesenc_i128(s1, k2);
        s2 = rx_aesdec_i128(s2, k6); s3 = rx_aesenc_i128(s3, k6);
        s0 = rx_aesdec_i128(s0, k3); s1 = rx_aesenc_i128(s1, k3);
        s2 = rx_aesdec_i128(s2, k7); s3 = rx_aesenc_i128(s3, k7);
        _mm_store_si128((__m128i *)outptr + 0, s0);
        _mm_store_si128((__m128i *)outptr + 1, s1);
        _mm_store_si128((__m128i *)outptr + 2, s2);
        _mm_store_si128((__m128i *)outptr + 3, s3);
        outptr += 64;
    }
}

void rx_hash_and_fill_aes1rx4(void *scratchpad, size_t scratchpadSize, void *hash, void *fill_state) {
    uint8_t *sp = (uint8_t *)scratchpad;
    const uint8_t *spEnd = sp + scratchpadSize;

#if RX_HAVE_VAES_CODE
    if (g_aes_use_vaes && cpu_has_vaes()) {
        __m256i hs02 = _mm256_set_m128i(rx_set_i128(AES_HASH_1R_STATE2), rx_set_i128(AES_HASH_1R_STATE0));
        __m256i hs13 = _mm256_set_m128i(rx_set_i128(AES_HASH_1R_STATE3), rx_set_i128(AES_HASH_1R_STATE1));
        const __m256i fk02 = _mm256_set_m128i(rx_set_i128(AES_GEN_1R_KEY2), rx_set_i128(AES_GEN_1R_KEY0));
        const __m256i fk13 = _mm256_set_m128i(rx_set_i128(AES_GEN_1R_KEY3), rx_set_i128(AES_GEN_1R_KEY1));
        __m256i fs02 = _mm256_set_m128i(_mm_loadu_si128((const __m128i *)fill_state + 2),
                                        _mm_loadu_si128((const __m128i *)fill_state + 0));
        __m256i fs13 = _mm256_set_m128i(_mm_loadu_si128((const __m128i *)fill_state + 3),
                                        _mm_loadu_si128((const __m128i *)fill_state + 1));

        if (scratchpadSize >= 128) {
            const uint8_t *spEnd2 = spEnd - 128;
            while (sp <= spEnd2) {
                __m256i a0 = _mm256_loadu_si256((const __m256i *)sp + 0);
                __m256i a1 = _mm256_loadu_si256((const __m256i *)sp + 1);
                __m256i b0 = _mm256_loadu_si256((const __m256i *)sp + 2);
                __m256i b1 = _mm256_loadu_si256((const __m256i *)sp + 3);

                __m256i l02 = _mm256_permute2x128_si256(a0, a1, 0x20);
                __m256i l13 = _mm256_permute2x128_si256(a0, a1, 0x31);
                hs02 = _mm256_aesenc_epi128(hs02, l02);
                hs13 = _mm256_aesdec_epi128(hs13, l13);
                fs02 = _mm256_aesdec_epi128(fs02, fk02);
                fs13 = _mm256_aesenc_epi128(fs13, fk13);
                _mm256_storeu_si256((__m256i *)sp + 0, _mm256_permute2x128_si256(fs02, fs13, 0x20));
                _mm256_storeu_si256((__m256i *)sp + 1, _mm256_permute2x128_si256(fs02, fs13, 0x31));

                __m256i r02 = _mm256_permute2x128_si256(b0, b1, 0x20);
                __m256i r13 = _mm256_permute2x128_si256(b0, b1, 0x31);
                hs02 = _mm256_aesenc_epi128(hs02, r02);
                hs13 = _mm256_aesdec_epi128(hs13, r13);
                fs02 = _mm256_aesdec_epi128(fs02, fk02);
                fs13 = _mm256_aesenc_epi128(fs13, fk13);
                _mm256_storeu_si256((__m256i *)sp + 2, _mm256_permute2x128_si256(fs02, fs13, 0x20));
                _mm256_storeu_si256((__m256i *)sp + 3, _mm256_permute2x128_si256(fs02, fs13, 0x31));

                sp += 128;
            }
        }
        while (sp < spEnd) {
            __m256i a0 = _mm256_loadu_si256((const __m256i *)sp + 0);
            __m256i a1 = _mm256_loadu_si256((const __m256i *)sp + 1);
            hs02 = _mm256_aesenc_epi128(hs02, _mm256_permute2x128_si256(a0, a1, 0x20));
            hs13 = _mm256_aesdec_epi128(hs13, _mm256_permute2x128_si256(a0, a1, 0x31));
            fs02 = _mm256_aesdec_epi128(fs02, fk02);
            fs13 = _mm256_aesenc_epi128(fs13, fk13);
            _mm256_storeu_si256((__m256i *)sp + 0, _mm256_permute2x128_si256(fs02, fs13, 0x20));
            _mm256_storeu_si256((__m256i *)sp + 1, _mm256_permute2x128_si256(fs02, fs13, 0x31));
            sp += 64;
        }

        _mm256_storeu_si256((__m256i *)fill_state + 0, _mm256_permute2x128_si256(fs02, fs13, 0x20));
        _mm256_storeu_si256((__m256i *)fill_state + 1, _mm256_permute2x128_si256(fs02, fs13, 0x31));

        __m128i xk0_128 = rx_set_i128(AES_HASH_1R_XKEY0);
        __m128i xk1_128 = rx_set_i128(AES_HASH_1R_XKEY1);
        __m256i xk0 = _mm256_set_m128i(xk0_128, xk0_128);
        __m256i xk1 = _mm256_set_m128i(xk1_128, xk1_128);
        hs02 = _mm256_aesenc_epi128(hs02, xk0);
        hs13 = _mm256_aesdec_epi128(hs13, xk0);
        hs02 = _mm256_aesenc_epi128(hs02, xk1);
        hs13 = _mm256_aesdec_epi128(hs13, xk1);

        _mm256_storeu_si256((__m256i *)hash + 0, _mm256_permute2x128_si256(hs02, hs13, 0x20));
        _mm256_storeu_si256((__m256i *)hash + 1, _mm256_permute2x128_si256(hs02, hs13, 0x31));
        _mm256_zeroupper();
        return;
    }
#endif

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

    if (g_aes_hash_fill_upstream) {
        const int prefetchDistance = 4096;
        const uint8_t *mainEnd = spEnd - prefetchDistance;
        const char *prefetchPtr = (const char *)sp + prefetchDistance;

        for (int pass = 0; pass < 2; ++pass) {
            while (sp < mainEnd) {
                hs0 = rx_aesenc_i128(hs0, rx_load_i128((const rx_vec_i128 *)sp + 0));
                hs1 = rx_aesdec_i128(hs1, rx_load_i128((const rx_vec_i128 *)sp + 1));
                hs2 = rx_aesenc_i128(hs2, rx_load_i128((const rx_vec_i128 *)sp + 2));
                hs3 = rx_aesdec_i128(hs3, rx_load_i128((const rx_vec_i128 *)sp + 3));
                fs0 = rx_aesdec_i128(fs0, fk0);
                fs1 = rx_aesenc_i128(fs1, fk1);
                fs2 = rx_aesdec_i128(fs2, fk2);
                fs3 = rx_aesenc_i128(fs3, fk3);
                _mm_store_si128((__m128i *)sp + 0, fs0);
                _mm_store_si128((__m128i *)sp + 1, fs1);
                _mm_store_si128((__m128i *)sp + 2, fs2);
                _mm_store_si128((__m128i *)sp + 3, fs3);
                _mm_prefetch(prefetchPtr, _MM_HINT_T0);
                sp += 64;
                prefetchPtr += 64;
            }
            prefetchPtr = (const char *)scratchpad;
            mainEnd += prefetchDistance;
        }
    } else {
        const uint8_t *spEnd2 = spEnd - 128;
        while (sp <= spEnd2) {
            if (g_aes_hash_fill_prefetch && sp + 4096 < spEnd) {
                _mm_prefetch((const char *)sp + 4096, _MM_HINT_T0);
                _mm_prefetch((const char *)sp + 4160, _MM_HINT_T0);
            }
            rx_vec_i128 l0 = rx_load_i128((const rx_vec_i128 *)sp + 0);
            rx_vec_i128 l1 = rx_load_i128((const rx_vec_i128 *)sp + 1);
            rx_vec_i128 l2 = rx_load_i128((const rx_vec_i128 *)sp + 2);
            rx_vec_i128 l3 = rx_load_i128((const rx_vec_i128 *)sp + 3);
            rx_vec_i128 l4 = rx_load_i128((const rx_vec_i128 *)sp + 4);
            rx_vec_i128 l5 = rx_load_i128((const rx_vec_i128 *)sp + 5);
            rx_vec_i128 l6 = rx_load_i128((const rx_vec_i128 *)sp + 6);
            rx_vec_i128 l7 = rx_load_i128((const rx_vec_i128 *)sp + 7);
            hs0 = rx_aesenc_i128(hs0, l0);
            hs1 = rx_aesdec_i128(hs1, l1);
            hs2 = rx_aesenc_i128(hs2, l2);
            hs3 = rx_aesdec_i128(hs3, l3);
            fs0 = rx_aesdec_i128(fs0, fk0);
            fs1 = rx_aesenc_i128(fs1, fk1);
            fs2 = rx_aesdec_i128(fs2, fk2);
            fs3 = rx_aesenc_i128(fs3, fk3);
            _mm_store_si128((__m128i *)sp + 0, fs0);
            _mm_store_si128((__m128i *)sp + 1, fs1);
            _mm_store_si128((__m128i *)sp + 2, fs2);
            _mm_store_si128((__m128i *)sp + 3, fs3);
            hs0 = rx_aesenc_i128(hs0, l4);
            hs1 = rx_aesdec_i128(hs1, l5);
            hs2 = rx_aesenc_i128(hs2, l6);
            hs3 = rx_aesdec_i128(hs3, l7);
            fs0 = rx_aesdec_i128(fs0, fk0);
            fs1 = rx_aesenc_i128(fs1, fk1);
            fs2 = rx_aesdec_i128(fs2, fk2);
            fs3 = rx_aesenc_i128(fs3, fk3);
            _mm_store_si128((__m128i *)sp + 4, fs0);
            _mm_store_si128((__m128i *)sp + 5, fs1);
            _mm_store_si128((__m128i *)sp + 6, fs2);
            _mm_store_si128((__m128i *)sp + 7, fs3);
            sp += 128;
        }
        while (sp < spEnd) {
            rx_vec_i128 l0 = rx_load_i128((const rx_vec_i128 *)sp + 0);
            rx_vec_i128 l1 = rx_load_i128((const rx_vec_i128 *)sp + 1);
            rx_vec_i128 l2 = rx_load_i128((const rx_vec_i128 *)sp + 2);
            rx_vec_i128 l3 = rx_load_i128((const rx_vec_i128 *)sp + 3);
            hs0 = rx_aesenc_i128(hs0, l0);
            hs1 = rx_aesdec_i128(hs1, l1);
            hs2 = rx_aesenc_i128(hs2, l2);
            hs3 = rx_aesdec_i128(hs3, l3);
            fs0 = rx_aesdec_i128(fs0, fk0);
            fs1 = rx_aesenc_i128(fs1, fk1);
            fs2 = rx_aesdec_i128(fs2, fk2);
            fs3 = rx_aesenc_i128(fs3, fk3);
            _mm_store_si128((__m128i *)sp + 0, fs0);
            _mm_store_si128((__m128i *)sp + 1, fs1);
            _mm_store_si128((__m128i *)sp + 2, fs2);
            _mm_store_si128((__m128i *)sp + 3, fs3);
            sp += 64;
        }
    }

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
