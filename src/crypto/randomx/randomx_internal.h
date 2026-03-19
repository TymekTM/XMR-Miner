#ifndef RX_INTERNAL_H
#define RX_INTERNAL_H

#include "common/osdep.h"
#include "crypto/blake2/blake2b.h"
#include "randomx.h"
#include <string.h>
#include <math.h>
#include <windows.h>
#include <smmintrin.h>
#include <wmmintrin.h>
#include <immintrin.h>
#include <xmmintrin.h>

#ifdef __cplusplus
#define RX_ALIGNAS(x) alignas(x)
#else
#define RX_ALIGNAS(x) _Alignas(x)
#endif

#define RX_ARGON_MEMORY       262144
#define RX_ARGON_ITERATIONS   3
#define RX_ARGON_LANES        1
#define RX_ARGON_SALT         "RandomX\x03"
#define RX_ARGON_SALT_LEN     8

#define RX_CACHE_ACCESSES     8
#define RX_SUPERSCALAR_LATENCY 170
#define RX_SUPERSCALAR_MAX_SIZE (3 * RX_SUPERSCALAR_LATENCY + 2)

#define RX_DATASET_BASE_SIZE  2147483648ULL
#define RX_DATASET_EXTRA_SIZE 33554368ULL
#define RX_DATASET_SIZE       (RX_DATASET_BASE_SIZE + RX_DATASET_EXTRA_SIZE)
#define RX_DATASET_EXTRA_ITEMS (RX_DATASET_EXTRA_SIZE / RX_CACHE_LINE_SIZE)
#define RX_DATASET_ITEMS      (RX_DATASET_BASE_SIZE / RX_CACHE_LINE_SIZE)

#define RX_PROGRAM_SIZE       256
#define RX_PROGRAM_ITERATIONS 2048
#define RX_PROGRAM_COUNT      8

#define RX_SCRATCHPAD_L3      2097152
#define RX_SCRATCHPAD_L2      262144
#define RX_SCRATCHPAD_L1      16384

#define RX_JUMP_BITS          8
#define RX_JUMP_OFFSET        8
#define RX_CONDITION_MASK     ((1 << RX_JUMP_BITS) - 1)
#define RX_STORE_L3_COND      14

#define RX_REGISTERS_COUNT    8
#define RX_REG_FLT_COUNT      4

#define RX_CACHE_LINE_SIZE    64
#define RX_CACHE_SIZE         ((size_t)RX_ARGON_MEMORY * 1024)

#define RX_CACHE_LINE_ALIGN_MASK ((RX_DATASET_BASE_SIZE - 1) & ~(RX_CACHE_LINE_SIZE - 1))

#define RX_MANTISSA_SIZE      52
#define RX_EXPONENT_SIZE      11
#define RX_EXPONENT_BIAS      1023
#define RX_MANTISSA_MASK      ((1ULL << RX_MANTISSA_SIZE) - 1)
#define RX_EXPONENT_MASK      ((1ULL << RX_EXPONENT_SIZE) - 1)
#define RX_CONST_EXP_BITS     0x300
#define RX_DYN_EXP_BITS       4
#define RX_STAT_EXP_BITS      4
#define RX_DYN_MANTISSA_MASK  ((1ULL << (RX_MANTISSA_SIZE + RX_DYN_EXP_BITS)) - 1)

static inline int64_t rx_smulh(int64_t a, int64_t b) {
    int64_t high;
    (void)_mul128(a, b, &high);
    return high;
}

static inline uint64_t rx_mulh(uint64_t a, uint64_t b) {
    uint64_t high;
    (void)_umul128(a, b, &high);
    return high;
}

static inline uint64_t rx_rotr(uint64_t x, unsigned int n) {
    n &= 63;
    return (x >> n) | (x << (64 - n));
}

static inline uint64_t rx_rotl(uint64_t x, unsigned int n) {
    n &= 63;
    return (x << n) | (x >> (64 - n));
}

static inline int32_t rx_u32_to_s32(uint32_t x) {
    return (int32_t)x;
}

static inline uint64_t rx_sign_extend_32(uint32_t x) {
    return (uint64_t)(int64_t)(int32_t)x;
}

static inline int64_t rx_u64_to_s64(uint64_t x) {
    return (int64_t)x;
}

static inline uint64_t rx_get_small_positive_float_bits(uint64_t entropy) {
    uint64_t exponent = entropy >> 59;
    uint64_t mantissa = entropy & RX_MANTISSA_MASK;
    exponent += RX_EXPONENT_BIAS;
    exponent &= RX_EXPONENT_MASK;
    exponent <<= RX_MANTISSA_SIZE;
    return exponent | mantissa;
}

static inline uint64_t rx_get_static_exponent(uint64_t entropy) {
    uint64_t exponent = RX_CONST_EXP_BITS;
    exponent |= (entropy >> (64 - RX_STAT_EXP_BITS)) << RX_DYN_EXP_BITS;
    exponent <<= RX_MANTISSA_SIZE;
    return exponent;
}

static inline uint64_t rx_get_float_mask(uint64_t entropy) {
    uint64_t mask22 = (1ULL << 22) - 1;
    return (entropy & mask22) | rx_get_static_exponent(entropy);
}

typedef __m128d rx_vec_f128;
typedef __m128i rx_vec_i128;

static inline rx_vec_f128 rx_load_f128(const double *p) { return _mm_load_pd(p); }
static inline void rx_store_f128(double *p, rx_vec_f128 v) { _mm_store_pd(p, v); }
static inline rx_vec_f128 rx_add_f128(rx_vec_f128 a, rx_vec_f128 b) { return _mm_add_pd(a, b); }
static inline rx_vec_f128 rx_sub_f128(rx_vec_f128 a, rx_vec_f128 b) { return _mm_sub_pd(a, b); }
static inline rx_vec_f128 rx_mul_f128(rx_vec_f128 a, rx_vec_f128 b) { return _mm_mul_pd(a, b); }
static inline rx_vec_f128 rx_div_f128(rx_vec_f128 a, rx_vec_f128 b) { return _mm_div_pd(a, b); }
static inline rx_vec_f128 rx_sqrt_f128(rx_vec_f128 a) { return _mm_sqrt_pd(a); }
static inline rx_vec_f128 rx_swap_f128(rx_vec_f128 a) { return _mm_shuffle_pd(a, a, 1); }
static inline rx_vec_f128 rx_xor_f128(rx_vec_f128 a, rx_vec_f128 b) { return _mm_xor_pd(a, b); }
static inline rx_vec_f128 rx_and_f128(rx_vec_f128 a, rx_vec_f128 b) { return _mm_and_pd(a, b); }
static inline rx_vec_f128 rx_or_f128(rx_vec_f128 a, rx_vec_f128 b) { return _mm_or_pd(a, b); }

static inline rx_vec_f128 rx_set_f128(uint64_t hi, uint64_t lo) {
    return _mm_castsi128_pd(_mm_set_epi64x((long long)hi, (long long)lo));
}
static inline rx_vec_f128 rx_set1_f128(uint64_t x) {
    return _mm_castsi128_pd(_mm_set1_epi64x((long long)x));
}

static inline rx_vec_f128 rx_cast_i2f(rx_vec_i128 a) { return _mm_castsi128_pd(a); }
static inline rx_vec_i128 rx_cast_f2i(rx_vec_f128 a) { return _mm_castpd_si128(a); }

static inline rx_vec_f128 rx_cvt_int_f128(const void *addr) {
    __m128i ix = _mm_loadl_epi64((const __m128i *)addr);
    return _mm_cvtepi32_pd(ix);
}

static inline rx_vec_i128 rx_load_i128(const rx_vec_i128 *p) { return _mm_load_si128(p); }
static inline void rx_store_i128(rx_vec_i128 *p, rx_vec_i128 v) { _mm_store_si128(p, v); }

static inline rx_vec_i128 rx_set_i128(int i3, int i2, int i1, int i0) {
    return _mm_set_epi32(i3, i2, i1, i0);
}

static inline rx_vec_i128 rx_aesenc_i128(rx_vec_i128 v, rx_vec_i128 k) {
    return _mm_aesenc_si128(v, k);
}
static inline rx_vec_i128 rx_aesdec_i128(rx_vec_i128 v, rx_vec_i128 k) {
    return _mm_aesdec_si128(v, k);
}

#define RX_MXCSR_DEFAULT 0x9FC0

static inline void rx_reset_float_state(void) { _mm_setcsr(RX_MXCSR_DEFAULT); }
static inline void rx_set_rounding_mode(uint32_t mode) {
    _mm_setcsr(RX_MXCSR_DEFAULT | (mode << 13));
}
static inline uint32_t rx_get_rounding_mode(void) {
    return (_mm_getcsr() >> 13) & 3;
}

#define RX_SPL1_MASK16 (((RX_SCRATCHPAD_L1 / 8) / 2 - 1) * 16)
#define RX_SPL2_MASK16 (((RX_SCRATCHPAD_L2 / 8) / 2 - 1) * 16)
#define RX_SPL1_MASK (((RX_SCRATCHPAD_L1 / 8) - 1) * 8)
#define RX_SPL2_MASK (((RX_SCRATCHPAD_L2 / 8) - 1) * 8)
#define RX_SPL3_MASK (((RX_SCRATCHPAD_L3 / 8) - 1) * 8)
#define RX_SPL3_MASK64 (((RX_SCRATCHPAD_L3 / 8) / 8 - 1) * 64)

enum {
    RX_OP_IADD_RS = 0,
    RX_OP_IADD_M,
    RX_OP_ISUB_R,
    RX_OP_ISUB_M,
    RX_OP_IMUL_R,
    RX_OP_IMUL_M,
    RX_OP_IMULH_R,
    RX_OP_IMULH_M,
    RX_OP_ISMULH_R,
    RX_OP_ISMULH_M,
    RX_OP_IMUL_RCP,
    RX_OP_INEG_R,
    RX_OP_IXOR_R,
    RX_OP_IXOR_M,
    RX_OP_IROR_R,
    RX_OP_IROL_R,
    RX_OP_ISWAP_R,
    RX_OP_FSWAP_R,
    RX_OP_FADD_R,
    RX_OP_FADD_M,
    RX_OP_FSUB_R,
    RX_OP_FSUB_M,
    RX_OP_FSCAL_R,
    RX_OP_FMUL_R,
    RX_OP_FDIV_M,
    RX_OP_FSQRT_R,
    RX_OP_CBRANCH,
    RX_OP_CFROUND,
    RX_OP_ISTORE,
    RX_OP_NOP,
    RX_OP_COUNT
};

#define RX_FREQ_IADD_RS  16
#define RX_FREQ_IADD_M    7
#define RX_FREQ_ISUB_R   16
#define RX_FREQ_ISUB_M    7
#define RX_FREQ_IMUL_R   16
#define RX_FREQ_IMUL_M    4
#define RX_FREQ_IMULH_R   4
#define RX_FREQ_IMULH_M   1
#define RX_FREQ_ISMULH_R  4
#define RX_FREQ_ISMULH_M  1
#define RX_FREQ_IMUL_RCP  8
#define RX_FREQ_INEG_R    2
#define RX_FREQ_IXOR_R   15
#define RX_FREQ_IXOR_M    5
#define RX_FREQ_IROR_R    8
#define RX_FREQ_IROL_R    2
#define RX_FREQ_ISWAP_R   4
#define RX_FREQ_FSWAP_R   4
#define RX_FREQ_FADD_R   16
#define RX_FREQ_FADD_M    5
#define RX_FREQ_FSUB_R   16
#define RX_FREQ_FSUB_M    5
#define RX_FREQ_FSCAL_R   6
#define RX_FREQ_FMUL_R   32
#define RX_FREQ_FDIV_M    4
#define RX_FREQ_FSQRT_R   6
#define RX_FREQ_CBRANCH  25
#define RX_FREQ_CFROUND   1
#define RX_FREQ_ISTORE   16
#define RX_FREQ_NOP       0

#define RX_CEIL(x, prev) RX_CEIL_RX_##x = RX_CEIL_RX_##prev + RX_FREQ_##x
enum {
    RX_CEIL_RX_NULL = 0,
    RX_CEIL(IADD_RS, NULL),
    RX_CEIL(IADD_M, IADD_RS),
    RX_CEIL(ISUB_R, IADD_M),
    RX_CEIL(ISUB_M, ISUB_R),
    RX_CEIL(IMUL_R, ISUB_M),
    RX_CEIL(IMUL_M, IMUL_R),
    RX_CEIL(IMULH_R, IMUL_M),
    RX_CEIL(IMULH_M, IMULH_R),
    RX_CEIL(ISMULH_R, IMULH_M),
    RX_CEIL(ISMULH_M, ISMULH_R),
    RX_CEIL(IMUL_RCP, ISMULH_M),
    RX_CEIL(INEG_R, IMUL_RCP),
    RX_CEIL(IXOR_R, INEG_R),
    RX_CEIL(IXOR_M, IXOR_R),
    RX_CEIL(IROR_R, IXOR_M),
    RX_CEIL(IROL_R, IROR_R),
    RX_CEIL(ISWAP_R, IROL_R),
    RX_CEIL(FSWAP_R, ISWAP_R),
    RX_CEIL(FADD_R, FSWAP_R),
    RX_CEIL(FADD_M, FADD_R),
    RX_CEIL(FSUB_R, FADD_M),
    RX_CEIL(FSUB_M, FSUB_R),
    RX_CEIL(FSCAL_R, FSUB_M),
    RX_CEIL(FMUL_R, FSCAL_R),
    RX_CEIL(FDIV_M, FMUL_R),
    RX_CEIL(FSQRT_R, FDIV_M),
    RX_CEIL(CBRANCH, FSQRT_R),
    RX_CEIL(CFROUND, CBRANCH),
    RX_CEIL(ISTORE, CFROUND),
    RX_CEIL(NOP, ISTORE),
};

#undef RX_CEIL

typedef struct {
    u8 opcode;
    u8 dst;
    u8 src;
    u8 mod;
    u32 imm32;
} rx_instruction;

static_assert(sizeof(rx_instruction) == 8, "rx_instruction must be 8 bytes");

typedef struct {
    uint64_t r[RX_REGISTERS_COUNT];
    double f[RX_REG_FLT_COUNT][2];
    double e[RX_REG_FLT_COUNT][2];
    double a[RX_REG_FLT_COUNT][2];
} rx_register_file;

typedef struct {
    uint64_t eMask[2];
    uint32_t readReg0, readReg1, readReg2, readReg3;
} rx_program_config;

typedef struct {
    uint64_t entropyBuffer[16];
    rx_instruction programBuffer[RX_PROGRAM_SIZE];
} rx_program;

typedef struct {
    union { uint64_t *idst; rx_vec_f128 *fdst; };
    union { uint64_t *isrc; rx_vec_f128 *fsrc; };
    union { uint64_t imm; int64_t simm; };
    int type;
    union { int target; int shift; };
    uint32_t memMask;
} rx_bytecode;

typedef struct {
    uint32_t mx;
    uint32_t ma;
    uint8_t *memory;
} rx_memory_regs;

enum {
    RX_SS_ISUB_R = 0,
    RX_SS_IXOR_R,
    RX_SS_IADD_RS,
    RX_SS_IMUL_R,
    RX_SS_IROR_C,
    RX_SS_IADD_C7,
    RX_SS_IXOR_C7,
    RX_SS_IADD_C8,
    RX_SS_IXOR_C8,
    RX_SS_IADD_C9,
    RX_SS_IXOR_C9,
    RX_SS_IMULH_R,
    RX_SS_ISMULH_R,
    RX_SS_IMUL_RCP,
    RX_SS_COUNT
};

typedef struct {
    rx_instruction buffer[RX_SUPERSCALAR_MAX_SIZE];
    uint32_t size;
    int addrReg;
} rx_superscalar_program;

typedef struct rx_cache {
    uint8_t *memory;
    int large_pages;
    rx_superscalar_program programs[RX_CACHE_ACCESSES];
    uint64_t *reciprocalCache;
    int reciprocalCount;
    int reciprocalCapacity;
} rx_cache;

typedef struct rx_dataset {
    uint8_t *memory;
    int large_pages;
} rx_dataset;

typedef struct rx_jit rx_jit;

typedef struct rx_vm {
    rx_program program;
    rx_register_file reg;
    rx_program_config config;
    rx_memory_regs mem;
    uint8_t *scratchpad;
    rx_cache *cachePtr;
    rx_dataset *datasetPtr;
    uint64_t datasetOffset;
    int fullMem;
    int lightClient;
    int useJit;
    int large_pages;
    rx_jit *jit;
    uint8_t datasetItem[64];
    RX_ALIGNAS(16) uint64_t tempHash[8];
    RX_ALIGNAS(16) uint64_t fillState[8];
} rx_vm;

#ifdef __cplusplus
extern "C" {
#endif

uint64_t rx_reciprocal(uint32_t divisor);

static inline int is_zero_or_power_of_2(uint32_t x) {
    return (x & (x - 1)) == 0;
}

#include "crypto/blake2/blake2_generator.h"

void rx_init_cache_internal(rx_cache *cache, const void *key, size_t key_size);
void rx_init_dataset_internal(rx_dataset *ds, rx_cache *cache, uint32_t start_item, uint32_t count, int num_threads);
void rx_init_dataset_item(rx_cache *cache, uint8_t *out, uint64_t item_number);
void generate_superscalar(rx_superscalar_program *prog, blake2_gen *gen);

void rx_hash_aes1rx4(const void *input, size_t inputSize, void *hash);
void rx_fill_aes1rx4(void *state, size_t outputSize, void *buffer);
void rx_fill_aes4rx4(void *state, size_t outputSize, void *buffer);
void rx_hash_and_fill_aes1rx4(void *scratchpad, size_t scratchpadSize, void *hash, void *fill_state);

#ifdef __cplusplus
}
#endif

#endif
