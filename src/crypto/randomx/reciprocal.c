#include "randomx_internal.h"

uint64_t rx_reciprocal(uint32_t divisor) {
    const uint64_t p2exp63 = 1ULL << 63;
    const uint64_t q = p2exp63 / divisor;
    const uint64_t r = p2exp63 % divisor;
    uint32_t shift = 32;
    for (uint32_t k = 1U << 31; (k & divisor) == 0; k >>= 1)
        --shift;
    return (q << shift) + ((r << shift) / divisor);
}
