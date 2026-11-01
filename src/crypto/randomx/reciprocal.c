#include "randomx_internal.h"
#ifdef _MSC_VER
#include <intrin.h>
#endif

uint64_t rx_reciprocal(uint32_t divisor) {
    const uint64_t p2exp63 = 1ULL << 63;
    const uint64_t q = p2exp63 / divisor;
    const uint64_t r = p2exp63 % divisor;
    unsigned long index = 0;
    _BitScanReverse(&index, divisor);
    uint32_t shift = (uint32_t)(index + 1);
    return (q << shift) + ((r << shift) / divisor);
}
