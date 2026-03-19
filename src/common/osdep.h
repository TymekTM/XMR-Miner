#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef _WIN64
#define PLATFORM_WINDOWS 1
#define PLATFORM_64BIT 1
#else
#define PLATFORM_WINDOWS 0
#define PLATFORM_64BIT 0
#endif

#define UNUSED(x) ((void)(x))
#define ALIGN(x, a) (((x) + ((a) - 1)) & ~((a) - 1))
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

#define RX_SUCCESS 0
#define RX_ERROR   -1

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t   i8;
typedef int16_t  i16;
typedef int32_t  i32;
typedef int64_t  i64;

static inline u64 read_u64_le(const void *p) {
    const u8 *b = (const u8 *)p;
    return (u64)b[0] | ((u64)b[1] << 8) | ((u64)b[2] << 16) | ((u64)b[3] << 24)
         | ((u64)b[4] << 32) | ((u64)b[5] << 40) | ((u64)b[6] << 48) | ((u64)b[7] << 56);
}

static inline void write_u64_le(void *p, u64 v) {
    u8 *b = (u8 *)p;
    b[0] = (u8)(v);
    b[1] = (u8)(v >> 8);
    b[2] = (u8)(v >> 16);
    b[3] = (u8)(v >> 24);
    b[4] = (u8)(v >> 32);
    b[5] = (u8)(v >> 40);
    b[6] = (u8)(v >> 48);
    b[7] = (u8)(v >> 56);
}

static inline u32 read_u32_le(const void *p) {
    const u8 *b = (const u8 *)p;
    return (u32)b[0] | ((u32)b[1] << 8) | ((u32)b[2] << 16) | ((u32)b[3] << 24);
}

static inline void write_u32_le(void *p, u32 v) {
    u8 *b = (u8 *)p;
    b[0] = (u8)(v);
    b[1] = (u8)(v >> 8);
    b[2] = (u8)(v >> 16);
    b[3] = (u8)(v >> 24);
}
