#ifndef BLAKE2_IMPL_H
#define BLAKE2_IMPL_H

#include <stdint.h>
#include <string.h>
#ifdef _MSC_VER
#include <intrin.h>
#endif

#if !defined(__cplusplus) && (!defined(__STDC_VERSION__) || __STDC_VERSION__ < 199901L)
  #if   defined(_MSC_VER)
    #define BLAKE2_INLINE __inline
  #elif defined(__GNUC__)
    #define BLAKE2_INLINE __inline__
  #else
    #define BLAKE2_INLINE
  #endif
#else
  #define BLAKE2_INLINE inline
#endif

static BLAKE2_INLINE uint32_t load32( const void *src )
{
#if defined(NDEBUG) && defined(_MSC_VER) && defined(NATIVE_LITTLE_ENDIAN)
  return *(const uint32_t *)src;
#else
  uint32_t w;
  memcpy(&w, src, sizeof w);
  return w;
#endif
}

static BLAKE2_INLINE uint64_t load64( const void *src )
{
#if defined(NDEBUG) && defined(_MSC_VER) && defined(NATIVE_LITTLE_ENDIAN)
  return *(const uint64_t *)src;
#else
  uint64_t w;
  memcpy(&w, src, sizeof w);
  return w;
#endif
}

static BLAKE2_INLINE void store64( void *dst, uint64_t w ) {
#if defined(NDEBUG) && defined(_MSC_VER) && defined(NATIVE_LITTLE_ENDIAN)
  *(uint64_t *)dst = w;
#else
  memcpy(dst, &w, sizeof w);
#endif
}

static BLAKE2_INLINE void store32( void *dst, uint32_t w ) {
#if defined(NDEBUG) && defined(_MSC_VER) && defined(NATIVE_LITTLE_ENDIAN)
  *(uint32_t *)dst = w;
#else
  memcpy(dst, &w, sizeof w);
#endif
}

static BLAKE2_INLINE uint64_t rotr64( const uint64_t w, const unsigned c )
{
#if defined(_MSC_VER)
  return _rotl64(w, 64 - c);
#else
  return ( w >> c ) | ( w << ( 64 - c ) );
#endif
}

static BLAKE2_INLINE void secure_zero_memory(void *v, size_t n)
{
  memset(v, 0, n);
}

#endif
