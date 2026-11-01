#pragma once

/*
 * Portable virtual-memory helpers used by the RandomX core.
 *
 * Windows: VirtualAlloc (MEM_LARGE_PAGES when requested).
 * POSIX:   mmap with MAP_HUGETLB (2 MB or 1 GB pages) when requested, falling
 *          back to normal pages + madvise(MADV_HUGEPAGE) so transparent huge
 *          pages can still back large buffers.
 */

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VMEM_LARGE_PAGES 1  /* try 2 MB pages */
#define VMEM_EXEC        2  /* RWX mapping (JIT code) */
#define VMEM_1GB_PAGES   4  /* try 1 GB pages first (POSIX only) */

/* Page kind actually obtained, reported through *got_kind. */
#define VMEM_KIND_NORMAL 0
#define VMEM_KIND_2MB    1
#define VMEM_KIND_1GB    2
#define VMEM_KIND_THP    3

void *vmem_alloc(size_t size, int flags, int *got_kind);
void  vmem_free(void *ptr);
int   vmem_lock(void *ptr, size_t size);
int   vmem_protect_rx(void *ptr, size_t size);
int   vmem_protect_rw(void *ptr, size_t size);
int   vmem_enable_large_page_privilege(void);
const char *vmem_kind_name(int kind);

#ifdef __cplusplus
}
#endif
