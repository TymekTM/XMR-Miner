#include "vmem.h"

#include <stdint.h>
#include <string.h>

#define VMEM_2MB ((size_t)2 * 1024 * 1024)
#define VMEM_1GB ((size_t)1024 * 1024 * 1024)

static size_t round_up(size_t v, size_t a) { return (v + a - 1) / a * a; }

const char *vmem_kind_name(int kind) {
    switch (kind) {
    case VMEM_KIND_2MB: return "2MB huge pages";
    case VMEM_KIND_1GB: return "1GB huge pages";
    case VMEM_KIND_THP: return "transparent huge pages";
    default:            return "4KB pages";
    }
}

#ifdef _WIN32

#include <windows.h>

int vmem_enable_large_page_privilege(void) {
    static int checked = 0, ok = 0;
    if (checked) return ok;
    checked = 1;
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return 0;
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (LookupPrivilegeValueA(NULL, SE_LOCK_MEMORY_NAME, &tp.Privileges[0].Luid))
        ok = AdjustTokenPrivileges(token, FALSE, &tp, 0, NULL, NULL) && GetLastError() == 0;
    CloseHandle(token);
    return ok;
}

void *vmem_alloc(size_t size, int flags, int *got_kind) {
    DWORD prot = (flags & VMEM_EXEC) ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;
    void *p = NULL;
    if (got_kind) *got_kind = VMEM_KIND_NORMAL;
    if (flags & (VMEM_LARGE_PAGES | VMEM_1GB_PAGES)) {
        SIZE_T lp = GetLargePageMinimum();
        if (lp) {
            vmem_enable_large_page_privilege();
            p = VirtualAlloc(NULL, round_up(size, lp),
                             MEM_RESERVE | MEM_COMMIT | MEM_LARGE_PAGES, prot);
            if (p && got_kind) *got_kind = VMEM_KIND_2MB;
        }
    }
    if (!p) p = VirtualAlloc(NULL, size, MEM_RESERVE | MEM_COMMIT, prot);
    return p;
}

void vmem_free(void *ptr) {
    if (ptr) VirtualFree(ptr, 0, MEM_RELEASE);
}

int vmem_lock(void *ptr, size_t size) { return VirtualLock(ptr, size) ? 0 : -1; }

int vmem_protect_rx(void *ptr, size_t size) {
    DWORD old;
    return VirtualProtect(ptr, size, PAGE_EXECUTE_READ, &old) ? 0 : -1;
}

int vmem_protect_rw(void *ptr, size_t size) {
    DWORD old;
    return VirtualProtect(ptr, size, PAGE_READWRITE, &old) ? 0 : -1;
}

#else /* POSIX */

#include <sys/mman.h>
#include <pthread.h>
#include <stdlib.h>

#ifndef MAP_HUGE_SHIFT
#define MAP_HUGE_SHIFT 26
#endif
#ifndef MAP_HUGE_2MB
#define MAP_HUGE_2MB (21 << MAP_HUGE_SHIFT)
#endif
#ifndef MAP_HUGE_1GB
#define MAP_HUGE_1GB (30 << MAP_HUGE_SHIFT)
#endif

/* munmap needs the mapping length; keep a tiny registry of live mappings. */
#define VMEM_MAX_MAPPINGS 1024
static struct { void *ptr; size_t len; } g_maps[VMEM_MAX_MAPPINGS];
static pthread_mutex_t g_maps_lock = PTHREAD_MUTEX_INITIALIZER;

static void registry_add(void *p, size_t len) {
    pthread_mutex_lock(&g_maps_lock);
    for (int i = 0; i < VMEM_MAX_MAPPINGS; i++) {
        if (!g_maps[i].ptr) { g_maps[i].ptr = p; g_maps[i].len = len; break; }
    }
    pthread_mutex_unlock(&g_maps_lock);
}

static size_t registry_remove(void *p) {
    size_t len = 0;
    pthread_mutex_lock(&g_maps_lock);
    for (int i = 0; i < VMEM_MAX_MAPPINGS; i++) {
        if (g_maps[i].ptr == p) { len = g_maps[i].len; g_maps[i].ptr = NULL; break; }
    }
    pthread_mutex_unlock(&g_maps_lock);
    return len;
}

int vmem_enable_large_page_privilege(void) { return 1; }

static void *try_map(size_t len, int prot, int extra) {
    void *p = mmap(NULL, len, prot, MAP_PRIVATE | MAP_ANONYMOUS | extra, -1, 0);
    return p == MAP_FAILED ? NULL : p;
}

void *vmem_alloc(size_t size, int flags, int *got_kind) {
    int prot = PROT_READ | PROT_WRITE | ((flags & VMEM_EXEC) ? PROT_EXEC : 0);
    void *p = NULL;
    size_t len = size;
    int kind = VMEM_KIND_NORMAL;

    if (flags & VMEM_1GB_PAGES) {
        len = round_up(size, VMEM_1GB);
        p = try_map(len, prot, MAP_HUGETLB | MAP_HUGE_1GB | MAP_POPULATE);
        if (p) kind = VMEM_KIND_1GB;
    }
    if (!p && (flags & (VMEM_LARGE_PAGES | VMEM_1GB_PAGES))) {
        len = round_up(size, VMEM_2MB);
        p = try_map(len, prot, MAP_HUGETLB | MAP_HUGE_2MB | MAP_POPULATE);
        if (p) kind = VMEM_KIND_2MB;
    }
    if (!p) {
        len = size;
        p = try_map(len, prot, 0);
        if (p && len >= VMEM_2MB && (flags & (VMEM_LARGE_PAGES | VMEM_1GB_PAGES))) {
#ifdef MADV_HUGEPAGE
            if (madvise(p, len, MADV_HUGEPAGE) == 0) kind = VMEM_KIND_THP;
#endif
        }
    }
    if (p) registry_add(p, len);
    if (got_kind) *got_kind = p ? kind : VMEM_KIND_NORMAL;
    return p;
}

void vmem_free(void *ptr) {
    if (!ptr) return;
    size_t len = registry_remove(ptr);
    if (len) munmap(ptr, len);
}

int vmem_lock(void *ptr, size_t size) { return mlock(ptr, size); }

int vmem_protect_rx(void *ptr, size_t size) {
    return mprotect(ptr, size, PROT_READ | PROT_EXEC);
}

int vmem_protect_rw(void *ptr, size_t size) {
    return mprotect(ptr, size, PROT_READ | PROT_WRITE);
}

#endif
