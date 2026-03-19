#include "memory.h"
#include "log.h"
#include <windows.h>

void *memory_alloc_large(size_t size) {
    void *ptr = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!ptr) {
        LOG_ERR("VirtualAlloc failed for %zu bytes, error=%lu", size, GetLastError());
    }
    return ptr;
}

void *memory_alloc_huge_pages(size_t size) {
    SIZE_T huge_page_min = GetLargePageMinimum();
    if (huge_page_min == 0) {
        LOG_WARN("Huge pages not supported by system");
        return memory_alloc_large(size);
    }

    size_t aligned_size = ALIGN(size, (size_t)huge_page_min);

    TOKEN_PRIVILEGES tp = {0};
    LUID luid;
    HANDLE token;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        LOG_WARN("Cannot open process token for huge pages privilege");
        return memory_alloc_large(size);
    }

    if (!LookupPrivilegeValueA(NULL, "SeLockMemoryPrivilege", &luid)) {
        CloseHandle(token);
        LOG_WARN("SeLockMemoryPrivilege not available");
        return memory_alloc_large(size);
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        CloseHandle(token);
        LOG_WARN("Cannot enable SeLockMemoryPrivilege");
        return memory_alloc_large(size);
    }

    CloseHandle(token);

    void *ptr = VirtualAlloc(NULL, aligned_size, MEM_COMMIT | MEM_RESERVE | MEM_LARGE_PAGES, PAGE_READWRITE);
    if (!ptr) {
        LOG_WARN("VirtualAlloc with MEM_LARGE_PAGES failed for %zu bytes, falling back", aligned_size);
        return memory_alloc_large(size);
    }

    LOG_INFO("Allocated %zu bytes with huge pages (page size: %zu)", aligned_size, (size_t)huge_page_min);
    return ptr;
}

void memory_free_large(void *ptr, size_t size) {
    UNUSED(size);
    if (ptr) VirtualFree(ptr, 0, MEM_RELEASE);
}

void memory_free_huge_pages(void *ptr, size_t size) {
    memory_free_large(ptr, size);
}

void memory_flush_instruction_cache(void *ptr, size_t size) {
    FlushInstructionCache(GetCurrentProcess(), ptr, size);
}
