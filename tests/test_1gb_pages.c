#include <stdio.h>
#include <windows.h>

int main(void) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    printf("AllocationGranularity: %u KB\n", si.dwAllocationGranularity / 1024);

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    typedef LPVOID (*VirtualAllocExNuma_t)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD, DWORD);
    VirtualAllocExNuma_t pVirtualAllocExNuma = (VirtualAllocExNuma_t)GetProcAddress(hKernel32, "VirtualAllocExNuma");
    printf("VirtualAllocExNuma: %s\n", pVirtualAllocExNuma ? "available" : "NOT available");

    typedef BOOL (*GetLargePageMinimum_t)(void);
    // Actually it's GetLargePageMinimum
    typedef SIZE_T (*GetLargePageMinimum2_t)(void);
    GetLargePageMinimum2_t pGetLPM = (GetLargePageMinimum2_t)GetProcAddress(hKernel32, "GetLargePageMinimum");
    if (pGetLPM) {
        SIZE_T min = pGetLPM();
        printf("GetLargePageMinimum: %llu bytes (%.0f MB)\n", (unsigned long long)min, (double)min / (1024*1024));
    }

    printf("\nAttempting 1GB huge page allocation (VirtualAlloc with MEM_LARGE_PAGES)...\n");
    SIZE_T oneGB = 1ULL << 30;
    
    // Try allocating just 1GB with large pages first
    void *ptr = VirtualAlloc(NULL, oneGB, MEM_RESERVE | MEM_COMMIT | MEM_LARGE_PAGES, PAGE_READWRITE);
    if (ptr) {
        printf("SUCCESS: Allocated 1GB with MEM_LARGE_PAGES at %p\n", ptr);
        VirtualFree(ptr, 0, MEM_RELEASE);
    } else {
        printf("FAILED: VirtualAlloc 1GB MEM_LARGE_PAGES, error=%lu\n", GetLastError());
        printf("  (Lock Pages in Memory privilege may be needed, or CPU/OS doesn't support 1GB pages)\n");
    }

    // Try 2GB with 2MB pages (current approach) to compare
    printf("\nAttempting 2GB with standard large pages...\n");
    SIZE_T twoGB = 2ULL << 30;
    ptr = VirtualAlloc(NULL, twoGB, MEM_RESERVE | MEM_COMMIT | MEM_LARGE_PAGES, PAGE_READWRITE);
    if (ptr) {
        printf("SUCCESS: Allocated 2GB with MEM_LARGE_PAGES at %p\n", ptr);
        VirtualFree(ptr, 0, MEM_RELEASE);
    } else {
        printf("FAILED: VirtualAlloc 2GB MEM_LARGE_PAGES, error=%lu\n", GetLastError());
    }

    // Check if we can use TLB flush / address space for 1GB pages
    // On Windows, 1GB pages require: CPU support + Registry key + Lock Pages privilege
    printf("\nCPUID check for 1GB page support:\n");
    int cpuid_result[4];
    __cpuid(cpuid_result, 0x80000001);
    int edx = cpuid_result[3];
    printf("  EDX bit 26 (1GB pages): %s\n", (edx & (1 << 26)) ? "YES - CPU supports 1GB pages" : "NO - CPU does NOT support 1GB pages");

    return 0;
}
