#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <windows.h>
#include <psapi.h>
#include "crypto/randomx/randomx_internal.h"
#include "common/cpu.h"
#include "common/log.h"

static void enable_huge_pages() {
    TOKEN_PRIVILEGES tp = {0};
    LUID luid;
    HANDLE token;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        if (LookupPrivilegeValueA(NULL, "SeLockMemoryPrivilege", &luid)) {
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL);
        }
        CloseHandle(token);
    }
}

static void print_mem(const char *label) {
    PROCESS_MEMORY_COUNTERS_EX pmc = {0};
    pmc.cb = sizeof(pmc);
    GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc));
    printf("[MEM] %-40s WS=%7.1fMB  Private=%7.1fMB\n", label,
        pmc.WorkingSetSize/(1024.0*1024), pmc.PrivateUsage/(1024.0*1024));
}

int main() {
    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
    enable_huge_pages();

    SIZE_T ds_size = (SIZE_T)RX_DATASET_SIZE;
    printf("ds_size = %llu MB\n", (unsigned long long)(ds_size / (1024*1024)));
    printf("MEMORYSTATUSEX:\n");
    MEMORYSTATUSEX msx = {0};
    msx.dwLength = sizeof(msx);
    GlobalMemoryStatusEx(&msx);
    printf("  TotalPhys = %llu MB\n", msx.ullTotalPhys/(1024*1024));
    printf("  AvailPhys = %llu MB\n", msx.ullAvailPhys/(1024*1024));
    printf("  TotalVirtual = %llu MB\n", msx.ullTotalVirtual/(1024*1024));
    printf("  AvailVirtual = %llu MB\n", msx.ullAvailVirtual/(1024*1024));

    print_mem("start");

    rx_cache *cache = rx_alloc_cache(0);
    uint8_t key[] = "test_key_123456";
    rx_init_cache(cache, key, sizeof(key));
    print_mem("after cache");

    rx_dataset *ds = (rx_dataset*)calloc(1, sizeof(rx_dataset));
    ds->large_pages = 0;
    ds->memory = (uint8_t*)VirtualAlloc(NULL, ds_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!ds->memory) { printf("FATAL: alloc failed error=%lu\n", GetLastError()); return 1; }
    print_mem("after dataset alloc");

    rx_init_dataset_cached(ds, cache, 0, RX_DATASET_ITEMS, 8, 8);
    print_mem("after dataset init");

    printf("Attempting VirtualLock...\n");
    fflush(stdout);
    BOOL locked = VirtualLock(ds->memory, ds_size);
    printf("VirtualLock: %s error=%lu\n", locked ? "OK" : "FAILED", GetLastError());
    print_mem("after VirtualLock");

    rx_vm *vm = rx_create_vm(1, 1, 0, cache, ds);
    print_mem("after VM");

    if (vm) {
        uint8_t seed[32] = {0};
        uint8_t hash[32];
        LARGE_INTEGER freq, s, e;
        QueryPerformanceFrequency(&freq);
        rx_calculate_hash(vm, seed, sizeof(seed), hash);
        QueryPerformanceCounter(&s);
        for (int i = 0; i < 20; i++) rx_calculate_hash(vm, seed, sizeof(seed), hash);
        QueryPerformanceCounter(&e);
        double dt = (double)(e.QuadPart - s.QuadPart) / freq.QuadPart;
        printf("Single-thread: %.1f H/s\n", 20.0 / dt);
        rx_destroy_vm(vm);
    }

    if (locked) VirtualUnlock(ds->memory, ds_size);
    VirtualFree(ds->memory, 0, MEM_RELEASE);
    free(ds);
    rx_free_cache(cache);
    print_mem("end");
    return 0;
}
