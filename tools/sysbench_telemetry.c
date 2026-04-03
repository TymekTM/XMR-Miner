#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <windows.h>
#include <intrin.h>

#include "crypto/randomx/randomx.h"
#include "common/cpu.h"

#define MAX_BENCH_CORES 128
#define RX_ITERATIONS 500
#define MEM_BENCH_SIZE (256ULL * 1024ULL * 1024ULL)
#define MEM_BENCH_ITERS 10

typedef struct {
    int os_index;
    int is_pcore;
    int sibling;
} core_info_t;

typedef struct {
    int count;
    core_info_t cores[MAX_BENCH_CORES];
} core_list_t;

typedef struct {
    int thread_id;
    int mode;
    double hashrate;
    double per_thread_time;
} bench_result_t;

static core_list_t g_cores;
static FILE *g_file = NULL;

static void tee_print(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    if (g_file) {
        va_start(ap, fmt);
        vfprintf(g_file, fmt, ap);
        va_end(ap);
    }
}

static void cpuid_func(int func, int subfunc, int regs[4]) {
    __cpuidex(regs, func, subfunc);
}

static int detect_cores(core_list_t *cores) {
    cores->count = 0;
    DWORD len = 0;
    GetLogicalProcessorInformationEx(RelationProcessorCore, NULL, &len);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) return 0;

    SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *buf =
        (SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *)malloc(len);
    if (!buf) return 0;
    if (!GetLogicalProcessorInformationEx(RelationProcessorCore, buf, &len)) {
        free(buf);
        return 0;
    }

    BYTE *ptr = (BYTE *)buf;
    DWORD remaining = len;
    while (remaining > 0) {
        SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *item =
            (SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *)ptr;
        if (item->Relationship == RelationProcessorCore && item->Processor.GroupCount > 0) {
            GROUP_AFFINITY mask = item->Processor.GroupMask[0];
            int first = -1, second = -1, bits = 0;
            for (int b = 0; b < 64; b++) {
                if (mask.Mask & (1ULL << b)) {
                    int os_idx = b + mask.Group * 64;
                    if (first < 0) first = os_idx;
                    else if (second < 0) second = os_idx;
                    bits++;
                }
            }
            if (first >= 0 && cores->count < MAX_BENCH_CORES) {
                int i = cores->count++;
                cores->cores[i].os_index = first;
                cores->cores[i].sibling = second;
                cores->cores[i].is_pcore = (bits >= 2) ? 1 : 0;
            }
        }
        ptr += item->Size;
        remaining -= item->Size;
    }
    free(buf);
    return cores->count;
}

static int build_affinity_order(int *order, int max_order) {
    if (g_cores.count <= 0) return 0;
    int n = 0;
    for (int i = 0; i < g_cores.count && n < max_order; i++)
        if (g_cores.cores[i].is_pcore) order[n++] = g_cores.cores[i].os_index;
    int has_ecores = 0;
    for (int i = 0; i < g_cores.count; i++)
        if (!g_cores.cores[i].is_pcore) has_ecores = 1;
    if (!has_ecores) {
        for (int i = 0; i < g_cores.count && n < max_order; i++)
            if (g_cores.cores[i].is_pcore && g_cores.cores[i].sibling >= 0)
                order[n++] = g_cores.cores[i].sibling;
    }
    for (int i = 0; i < g_cores.count && n < max_order; i++)
        if (!g_cores.cores[i].is_pcore) order[n++] = g_cores.cores[i].os_index;
    return n;
}

static void enable_huge_pages(void) {
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

static void print_section_header(const char *title) {
    tee_print("============================================================\n");
    tee_print(" %s\n", title);
    tee_print("============================================================\n\n");
}

static void print_telemetry_header(void) {
    time_t now = time(NULL);
    struct tm t;
    localtime_s(&t, &now);
    char ts[64];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &t);
    tee_print("============================================================\n");
    tee_print(" SYSTEM TELEMETRY - %s\n", ts);
    tee_print("============================================================\n\n");
}

static void print_cpu_info(void) {
    tee_print("--- CPU ---\n");

    char brand[49] = {0};
    int regs[4];
    cpuid_func(0x80000000, 0, regs);
    int max_ext = regs[0];
    if (max_ext >= 0x80000004) {
        u32 *bs = (u32 *)brand;
        cpuid_func(0x80000002, 0, (int *)&bs[0]);
        cpuid_func(0x80000003, 0, (int *)&bs[4]);
        cpuid_func(0x80000004, 0, (int *)&bs[8]);
    }
    tee_print("Model:        %s\n", brand);

    cpuid_func(0, 0, regs);
    int max_func = regs[0];
    if (max_func >= 0x16) {
        cpuid_func(0x16, 0, regs);
        int base_mhz = regs[0];
        int max_turbo = regs[2];
        if (base_mhz > 0) tee_print("Base freq:    %d MHz\n", base_mhz);
        if (max_turbo > 0) tee_print("Max turbo:    %d MHz\n", max_turbo);
    }

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    int logical = (int)si.dwNumberOfProcessors;

    int physical = 0;
    DWORD len = 0;
    GetLogicalProcessorInformationEx(RelationProcessorCore, NULL, &len);
    SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *buf =
        (SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *)malloc(len);
    if (buf && GetLogicalProcessorInformationEx(RelationProcessorCore, buf, &len)) {
        BYTE *ptr = (BYTE *)buf;
        while (ptr < (BYTE *)buf + len) {
            SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *item =
                (SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *)ptr;
            if (item->Relationship == RelationProcessorCore)
                physical += item->Processor.GroupCount;
            ptr += item->Size;
        }
    }
    free(buf);
    if (physical <= 0) physical = logical;

    int ht = (logical > physical) ? 1 : 0;

    int pcores = 0, ecores = 0;
    if (detect_cores(&g_cores) > 0) {
        for (int i = 0; i < g_cores.count; i++) {
            if (g_cores.cores[i].is_pcore) pcores++;
            else ecores++;
        }
    }

    tee_print("Cores:        %d logical, %d physical, HT=%s\n",
              logical, physical, ht ? "yes" : "no");
    if (pcores > 0 || ecores > 0)
        tee_print("Big.Little:   %d P-cores, %d E-cores\n", pcores, ecores);
    tee_print("\n");
}

static void print_cpu_features(void) {
    tee_print("--- CPU Features ---\n");

    int regs[4];

    cpuid_func(1, 0, regs);
    int sse2    = (regs[3] >> 26) & 1;
    int sse41   = (regs[2] >> 19) & 1;
    int sse42   = (regs[2] >> 20) & 1;
    int aes_ni  = (regs[2] >> 25) & 1;
    int avx     = (regs[2] >> 28) & 1;
    int fma3    = (regs[2] >> 12) & 1;
    int popcnt  = (regs[2] >> 23) & 1;
    int rdrand  = (regs[2] >> 30) & 1;

    cpuid_func(0, 0, regs);
    int max_func = regs[0];

    int avx2 = 0, bmi1 = 0, bmi2 = 0, rdseed = 0;
    int avx512f = 0, avx512cd = 0, avx512dq = 0, avx512bw = 0, avx512vl = 0;

    if (max_func >= 7) {
        cpuid_func(7, 0, regs);
        avx2    = (regs[1] >> 5) & 1;
        bmi1    = (regs[1] >> 3) & 1;
        bmi2    = (regs[1] >> 8) & 1;
        rdseed  = (regs[1] >> 18) & 1;
        avx512f = (regs[1] >> 16) & 1;
        avx512cd = (regs[1] >> 28) & 1;
        avx512dq = (regs[1] >> 17) & 1;
        avx512bw = (regs[2] >> 30) & 1;
        avx512vl = (regs[2] >> 31) & 1;
    }

    tee_print("SSE2:     %s\n", sse2    ? "yes" : "no");
    tee_print("SSE4.1:   %s\n", sse41   ? "yes" : "no");
    tee_print("SSE4.2:   %s\n", sse42   ? "yes" : "no");
    tee_print("AES-NI:   %s\n", aes_ni  ? "yes" : "no");
    tee_print("AVX:      %s\n", avx     ? "yes" : "no");
    tee_print("AVX2:     %s\n", avx2    ? "yes" : "no");
    tee_print("AVX-512F: %s\n", avx512f ? "yes" : "no");
    if (avx512f) {
        tee_print("AVX-512CD: %s\n", avx512cd ? "yes" : "no");
        tee_print("AVX-512DQ: %s\n", avx512dq ? "yes" : "no");
        tee_print("AVX-512BW: %s\n", avx512bw ? "yes" : "no");
        tee_print("AVX-512VL: %s\n", avx512vl ? "yes" : "no");
    }
    tee_print("BMI1:     %s\n", bmi1    ? "yes" : "no");
    tee_print("BMI2:     %s\n", bmi2    ? "yes" : "no");
    tee_print("FMA3:     %s\n", fma3    ? "yes" : "no");
    tee_print("POPCNT:   %s\n", popcnt  ? "yes" : "no");
    tee_print("RDRAND:   %s\n", rdrand  ? "yes" : "no");
    tee_print("RDSEED:   %s\n", rdseed  ? "yes" : "no");
    tee_print("\n");
}

static void print_cache_info(void) {
    tee_print("--- Cache ---\n");

    DWORD len = 0;
    GetLogicalProcessorInformationEx(RelationCache, NULL, &len);
    SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *buf =
        (SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *)malloc(len);

    #define MAX_CACHE_ENTRIES 64
    typedef struct { int level; int type; int size_kb; int count; } cache_entry_t;
    cache_entry_t entries[MAX_CACHE_ENTRIES];
    int entry_count = 0;

    if (buf && GetLogicalProcessorInformationEx(RelationCache, buf, &len)) {
        BYTE *ptr = (BYTE *)buf;
        while (ptr < (BYTE *)buf + len) {
            SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *item =
                (SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *)ptr;
            if (item->Relationship == RelationCache) {
                CACHE_RELATIONSHIP cr = item->Cache;
                int level = cr.Level;
                int size_kb = (int)(cr.CacheSize / 1024);
                int type = cr.Type;

                int found = 0;
                for (int j = 0; j < entry_count; j++) {
                    if (entries[j].level == level && entries[j].type == type && entries[j].size_kb == size_kb) {
                        entries[j].count++;
                        found = 1;
                        break;
                    }
                }
                if (!found && entry_count < MAX_CACHE_ENTRIES) {
                    entries[entry_count].level = level;
                    entries[entry_count].type = type;
                    entries[entry_count].size_kb = size_kb;
                    entries[entry_count].count = 1;
                    entry_count++;
                }
            }
            ptr += item->Size;
        }
    }
    free(buf);

    int printed_l1d = 0, printed_l1i = 0, printed_l2 = 0, printed_l3 = 0;
    for (int i = 0; i < entry_count; i++) {
        cache_entry_t *e = &entries[i];
        if (e->level == 1 && e->type == CacheData) {
            if (!printed_l1d) { tee_print("L1d:  "); printed_l1d = 1; }
            else tee_print("      ");
            if (e->size_kb >= 1024)
                tee_print("%d MB x%d\n", e->size_kb / 1024, e->count);
            else
                tee_print("%d KB x%d\n", e->size_kb, e->count);
        }
    }
    for (int i = 0; i < entry_count; i++) {
        cache_entry_t *e = &entries[i];
        if (e->level == 1 && e->type == CacheInstruction) {
            if (!printed_l1i) { tee_print("L1i:  "); printed_l1i = 1; }
            else tee_print("      ");
            if (e->size_kb >= 1024)
                tee_print("%d MB x%d\n", e->size_kb / 1024, e->count);
            else
                tee_print("%d KB x%d\n", e->size_kb, e->count);
        }
    }
    for (int i = 0; i < entry_count; i++) {
        cache_entry_t *e = &entries[i];
        if (e->level == 2) {
            if (!printed_l2) { tee_print("L2:   "); printed_l2 = 1; }
            else tee_print("      ");
            if (e->size_kb >= 1024)
                tee_print("%d MB x%d\n", e->size_kb / 1024, e->count);
            else
                tee_print("%d KB x%d\n", e->size_kb, e->count);
        }
    }
    for (int i = 0; i < entry_count; i++) {
        cache_entry_t *e = &entries[i];
        if (e->level == 3) {
            if (!printed_l3) { tee_print("L3:   "); printed_l3 = 1; }
            else tee_print("      ");
            if (e->size_kb >= 1024)
                tee_print("%d MB x%d\n", e->size_kb / 1024, e->count);
            else
                tee_print("%d KB x%d\n", e->size_kb, e->count);
        }
    }

    if (entry_count == 0) tee_print("(cache info not available)\n");
    tee_print("\n");
}

static void print_ram_info(void) {
    tee_print("--- RAM ---\n");

    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);

    uint64_t total_gb = ms.ullTotalPhys / (1024ULL * 1024ULL * 1024ULL);
    uint64_t total_mb = ms.ullTotalPhys / (1024ULL * 1024ULL);
    uint64_t avail_mb = ms.ullAvailPhys / (1024ULL * 1024ULL);

    tee_print("Total:     %llu MB (%llu GB)\n", total_mb, total_gb);
    tee_print("Available: %llu MB\n", avail_mb);

    HKEY hkey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
        0, KEY_READ, &hkey) == ERROR_SUCCESS) {
        DWORD mhz = 0, sz = sizeof(mhz), typ = REG_DWORD;
        if (RegQueryValueExA(hkey, "~MHz", NULL, &typ, (BYTE *)&mhz, &sz) == ERROR_SUCCESS) {
            tee_print("CPU clock: %lu MHz (registry)\n", mhz);
        }
        RegCloseKey(hkey);
    }

    tee_print("\n");
}

static void print_os_info(void) {
    tee_print("--- OS ---\n");

    HKEY hkey;
    char buf[256] = {0};
    DWORD sz = sizeof(buf);

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        0, KEY_READ, &hkey) == ERROR_SUCCESS) {
        sz = sizeof(buf);
        if (RegQueryValueExA(hkey, "ProductName", NULL, NULL, (BYTE *)buf, &sz) == ERROR_SUCCESS)
            tee_print("Name:    %s\n", buf);

        DWORD ubr = 0;
        sz = sizeof(ubr);
        DWORD typ = REG_DWORD;
        if (RegQueryValueExA(hkey, "UBR", NULL, &typ, (BYTE *)&ubr, &sz) == ERROR_SUCCESS) {
            DWORD build = 0;
            sz = sizeof(build);
            if (RegQueryValueExA(hkey, "CurrentBuildNumber", NULL, NULL, (BYTE *)&build, &sz) == ERROR_SUCCESS) {
                tee_print("Build:   %lu.%lu\n", build, ubr);
            }
        } else {
            sz = sizeof(buf);
            memset(buf, 0, sizeof(buf));
            if (RegQueryValueExA(hkey, "CurrentBuildNumber", NULL, NULL, (BYTE *)buf, &sz) == ERROR_SUCCESS)
                tee_print("Build:   %s\n", buf);
        }

        RegCloseKey(hkey);
    }

#ifdef _WIN64
    tee_print("Arch:    x64\n");
#else
    tee_print("Arch:    x86\n");
#endif
    tee_print("\n");
}

static void print_numa_info(void) {
    tee_print("--- NUMA ---\n");

    ULONG highest = 0;
    if (GetNumaHighestNodeNumber(&highest)) {
        tee_print("Nodes:   %lu\n", highest + 1);
    } else {
        tee_print("Nodes:   1 (UMA)\n");
    }
    tee_print("\n");
}

static void print_all_telemetry(void) {
    print_telemetry_header();
    print_cpu_info();
    print_cpu_features();
    print_cache_info();
    print_ram_info();
    print_os_info();
    print_numa_info();
}

static double now_seconds(void) {
    static LARGE_INTEGER freq = {0};
    if (freq.QuadPart == 0) QueryPerformanceFrequency(&freq);
    LARGE_INTEGER t;
    QueryPerformanceCounter(&t);
    return (double)t.QuadPart / (double)freq.QuadPart;
}

DWORD WINAPI bench_thread(LPVOID arg) {
    bench_result_t *d = (bench_result_t *)arg;
    int tid = d->thread_id;

    int order[MAX_BENCH_CORES * 2];
    int order_count = build_affinity_order(order, (int)(sizeof(order) / sizeof(order[0])));
    if (order_count > 0) {
        int os_idx = order[tid % order_count];
        GROUP_AFFINITY ga = {0};
        ga.Group = (WORD)(os_idx / 64);
        ga.Mask = (KAFFINITY)(1ULL << (os_idx % 64));
        SetThreadGroupAffinity(GetCurrentThread(), &ga, NULL);
    }

    rx_cache *cache_local = NULL;
    rx_dataset *dataset_local = NULL;
    rx_vm *vm1 = NULL, *vm2 = NULL;

    uint8_t key[] = "telemetry_bench_key";
    cache_local = rx_alloc_cache(1);
    rx_init_cache(cache_local, key, sizeof(key));
    dataset_local = rx_alloc_dataset(1);
    rx_init_dataset_cached(dataset_local, cache_local, 0, RX_DATASET_ITEMS, 4, 4);

    uint8_t seed[32] = {0};
    seed[0] = (uint8_t)tid;
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);

    if (d->mode == 0) {
        vm1 = rx_create_vm(RX_FLAG_DEFAULT, cache_local, dataset_local);
        uint8_t hash[32];
        for (int i = 0; i < 2; i++) rx_calculate_hash(vm1, seed, sizeof(seed), hash);
        QueryPerformanceCounter(&start);
        for (int i = 0; i < RX_ITERATIONS; i++) rx_calculate_hash(vm1, seed, sizeof(seed), hash);
        QueryPerformanceCounter(&end);
        rx_destroy_vm(vm1);
    } else if (d->mode == 1) {
        vm1 = rx_create_vm(RX_FLAG_JIT, cache_local, dataset_local);
        uint8_t hash[32];
        for (int i = 0; i < 2; i++) rx_calculate_hash(vm1, seed, sizeof(seed), hash);
        QueryPerformanceCounter(&start);
        for (int i = 0; i < RX_ITERATIONS; i++) rx_calculate_hash(vm1, seed, sizeof(seed), hash);
        QueryPerformanceCounter(&end);
        rx_destroy_vm(vm1);
    } else {
        vm1 = rx_create_vm(RX_FLAG_JIT, cache_local, dataset_local);
        vm2 = rx_create_vm(RX_FLAG_JIT, cache_local, dataset_local);
        uint8_t seed2[32] = {0};
        seed2[0] = (uint8_t)(tid + 200);
        uint8_t h1[32], h2[32];
        for (int i = 0; i < 2; i++)
            rx_calculate_hash_dual(vm1, vm2, seed, sizeof(seed), seed2, sizeof(seed2), h1, h2);
        QueryPerformanceCounter(&start);
        for (int i = 0; i < RX_ITERATIONS; i++)
            rx_calculate_hash_dual(vm1, vm2, seed, sizeof(seed), seed2, sizeof(seed2), h1, h2);
        QueryPerformanceCounter(&end);
        rx_destroy_vm(vm1);
        rx_destroy_vm(vm2);
    }

    double elapsed = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;
    int hashes = (d->mode == 2) ? RX_ITERATIONS * 2 : RX_ITERATIONS;
    d->hashrate = (double)hashes / elapsed;
    d->per_thread_time = elapsed;

    rx_free_dataset(dataset_local);
    rx_free_cache(cache_local);
    return 0;
}

static double run_bench_mode(int num_threads, int mode) {
    bench_result_t *tdata = (bench_result_t *)calloc(num_threads, sizeof(bench_result_t));
    HANDLE *threads = (HANDLE *)calloc(num_threads, sizeof(HANDLE));

    for (int i = 0; i < num_threads; i++) {
        tdata[i].thread_id = i;
        tdata[i].mode = mode;
    }

    double t0 = now_seconds();
    for (int i = 0; i < num_threads; i++)
        threads[i] = CreateThread(NULL, 0, bench_thread, &tdata[i], 0, NULL);
    WaitForMultipleObjects(num_threads, threads, TRUE, INFINITE);
    double t1 = now_seconds();

    double wall = t1 - t0;
    double total_hr = 0;
    for (int i = 0; i < num_threads; i++) total_hr += tdata[i].hashrate;

    double min_t = 1e18, max_t = 0, avg_t = 0;
    for (int i = 0; i < num_threads; i++) {
        avg_t += tdata[i].per_thread_time;
        if (tdata[i].per_thread_time < min_t) min_t = tdata[i].per_thread_time;
        if (tdata[i].per_thread_time > max_t) max_t = tdata[i].per_thread_time;
    }
    avg_t /= num_threads;

    double imbalance = (avg_t > 0) ? (max_t - min_t) / avg_t * 100.0 : 0;

    for (int i = 0; i < num_threads; i++) CloseHandle(threads[i]);
    free(threads);
    free(tdata);

    tee_print("  %3d  %10.1f H/s  %10.1f H/s  %10.1f H/s  %8.1f%%\n",
              num_threads, total_hr, wall, avg_t, imbalance);

    return total_hr;
}

static void bench_dataset_init(int num_threads) {
    uint8_t key[] = "dataset_init_bench_key";

    rx_cache *cache = rx_alloc_cache(1);
    if (!cache) {
        tee_print("  (cache alloc failed)\n");
        return;
    }
    rx_init_cache(cache, key, sizeof(key));

    rx_dataset *dataset = rx_alloc_dataset(1);
    if (!dataset) {
        tee_print("  (dataset alloc failed)\n");
        rx_free_cache(cache);
        return;
    }

    double t0 = now_seconds();
    rx_init_dataset_cached(dataset, cache, 0, RX_DATASET_ITEMS, num_threads, num_threads);
    double t1 = now_seconds();

    tee_print("  %d threads: %.2f s\n", num_threads, t1 - t0);

    rx_free_dataset(dataset);
    rx_free_cache(cache);
}

static void bench_memory(void) {
    tee_print("--- Memory Bandwidth ---\n");

    uint8_t *buf = (uint8_t *)VirtualAlloc(NULL, (SIZE_T)MEM_BENCH_SIZE,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) {
        tee_print("  (allocation failed)\n\n");
        return;
    }

    memset(buf, 0xAA, (size_t)MEM_BENCH_SIZE);

    double best_read = 0, best_write = 0;
    size_t iters = MEM_BENCH_SIZE;

    for (int pass = 0; pass < MEM_BENCH_ITERS; pass++) {
        double t0 = now_seconds();
        volatile uint8_t sum = 0;
        for (size_t i = 0; i < iters; i += 64) {
            sum += buf[i];
        }
        (void)sum;
        double t1 = now_seconds();
        double bw = (double)iters / (t1 - t0) / (1024.0 * 1024.0 * 1024.0);
        if (bw > best_read) best_read = bw;

        t0 = now_seconds();
        for (size_t i = 0; i < iters; i += 64) {
            buf[i] = (uint8_t)i;
        }
        t1 = now_seconds();
        bw = (double)iters / (t1 - t0) / (1024.0 * 1024.0 * 1024.0);
        if (bw > best_write) best_write = bw;
    }

    tee_print("  Sequential read:  %.2f GB/s (best of %d)\n", best_read, MEM_BENCH_ITERS);
    tee_print("  Sequential write: %.2f GB/s (best of %d)\n", best_write, MEM_BENCH_ITERS);
    tee_print("  Buffer size:      %d MB\n", (int)(MEM_BENCH_SIZE / (1024 * 1024)));
    tee_print("\n");

    VirtualFree(buf, 0, MEM_RELEASE);
}

int main(int argc, char **argv) {
    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
    enable_huge_pages();

    detect_cores(&g_cores);

    char filename[128];
    time_t now = time(NULL);
    struct tm t;
    localtime_s(&t, &now);
    strftime(filename, sizeof(filename), "telemetry_%Y%m%d_%H%M%S.txt", &t);

    g_file = fopen(filename, "w");
    if (!g_file) {
        printf("WARNING: cannot open %s for writing, output to console only\n", filename);
    } else {
        printf("Writing telemetry to: %s\n\n", filename);
    }

    print_all_telemetry();

    int all_physical_cores = g_cores.count;
    if (all_physical_cores <= 0) {
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        all_physical_cores = (int)si.dwNumberOfProcessors;
    }
    if (all_physical_cores > 64) all_physical_cores = 64;

    int max_threads = all_physical_cores;
    if (argc > 1) {
        int arg_t = atoi(argv[1]);
        if (arg_t > 0) max_threads = arg_t;
    }

    print_section_header("RANDOMX BENCHMARK");
    tee_print("Each thread owns its own cache+dataset (realistic scenario)\n");
    tee_print("Iterations per thread: %d\n", max_threads);
    tee_print("Thread range: 1..%d\n\n", max_threads);

    tee_print("%-6s  %-12s  %-10s  %-10s  %-8s  %s\n",
              "Thr", "Total H/s", "Wall(s)", "Avg T(s)", "Imbal", "S/I  D/I");
    tee_print("------  ------------  ----------  ----------  --------  ----------\n");

    double best_single = 0, best_dual = 0;
    int best_single_t = 1, best_dual_t = 1;
    double first_interp = 0;

    for (int t = 1; t <= max_threads; t++) {
        double ri = run_bench_mode(t, 0);
        double rs = run_bench_mode(t, 1);
        double rd = run_bench_mode(t, 2);

        double si_ratio = (ri > 0) ? rs / ri : 0;
        double di_ratio = (ri > 0) ? rd / ri : 0;
        tee_print("        %9.3fx  %9.3fx\n", si_ratio, di_ratio);

        if (t == 1) first_interp = ri;
        if (rs > best_single) { best_single = rs; best_single_t = t; }
        if (rd > best_dual)   { best_dual = rd;   best_dual_t = t; }
    }

    tee_print("\n");
    tee_print("Best Single JIT: %d threads @ %.1f H/s\n", best_single_t, best_single);
    tee_print("Best Dual JIT:   %d threads @ %.1f H/s\n", best_dual_t, best_dual);
    if (best_single > 0)
        tee_print("Scaling (S JIT): %.2fx from 1T to %dT\n", best_single / (first_interp > 0 ? first_interp : 1), best_single_t);
    tee_print("\n");

    print_section_header("DATASET INIT BENCHMARK");
    tee_print("Measuring dataset init time with different thread counts\n\n");
    int ds_threads[] = {1, 2, 4, 8, 16};
    int ds_count = sizeof(ds_threads) / sizeof(ds_threads[0]);
    for (int i = 0; i < ds_count; i++) {
        if (ds_threads[i] > max_threads) break;
        bench_dataset_init(ds_threads[i]);
    }
    tee_print("\n");

    bench_memory();

    print_section_header("END OF TELEMETRY");
    tee_print("File saved: %s\n", filename);

    if (g_file) fclose(g_file);

    return 0;
}
