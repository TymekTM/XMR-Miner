#include "cpu.h"
#include "log.h"
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

#ifdef _MSC_VER
#include <intrin.h>
#endif

static void cpuid(u32 func, u32 subfunc, u32 *eax, u32 *ebx, u32 *ecx, u32 *edx) {
    int cpuinfo[4];
    __cpuidex(cpuinfo, (int)func, (int)subfunc);
    *eax = (u32)cpuinfo[0];
    *ebx = (u32)cpuinfo[1];
    *ecx = (u32)cpuinfo[2];
    *edx = (u32)cpuinfo[3];
}

#ifdef _WIN32
static int get_logical_cores(void) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return (int)si.dwNumberOfProcessors;
}

static int get_physical_cores(void) {
    int count = 0;
    DWORD len = 0;
    GetLogicalProcessorInformationEx(RelationProcessorCore, NULL, &len);
    SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *buf = (SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *)malloc(len);
    if (buf && GetLogicalProcessorInformationEx(RelationProcessorCore, buf, &len)) {
        BYTE *ptr = (BYTE *)buf;
        while (ptr < (BYTE *)buf + len) {
            SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *item = (SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *)ptr;
            if (item->Relationship == RelationProcessorCore) {
                count += item->Processor.GroupCount;
            }
            ptr += item->Size;
        }
    }
    free(buf);
    return count > 0 ? count : get_logical_cores();
}

#else
static int get_logical_cores(void) {
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    return n > 0 ? (int)n : 1;
}

/* Count distinct (physical_package_id, core_id) pairs from sysfs. */
static int get_physical_cores(void) {
    int n = get_logical_cores();
    int seen[1024];
    int count = 0;
    for (int cpu = 0; cpu < n && cpu < 1024; cpu++) {
        char path[128];
        int pkg = 0, core = cpu;
        snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%d/topology/core_id", cpu);
        FILE *f = fopen(path, "r");
        if (f) { if (fscanf(f, "%d", &core) != 1) core = cpu; fclose(f); }
        snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%d/topology/physical_package_id", cpu);
        f = fopen(path, "r");
        if (f) { if (fscanf(f, "%d", &pkg) != 1) pkg = 0; fclose(f); }
        int key = pkg * 4096 + core;
        int dup = 0;
        for (int i = 0; i < count; i++) if (seen[i] == key) { dup = 1; break; }
        if (!dup) seen[count++] = key;
    }
    return count > 0 ? count : n;
}

#endif

void cpu_detect(cpu_info_t *info) {
    memset(info, 0, sizeof(*info));

    u32 eax, ebx, ecx, edx;

    cpuid(1, 0, &eax, &ebx, &ecx, &edx);
    info->has_sse2  = (edx >> 26) & 1;
    info->has_aes_ni = (ecx >> 25) & 1;
    info->has_avx   = (ecx >> 28) & 1;

    if (info->has_avx) {
        cpuid(7, 0, &eax, &ebx, &ecx, &edx);
        info->has_avx2 = (ebx >> 5) & 1;
        info->has_bmi2 = (ebx >> 8) & 1;
    }

    u32 max_ext;
    cpuid(0x80000000, 0, &max_ext, &ebx, &ecx, &edx);
    if (max_ext >= 0x80000004) {
        u32 *bs = (u32 *)info->brand_string;
        cpuid(0x80000002, 0, &bs[0], &bs[1], &bs[2], &bs[3]);
        cpuid(0x80000003, 0, &bs[4], &bs[5], &bs[6], &bs[7]);
        cpuid(0x80000004, 0, &bs[8], &bs[9], &bs[10], &bs[11]);
    }

    info->logical_cores = get_logical_cores();
    info->physical_cores = get_physical_cores();

    info->l3_cache_kb = 0;
#ifdef _WIN32
    {
        DWORD len = 0;
        GetLogicalProcessorInformationEx(RelationCache, NULL, &len);
        SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *buf = (SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *)malloc(len);
        if (buf && GetLogicalProcessorInformationEx(RelationCache, buf, &len)) {
            BYTE *ptr = (BYTE *)buf;
            DWORD max_l3 = 0;
            while (ptr < (BYTE *)buf + len) {
                SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *item = (SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *)ptr;
                if (item->Relationship == RelationCache &&
                    item->Cache.Level == 3 &&
                    item->Cache.CacheSize > max_l3) {
                    max_l3 = item->Cache.CacheSize;
                }
                ptr += item->Size;
            }
            info->l3_cache_kb = (max_l3 + 1023) / 1024;
        }
        free(buf);
    }
#else
    {
        FILE *f = fopen("/sys/devices/system/cpu/cpu0/cache/index3/size", "r");
        if (f) {
            int kb = 0; char unit = 0;
            if (fscanf(f, "%d%c", &kb, &unit) >= 1) {
                if (unit == 'M') kb *= 1024;
                info->l3_cache_kb = kb;
            }
            fclose(f);
        }
    }
#endif
    if (info->l3_cache_kb == 0) {
        u32 max_ext2;
        cpuid(0x80000000, 0, &max_ext2, &ebx, &ecx, &edx);
        if (max_ext2 >= 0x80000006) {
            u32 regs4[4];
            __cpuidex((int*)regs4, 0x80000006, 0);
            info->l3_cache_kb = ((regs4[2] >> 16) & 0xFFFF) * 64;
        }
    }
}

void cpu_print_info(const cpu_info_t *info) {
    LOG_INFO("CPU: %s", info->brand_string);
    LOG_INFO("Cores: %d logical", info->logical_cores);
    if (info->l3_cache_kb > 0)
        LOG_INFO("L3 cache: %d MB", info->l3_cache_kb / 1024);
    LOG_INFO("Features: AES-NI=%s AVX2=%s SSE2=%s BMI2=%s",
        info->has_aes_ni ? "yes" : "no",
        info->has_avx2 ? "yes" : "no",
        info->has_sse2 ? "yes" : "no",
        info->has_bmi2 ? "yes" : "no");
}

int cpu_has_aes_ni(void) {
    u32 eax, ebx, ecx, edx;
    cpuid(1, 0, &eax, &ebx, &ecx, &edx);
    return (ecx >> 25) & 1;
}

int cpu_has_avx2(void) {
    u32 eax, ebx, ecx, edx;
    cpuid(7, 0, &eax, &ebx, &ecx, &edx);
    return (ebx >> 5) & 1;
}

int cpu_has_sse2(void) {
    u32 eax, ebx, ecx, edx;
    cpuid(1, 0, &eax, &ebx, &ecx, &edx);
    return (edx >> 26) & 1;
}

int cpu_has_bmi2(void) {
    u32 eax, ebx, ecx, edx;
    cpuid(0, 0, &eax, &ebx, &ecx, &edx);
    if (eax < 7) return 0;
    cpuid(7, 0, &eax, &ebx, &ecx, &edx);
    return (ebx >> 8) & 1;
}

int cpu_count_logical(void) {
    return get_logical_cores();
}
