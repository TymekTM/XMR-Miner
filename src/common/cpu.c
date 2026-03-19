#include "cpu.h"
#include "log.h"
#include <windows.h>

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

void cpu_detect(cpu_info_t *info) {
    memset(info, 0, sizeof(*info));

    u32 eax, ebx, ecx, edx;

    cpuid(1, 0, &eax, &ebx, &ecx, &edx);
    info->has_sse2  = (edx >> 26) & 1;
    info->has_aes_ni = (ecx >> 25) & 1;
    info->has_avx   = (ecx >> 28) & 1;
    info->has_bmi2  = (ebx >> 8) & 1;

    if (info->has_avx) {
        cpuid(7, 0, &eax, &ebx, &ecx, &edx);
        info->has_avx2 = (ebx >> 5) & 1;
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
    u32 max_ext2;
    cpuid(0x80000000, 0, &max_ext2, &ebx, &ecx, &edx);
    if (max_ext2 >= 0x80000006) {
        u32 regs4[4];
        __cpuidex((int*)regs4, 0x80000006, 0);
        info->l3_cache_kb = (regs4[2] >> 16) & 0xFFFF;
    }
    if (info->l3_cache_kb == 0) {
        u32 regs4[4];
        __cpuidex((int*)regs4, 4, 3);
        int sets = (regs4[0] & 0x1FF) + 1;
        int line_size = ((regs4[0] >> 0) & 0xFFF) + 1;
        int ways = ((regs4[0] >> 22) & 0x3FF) + 1;
        info->l3_cache_kb = (sets * line_size * ways) / 1024;
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
