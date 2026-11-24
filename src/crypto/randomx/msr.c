#include "randomx_internal.h"
#include "msr.h"
#ifdef _WIN32
#include <windows.h>
#include <stdio.h>

#ifndef CTL_CODE
#define CTL_CODE(DeviceType, Function, Method, Access) \
    (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
#endif

#ifndef METHOD_BUFFERED
#define METHOD_BUFFERED 0
#endif

#ifndef FILE_ANY_ACCESS
#define FILE_ANY_ACCESS 0
#endif

#define OLS_DEVICE_TYPE 40000
#define IOCTL_OLS_GET_DRIVER_VERSION CTL_CODE(OLS_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_OLS_DRIVER_OPEN        CTL_CODE(OLS_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_OLS_DRIVER_CLOSE       CTL_CODE(OLS_DEVICE_TYPE, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_OLS_READ_MSR           CTL_CODE(OLS_DEVICE_TYPE, 0x821, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_OLS_WRITE_MSR          CTL_CODE(OLS_DEVICE_TYPE, 0x822, METHOD_BUFFERED, FILE_ANY_ACCESS)

static HANDLE g_hDriver = INVALID_HANDLE_VALUE;
static int g_msr_supported = -1;
static DWORD g_last_msr_error = 0;

static const char *k_driver_devices[] = {
    "\\\\.\\WinRing0_1_2",
    "\\\\.\\WinRing0_1_2_0",
    "\\\\.\\WinRing0_1_2_1",
};

typedef struct {
    uint32_t reg;
    uint64_t value;
} MsrItem;

static const MsrItem intel_msrs[] = {
    { 0x1A4, 0x000000000000000FULL },
};

static const int intel_msrs_count = sizeof(intel_msrs) / sizeof(intel_msrs[0]);

static int load_driver(void) {
    SC_HANDLE hSCManager;
    SC_HANDLE hService;

    char sysPath[MAX_PATH];
    char currentDir[MAX_PATH];

    if (GetModuleFileNameA(NULL, currentDir, sizeof(currentDir)) == 0)
        return -1;

    char *lastSlash = strrchr(currentDir, '\\');
    if (lastSlash) *lastSlash = 0;
    snprintf(sysPath, sizeof(sysPath), "%s\\WinRing0x64.sys", currentDir);

    if (GetFileAttributesA(sysPath) == INVALID_FILE_ATTRIBUTES) {
        printf("[MSR] Driver not found at %s\n", sysPath);
        return -1;
    }

    hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCManager) {
        printf("[MSR] OpenSCManager failed (error=%lu)\n", GetLastError());
        return -1;
    }

    hService = OpenServiceA(hSCManager, "WinRing0_1_2", SERVICE_ALL_ACCESS);
    if (hService) {
        StartServiceA(hService, 0, NULL);
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        printf("[MSR] Reusing existing WinRing0 driver\n");
        return 0;
    }

    hService = CreateServiceA(hSCManager, "WinRing0_1_2", "WinRing0_1_2",
        SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL,
        sysPath,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL);
    if (!hService) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS) {
            hService = OpenServiceA(hSCManager, "WinRing0_1_2", SERVICE_ALL_ACCESS);
            if (hService) {
                StartServiceA(hService, 0, NULL);
                CloseServiceHandle(hService);
                CloseServiceHandle(hSCManager);
                printf("[MSR] Reusing existing WinRing0 driver\n");
                return 0;
            }
        }
        printf("[MSR] CreateService failed (error=%lu)\n", err);
        CloseServiceHandle(hSCManager);
        return -1;
    }

    StartServiceA(hService, 0, NULL);
    DWORD err = GetLastError();
    if (err && err != ERROR_SERVICE_ALREADY_RUNNING) {
        printf("[MSR] StartService error=%lu\n", err);
        DeleteService(hService);
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        return -1;
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    Sleep(100);
    return 0;
}

static int open_driver(void) {
    for (int i = 0; i < (int)(sizeof(k_driver_devices) / sizeof(k_driver_devices[0])); i++) {
        g_hDriver = CreateFileA(k_driver_devices[i], GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (g_hDriver != INVALID_HANDLE_VALUE) {
            DWORD bytes = 0;
            DeviceIoControl(g_hDriver, IOCTL_OLS_DRIVER_OPEN, NULL, 0, NULL, 0, &bytes, NULL);
            return 0;
        }
    }

    if (load_driver() < 0) return -1;

    for (int i = 0; i < (int)(sizeof(k_driver_devices) / sizeof(k_driver_devices[0])); i++) {
        g_hDriver = CreateFileA(k_driver_devices[i], GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (g_hDriver != INVALID_HANDLE_VALUE) {
            DWORD bytes = 0;
            DeviceIoControl(g_hDriver, IOCTL_OLS_DRIVER_OPEN, NULL, 0, NULL, 0, &bytes, NULL);
            return 0;
        }
    }

    printf("[MSR] Cannot open driver handle (error=%lu)\n", GetLastError());
    return -1;
}

static void close_driver(void) {
    if (g_hDriver != INVALID_HANDLE_VALUE) {
        DeviceIoControl(g_hDriver, IOCTL_OLS_DRIVER_CLOSE, NULL, 0, NULL, 0, NULL, NULL);
        CloseHandle(g_hDriver);
        g_hDriver = INVALID_HANDLE_VALUE;
    }
}

static int write_msr(uint32_t reg, uint64_t value) {
    DWORD bytes_returned = 0;
    struct {
        uint32_t reg;
        uint32_t value_lo;
        uint32_t value_hi;
    } input;
    input.reg = reg;
    input.value_lo = (uint32_t)(value & 0xFFFFFFFFu);
    input.value_hi = (uint32_t)(value >> 32);

    if (!DeviceIoControl(g_hDriver, IOCTL_OLS_WRITE_MSR,
        &input, sizeof(input), NULL, 0, &bytes_returned, NULL)) {
        g_last_msr_error = GetLastError();
        return -1;
    }
    g_last_msr_error = 0;
    return 0;
}

static int read_msr(uint32_t reg, uint64_t *value) {
    DWORD bytes_returned = 0;
    uint32_t output[2] = {0, 0};
    if (!value || g_hDriver == INVALID_HANDLE_VALUE) return -1;

    if (!DeviceIoControl(g_hDriver, IOCTL_OLS_READ_MSR,
        &reg, sizeof(reg), output, sizeof(output), &bytes_returned, NULL) ||
        bytes_returned < sizeof(output)) {
        g_last_msr_error = GetLastError();
        return -1;
    }

    *value = (uint64_t)output[0] | ((uint64_t)output[1] << 32);
    g_last_msr_error = 0;
    return 0;
}

static double g_energy_unit = 0.0;

int msr_read_package_energy(double *joules) {
    uint64_t units = 0;
    uint64_t energy = 0;

    if (!joules) return 0;
    if (g_hDriver == INVALID_HANDLE_VALUE && open_driver() < 0) return 0;

    if (g_energy_unit == 0.0) {
        if (read_msr(0x606, &units) < 0) return 0;
        unsigned shift = (unsigned)((units >> 8) & 0x1F);
        g_energy_unit = 1.0 / (double)(1ULL << shift);
    }

    if (read_msr(0x611, &energy) < 0) return 0;
    *joules = (double)(uint32_t)energy * g_energy_unit;
    return 1;
}

double msr_get_energy_wrap_joules(void) {
    if (g_energy_unit > 0.0) return 4294967296.0 * g_energy_unit;
    return 4294967296.0 / 16384.0;
}

int msr_set_package_power_limit(double watts, uint64_t *original) {
    uint64_t units = 0;
    uint64_t limit = 0;
    if (watts <= 0.0 || !original) return 0;
    if (g_hDriver == INVALID_HANDLE_VALUE && open_driver() < 0) return 0;
    if (read_msr(0x606, &units) < 0 || read_msr(0x610, &limit) < 0) return 0;
    if (limit & (1ULL << 63)) {
        printf("[MSR] Package power limit is locked\n");
        return 0;
    }

    unsigned shift = (unsigned)(units & 0x0F);
    double power_unit = 1.0 / (double)(1ULL << shift);
    uint64_t raw = (uint64_t)(watts / power_unit + 0.5);
    if (raw > 0x7FFF) raw = 0x7FFF;

    *original = limit;
    limit &= ~((uint64_t)0x7FFF | ((uint64_t)0x7FFF << 32));
    limit |= raw | (1ULL << 15);
    limit |= (raw << 32) | (1ULL << 47);
    if (write_msr(0x610, limit) < 0) return 0;

    uint64_t verify = 0;
    if (read_msr(0x610, &verify) < 0) {
        write_msr(0x610, *original);
        return 0;
    }
    if ((verify & 0x7FFF) != raw || ((verify >> 32) & 0x7FFF) != raw) {
        printf("[MSR] Package power limit verification failed\n");
        write_msr(0x610, *original);
        return 0;
    }
    printf("[MSR] Package PL1/PL2 set to %.1f W\n", raw * power_unit);
    return 1;
}

int msr_restore_package_power_limit(uint64_t original) {
    if (g_hDriver == INVALID_HANDLE_VALUE) return 0;
    return write_msr(0x610, original) == 0;
}

int msr_set_prefetch_control(uint64_t value, uint64_t *original) {
    uint64_t verify = 0;
    if (!original) return 0;
    if (g_hDriver == INVALID_HANDLE_VALUE && open_driver() < 0) return 0;
    if (read_msr(0x1A4, original) < 0) return 0;
    if (write_msr(0x1A4, value) < 0 || read_msr(0x1A4, &verify) < 0)
        return 0;
    return (verify & 0x0F) == (value & 0x0F);
}

int msr_restore_prefetch_control(uint64_t original) {
    if (g_hDriver == INVALID_HANDLE_VALUE) return 0;
    return write_msr(0x1A4, original) == 0;
}

#define MSR_MAX_CPUS 256
static uint64_t g_saved_0x1a4[MSR_MAX_CPUS];
static uint8_t g_saved_0x1a4_ok[MSR_MAX_CPUS];
static int g_saved_cpu_count = 0;

static int cpu_is_intel(void) {
    int info[4] = {0};
    __cpuidex(info, 0, 0);
    return info[1] == 0x756e6547 && info[3] == 0x49656e69 && info[2] == 0x6c65746e; /* GenuineIntel */
}

int msr_init(void) {
    if (g_msr_supported >= 0) return g_msr_supported;

    g_msr_supported = 0;
    if (!cpu_is_intel()) {
        printf("[MSR] Non-Intel CPU detected, skipping Intel prefetcher MSR\n");
        return 0;
    }
    if (open_driver() < 0) {
        printf("[MSR] Failed to open WinRing0 driver\n");
        g_msr_supported = 0;
        return 0;
    }

    DWORD total_cpus = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    if (total_cpus == 0) total_cpus = 1;
    if (total_cpus > MSR_MAX_CPUS) total_cpus = MSR_MAX_CPUS;

    GROUP_AFFINITY orig_ga;
    int have_orig = GetThreadGroupAffinity(GetCurrentThread(), &orig_ga) ? 1 : 0;

    int applied = 0;
    g_saved_cpu_count = (int)total_cpus;
    for (DWORD cpu = 0; cpu < total_cpus; cpu++) {
        g_saved_0x1a4_ok[cpu] = 0;
        GROUP_AFFINITY ga = {0};
        ga.Group = (WORD)(cpu / 64);
        ga.Mask = (KAFFINITY)(1ULL << (cpu % 64));
        if (!SetThreadGroupAffinity(GetCurrentThread(), &ga, NULL)) continue;
        uint64_t orig = 0;
        if (read_msr(0x1A4, &orig) == 0) {
            g_saved_0x1a4[cpu] = orig;
            g_saved_0x1a4_ok[cpu] = 1;
        }
        int cpu_ok = 1;
        for (int i = 0; i < intel_msrs_count; i++) {
            if (write_msr(intel_msrs[i].reg, intel_msrs[i].value) < 0) cpu_ok = 0;
        }
        if (cpu_ok) applied++;
    }
    if (have_orig) SetThreadGroupAffinity(GetCurrentThread(), &orig_ga, NULL);

    if (applied > 0) {
        printf("[MSR] Applied Intel prefetcher MSR (0x1A4=0xF) on %d/%lu logical CPUs\n",
               applied, (unsigned long)total_cpus);
        g_msr_supported = 1;
    } else {
        printf("[MSR] Failed to apply MSR configuration\n");
        g_msr_supported = 0;
        close_driver();
    }
    return g_msr_supported;
}

void msr_destroy(void) {
    if (g_hDriver != INVALID_HANDLE_VALUE && g_saved_cpu_count > 0) {
        GROUP_AFFINITY orig_ga;
        int have_orig = GetThreadGroupAffinity(GetCurrentThread(), &orig_ga) ? 1 : 0;
        for (int cpu = 0; cpu < g_saved_cpu_count; cpu++) {
            if (!g_saved_0x1a4_ok[cpu]) continue;
            GROUP_AFFINITY ga = {0};
            ga.Group = (WORD)(cpu / 64);
            ga.Mask = (KAFFINITY)(1ULL << (cpu % 64));
            if (SetThreadGroupAffinity(GetCurrentThread(), &ga, NULL)) {
                write_msr(0x1A4, g_saved_0x1a4[cpu]);
            }
            g_saved_0x1a4_ok[cpu] = 0;
        }
        if (have_orig) SetThreadGroupAffinity(GetCurrentThread(), &orig_ga, NULL);
        g_saved_cpu_count = 0;
    }
    close_driver();
}
#else
/* MSR access via WinRing0 is Windows-only; on other OSes these are no-ops. */
int msr_init(void) { return 0; }
void msr_destroy(void) {}
int msr_read_package_energy(double *joules) { (void)joules; return 0; }
double msr_get_energy_wrap_joules(void) { return 4294967296.0 / 16384.0; }
int msr_set_package_power_limit(double watts, uint64_t *original) { (void)watts; (void)original; return 0; }
int msr_restore_package_power_limit(uint64_t original) { (void)original; return 0; }
int msr_set_prefetch_control(uint64_t value, uint64_t *original) { (void)value; (void)original; return 0; }
int msr_restore_prefetch_control(uint64_t original) { (void)original; return 0; }
#endif
