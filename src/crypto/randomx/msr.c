#include "randomx_internal.h"
#include <windows.h>
#include <stdio.h>

#define IOCTL_OLS_GET_DRIVER_VERSION   ((0x40000 << 16) | (0x800 << 2) | 0 | 3)
#define IOCTL_OLS_DRIVER_OPEN         ((0x40000 << 16) | (0x802 << 2) | 0 | 3)
#define IOCTL_OLS_DRIVER_CLOSE        ((0x40000 << 16) | (0x804 << 2) | 0 | 3)
#define IOCTL_OLS_READ_MSR            ((0x40000 << 16) | (0x821 << 2) | 0 | 3)
#define IOCTL_OLS_WRITE_MSR           ((0x40000 << 16) | (0x822 << 2) | 0 | 3)

static HANDLE g_hDriver = INVALID_HANDLE_VALUE;
static int g_msr_supported = -1;

typedef struct {
    uint32_t reg;
    uint64_t value;
} MsrItem;

static const MsrItem intel_msrs[] = {
    { 0x1A2, 0x1010 },
    { 0x1A4, 0x1010 },
    { 0x199, 0x00000500500F03F3ULL },
    { 0x198, 0x00000404840303E6ULL },
    { 0x19A, 0x00000D060900C3ULL },
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
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        printf("[MSR] Reusing existing WinRing0 driver\n");
        return 0;
    }

    hService = CreateServiceA(hSCManager, "WinRing0_1_2", "WinRing0_1_2",
        SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
        sysPath, NULL, NULL, NULL, NULL, NULL, NULL);
    if (!hService) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS) {
            hService = OpenServiceA(hSCManager, "WinRing0_1_2", SERVICE_ALL_ACCESS);
            if (hService) {
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

    hService = CreateServiceA(hSCManager, "WinRing0_1_2", "WinRing0_1_2",
        SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
        sysPath, NULL, NULL, NULL, NULL, NULL, NULL);
    if (!hService) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS) {
            hService = OpenServiceA(hSCManager, "WinRing0_1_2", SERVICE_ALL_ACCESS);
            if (hService) {
                CloseServiceHandle(hService);
                CloseServiceHandle(hSCManager);
                printf("[MSR] Reusing existing WinRing0 driver\n");
                Sleep(100);
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
    g_hDriver = CreateFileA("\\\\.\\WinRing0_1_2", GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (g_hDriver != INVALID_HANDLE_VALUE) return 0;

    if (load_driver() < 0) return -1;
    g_hDriver = CreateFileA("\\\\.\\WinRing0_1_2", GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (g_hDriver == INVALID_HANDLE_VALUE) {
            printf("[MSR] Cannot open driver handle\n");
            return -1;
    }
    return 0;
}

static void close_driver(void) {
    if (g_hDriver != INVALID_HANDLE_VALUE) {
        DeviceIoControl(g_hDriver, IOCTL_OLS_DRIVER_CLOSE, NULL, 0, NULL, 0, NULL, NULL);
        CloseHandle(g_hDriver);
        g_hDriver = INVALID_HANDLE_VALUE;
    }
}

static int write_msr(uint32_t reg, uint64_t value) {
    DWORD bytes_returned;
    struct { uint32_t reg; uint64_t value; } input;
    input.reg = reg;
    input.value = value;

    if (!DeviceIoControl(g_hDriver, IOCTL_OLS_WRITE_MSR,
        &input, sizeof(input), NULL, 0, &bytes_returned, NULL)) {
        return -1;
    }
    return 0;
}

int msr_init(void) {
    if (g_msr_supported >= 0) return g_msr_supported;

    g_msr_supported = 0;
    if (open_driver() < 0) {
        printf("[MSR] Failed to open WinRing0 driver\n");
        g_msr_supported = 0;
        return 0;
    }

    int success = 0;
    for (int i = 0; i < intel_msrs_count; i++) {
        if (write_msr(intel_msrs[i].reg, intel_msrs[i].value) < 0) {
            printf("[MSR] Write failed for MSR 0x%08X\n", intel_msrs[i].reg);
            success = -1;
        }
    }

    if (success == 0) {
        printf("[MSR] Applied %d Intel MSR registers successfully\n", intel_msrs_count);
        g_msr_supported = 1;
    } else {
        printf("[MSR] Partial failure in MSR configuration\n");
        g_msr_supported = 0;
        close_driver();
    }
    return g_msr_supported;
}

void msr_destroy(void) {
    close_driver();
}
