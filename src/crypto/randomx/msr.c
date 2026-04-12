#include "randomx_internal.h"
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
            printf("[MSR] Write failed for MSR 0x%08X (error=%lu)\n", intel_msrs[i].reg, g_last_msr_error);
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
