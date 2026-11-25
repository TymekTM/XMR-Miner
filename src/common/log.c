#include "log.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
static CRITICAL_SECTION g_log_lock;
static LONG g_log_lock_init = 0;
#endif

static log_level_t g_log_level = LOG_INFO;
static FILE *g_log_file = NULL;
static char g_log_file_path[512] = {0};

static const char *level_prefix[] = {
    "\x1b[36m[D]\x1b[0m",
    "\x1b[32m[I]\x1b[0m",
    "\x1b[33m[W]\x1b[0m",
    "\x1b[31m[E]\x1b[0m",
};

static const char *level_prefix_plain[] = {
    "[D]", "[I]", "[W]", "[E]",
};

static void ensure_log_lock(void) {
#ifdef _WIN32
    if (InterlockedCompareExchange(&g_log_lock_init, 1, 0) == 0) {
        InitializeCriticalSection(&g_log_lock);
        InterlockedExchange(&g_log_lock_init, 2);
    } else {
        while (InterlockedCompareExchange(&g_log_lock_init, 2, 2) != 2) {
            Sleep(0);
        }
    }
#endif
}

void log_init(log_level_t level) {
    ensure_log_lock();
    g_log_level = level;
#ifdef _WIN32
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut && hOut != INVALID_HANDLE_VALUE) {
        DWORD mode = 0;
        if (GetConsoleMode(hOut, &mode)) {
            SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        }
    }
#endif
}

int log_set_file(const char *path) {
    ensure_log_lock();
#ifdef _WIN32
    EnterCriticalSection(&g_log_lock);
#endif
    if (g_log_file) {
        fclose(g_log_file);
        g_log_file = NULL;
    }
    g_log_file_path[0] = '\0';
    int rc = 0;
    if (path && path[0]) {
        g_log_file = fopen(path, "w");
        if (g_log_file) {
            snprintf(g_log_file_path, sizeof(g_log_file_path), "%s", path);
        } else {
            rc = -1;
        }
    }
#ifdef _WIN32
    LeaveCriticalSection(&g_log_lock);
#endif
    return rc;
}

const char *log_get_file_path(void) {
    return g_log_file_path;
}

void log_close_file(void) {
    if (!g_log_file) return;
    ensure_log_lock();
#ifdef _WIN32
    EnterCriticalSection(&g_log_lock);
#endif
    if (g_log_file) {
        fclose(g_log_file);
        g_log_file = NULL;
    }
#ifdef _WIN32
    LeaveCriticalSection(&g_log_lock);
#endif
}

void log_msg(log_level_t level, const char *fmt, ...) {
    if (level < g_log_level) return;

    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

#ifdef _WIN32
    ensure_log_lock();
    EnterCriticalSection(&g_log_lock);
    if (g_log_file) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        fprintf(g_log_file, "%02u:%02u:%02u %s %s\n",
                st.wHour, st.wMinute, st.wSecond, level_prefix_plain[level], buf);
        fflush(g_log_file);
    }
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    BOOL has_console = (hOut && hOut != INVALID_HANDLE_VALUE && GetConsoleMode(hOut, &mode));
    if (has_console) {
        if (mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING) {
            fprintf(stderr, "%s %s\n", level_prefix[level], buf);
        } else {
            fprintf(stderr, "%s %s\n", level_prefix_plain[level], buf);
        }
    } else if (!g_log_file) {
        fprintf(stderr, "%s %s\n", level_prefix_plain[level], buf);
    }
    LeaveCriticalSection(&g_log_lock);
#else
    if (g_log_file) {
        fprintf(g_log_file, "%s %s\n", level_prefix_plain[level], buf);
        fflush(g_log_file);
    }
    fprintf(stderr, "%s %s\n", level_prefix_plain[level], buf);
#endif
}
