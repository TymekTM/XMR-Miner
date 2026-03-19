#include "log.h"
#include <stdarg.h>
#include <stdio.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#endif

static log_level_t g_log_level = LOG_INFO;

static const char *level_prefix[] = {
    "\x1b[36m[D]\x1b[0m",
    "\x1b[32m[I]\x1b[0m",
    "\x1b[33m[W]\x1b[0m",
    "\x1b[31m[E]\x1b[0m",
};

static const char *level_prefix_plain[] = {
    "[D]", "[I]", "[W]", "[E]",
};

void log_init(log_level_t level) {
    g_log_level = level;
#ifdef _WIN32
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(hOut, &mode);
    SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
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
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    BOOL has_color = GetConsoleMode(hOut, &mode) && (mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    if (has_color) {
        fprintf(stderr, "%s %s\n", level_prefix[level], buf);
    } else {
        fprintf(stderr, "%s %s\n", level_prefix_plain[level], buf);
    }
#else
    fprintf(stderr, "%s %s\n", level_prefix[level], buf);
#endif
}
