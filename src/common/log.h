#pragma once

#include "osdep.h"

typedef enum {
    LOG_DEBUG = 0,
    LOG_INFO  = 1,
    LOG_WARN  = 2,
    LOG_ERR   = 3,
    LOG_NONE  = 4,
} log_level_t;

void log_init(log_level_t level);
void log_msg(log_level_t level, const char *fmt, ...);

#define LOG_DEBUG(...) log_msg(LOG_DEBUG, __VA_ARGS__)
#define LOG_INFO(...)  log_msg(LOG_INFO,  __VA_ARGS__)
#define LOG_WARN(...)  log_msg(LOG_WARN,  __VA_ARGS__)
#define LOG_ERR(...)   log_msg(LOG_ERR,   __VA_ARGS__)
