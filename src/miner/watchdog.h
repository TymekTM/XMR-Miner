#pragma once

#include "common/osdep.h"

typedef struct miner_ctx miner_ctx_t;

typedef enum {
    YIELD_STATE_FULL   = 0,  /* All workers active (P+E) */
    YIELD_STATE_ECO    = 1,  /* E-cores only (P-cores parked on kernel Event) */
    YIELD_STATE_PAUSED = 2   /* All workers parked (0% CPU, 0 L3/RAM traffic) */
} yield_state_t;

typedef enum {
    YIELD_OVERRIDE_AUTO   = 0,
    YIELD_OVERRIDE_FULL   = 1,
    YIELD_OVERRIDE_ECO    = 2,
    YIELD_OVERRIDE_PAUSED = 3
} yield_override_t;

typedef struct {
    int  enabled;          /* 1 = dynamic auto-yield active */
    int  cpu_eco_pct;      /* external CPU % to step down to ECO (default 15) */
    int  cpu_pause_pct;    /* external CPU % to step down to PAUSED (default 30) */
    int  resume_delay_sec; /* quiet seconds before stepping back up (default 12) */
    int  idle_full_sec;    /* AFK seconds required for FULL (0 = allow FULL while active) */
    int  pause_fullscreen; /* 1 = pause during D3D fullscreen / presentation */
    int  pause_gpu_pct;    /* GPU utilization % to pause (0 = disabled, default 25) */
    int  ram_pause_mb;     /* pause if available RAM < MB (0 = disabled, default 3072) */
    int  pause_on_battery; /* 1 = pause on battery power */
    char pause_processes[512]; /* comma-separated .exe names (case-insensitive) */
} watchdog_config_t;

typedef struct {
    double   ext_cpu_pct;      /* Non-miner CPU utilization 0..100 */
    double   gpu_pct;          /* Peak GPU engine utilization 0..100 (-1 if unavailable) */
    int      fullscreen;       /* 1 if fullscreen D3D / presentation / busy */
    uint32_t user_idle_sec;    /* Seconds since last mouse/keyboard input */
    uint64_t avail_ram_mb;     /* Available physical RAM in MB */
    int      on_battery;       /* 1 if running on battery */
    char     matched_proc[64]; /* Blacklisted process name if running, else "" */
} watchdog_sample_t;

typedef struct {
    yield_state_t    state;
    yield_override_t override_mode;
    uint64_t         override_until_ms; /* 0 = indefinite, else GetTickCount64() deadline */
    int              pause_hits;        /* consecutive samples triggering PAUSED */
    int              eco_hits;          /* consecutive samples triggering ECO */
    uint64_t         quiet_since_ms;    /* timestamp when higher state became eligible */
    char             reason[64];
} watchdog_fsm_t;

typedef struct watchdog_ctx watchdog_ctx_t;

/* Pure deterministic FSM helpers (unit-tested in test_watchdog.c) */
void watchdog_config_defaults(watchdog_config_t *cfg);
void watchdog_fsm_init(watchdog_fsm_t *fsm, yield_state_t initial_state);
yield_state_t watchdog_fsm_step(watchdog_fsm_t *fsm,
                                const watchdog_config_t *cfg,
                                const watchdog_sample_t *sample,
                                uint64_t now_ms);
int watchdog_match_process_list(const char *proc_name, const char *csv_list);
const char *yield_state_str(yield_state_t state);

/* Runtime background watchdog thread (Windows user-space, 500 ms polling) */
watchdog_ctx_t *watchdog_create(const watchdog_config_t *cfg, miner_ctx_t *miner);
void watchdog_start(watchdog_ctx_t *wd);
void watchdog_stop(watchdog_ctx_t *wd);
void watchdog_destroy(watchdog_ctx_t *wd);

/* Live control & status (thread-safe, used by System Tray) */
void watchdog_set_override(watchdog_ctx_t *wd, yield_override_t mode, uint32_t duration_sec);
yield_override_t watchdog_get_override(watchdog_ctx_t *wd, uint32_t *remaining_sec_out);
yield_state_t watchdog_get_state(watchdog_ctx_t *wd, char *reason_out, size_t reason_size);
void watchdog_get_last_sample(watchdog_ctx_t *wd, watchdog_sample_t *out);
