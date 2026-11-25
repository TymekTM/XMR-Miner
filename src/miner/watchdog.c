#include "watchdog.h"
#include "miner.h"
#include "common/log.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#ifdef _WIN32
#include <windows.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <pdh.h>
#include <pdhmsg.h>
#endif

void watchdog_config_defaults(watchdog_config_t *cfg) {
    if (!cfg) return;
    memset(cfg, 0, sizeof(*cfg));
    cfg->enabled = 0;
    cfg->cpu_eco_pct = 15;
    cfg->cpu_pause_pct = 30;
    cfg->resume_delay_sec = 12;
    cfg->idle_full_sec = 180;
    cfg->pause_fullscreen = 1;
    cfg->pause_gpu_pct = 45;
    cfg->ram_pause_mb = 3072;
    cfg->pause_on_battery = 1;
    cfg->pause_processes[0] = '\0';
}

const char *yield_state_str(yield_state_t state) {
    switch (state) {
    case YIELD_STATE_FULL:   return "FULL";
    case YIELD_STATE_ECO:    return "ECO";
    case YIELD_STATE_PAUSED: return "PAUSED";
    default:                 return "UNKNOWN";
    }
}

static int stricmp_ascii(const char *a, const char *b) {
    while (*a && *b) {
        int ca = tolower((unsigned char)*a);
        int cb = tolower((unsigned char)*b);
        if (ca != cb) return ca - cb;
        a++;
        b++;
    }
    return tolower((unsigned char)*a) - tolower((unsigned char)*b);
}

int watchdog_match_process_list(const char *proc_name, const char *csv_list) {
    if (!proc_name || !proc_name[0] || !csv_list || !csv_list[0]) return 0;

    /* Strip path prefix if any */
    const char *base = proc_name;
    for (const char *s = proc_name; *s; s++) {
        if (*s == '\\' || *s == '/') base = s + 1;
    }

    const char *p = csv_list;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == ',' || *p == ';') p++;
        if (!*p) break;
        const char *start = p;
        while (*p && *p != ',' && *p != ';') p++;
        const char *end = p;
        while (end > start && (end[-1] == ' ' || end[-1] == '\t')) end--;
        size_t len = (size_t)(end - start);
        if (len > 0 && len < 128) {
            char token[128];
            memcpy(token, start, len);
            token[len] = '\0';
            if (stricmp_ascii(base, token) == 0) return 1;
        }
    }
    return 0;
}

void watchdog_fsm_init(watchdog_fsm_t *fsm, yield_state_t initial_state) {
    if (!fsm) return;
    memset(fsm, 0, sizeof(*fsm));
    fsm->state = initial_state;
    fsm->override_mode = YIELD_OVERRIDE_AUTO;
    snprintf(fsm->reason, sizeof(fsm->reason), "init");
}

yield_state_t watchdog_fsm_step(watchdog_fsm_t *fsm,
                                const watchdog_config_t *cfg,
                                const watchdog_sample_t *sample,
                                uint64_t now_ms) {
    if (!fsm || !cfg || !sample) return YIELD_STATE_FULL;

    /* Handle timed or manual override first */
    if (fsm->override_mode != YIELD_OVERRIDE_AUTO) {
        if (fsm->override_until_ms > 0 && now_ms >= fsm->override_until_ms) {
            fsm->override_mode = YIELD_OVERRIDE_AUTO;
            fsm->override_until_ms = 0;
            fsm->quiet_since_ms = 0;
        } else {
            fsm->pause_hits = 0;
            fsm->eco_hits = 0;
            fsm->quiet_since_ms = 0;
            if (fsm->override_mode == YIELD_OVERRIDE_FULL) {
                fsm->state = YIELD_STATE_FULL;
                snprintf(fsm->reason, sizeof(fsm->reason), "manual FULL");
            } else if (fsm->override_mode == YIELD_OVERRIDE_ECO) {
                fsm->state = YIELD_STATE_ECO;
                snprintf(fsm->reason, sizeof(fsm->reason), "manual ECO");
            } else {
                fsm->state = YIELD_STATE_PAUSED;
                if (fsm->override_until_ms > now_ms) {
                    uint64_t rem = (fsm->override_until_ms - now_ms + 59999ULL) / 60000ULL;
                    snprintf(fsm->reason, sizeof(fsm->reason), "manual pause (%llumin)", (unsigned long long)rem);
                } else {
                    snprintf(fsm->reason, sizeof(fsm->reason), "manual pause");
                }
            }
            return fsm->state;
        }
    }

    if (!cfg->enabled) {
        fsm->state = YIELD_STATE_FULL;
        snprintf(fsm->reason, sizeof(fsm->reason), "auto-yield off");
        return fsm->state;
    }

    /* Evaluate instantaneous desired state from all sensors */
    int immediate_pause = 0;
    int soft_pause = 0;
    int want_eco = 0;
    char trig_reason[64] = "idle";

    if (cfg->pause_on_battery && sample->on_battery) {
        immediate_pause = 1;
        snprintf(trig_reason, sizeof(trig_reason), "battery");
    } else if (sample->matched_proc[0] != '\0') {
        immediate_pause = 1;
        snprintf(trig_reason, sizeof(trig_reason), "proc %s", sample->matched_proc);
    } else if (cfg->pause_fullscreen && sample->fullscreen) {
        immediate_pause = 1;
        snprintf(trig_reason, sizeof(trig_reason), "fullscreen");
    } else if (cfg->ram_pause_mb > 0 && sample->avail_ram_mb > 0 &&
               sample->avail_ram_mb < (uint64_t)cfg->ram_pause_mb) {
        immediate_pause = 1;
        snprintf(trig_reason, sizeof(trig_reason), "low RAM %lluMB", (unsigned long long)sample->avail_ram_mb);
    } else if (cfg->pause_gpu_pct > 0 && sample->gpu_pct >= (double)cfg->pause_gpu_pct) {
        soft_pause = 1;
        snprintf(trig_reason, sizeof(trig_reason), "GPU %.0f%%", sample->gpu_pct);
    } else if (cfg->cpu_pause_pct > 0 && sample->ext_cpu_pct >= (double)cfg->cpu_pause_pct) {
        soft_pause = 1;
        snprintf(trig_reason, sizeof(trig_reason), "CPU %.0f%%", sample->ext_cpu_pct);
    } else if (cfg->cpu_eco_pct > 0 && sample->ext_cpu_pct >= (double)cfg->cpu_eco_pct) {
        want_eco = 1;
        snprintf(trig_reason, sizeof(trig_reason), "CPU %.0f%%", sample->ext_cpu_pct);
    } else if (cfg->idle_full_sec > 0 && sample->user_idle_sec < (uint32_t)cfg->idle_full_sec) {
        want_eco = 1;
        snprintf(trig_reason, sizeof(trig_reason), "active user");
    }

    /* Step-down logic: immediate for hard triggers (fullscreen/game/battery/RAM),
       2 consecutive samples (~1s) for CPU/GPU spikes to filter 1-tick glitches. */
    if (immediate_pause) {
        fsm->pause_hits = 2;
        fsm->eco_hits = 0;
        fsm->quiet_since_ms = 0;
        fsm->state = YIELD_STATE_PAUSED;
        snprintf(fsm->reason, sizeof(fsm->reason), "%s", trig_reason);
        return fsm->state;
    }

    if (soft_pause) {
        fsm->pause_hits++;
        fsm->eco_hits = 0;
        fsm->quiet_since_ms = 0;
        if (fsm->pause_hits >= 2) {
            fsm->state = YIELD_STATE_PAUSED;
            snprintf(fsm->reason, sizeof(fsm->reason), "%s", trig_reason);
        } else if (fsm->state == YIELD_STATE_FULL) {
            /* First spike tick: step down to ECO immediately for snappy feel */
            fsm->state = YIELD_STATE_ECO;
            snprintf(fsm->reason, sizeof(fsm->reason), "%s", trig_reason);
        }
        return fsm->state;
    }

    fsm->pause_hits = 0;

    /* Hysteresis band for stepping UP out of PAUSED:
       require CPU < 70% of pause threshold and GPU < 70% of GPU threshold. */
    int pause_cleared = 1;
    if (fsm->state == YIELD_STATE_PAUSED) {
        double cpu_clear = cfg->cpu_pause_pct > 0 ? cfg->cpu_pause_pct * 0.70 : 100.0;
        double gpu_clear = cfg->pause_gpu_pct > 0 ? cfg->pause_gpu_pct * 0.70 : 100.0;
        if (sample->ext_cpu_pct >= cpu_clear ||
            (sample->gpu_pct >= 0.0 && sample->gpu_pct >= gpu_clear)) {
            pause_cleared = 0;
        }
    }

    if (fsm->state == YIELD_STATE_PAUSED) {
        if (!pause_cleared) {
            fsm->quiet_since_ms = 0;
            return fsm->state;
        }
        if (fsm->quiet_since_ms == 0) fsm->quiet_since_ms = now_ms;
        uint64_t delay_ms = (uint64_t)(cfg->resume_delay_sec > 0 ? cfg->resume_delay_sec : 1) * 1000ULL;
        if (now_ms - fsm->quiet_since_ms >= delay_ms) {
            fsm->quiet_since_ms = 0;
            if (want_eco) {
                fsm->state = YIELD_STATE_ECO;
                snprintf(fsm->reason, sizeof(fsm->reason), "%s", trig_reason);
            } else {
                fsm->state = YIELD_STATE_FULL;
                snprintf(fsm->reason, sizeof(fsm->reason), "system idle");
            }
        }
        return fsm->state;
    }

    /* Currently in FULL or ECO */
    if (want_eco) {
        fsm->quiet_since_ms = 0;
        if (fsm->state == YIELD_STATE_FULL) {
            /* Active user drops to ECO immediately; CPU spike uses 2-tick debounce */
            if (cfg->idle_full_sec > 0 && sample->user_idle_sec < (uint32_t)cfg->idle_full_sec) {
                fsm->state = YIELD_STATE_ECO;
                snprintf(fsm->reason, sizeof(fsm->reason), "%s", trig_reason);
            } else {
                fsm->eco_hits++;
                if (fsm->eco_hits >= 2) {
                    fsm->state = YIELD_STATE_ECO;
                    snprintf(fsm->reason, sizeof(fsm->reason), "%s", trig_reason);
                }
            }
        } else {
            snprintf(fsm->reason, sizeof(fsm->reason), "%s", trig_reason);
        }
        return fsm->state;
    }

    fsm->eco_hits = 0;

    /* Currently in ECO and eligible to return to FULL */
    if (fsm->state == YIELD_STATE_ECO) {
        double eco_clear = cfg->cpu_eco_pct > 0 ? cfg->cpu_eco_pct * 0.70 : 100.0;
        if (sample->ext_cpu_pct >= eco_clear) {
            fsm->quiet_since_ms = 0;
            return fsm->state;
        }
        if (fsm->quiet_since_ms == 0) fsm->quiet_since_ms = now_ms;
        uint64_t delay_ms = (uint64_t)(cfg->resume_delay_sec > 0 ? cfg->resume_delay_sec : 1) * 1000ULL;
        if (now_ms - fsm->quiet_since_ms >= delay_ms) {
            fsm->quiet_since_ms = 0;
            fsm->state = YIELD_STATE_FULL;
            snprintf(fsm->reason, sizeof(fsm->reason), "AFK / idle");
        }
        return fsm->state;
    }

    snprintf(fsm->reason, sizeof(fsm->reason), "idle");
    return fsm->state;
}

#ifdef _WIN32

/* Dynamic PDH loader so unit tests and minimal builds don't require pdh.lib */
typedef PDH_STATUS (WINAPI *pfn_PdhOpenQueryA)(LPCSTR, DWORD_PTR, PDH_HQUERY*);
typedef PDH_STATUS (WINAPI *pfn_PdhAddEnglishCounterA)(PDH_HQUERY, LPCSTR, DWORD_PTR, PDH_HCOUNTER*);
typedef PDH_STATUS (WINAPI *pfn_PdhCollectQueryData)(PDH_HQUERY);
typedef PDH_STATUS (WINAPI *pfn_PdhGetFormattedCounterArrayA)(PDH_HCOUNTER, DWORD, LPDWORD, LPDWORD, PPDH_FMT_COUNTERVALUE_ITEM_A);
typedef PDH_STATUS (WINAPI *pfn_PdhCloseQuery)(PDH_HQUERY);

typedef struct {
    HMODULE hmod;
    pfn_PdhOpenQueryA open_query;
    pfn_PdhAddEnglishCounterA add_counter;
    pfn_PdhCollectQueryData collect;
    pfn_PdhGetFormattedCounterArrayA get_array;
    pfn_PdhCloseQuery close_query;
    PDH_HQUERY query;
    PDH_HCOUNTER counter;
    int ready;
    int primed;
} gpu_pdh_t;

static void gpu_pdh_init(gpu_pdh_t *g) {
    memset(g, 0, sizeof(*g));
    g->hmod = LoadLibraryA("pdh.dll");
    if (!g->hmod) return;
    g->open_query  = (pfn_PdhOpenQueryA)GetProcAddress(g->hmod, "PdhOpenQueryA");
    g->add_counter = (pfn_PdhAddEnglishCounterA)GetProcAddress(g->hmod, "PdhAddEnglishCounterA");
    g->collect     = (pfn_PdhCollectQueryData)GetProcAddress(g->hmod, "PdhCollectQueryData");
    g->get_array   = (pfn_PdhGetFormattedCounterArrayA)GetProcAddress(g->hmod, "PdhGetFormattedCounterArrayA");
    g->close_query = (pfn_PdhCloseQuery)GetProcAddress(g->hmod, "PdhCloseQuery");
    if (!g->open_query || !g->add_counter || !g->collect || !g->get_array || !g->close_query) {
        FreeLibrary(g->hmod);
        g->hmod = NULL;
        return;
    }
    if (g->open_query(NULL, 0, &g->query) != ERROR_SUCCESS) {
        FreeLibrary(g->hmod);
        g->hmod = NULL;
        return;
    }
    if (g->add_counter(g->query, "\\GPU Engine(*)\\Utilization Percentage", 0, &g->counter) != ERROR_SUCCESS) {
        g->close_query(g->query);
        FreeLibrary(g->hmod);
        g->hmod = NULL;
        return;
    }
    g->ready = 1;
}

static void gpu_pdh_destroy(gpu_pdh_t *g) {
    if (g->ready && g->close_query && g->query) g->close_query(g->query);
    if (g->hmod) FreeLibrary(g->hmod);
    memset(g, 0, sizeof(*g));
}

static double gpu_pdh_sample(gpu_pdh_t *g) {
    if (!g || !g->ready) return -1.0;
    if (g->collect(g->query) != ERROR_SUCCESS) return -1.0;
    if (!g->primed) {
        g->primed = 1;
        return 0.0;
    }
    DWORD buf_size = 0, item_count = 0;
    PDH_STATUS st = g->get_array(g->counter, PDH_FMT_DOUBLE, &buf_size, &item_count, NULL);
    if (st != (PDH_STATUS)PDH_MORE_DATA || buf_size == 0) return 0.0;

    PPDH_FMT_COUNTERVALUE_ITEM_A items = (PPDH_FMT_COUNTERVALUE_ITEM_A)malloc(buf_size);
    if (!items) return -1.0;

    double sum_3d = 0.0, sum_compute = 0.0, sum_copy = 0.0, sum_video = 0.0;
    if (g->get_array(g->counter, PDH_FMT_DOUBLE, &buf_size, &item_count, items) == ERROR_SUCCESS) {
        for (DWORD i = 0; i < item_count; i++) {
            if (items[i].FmtValue.CStatus != ERROR_SUCCESS) continue;
            double v = items[i].FmtValue.doubleValue;
            if (v <= 0.0) continue;
            const char *name = items[i].szName ? items[i].szName : "";
            if (strstr(name, "engtype_3D")) sum_3d += v;
            else if (strstr(name, "engtype_Compute") || strstr(name, "engtype_Cuda")) sum_compute += v;
            else if (strstr(name, "engtype_Copy")) sum_copy += v;
            else if (strstr(name, "engtype_VideoEncode")) sum_video += v;
        }
    }
    free(items);

    double peak = sum_3d;
    if (sum_compute > peak) peak = sum_compute;
    if (sum_copy > peak) peak = sum_copy;
    if (sum_video > peak) peak = sum_video;
    if (peak > 100.0) peak = 100.0;
    return peak;
}

static uint64_t ft_to_u64(FILETIME ft) {
    ULARGE_INTEGER u;
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    return u.QuadPart;
}

static void scan_blacklisted_process(const char *csv_list, char *matched_out, size_t matched_size) {
    matched_out[0] = '\0';
    if (!csv_list || !csv_list[0]) return;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            if (watchdog_match_process_list(pe.szExeFile, csv_list)) {
                snprintf(matched_out, matched_size, "%s", pe.szExeFile);
                break;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
}

struct watchdog_ctx {
    watchdog_config_t cfg;
    miner_ctx_t      *miner;
    watchdog_fsm_t    fsm;
    watchdog_sample_t last_sample;
    CRITICAL_SECTION  lock;
    HANDLE            stop_event;
    HANDLE            thread;
    volatile int      running;
    gpu_pdh_t         gpu;
    uint64_t          prev_sys_idle;
    uint64_t          prev_sys_kernel;
    uint64_t          prev_sys_user;
    uint64_t          prev_proc_busy;
    int               cpu_primed;
};

static double sample_external_cpu(watchdog_ctx_t *wd) {
    FILETIME si, sk, su;
    FILETIME pc, pe, pk, pu;
    if (!GetSystemTimes(&si, &sk, &su)) return 0.0;
    if (!GetProcessTimes(GetCurrentProcess(), &pc, &pe, &pk, &pu)) return 0.0;

    uint64_t cur_idle   = ft_to_u64(si);
    uint64_t cur_kernel = ft_to_u64(sk);
    uint64_t cur_user   = ft_to_u64(su);
    uint64_t cur_pbusy  = ft_to_u64(pk) + ft_to_u64(pu);

    if (!wd->cpu_primed) {
        wd->prev_sys_idle   = cur_idle;
        wd->prev_sys_kernel = cur_kernel;
        wd->prev_sys_user   = cur_user;
        wd->prev_proc_busy  = cur_pbusy;
        wd->cpu_primed = 1;
        return 0.0;
    }

    uint64_t d_idle   = cur_idle   >= wd->prev_sys_idle   ? (cur_idle   - wd->prev_sys_idle)   : 0;
    uint64_t d_kernel = cur_kernel >= wd->prev_sys_kernel ? (cur_kernel - wd->prev_sys_kernel) : 0;
    uint64_t d_user   = cur_user   >= wd->prev_sys_user   ? (cur_user   - wd->prev_sys_user)   : 0;
    uint64_t d_pbusy  = cur_pbusy  >= wd->prev_proc_busy  ? (cur_pbusy  - wd->prev_proc_busy)  : 0;

    wd->prev_sys_idle   = cur_idle;
    wd->prev_sys_kernel = cur_kernel;
    wd->prev_sys_user   = cur_user;
    wd->prev_proc_busy  = cur_pbusy;

    /* Note: in Win32 GetSystemTimes, kernel time INCLUDES idle time. */
    uint64_t total_time = d_kernel + d_user;
    if (total_time == 0) return 0.0;
    uint64_t total_busy = (total_time > d_idle) ? (total_time - d_idle) : 0;
    uint64_t ext_busy   = (total_busy > d_pbusy) ? (total_busy - d_pbusy) : 0;

    double pct = 100.0 * (double)ext_busy / (double)total_time;
    if (pct < 0.0) pct = 0.0;
    if (pct > 100.0) pct = 100.0;
    return pct;
}

static DWORD WINAPI watchdog_thread_entry(LPVOID arg) {
    watchdog_ctx_t *wd = (watchdog_ctx_t *)arg;
    uint32_t tick = 0;
    char cached_proc[64] = {0};

    /* Prime CPU + GPU counters immediately */
    sample_external_cpu(wd);
    if (wd->cfg.pause_gpu_pct > 0) gpu_pdh_sample(&wd->gpu);

    while (wd->running) {
        if (WaitForSingleObject(wd->stop_event, 500) == WAIT_OBJECT_0) break;
        if (!wd->running) break;

        watchdog_sample_t s;
        memset(&s, 0, sizeof(s));
        s.ext_cpu_pct = sample_external_cpu(wd);
        s.gpu_pct = (wd->cfg.pause_gpu_pct > 0) ? gpu_pdh_sample(&wd->gpu) : -1.0;

        /* Exclusive D3D fullscreen game detection (do not trigger on QUNS_BUSY,
           which Windows 11 sets for Focus Assist / maximized borderless desktop apps;
           borderless games are caught by GPU% + external CPU% + process blacklist). */
        QUERY_USER_NOTIFICATION_STATE quns = QUNS_ACCEPTS_NOTIFICATIONS;
        if (SHQueryUserNotificationState(&quns) == S_OK) {
            if (quns == QUNS_RUNNING_D3D_FULL_SCREEN) {
                s.fullscreen = 1;
            }
        }

        /* User idle time */
        LASTINPUTINFO lii;
        lii.cbSize = sizeof(lii);
        if (GetLastInputInfo(&lii)) {
            DWORD now32 = GetTickCount();
            DWORD delta_ms = now32 - lii.dwTime;
            s.user_idle_sec = (uint32_t)(delta_ms / 1000U);
        }

        /* Available RAM */
        MEMORYSTATUSEX ms;
        ms.dwLength = sizeof(ms);
        if (GlobalMemoryStatusEx(&ms)) {
            s.avail_ram_mb = (uint64_t)(ms.ullAvailPhys / (1024ULL * 1024ULL));
        }

        /* Power status (AC vs battery) */
        SYSTEM_POWER_STATUS sps;
        if (GetSystemPowerStatus(&sps)) {
            if (sps.ACLineStatus == 0) s.on_battery = 1;
        }

        /* Process blacklist scan every 2 seconds (4 ticks) */
        if ((tick & 3U) == 0 && wd->cfg.pause_processes[0] != '\0') {
            scan_blacklisted_process(wd->cfg.pause_processes, cached_proc, sizeof(cached_proc));
        }
        snprintf(s.matched_proc, sizeof(s.matched_proc), "%s", cached_proc);
        tick++;

        uint64_t now_ms = GetTickCount64();
        yield_state_t prev_state, next_state;
        char reason_copy[64];

        EnterCriticalSection(&wd->lock);
        wd->last_sample = s;
        prev_state = wd->fsm.state;
        next_state = watchdog_fsm_step(&wd->fsm, &wd->cfg, &s, now_ms);
        snprintf(reason_copy, sizeof(reason_copy), "%s", wd->fsm.reason);
        LeaveCriticalSection(&wd->lock);

        if (next_state != prev_state) {
            LOG_INFO("[YIELD] %s -> %s (%s | extCPU=%.1f%% GPU=%.0f%% idle=%us RAM=%lluMB)",
                     yield_state_str(prev_state), yield_state_str(next_state), reason_copy,
                     s.ext_cpu_pct, s.gpu_pct >= 0.0 ? s.gpu_pct : 0.0,
                     s.user_idle_sec, (unsigned long long)s.avail_ram_mb);
            if (wd->miner) {
                miner_set_yield_state(wd->miner, (int)next_state, reason_copy);
            }
        } else if (wd->miner) {
            miner_update_yield_reason(wd->miner, reason_copy);
        }
    }
    return 0;
}

watchdog_ctx_t *watchdog_create(const watchdog_config_t *cfg, miner_ctx_t *miner) {
    watchdog_ctx_t *wd = (watchdog_ctx_t *)calloc(1, sizeof(watchdog_ctx_t));
    if (!wd) return NULL;
    if (cfg) wd->cfg = *cfg;
    else watchdog_config_defaults(&wd->cfg);
    wd->miner = miner;

    /* If auto-yield is enabled and user is likely active right now, start in ECO
       when idle_full_sec > 0 so startup doesn't spike P-cores during active desktop use. */
    yield_state_t init_state = YIELD_STATE_FULL;
    if (wd->cfg.enabled && wd->cfg.idle_full_sec > 0) {
        LASTINPUTINFO lii;
        lii.cbSize = sizeof(lii);
        if (GetLastInputInfo(&lii)) {
            uint32_t idle_s = (uint32_t)((GetTickCount() - lii.dwTime) / 1000U);
            if (idle_s < (uint32_t)wd->cfg.idle_full_sec) {
                init_state = YIELD_STATE_ECO;
            }
        }
    }
    watchdog_fsm_init(&wd->fsm, init_state);
    if (init_state == YIELD_STATE_ECO) {
        snprintf(wd->fsm.reason, sizeof(wd->fsm.reason), "active user");
    }
    InitializeCriticalSection(&wd->lock);
    wd->stop_event = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (wd->cfg.pause_gpu_pct > 0) {
        gpu_pdh_init(&wd->gpu);
    }
    return wd;
}

void watchdog_start(watchdog_ctx_t *wd) {
    if (!wd || wd->running) return;
    wd->running = 1;
    ResetEvent(wd->stop_event);

    /* Apply initial state immediately so workers start cleanly in ECO if active */
    if (wd->miner && wd->cfg.enabled) {
        EnterCriticalSection(&wd->lock);
        yield_state_t st = wd->fsm.state;
        char reason[64];
        snprintf(reason, sizeof(reason), "%s", wd->fsm.reason);
        LeaveCriticalSection(&wd->lock);
        miner_set_yield_state(wd->miner, (int)st, reason);
        LOG_INFO("[YIELD] Watchdog active: initial=%s (eco>=%d%% pause>=%d%% gpu>=%d%% idleFull=%ds resume=%ds)",
                 yield_state_str(st), wd->cfg.cpu_eco_pct, wd->cfg.cpu_pause_pct,
                 wd->cfg.pause_gpu_pct, wd->cfg.idle_full_sec, wd->cfg.resume_delay_sec);
    }

    wd->thread = CreateThread(NULL, 0, watchdog_thread_entry, wd, 0, NULL);
}

void watchdog_stop(watchdog_ctx_t *wd) {
    if (!wd || !wd->running) return;
    wd->running = 0;
    if (wd->stop_event) SetEvent(wd->stop_event);
    if (wd->thread) {
        WaitForSingleObject(wd->thread, 3000);
        CloseHandle(wd->thread);
        wd->thread = NULL;
    }
}

void watchdog_destroy(watchdog_ctx_t *wd) {
    if (!wd) return;
    watchdog_stop(wd);
    gpu_pdh_destroy(&wd->gpu);
    if (wd->stop_event) CloseHandle(wd->stop_event);
    DeleteCriticalSection(&wd->lock);
    free(wd);
}

void watchdog_set_override(watchdog_ctx_t *wd, yield_override_t mode, uint32_t duration_sec) {
    if (!wd) return;
    uint64_t now_ms = GetTickCount64();
    yield_state_t next_state;
    char reason[64];

    EnterCriticalSection(&wd->lock);
    wd->fsm.override_mode = mode;
    wd->fsm.override_until_ms = (mode != YIELD_OVERRIDE_AUTO && duration_sec > 0)
        ? (now_ms + (uint64_t)duration_sec * 1000ULL)
        : 0;
    wd->fsm.quiet_since_ms = 0;
    wd->fsm.pause_hits = 0;
    wd->fsm.eco_hits = 0;
    next_state = watchdog_fsm_step(&wd->fsm, &wd->cfg, &wd->last_sample, now_ms);
    snprintf(reason, sizeof(reason), "%s", wd->fsm.reason);
    LeaveCriticalSection(&wd->lock);

    LOG_INFO("[YIELD] Override set -> %s (%s)", yield_state_str(next_state), reason);
    if (wd->miner) {
        miner_set_yield_state(wd->miner, (int)next_state, reason);
    }
}

yield_override_t watchdog_get_override(watchdog_ctx_t *wd, uint32_t *remaining_sec_out) {
    if (!wd) {
        if (remaining_sec_out) *remaining_sec_out = 0;
        return YIELD_OVERRIDE_AUTO;
    }
    uint64_t now_ms = GetTickCount64();
    EnterCriticalSection(&wd->lock);
    yield_override_t m = wd->fsm.override_mode;
    uint32_t rem = 0;
    if (m != YIELD_OVERRIDE_AUTO && wd->fsm.override_until_ms > now_ms) {
        rem = (uint32_t)((wd->fsm.override_until_ms - now_ms) / 1000ULL);
    }
    LeaveCriticalSection(&wd->lock);
    if (remaining_sec_out) *remaining_sec_out = rem;
    return m;
}

yield_state_t watchdog_get_state(watchdog_ctx_t *wd, char *reason_out, size_t reason_size) {
    if (!wd) {
        if (reason_out && reason_size > 0) reason_out[0] = '\0';
        return YIELD_STATE_FULL;
    }
    EnterCriticalSection(&wd->lock);
    yield_state_t st = wd->fsm.state;
    if (reason_out && reason_size > 0) {
        snprintf(reason_out, reason_size, "%s", wd->fsm.reason);
    }
    LeaveCriticalSection(&wd->lock);
    return st;
}

void watchdog_get_last_sample(watchdog_ctx_t *wd, watchdog_sample_t *out) {
    if (!wd || !out) return;
    EnterCriticalSection(&wd->lock);
    *out = wd->last_sample;
    LeaveCriticalSection(&wd->lock);
}

#endif /* _WIN32 */
