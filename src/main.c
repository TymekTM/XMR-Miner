#include "common/log.h"
#include "common/config.h"
#include "common/cpu.h"
#include "common/tray.h"
#include "stratum/stratum.h"
#include "miner/miner.h"
#include "miner/affinity.h"
#include "miner/watchdog.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

static volatile int g_running = 1;

static void request_shutdown(void) {
    g_running = 0;
}

static BOOL WINAPI ctrl_handler(DWORD type) {
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT ||
        type == CTRL_CLOSE_EVENT || type == CTRL_LOGOFF_EVENT ||
        type == CTRL_SHUTDOWN_EVENT) {
        g_running = 0;
        return TRUE;
    }
    return FALSE;
}

/* Sleep that returns early if shutdown was requested. */
static void interruptible_sleep(DWORD ms) {
    DWORD step = 100;
    DWORD elapsed = 0;
    while (g_running && elapsed < ms) {
        DWORD chunk = (ms - elapsed < step) ? (ms - elapsed) : step;
        Sleep(chunk);
        elapsed += chunk;
    }
}

int main(int argc, char **argv) {
    config_t cfg;
    if (config_parse_args(&cfg, argc, argv) != 0) {
        return 1;
    }

    log_init((log_level_t)cfg.log_level);

#ifdef XMR_TRAY_APP
    /* GUI-subsystem tray build: never spawns a console window; log to file instead */
    cfg.tray = 1;
    {
        char log_path[512] = "xmr-miner.log";
        if (cfg.config_path[0]) {
            snprintf(log_path, sizeof(log_path), "%s", cfg.config_path);
            char *slash = strrchr(log_path, '\\');
            char *fslash = strrchr(log_path, '/');
            if (fslash > slash) slash = fslash;
            if (slash) snprintf(slash + 1, sizeof(log_path) - (size_t)(slash + 1 - log_path), "xmr-miner.log");
            else snprintf(log_path, sizeof(log_path), "xmr-miner.log");
        }
        log_set_file(log_path);
    }
#endif

    if (cfg.uninstall_autostart) {
        int rc = autostart_uninstall();
        LOG_INFO("Autostart removal: %s", rc == 0 ? "OK" : "FAILED");
        if (cfg.wallet[0] == '\0') return rc == 0 ? 0 : 1;
    }
    if (cfg.install_autostart) {
        int rc = autostart_install(cfg.config_path);
        LOG_INFO("Autostart install: %s", rc == 0 ? "OK" : "FAILED");
        if (cfg.wallet[0] == '\0') return rc == 0 ? 0 : 1;
    }

    HANDLE instance_mutex = NULL;
    if (cfg.tray) {
        instance_mutex = CreateMutexW(NULL, TRUE, L"Local\\XMR-Miner-Background-Instance");
        if (instance_mutex && GetLastError() == ERROR_ALREADY_EXISTS) {
            LOG_WARN("Another XMR-Miner tray instance is already running - exiting");
            CloseHandle(instance_mutex);
            return 0;
        }
        HWND con = GetConsoleWindow();
        if (con) ShowWindow(con, SW_HIDE);
    }

    LOG_INFO("XMR-Miner v0.2.0 - Custom Monero miner (C, Windows x64)");
    LOG_INFO("Monero stratum protocol (login + job + submit)");
    LOG_INFO("==============================================");

    config_print(&cfg);

    cpu_info_t cpu;
    cpu_detect(&cpu);
    cpu_print_info(&cpu);

    if (!cpu.has_aes_ni) {
        LOG_ERR("AES-NI not available - RandomX requires AES-NI");
        if (instance_mutex) CloseHandle(instance_mutex);
        return 1;
    }

    int threads = cfg.threads;
    if (threads <= 0) {
        core_list_t cl;
        memset(&cl, 0, sizeof(cl));
        int phys = affinity_detect_cores(&cl);
        int ec = (phys > 0) ? affinity_count_ecores(&cl) : 0;
        int pc = (phys > 0) ? (phys - ec) : 0;
        if (cfg.efficiency) {
            threads = ec > 0 ? ec : (cpu.physical_cores > 0 ? cpu.physical_cores : cpu.logical_cores);
        } else if (pc > 0 && ec >= 8) {
            /* Hybrid Intel P+E: 3 active E-cores per 4-core L2 cluster (e.g. 8P+9E = 17T on 14700KF)
               avoids 4-way E-L2 thrashing and leaves spare E-cores for OS/background tasks,
               beating full physical count in both H/s and H/W. */
            threads = pc + (ec * 3) / 4;
        } else {
            threads = cpu.physical_cores > 0 ? cpu.physical_cores : cpu.logical_cores;
        }
    }
    LOG_INFO("Using %d mining thread(s) (%d physical / %d logical cores%s)",
             threads, cpu.physical_cores, cpu.logical_cores,
             cfg.efficiency ? ", efficiency E-first" : "");
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);

    SetConsoleCtrlHandler(ctrl_handler, TRUE);

    stratum_config_t scfg;
    scfg.pool_url = cfg.pool_url;
    scfg.pool_port = cfg.pool_port;
    scfg.wallet = cfg.wallet;
    scfg.worker_name = cfg.worker;
    scfg.password = cfg.password;
    scfg.use_tls = cfg.use_tls;
    scfg.tls_allow = cfg.tls_allow;

    stratum_ctx_t *stratum = stratum_create(&scfg);
    if (!stratum) {
        LOG_ERR("Failed to create stratum context");
        if (instance_mutex) CloseHandle(instance_mutex);
        return 1;
    }

    /* Retry initial connection gracefully (important at Windows boot before Wi-Fi/NIC is up) */
    {
        int backoff = 3;
        while (g_running) {
            if (stratum_connect(stratum) == 0 && stratum_login(stratum) == 0) {
                break;
            }
            stratum_disconnect(stratum);
            if (!cfg.tray && !cfg.auto_yield) {
                LOG_ERR("Failed to connect/login to pool");
                stratum_destroy(stratum);
                if (instance_mutex) CloseHandle(instance_mutex);
                return 1;
            }
            LOG_WARN("Initial pool connection failed, retrying in %d s...", backoff);
            interruptible_sleep((DWORD)backoff * 1000);
            if (backoff < 60) backoff = backoff * 2;
        }
        if (!g_running) {
            stratum_destroy(stratum);
            if (instance_mutex) CloseHandle(instance_mutex);
            return 0;
        }
    }

    miner_ctx_t *miner = miner_create(threads, cfg.huge_pages, cpu.physical_cores,
                                      cfg.mode, cfg.power_limit, stratum);
    if (miner) {
        miner_set_lanes(miner, cfg.lanes);
        miner_set_efficiency(miner, cfg.efficiency, cfg.eco_qos);
    }
    if (!miner) {
        LOG_ERR("Failed to create miner");
        stratum_destroy(stratum);
        if (instance_mutex) CloseHandle(instance_mutex);
        return 1;
    }

    /* Create watchdog before miner_start if auto_yield or tray is enabled so
       tray manual pause/ECO works even when auto_yield=0. */
    watchdog_ctx_t *watchdog = NULL;
    if (cfg.auto_yield || cfg.tray) {
        watchdog_config_t wcfg;
        watchdog_config_defaults(&wcfg);
        wcfg.enabled = cfg.auto_yield;
        wcfg.cpu_eco_pct = cfg.yield_cpu_eco;
        wcfg.cpu_pause_pct = cfg.yield_cpu_pause;
        wcfg.resume_delay_sec = cfg.resume_delay_sec;
        wcfg.idle_full_sec = cfg.idle_full_sec;
        wcfg.pause_fullscreen = cfg.pause_fullscreen;
        wcfg.pause_gpu_pct = cfg.pause_gpu_pct;
        wcfg.ram_pause_mb = cfg.ram_pause_mb;
        wcfg.pause_on_battery = cfg.pause_on_battery;
        snprintf(wcfg.pause_processes, sizeof(wcfg.pause_processes), "%s", cfg.pause_processes);
        watchdog = watchdog_create(&wcfg, miner);
    }

    tray_ctx_t *tray = NULL;
    if (cfg.tray) {
        tray = tray_create(miner, watchdog, cfg.config_path, request_shutdown);
        if (tray) tray_start(tray, 1);
    }

    uint8_t initial_seed[32] = {0};
    int initial_seed_len = 0;
    stratum_job_t *init_job = stratum_get_job(stratum);
    if (init_job && init_job->seed_hash && strlen(init_job->seed_hash) == 64) {
        for (int i = 0; i < 32; i++) {
            char h[3] = { init_job->seed_hash[i * 2], init_job->seed_hash[i * 2 + 1], 0 };
            initial_seed[i] = (uint8_t)strtoul(h, NULL, 16);
        }
        initial_seed_len = 32;
        LOG_INFO("Using pool seed_hash: %.16s...", init_job->seed_hash);
    }

    if (miner_start(miner, initial_seed_len > 0 ? initial_seed : NULL, initial_seed_len) != 0) {
        LOG_ERR("Failed to start miner");
        if (tray) tray_destroy(tray);
        if (watchdog) watchdog_destroy(watchdog);
        miner_destroy(miner);
        stratum_destroy(stratum);
        if (instance_mutex) CloseHandle(instance_mutex);
        return 1;
    }

    if (watchdog) watchdog_start(watchdog);

    uint64_t last_perf_ms = GetTickCount64();
    uint64_t last_keepalive_ms = GetTickCount64();

    while (g_running && stratum_running(stratum)) {
        uint64_t now_ms = GetTickCount64();
        if (now_ms - last_perf_ms >= 10000ULL) {
            miner_report_performance(miner);
            last_perf_ms = now_ms;
        }
        if (now_ms - last_keepalive_ms >= 55000ULL) {
            stratum_keepalive(stratum);
            last_keepalive_ms = now_ms;
        }

        if (stratum_recv(stratum) != 0) {
            LOG_WARN("Connection lost, reconnecting...");
            stratum_disconnect(stratum);

            /* If fully paused (e.g. long gaming session), wait until mining resumes
               before hammering the pool with reconnect attempts. */
            if (miner_get_yield_state(miner) == YIELD_STATE_PAUSED) {
                LOG_INFO("[STRATUM] Miner is PAUSED - deferring reconnect until resume");
                while (g_running && stratum_running(stratum) &&
                       miner_get_yield_state(miner) == YIELD_STATE_PAUSED) {
                    uint64_t tnow = GetTickCount64();
                    if (tnow - last_perf_ms >= 10000ULL) {
                        miner_report_performance(miner);
                        last_perf_ms = tnow;
                    }
                    interruptible_sleep(500);
                }
                if (!g_running || !stratum_running(stratum)) break;
            }

            int backoff = 5;      /* seconds, grows on repeated failure */
            const int cap = 300;  /* 5 min max */
            while (g_running && stratum_running(stratum)) {
                int jitter = backoff / 4;
                int delay = backoff + (int)(jitter * 2.0 * ((double)rand() / RAND_MAX)) - jitter;
                if (delay < 1) delay = 1;
                LOG_INFO("Reconnect attempt in %d s (next backoff %d s)...", delay, backoff);
                interruptible_sleep((DWORD)delay * 1000);
                if (!g_running) break;

                if (stratum_connect(stratum) == 0) {
                    if (stratum_login(stratum) == 0) {
                        LOG_INFO("Reconnected successfully");
                        last_keepalive_ms = GetTickCount64();
                        backoff = 5;  /* reset after success */
                        break;
                    }
                    LOG_WARN("Login failed after reconnect");
                    stratum_disconnect(stratum);
                }
                backoff = backoff + (backoff >> 1);  /* x1.5 */
                if (backoff > cap) backoff = cap;
            }
        }
        interruptible_sleep(10);
    }

    LOG_INFO("Shutting down...");
    if (tray) tray_destroy(tray);
    if (watchdog) watchdog_destroy(watchdog);
    miner_stop(miner);
    miner_destroy(miner);
    stratum_disconnect(stratum);
    stratum_destroy(stratum);
    if (instance_mutex) CloseHandle(instance_mutex);

    LOG_INFO("Goodbye!");
    log_close_file();
    return 0;
}
