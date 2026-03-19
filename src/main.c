#include "common/log.h"
#include "common/config.h"
#include "common/cpu.h"
#include "stratum/stratum.h"
#include "miner/miner.h"
#include <windows.h>
#include <stdio.h>
#include <signal.h>

static volatile int g_running = 1;

static BOOL WINAPI ctrl_handler(DWORD type) {
    if (type == CTRL_C_EVENT) {
        g_running = 0;
        return TRUE;
    }
    return FALSE;
}

int main(int argc, char **argv) {
    config_t cfg;
    if (config_parse_args(&cfg, argc, argv) != 0) {
        return 1;
    }

    log_init((log_level_t)cfg.log_level);

    LOG_INFO("XMR-Miner v0.2.0 - Custom Monero miner (C, Windows x64)");
    LOG_INFO("Monero stratum protocol (login + job + submit)");
    LOG_INFO("==============================================");

    config_print(&cfg);

    cpu_info_t cpu;
    cpu_detect(&cpu);
    cpu_print_info(&cpu);

    if (!cpu.has_aes_ni) {
        LOG_ERR("AES-NI not available - RandomX requires AES-NI");
        return 1;
    }

    int threads = cfg.threads > 0 ? cfg.threads : cpu.logical_cores;
    LOG_INFO("Using %d mining thread(s)", threads);

    SetConsoleCtrlHandler(ctrl_handler, TRUE);

    stratum_config_t scfg;
    scfg.pool_url = cfg.pool_url;
    scfg.pool_port = cfg.pool_port;
    scfg.wallet = cfg.wallet;
    scfg.worker_name = cfg.worker;
    scfg.password = cfg.password;

    stratum_ctx_t *stratum = stratum_create(&scfg);
    if (!stratum) {
        LOG_ERR("Failed to create stratum context");
        return 1;
    }

    if (stratum_connect(stratum) != 0) {
        LOG_ERR("Failed to connect to pool");
        stratum_destroy(stratum);
        return 1;
    }

    if (stratum_login(stratum) != 0) {
        LOG_ERR("Failed to login");
        stratum_destroy(stratum);
        return 1;
    }

    miner_ctx_t *miner = miner_create(threads, stratum);
    if (!miner) {
        LOG_ERR("Failed to create miner");
        stratum_destroy(stratum);
        return 1;
    }

    if (miner_start(miner) != 0) {
        LOG_ERR("Failed to start miner");
        miner_destroy(miner);
        stratum_destroy(stratum);
        return 1;
    }

    while (g_running && stratum_running(stratum)) {
        if (stratum_recv(stratum) != 0) {
            LOG_WARN("Connection lost, reconnecting in 5s...");
            Sleep(5000);
            stratum_disconnect(stratum);
            if (stratum_connect(stratum) != 0) {
                LOG_ERR("Reconnect failed, retrying in 15s...");
                Sleep(15000);
                continue;
            }
            stratum_login(stratum);
        }
        Sleep(10);
    }

    LOG_INFO("Shutting down...");
    miner_stop(miner);
    miner_destroy(miner);
    stratum_disconnect(stratum);
    stratum_destroy(stratum);

    LOG_INFO("Goodbye!");
    return 0;
}
