#include "config.h"
#include "log.h"
#include <string.h>
#include <stdlib.h>

static const char *mode_to_str(int mode) {
    switch (mode) {
    case MINER_MODE_SINGLE: return "single";
    case MINER_MODE_DUAL: return "dual";
    default: return "auto";
    }
}

void config_set_defaults(config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    strncpy(cfg->pool_url, "supportxmr.com", MAX_STRATUM_URL);
    cfg->pool_port = 3333;
    cfg->threads = 0;
    cfg->huge_pages = 1;
    cfg->mode = MINER_MODE_AUTO;
    cfg->log_level = LOG_INFO;
}

static void print_usage(const char *prog) {
    printf("Usage: %s [options]\n", prog);
    printf("Options:\n");
    printf("  -o, --pool <host:port>   Mining pool (default: supportxmr.com:3333)\n");
    printf("  -u, --user <wallet>      Monero wallet address\n");
    printf("  -p, --pass <password>    Worker password (default: x)\n");
    printf("  -t, --threads <N>        Number of mining threads (default: auto)\n");
    printf("  --mode <auto|single|dual> Mining mode (default: auto)\n");
    printf("  --no-huge-pages          Disable huge pages\n");
    printf("  -v, --verbose            Verbose output\n");
    printf("  -h, --help               Show this help\n");
}

int config_parse_args(config_t *cfg, int argc, char **argv) {
    config_set_defaults(cfg);
    strncpy(cfg->password, "x", MAX_POOL_PASS);

    for (int i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--pool") == 0) && i + 1 < argc) {
            i++;
            char *colon = strchr(argv[i], ':');
            if (colon) {
                size_t host_len = colon - argv[i];
                if (host_len >= MAX_STRATUM_URL) host_len = MAX_STRATUM_URL - 1;
                memcpy(cfg->pool_url, argv[i], host_len);
                cfg->pool_url[host_len] = '\0';
                cfg->pool_port = atoi(colon + 1);
            } else {
                strncpy(cfg->pool_url, argv[i], MAX_STRATUM_URL - 1);
            }
        } else if ((strcmp(argv[i], "-u") == 0 || strcmp(argv[i], "--user") == 0) && i + 1 < argc) {
            i++;
            strncpy(cfg->wallet, argv[i], MAX_WALLET_ADDR - 1);
        } else if ((strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--pass") == 0) && i + 1 < argc) {
            i++;
            strncpy(cfg->password, argv[i], MAX_POOL_PASS - 1);
        } else if ((strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--threads") == 0) && i + 1 < argc) {
            i++;
            cfg->threads = atoi(argv[i]);
        } else if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
            i++;
            if (strcmp(argv[i], "auto") == 0) cfg->mode = MINER_MODE_AUTO;
            else if (strcmp(argv[i], "single") == 0) cfg->mode = MINER_MODE_SINGLE;
            else if (strcmp(argv[i], "dual") == 0) cfg->mode = MINER_MODE_DUAL;
            else {
                LOG_ERR("Invalid mode: %s (expected auto|single|dual)", argv[i]);
                return RX_ERROR;
            }
        } else if (strcmp(argv[i], "--no-huge-pages") == 0) {
            cfg->huge_pages = 0;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            cfg->verbose = 1;
            cfg->log_level = LOG_DEBUG;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            exit(0);
        } else {
            LOG_ERR("Unknown option: %s", argv[i]);
            print_usage(argv[0]);
            return RX_ERROR;
        }
    }

    if (cfg->wallet[0] == '\0') {
        LOG_ERR("Wallet address required (-u)");
        return RX_ERROR;
    }

    return RX_SUCCESS;
}

void config_print(const config_t *cfg) {
    LOG_INFO("Pool: %s:%d", cfg->pool_url, cfg->pool_port);
    LOG_INFO("Wallet: %s...%.4s", cfg->wallet, cfg->wallet + strlen(cfg->wallet) - 4);
    if (cfg->threads <= 0)
        LOG_INFO("Threads: auto");
    else
        LOG_INFO("Threads: %d", cfg->threads);
    LOG_INFO("Mode: %s", mode_to_str(cfg->mode));
    LOG_INFO("Huge pages: %s", cfg->huge_pages ? "yes" : "no");
}
