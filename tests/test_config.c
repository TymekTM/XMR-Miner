/*
 * Unit tests for config parsing (config.c): CLI args and config file.
 * Returns non-zero on any failure.
 */
#include "common/config.h"
#include "common/log.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int checks = 0;
static int failures = 0;

#define CHECK(cond) do { \
    checks++; \
    if (!(cond)) { \
        printf("  [FAIL] %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        failures++; \
    } \
} while (0)

static void test_defaults(void) {
    config_t cfg;
    config_set_defaults(&cfg);
    CHECK(cfg.pool_port == 3333);
    CHECK(cfg.huge_pages == 1);
    CHECK(cfg.mode == MINER_MODE_AUTO);
    CHECK(cfg.threads == 0);
    CHECK(cfg.wallet[0] == '\0');
    CHECK(cfg.log_level == LOG_INFO);
}

static void test_requires_wallet(void) {
    config_t cfg;
    char *argv[] = { "xmr-miner" };
    int r = config_parse_args(&cfg, 1, argv);
    CHECK(r == RX_ERROR);  /* no wallet -> error */
}

static void test_basic_args(void) {
    config_t cfg;
    char *argv[] = { "xmr-miner",
        "-u", "48EdMv8LBTJhBZxWj6Yf9Kv2tPzQr4nHxYp",
        "-o", "pool.example.com:7777",
        "-t", "8",
        "--mode", "dual",
        "-p", "secret",
        NULL };
    int argc = 0;
    while (argv[argc]) argc++;
    int r = config_parse_args(&cfg, argc, argv);
    CHECK(r == RX_SUCCESS);
    CHECK(strncmp(cfg.wallet, "48EdMv8LBTJhBZxWj6Yf9Kv2tPzQr4nHxYp", 35) == 0);
    CHECK(strcmp(cfg.pool_url, "pool.example.com") == 0);
    CHECK(cfg.pool_port == 7777);
    CHECK(cfg.threads == 8);
    CHECK(cfg.mode == MINER_MODE_DUAL);
    CHECK(strcmp(cfg.password, "secret") == 0);
}

static void test_modes(void) {
    const char *modes[] = { "single", "dual", "auto" };
    const int expected[] = { MINER_MODE_SINGLE, MINER_MODE_DUAL, MINER_MODE_AUTO };
    for (int i = 0; i < 3; i++) {
        config_t cfg;
        char w[16]; snprintf(w, sizeof(w), "-u");
        char *argv[] = { "xmr-miner", "-u", "W", "--mode", (char*)modes[i], NULL };
        int argc = 0; while (argv[argc]) argc++;
        int r = config_parse_args(&cfg, argc, argv);
        CHECK(r == RX_SUCCESS);
        CHECK(cfg.mode == expected[i]);
    }
}

static void test_invalid_mode(void) {
    config_t cfg;
    char *argv[] = { "xmr-miner", "-u", "W", "--mode", "bogus", NULL };
    int argc = 0; while (argv[argc]) argc++;
    CHECK(config_parse_args(&cfg, argc, argv) == RX_ERROR);
}

static void test_negative_power_limit(void) {
    config_t cfg;
    char *argv[] = { "xmr-miner", "-u", "W", "--power-limit", "-5", NULL };
    int argc = 0; while (argv[argc]) argc++;
    CHECK(config_parse_args(&cfg, argc, argv) == RX_ERROR);
}

static void test_no_huge_pages(void) {
    config_t cfg;
    char *argv[] = { "xmr-miner", "-u", "W", "--no-huge-pages", NULL };
    int argc = 0; while (argv[argc]) argc++;
    CHECK(config_parse_args(&cfg, argc, argv) == RX_SUCCESS);
    CHECK(cfg.huge_pages == 0);
}

static void test_unknown_option(void) {
    config_t cfg;
    char *argv[] = { "xmr-miner", "-u", "W", "--bogus", NULL };
    int argc = 0; while (argv[argc]) argc++;
    CHECK(config_parse_args(&cfg, argc, argv) == RX_ERROR);
}

static void test_config_file(void) {
    const char *path = "test_config_tmp.conf";
    FILE *f = fopen(path, "w");
    CHECK(f != NULL);
    if (!f) return;
    fprintf(f, "# comment line\n");
    fprintf(f, "pool = my.pool.com:9000 \n");
    fprintf(f, "wallet=WalletFromConfig\n");
    fprintf(f, "=value_with_empty_key\n");
    fprintf(f, "threads = 4\n");
    fprintf(f, "mode=single\n");
    fprintf(f, "password=hunter2\n");
    fclose(f);

    config_t cfg;
    char *argv[] = { "xmr-miner", "-c", (char*)path, NULL };
    int argc = 0; while (argv[argc]) argc++;
    int r = config_parse_args(&cfg, argc, argv);
    CHECK(r == RX_SUCCESS);
    CHECK(strcmp(cfg.pool_url, "my.pool.com") == 0);
    CHECK(cfg.pool_port == 9000);
    CHECK(strcmp(cfg.wallet, "WalletFromConfig") == 0);
    CHECK(cfg.threads == 4);
    CHECK(cfg.mode == MINER_MODE_SINGLE);
    CHECK(strcmp(cfg.password, "hunter2") == 0);

    remove(path);
}

int main(void) {
    printf("[TEST] config parser\n");
    test_defaults();
    test_requires_wallet();
    test_basic_args();
    test_modes();
    test_invalid_mode();
    test_negative_power_limit();
    test_no_huge_pages();
    test_unknown_option();
    test_config_file();

    printf("[TEST] %d checks, %d failures\n", checks, failures);
    printf("[TEST] %s\n", failures == 0 ? "PASS" : "FAIL");
    return failures == 0 ? 0 : 1;
}
