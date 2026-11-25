/*
 * Unit tests for background Auto-Yield watchdog FSM (watchdog.c).
 * Tests fast-yield, hysteresis, slow-resume, GPU/fullscreen/RAM/process/battery
 * triggers, AFK idle_full_sec gating, and manual/timed overrides.
 */
#include "miner/watchdog.h"
#include "miner/miner.h"
#include <stdio.h>
#include <string.h>

/* Lightweight stubs so test_watchdog links standalone without full miner/RandomX */
void miner_set_yield_state(miner_ctx_t *ctx, int yield_state, const char *reason) {
    (void)ctx; (void)yield_state; (void)reason;
}
void miner_update_yield_reason(miner_ctx_t *ctx, const char *reason) {
    (void)ctx; (void)reason;
}

static int checks = 0;
static int failures = 0;

#define CHECK(cond) do { \
    checks++; \
    if (!(cond)) { \
        printf("  [FAIL] %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        failures++; \
    } \
} while (0)

static watchdog_sample_t make_idle_sample(void) {
    watchdog_sample_t s;
    memset(&s, 0, sizeof(s));
    s.ext_cpu_pct = 2.0;
    s.gpu_pct = 3.0;
    s.fullscreen = 0;
    s.user_idle_sec = 300;
    s.avail_ram_mb = 16384;
    s.on_battery = 0;
    return s;
}

static void test_process_matching(void) {
    const char *list = "cs2.exe, msbuild.exe ; CL.EXE,  Blender.exe ";
    CHECK(watchdog_match_process_list("cs2.exe", list) == 1);
    CHECK(watchdog_match_process_list("CS2.EXE", list) == 1);
    CHECK(watchdog_match_process_list("C:\\Program Files\\cl.exe", list) == 1);
    CHECK(watchdog_match_process_list("blender.exe", list) == 1);
    CHECK(watchdog_match_process_list("notepad.exe", list) == 0);
    CHECK(watchdog_match_process_list("cs2.exe", "") == 0);
}

static void test_cpu_hysteresis_and_resume(void) {
    watchdog_config_t cfg;
    watchdog_config_defaults(&cfg);
    cfg.enabled = 1;
    cfg.cpu_eco_pct = 15;
    cfg.cpu_pause_pct = 30;
    cfg.resume_delay_sec = 10;
    cfg.idle_full_sec = 0;

    watchdog_fsm_t fsm;
    watchdog_fsm_init(&fsm, YIELD_STATE_FULL);

    watchdog_sample_t s = make_idle_sample();
    CHECK(watchdog_fsm_step(&fsm, &cfg, &s, 1000) == YIELD_STATE_FULL);

    /* Single ECO CPU spike (1 tick) shouldn't drop FULL immediately */
    s.ext_cpu_pct = 20.0;
    CHECK(watchdog_fsm_step(&fsm, &cfg, &s, 1500) == YIELD_STATE_FULL);
    /* Second consecutive tick -> drops to ECO */
    CHECK(watchdog_fsm_step(&fsm, &cfg, &s, 2000) == YIELD_STATE_ECO);

    /* Hard CPU spike >= 30%: 1st tick stays ECO, 2nd tick -> PAUSED */
    s.ext_cpu_pct = 45.0;
    CHECK(watchdog_fsm_step(&fsm, &cfg, &s, 2500) == YIELD_STATE_ECO);
    CHECK(watchdog_fsm_step(&fsm, &cfg, &s, 3000) == YIELD_STATE_PAUSED);

    /* Drop to 24% (still inside hysteresis band >= 70% of 30% = 21%) -> stays PAUSED */
    s.ext_cpu_pct = 24.0;
    CHECK(watchdog_fsm_step(&fsm, &cfg, &s, 15000) == YIELD_STATE_PAUSED);

    /* Drop to 5% (quiet): stays PAUSED for resume_delay_sec (10s), then resumes FULL */
    s.ext_cpu_pct = 5.0;
    CHECK(watchdog_fsm_step(&fsm, &cfg, &s, 20000) == YIELD_STATE_PAUSED);
    CHECK(watchdog_fsm_step(&fsm, &cfg, &s, 29000) == YIELD_STATE_PAUSED);
    CHECK(watchdog_fsm_step(&fsm, &cfg, &s, 30000) == YIELD_STATE_FULL);
}

static void test_immediate_triggers(void) {
    watchdog_config_t cfg;
    watchdog_config_defaults(&cfg);
    cfg.enabled = 1;
    cfg.idle_full_sec = 0;

    /* Fullscreen -> immediate PAUSED */
    watchdog_fsm_t fsm;
    watchdog_fsm_init(&fsm, YIELD_STATE_FULL);
    watchdog_sample_t s = make_idle_sample();
    s.fullscreen = 1;
    CHECK(watchdog_fsm_step(&fsm, &cfg, &s, 1000) == YIELD_STATE_PAUSED);

    /* Blacklisted process -> immediate PAUSED */
    watchdog_fsm_init(&fsm, YIELD_STATE_FULL);
    s = make_idle_sample();
    snprintf(s.matched_proc, sizeof(s.matched_proc), "cs2.exe");
    CHECK(watchdog_fsm_step(&fsm, &cfg, &s, 1000) == YIELD_STATE_PAUSED);

    /* Low RAM -> immediate PAUSED */
    watchdog_fsm_init(&fsm, YIELD_STATE_FULL);
    s = make_idle_sample();
    s.avail_ram_mb = 2048;
    CHECK(watchdog_fsm_step(&fsm, &cfg, &s, 1000) == YIELD_STATE_PAUSED);

    /* Battery -> immediate PAUSED */
    watchdog_fsm_init(&fsm, YIELD_STATE_FULL);
    s = make_idle_sample();
    s.on_battery = 1;
    CHECK(watchdog_fsm_step(&fsm, &cfg, &s, 1000) == YIELD_STATE_PAUSED);
}

static void test_gpu_and_active_user(void) {
    watchdog_config_t cfg;
    watchdog_config_defaults(&cfg);
    cfg.enabled = 1;
    cfg.idle_full_sec = 180;
    cfg.pause_gpu_pct = 25;
    cfg.resume_delay_sec = 10;

    watchdog_fsm_t fsm;
    watchdog_fsm_init(&fsm, YIELD_STATE_FULL);

    /* Active user (idle < 180s) drops FULL -> ECO immediately */
    watchdog_sample_t s = make_idle_sample();
    s.user_idle_sec = 5;
    CHECK(watchdog_fsm_step(&fsm, &cfg, &s, 1000) == YIELD_STATE_ECO);

    /* GPU spike (borderless game!) >= 25%: 2 ticks -> PAUSED */
    s.gpu_pct = 65.0;
    CHECK(watchdog_fsm_step(&fsm, &cfg, &s, 1500) == YIELD_STATE_ECO);
    CHECK(watchdog_fsm_step(&fsm, &cfg, &s, 2000) == YIELD_STATE_PAUSED);

    /* Game exits, user still active: after 10s resumes to ECO (NOT FULL!) */
    s.gpu_pct = 2.0;
    CHECK(watchdog_fsm_step(&fsm, &cfg, &s, 3000) == YIELD_STATE_PAUSED);
    CHECK(watchdog_fsm_step(&fsm, &cfg, &s, 13000) == YIELD_STATE_ECO);

    /* User goes AFK >= 180s: after 10s steps up to FULL */
    s.user_idle_sec = 200;
    CHECK(watchdog_fsm_step(&fsm, &cfg, &s, 14000) == YIELD_STATE_ECO);
    CHECK(watchdog_fsm_step(&fsm, &cfg, &s, 24000) == YIELD_STATE_FULL);
}

static void test_manual_and_timed_override(void) {
    watchdog_config_t cfg;
    watchdog_config_defaults(&cfg);
    cfg.enabled = 1;
    cfg.idle_full_sec = 0;

    watchdog_fsm_t fsm;
    watchdog_fsm_init(&fsm, YIELD_STATE_FULL);
    watchdog_sample_t s = make_idle_sample();

    /* Timed pause for 60s */
    fsm.override_mode = YIELD_OVERRIDE_PAUSED;
    fsm.override_until_ms = 61000;
    CHECK(watchdog_fsm_step(&fsm, &cfg, &s, 1000) == YIELD_STATE_PAUSED);
    CHECK(watchdog_fsm_step(&fsm, &cfg, &s, 60000) == YIELD_STATE_PAUSED);
    /* Expires at 61000 -> starts quiet timer, resumes FULL after resume_delay_sec */
    CHECK(watchdog_fsm_step(&fsm, &cfg, &s, 61000) == YIELD_STATE_PAUSED);
    CHECK(fsm.override_mode == YIELD_OVERRIDE_AUTO);
    CHECK(watchdog_fsm_step(&fsm, &cfg, &s, 73000) == YIELD_STATE_FULL);

    /* Manual FULL overrides fullscreen */
    s.fullscreen = 1;
    fsm.override_mode = YIELD_OVERRIDE_FULL;
    fsm.override_until_ms = 0;
    CHECK(watchdog_fsm_step(&fsm, &cfg, &s, 80000) == YIELD_STATE_FULL);
}

int main(void) {
    printf("[TEST] watchdog auto-yield FSM\n");
    test_process_matching();
    test_cpu_hysteresis_and_resume();
    test_immediate_triggers();
    test_gpu_and_active_user();
    test_manual_and_timed_override();

    printf("[TEST] %d checks, %d failures\n", checks, failures);
    printf("[TEST] %s\n", failures == 0 ? "PASS" : "FAIL");
    return failures == 0 ? 0 : 1;
}
