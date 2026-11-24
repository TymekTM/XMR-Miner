#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/*
 * bench_rx - portable (POSIX + Windows) RandomX hashrate benchmark.
 *
 *   bench_rx [-t threads] [-n hashes/thread] [-r repeats] [-p pages]
 *            [--no-pin] [--full] [--no-check] [-c cpu_list]
 *
 *   pages: 0 = 4 KB, 1 = 2 MB huge pages, 2 = 1 GB pages (default; falls back to 2 MB)
 *
 * Before measuring it verifies the official RandomX test vector
 * (key "test key 000", input "This is a test") with the JIT VM, and that
 * the batch pipeline (hash_first/hash_next) matches rx_calculate_hash.
 * Hashrate is reported as the median of the repeats; every repeat runs all
 * threads concurrently and is timed from a common start barrier.
 */
#include "crypto/randomx/randomx.h"
#include "crypto/randomx/randomx_internal.h"
#include "crypto/randomx/msr.h"
#include "common/vmem.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#include <sched.h>
#include <time.h>
#include <unistd.h>
#endif

#define MAX_THREADS 256

static double now_sec(void) {
#ifdef _WIN32
    LARGE_INTEGER f, c;
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&c);
    return (double)c.QuadPart / (double)f.QuadPart;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + ts.tv_nsec * 1e-9;
#endif
}

static int num_cpus(void) {
#ifdef _WIN32
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return (int)si.dwNumberOfProcessors;
#else
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    return n > 0 ? (int)n : 1;
#endif
}

static void pin_self(int cpu) {
#ifdef _WIN32
    SetThreadAffinityMask(GetCurrentThread(), (DWORD_PTR)1 << cpu);
#else
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    pthread_setaffinity_np(pthread_self(), sizeof(set), &set);
#endif
}

/* ---- simple spinning barrier (portable) ---- */
#ifdef _MSC_VER
#include <intrin.h>
#define BAR_INC(p) _InterlockedIncrement((volatile long *)(p))
#define BAR_LOAD(p) _InterlockedOr((volatile long *)(p), 0)
#else
#define BAR_INC(p) __atomic_add_fetch((p), 1, __ATOMIC_SEQ_CST)
#define BAR_LOAD(p) __atomic_load_n((p), __ATOMIC_SEQ_CST)
#endif
static volatile long g_barrier_count = 0;
static volatile long g_barrier_gen = 0;
static int g_barrier_total = 0;

static void barrier_wait(void) {
    long gen = BAR_LOAD(&g_barrier_gen);
    if (BAR_INC(&g_barrier_count) == g_barrier_total) {
        g_barrier_count = 0;
        BAR_INC(&g_barrier_gen);
    } else {
        while (BAR_LOAD(&g_barrier_gen) == gen) _mm_pause();
    }
}

typedef struct {
    int tid;
    int cpu;
    int hashes;
    int repeats;
    int full_mode; /* 0 batch, 1 full, 2 dual, 3 group (multi-lane batch), 4 hetero (per-worker lanes/guard) */
    int lanes;
    int cfround_guard;
    rx_cache *cache;
    rx_dataset *dataset;
    double *seconds; /* [repeats] */
    uint8_t last_hash[32];
    int sp_kind;
} worker_t;

static int g_pin = 1;
static int g_eco_qos = 0; /* 0=off, 1=all threads, 2=P-cores only */

#ifdef _WIN32
static void apply_thread_eco_qos(int enable) {
    if (!enable) return;
    THREAD_POWER_THROTTLING_STATE pts;
    memset(&pts, 0, sizeof(pts));
    pts.Version = THREAD_POWER_THROTTLING_CURRENT_VERSION;
    pts.ControlMask = THREAD_POWER_THROTTLING_EXECUTION_SPEED;
    pts.StateMask = THREAD_POWER_THROTTLING_EXECUTION_SPEED;
    SetThreadInformation(GetCurrentThread(), ThreadPowerThrottling, &pts, sizeof(pts));
}
#endif

extern int g_jit_short_branches;
extern int g_jit_involution_pairs;
extern int g_jit_branch_align;
extern int g_jit_loop_nop;
extern int g_jit_sp_prefetch_hint;
extern int g_jit_bmi2_mulx;
extern int g_jit_cfround_elim;
extern int g_jit_jcc_align;
extern int g_jit_rorx;
extern int g_jit_cfround_rorx;
extern int g_jit_near_rcp_pool;
extern int g_jit_inline_rcp_pool;
extern int g_jit_stack_rcp_pool;
extern int g_jit_iswap_mov;
extern int g_jit_fast_iadd_rs;
extern int g_jit_ds_prefetch_hint;
extern int g_aes_hash_fill_prefetch;

extern rx_jit *rx_jit_create(void);
extern void rx_jit_destroy(rx_jit *jit);
extern void rx_jit_set_cfround_guard(rx_jit *jit, int enable);
extern void rx_jit_generate_program(rx_jit *jit, rx_program *prog, rx_program_config *cfg, rx_cache *cache);
extern void *rx_jit_get_program_func(rx_jit *jit);

/* ---- CFROUND-Aware Heterogeneous P/E Chain Router (--pe-route) ---- */
#define PE_MAX_VMS (MAX_THREADS + 64)

typedef struct {
    rx_vm *vm;
    uint8_t blob[76];
    uint32_t nonce;
    int chain;       /* 0..7: chain currently prepared in vm->program */
    int cf_count;    /* number of CFROUND ops in vm->program */
    int last_cpu;
} pe_slot_t;

typedef struct {
    pe_slot_t *items[PE_MAX_VMS];
    int count;
} pe_queue_t;

static volatile long g_pe_lock = 0;
static pe_queue_t g_pe_q[3]; /* 0: cf==0, 1: cf==1, 2: cf>=2 */
static pe_slot_t g_pe_slots[PE_MAX_VMS];
static int g_pe_extra_vms = 4;
static int g_pe_mode_flag = 0; /* 0 = normal strict-improve, 1 = pcore-strict-cf>=1 */
static volatile long g_pe_hashes_done = 0;
static volatile long g_pe_nonce_gen = 0;
static long g_pe_hashes_target = 0;

/* Telemetry counters (per-repeat) */
typedef struct {
    uint64_t chains_cf[3];
    uint64_t swaps;
    uint64_t keeps;
    uint64_t hashes;
} pe_stats_t;
static pe_stats_t g_pe_stats[MAX_THREADS];

/* Verification buffer for --pe-route correctness check */
#define PE_VERIFY_COUNT 32
static volatile long g_pe_verify_active = 0;
static volatile long g_pe_verify_idx = 0;
static uint8_t g_pe_verify_blobs[PE_VERIFY_COUNT][76];
static uint8_t g_pe_verify_hashes[PE_VERIFY_COUNT][32];

static __forceinline void pe_lock(void) {
#ifdef _MSC_VER
    while (_InterlockedExchange(&g_pe_lock, 1) != 0) {
        while (g_pe_lock) _mm_pause();
    }
#else
    while (__atomic_exchange_n(&g_pe_lock, 1, __ATOMIC_ACQUIRE) != 0) {
        while (__atomic_load_n(&g_pe_lock, __ATOMIC_RELAXED)) _mm_pause();
    }
#endif
}

static __forceinline void pe_unlock(void) {
#ifdef _MSC_VER
    _InterlockedExchange(&g_pe_lock, 0);
#else
    __atomic_store_n(&g_pe_lock, 0, __ATOMIC_RELEASE);
#endif
}

static __forceinline int pe_count_cfrounds(const rx_program *prog) {
    int c = 0;
    for (int i = 0; i < RX_PROGRAM_SIZE; i++) {
        uint8_t op = prog->programBuffer[i].opcode;
        if (op >= RX_CEIL_RX_CBRANCH && op < RX_CEIL_RX_CFROUND) c++;
    }
    return c;
}

static __forceinline void pe_vm_init_cfg(rx_vm *vm) {
    for (int i = 0; i < RX_REG_FLT_COUNT; i++) {
        uint64_t ent0 = vm->program.entropyBuffer[2 * i];
        uint64_t ent1 = vm->program.entropyBuffer[2 * i + 1];
        uint64_t bits0 = rx_get_small_positive_float_bits(ent0);
        uint64_t bits1 = rx_get_small_positive_float_bits(ent1);
        vm->reg.a[i][0] = *(double *)&bits0;
        vm->reg.a[i][1] = *(double *)&bits1;
    }
    uint32_t mem_ma = (uint32_t)(vm->program.entropyBuffer[8] & RX_CACHE_LINE_ALIGN_MASK);
    uint32_t mem_mx = (uint32_t)vm->program.entropyBuffer[10];
    vm->mem.mx_ma = ((uint64_t)mem_ma << 32) | mem_mx;
    uint64_t addrRegs = vm->program.entropyBuffer[12];
    vm->config.readReg0 = 0 + (int)(addrRegs & 1); addrRegs >>= 1;
    vm->config.readReg1 = 2 + (int)(addrRegs & 1); addrRegs >>= 1;
    vm->config.readReg2 = 4 + (int)(addrRegs & 1); addrRegs >>= 1;
    vm->config.readReg3 = 6 + (int)(addrRegs & 1);
    vm->datasetOffset = (uint32_t)(vm->program.entropyBuffer[13] % (RX_DATASET_EXTRA_ITEMS + 1)) * RX_CACHE_LINE_SIZE;
    vm->config.eMask[0] = rx_get_float_mask(vm->program.entropyBuffer[14]);
    vm->config.eMask[1] = rx_get_float_mask(vm->program.entropyBuffer[15]);
}

static __forceinline void pe_prepare_chain(pe_slot_t *s) {
    rx_fill_aes4rx4(s->vm->tempHash, sizeof(rx_program), &s->vm->program);
    pe_vm_init_cfg(s->vm);
    s->cf_count = pe_count_cfrounds(&s->vm->program);
}

static void pe_init_slot(pe_slot_t *s, uint32_t nonce) {
    memset(s->blob, 0, sizeof(s->blob));
    s->blob[0] = 0x10; s->blob[1] = 0x03; s->blob[2] = 0xe3;
    s->blob[3] = 0x42;
    s->nonce = nonce;
    memcpy(s->blob + 39, &nonce, 4);
    blake2b(s->vm->tempHash, sizeof(s->vm->tempHash), s->blob, sizeof(s->blob), NULL, 0);
    rx_fill_aes1rx4(s->vm->tempHash, RX_SCRATCHPAD_L3, s->vm->scratchpad);
    s->vm->mxcsrState = RX_MXCSR_DEFAULT;
    s->chain = 0;
    s->last_cpu = -1;
    pe_prepare_chain(s);
}

static __forceinline int pe_bucket(int cf) {
    return cf >= 2 ? 2 : cf;
}

static __forceinline pe_slot_t *pe_pop_best(pe_queue_t *q, int my_cpu) {
    /* Prefer same core, then same 4-core E-cluster, else LIFO (hottest in L3) */
    int best = q->count - 1;
    for (int i = q->count - 1; i >= 0; i--) {
        int lc = q->items[i]->last_cpu;
        if (lc == my_cpu) { best = i; break; }
        if (my_cpu >= 16 && lc >= 16 && (lc / 4) == (my_cpu / 4)) {
            best = i;
        }
    }
    pe_slot_t *res = q->items[best];
    q->items[best] = q->items[--q->count];
    return res;
}

static __forceinline pe_slot_t *pe_route_slot(pe_slot_t *cur, int is_pcore, int my_cpu, pe_stats_t *st) {
    int b = pe_bucket(cur->cf_count);
    if (!is_pcore) {
        /* E-core: keep cf==0 immediately without touching lock */
        if (b == 0) { st->keeps++; return cur; }
        pe_lock();
        int take_b = -1;
        if (g_pe_q[0].count > 0) take_b = 0;
        else if (b == 2 && g_pe_q[1].count > 0) take_b = 1;
        if (take_b >= 0) {
            pe_slot_t *next = pe_pop_best(&g_pe_q[take_b], my_cpu);
            g_pe_q[b].items[g_pe_q[b].count++] = cur;
            pe_unlock();
            st->swaps++;
            return next;
        }
        pe_unlock();
        st->keeps++;
        return cur;
    } else {
        /* P-core: keep cf>=2 immediately without touching lock */
        if (b == 2) { st->keeps++; return cur; }
        pe_lock();
        int take_b = -1;
        if (g_pe_q[2].count > 0) take_b = 2;
        else if (b == 0 && g_pe_q[1].count > 0) take_b = 1;
        if (take_b >= 0) {
            pe_slot_t *next = pe_pop_best(&g_pe_q[take_b], my_cpu);
            g_pe_q[b].items[g_pe_q[b].count++] = cur;
            pe_unlock();
            st->swaps++;
            return next;
        }
        pe_unlock();
        st->keeps++;
        return cur;
    }
}

static void pe_exec_one_chain(pe_slot_t *s, rx_jit *jit, uint32_t *cur_rm, int is_pcore, int my_cpu, pe_stats_t *st) {
    typedef void (RX_JIT_ABI *ProgramFunc)(rx_register_file *, rx_memory_regs *, uint8_t *, uint32_t);
    rx_vm *vm = s->vm;
    int b = pe_bucket(s->cf_count);
    st->chains_cf[b]++;

    rx_jit_generate_program(jit, &vm->program, &vm->config, vm->cachePtr);
    ProgramFunc func = (ProgramFunc)rx_jit_get_program_func(jit);

    uint32_t want_rm = (vm->mxcsrState >> 13) & 3;
    if (*cur_rm != want_rm) {
        _mm_setcsr(vm->mxcsrState);
        *cur_rm = want_rm;
    }

    rx_memory_regs memRegs;
    memRegs.mx_ma = vm->mem.mx_ma;
    memRegs.memory = vm->mem.memory + vm->datasetOffset;
    func(&vm->reg, &memRegs, vm->scratchpad, RX_PROGRAM_ITERATIONS);
    vm->mem.mx_ma = memRegs.mx_ma;

    if (s->cf_count > 0) {
        uint32_t after = _mm_getcsr();
        *cur_rm = (after >> 13) & 3;
        vm->mxcsrState = RX_MXCSR_DEFAULT | (after & 0x6000);
    }
    s->last_cpu = my_cpu;

    if (s->chain < RX_PROGRAM_COUNT - 1) {
        rx_blake2b_regfile(vm->tempHash, &vm->reg);
        s->chain++;
        pe_prepare_chain(s);
    } else {
        /* Completed a full 8-chain hash! */
        uint8_t prev_blob[76];
        int verifying = (int)BAR_LOAD(&g_pe_verify_active);
        if (verifying) memcpy(prev_blob, s->blob, 76);

        uint32_t next_nonce = (uint32_t)BAR_INC(&g_pe_nonce_gen);
        s->nonce = next_nonce;
        memcpy(s->blob + 39, &next_nonce, 4);

        uint8_t out_hash[32];
        rx_blake2b_blob(vm->tempHash, s->blob, sizeof(s->blob));
        rx_hash_and_fill_aes1rx4(vm->scratchpad, RX_SCRATCHPAD_L3, &vm->reg.a, vm->tempHash);
        blake2b(out_hash, RX_HASH_SIZE, &vm->reg, sizeof(rx_register_file), NULL, 0);

        if (verifying) {
            long vi = BAR_INC(&g_pe_verify_idx) - 1;
            if (vi >= 0 && vi < PE_VERIFY_COUNT) {
                memcpy(g_pe_verify_blobs[vi], prev_blob, 76);
                memcpy(g_pe_verify_hashes[vi], out_hash, 32);
            }
        }

        vm->mxcsrState = RX_MXCSR_DEFAULT;
        s->chain = 0;
        pe_prepare_chain(s);
        st->hashes++;
        BAR_INC(&g_pe_hashes_done);
        (void)is_pcore;
    }
}

/* ---- A/B experiment support ---- */
typedef struct { int lanes; char knobs[256]; } ab_config;
static ab_config g_ab[2];
static int g_ab_mode = 0;
static double *g_ab_time[2]; /* [round * threads + tid] */
static int g_ab_rounds = 0;

static int apply_knobs(const char *spec) {
    /* every config starts from the defaults so A and B differ only in spec */
    g_mjit_granularity = 256;
    g_mjit_mxcsr_skip = 0;
    g_mjit_rcp_pool = 1;
    g_mjit_prefetch_mode = 1;
    g_mjit_pinned_regs = 1;
    g_mjit_diag = 0;
    g_mjit_ds_prefetch = 0;
    g_mjit_fp_spill = 0;
    g_mjit_fp_bank2 = 1;
    g_mjit_stagger = 0;
    g_mjit_smart_cuts = 1;
    g_mjit_smart_mxcsr = 1;
    g_mjit_bmi2 = 1;
    g_mjit_refresh_dspf = 0;
    g_mjit_tail_order = 1;
    g_mjit_mxguard = 0;
    g_vm_warm_sp = 1;
    g_aes_use_vaes = 0;
    g_jit_cfround_guard = 0;
    g_jit_short_branches = 0;
    g_jit_involution_pairs = 0;
    g_jit_branch_align = 0;
    g_jit_loop_nop = 0;
    g_jit_sp_prefetch_hint = 0;
    g_jit_bmi2_mulx = 1;
    g_jit_cfround_elim = 0;
    g_jit_jcc_align = 0;
    g_jit_rorx = 0;
    g_jit_cfround_rorx = 0;
    g_jit_near_rcp_pool = 1;
    g_jit_inline_rcp_pool = 1;
    g_jit_stack_rcp_pool = 0;
    g_jit_iswap_mov = 1;
    g_jit_fast_iadd_rs = 0;
    g_jit_ds_prefetch_hint = 1;
    g_aes_hash_fill_upstream = 1;
    g_aes_hash_fill_prefetch = 0;
    char buf[256];
    snprintf(buf, sizeof(buf), "%s", spec);
    char *save = NULL;
    for (char *t = strtok_s(buf, ",", &save); t; t = strtok_s(NULL, ",", &save)) {
        char name[64]; int val;
        if (sscanf(t, "%63[^=]=%d", name, &val) != 2) continue;
        if (!strcmp(name, "gran")) g_mjit_granularity = val;
        else if (!strcmp(name, "mxskip")) g_mjit_mxcsr_skip = val;
        else if (!strcmp(name, "rcp_pool")) g_mjit_rcp_pool = val;
        else if (!strcmp(name, "prefetch")) g_mjit_prefetch_mode = val;
        else if (!strcmp(name, "pinned")) g_mjit_pinned_regs = val;
        else if (!strcmp(name, "diag")) g_mjit_diag = val;
        else if (!strcmp(name, "dspf")) g_mjit_ds_prefetch = val;
        else if (!strcmp(name, "spill")) g_mjit_fp_spill = val;
        else if (!strcmp(name, "bank2")) g_mjit_fp_bank2 = val;
        else if (!strcmp(name, "stagger")) g_mjit_stagger = val;
        else if (!strcmp(name, "scuts")) g_mjit_smart_cuts = val;
        else if (!strcmp(name, "smxcsr")) g_mjit_smart_mxcsr = val;
        else if (!strcmp(name, "bmi2")) g_mjit_bmi2 = val;
        else if (!strcmp(name, "rdspf")) g_mjit_refresh_dspf = val;
        else if (!strcmp(name, "torder")) g_mjit_tail_order = val;
        else if (!strcmp(name, "mxguard")) g_mjit_mxguard = val;
        else if (!strcmp(name, "warmsp")) g_vm_warm_sp = val;
        else if (!strcmp(name, "vaes")) g_aes_use_vaes = val;
        else if (!strcmp(name, "cfguard")) g_jit_cfround_guard = val;
        else if (!strcmp(name, "j_sbr")) g_jit_short_branches = val;
        else if (!strcmp(name, "j_invo")) g_jit_involution_pairs = val;
        else if (!strcmp(name, "j_balign")) g_jit_branch_align = val;
        else if (!strcmp(name, "j_lnop")) g_jit_loop_nop = val;
        else if (!strcmp(name, "j_sppf")) g_jit_sp_prefetch_hint = val;
        else if (!strcmp(name, "j_mulx")) g_jit_bmi2_mulx = val;
        else if (!strcmp(name, "j_cfelim")) g_jit_cfround_elim = val;
        else if (!strcmp(name, "j_jcc")) g_jit_jcc_align = val;
        else if (!strcmp(name, "j_rorx")) g_jit_rorx = val;
        else if (!strcmp(name, "j_cfrorx")) g_jit_cfround_rorx = val;
        else if (!strcmp(name, "j_nrcp")) g_jit_near_rcp_pool = val;
        else if (!strcmp(name, "j_ircp")) g_jit_inline_rcp_pool = val;
        else if (!strcmp(name, "j_srcp")) g_jit_stack_rcp_pool = val;
        else if (!strcmp(name, "j_iswap")) g_jit_iswap_mov = val;
        else if (!strcmp(name, "j_fadd")) g_jit_fast_iadd_rs = val;
        else if (!strcmp(name, "j_dspf")) g_jit_ds_prefetch_hint = val;
        else if (!strcmp(name, "aes_up")) g_aes_hash_fill_upstream = val;
        else if (!strcmp(name, "aes_pf")) g_aes_hash_fill_prefetch = val;
        else if (!strcmp(name, "lanes")) {}
        else { printf("unknown knob %s\n", name); return 0; }
    }
    return 1;
}

/* lanes=0 selects the original single-VM path (old JIT, hash_first/next) */
static int knob_lanes(const char *spec) {
    const char *p = strstr(spec, "lanes=");
    return p ? atoi(p + 6) : 1;
}

static int g_rapl_ok = 0;
static double g_run_e0[64], g_run_e1[64], g_run_dt[64];
static long g_run_hashes[64];
static double g_idle_watts = 0.0;

static void rapl_sample_start(int r) {
    if (r < 64) {
        g_run_dt[r] = now_sec();
        if (g_rapl_ok) msr_read_package_energy(&g_run_e0[r]);
    }
}

static void rapl_sample_end(int r, long total_hashes) {
    if (r < 64) {
        g_run_dt[r] = now_sec() - g_run_dt[r];
        g_run_hashes[r] = total_hashes;
        if (g_rapl_ok) msr_read_package_energy(&g_run_e1[r]);
    }
}

#ifdef _WIN32
static DWORD WINAPI worker_main(LPVOID p)
#else
static void *worker_main(void *p)
#endif
{
    worker_t *w = (worker_t *)p;
    if (g_pin && w->cpu >= 0) pin_self(w->cpu);
#ifdef _WIN32
    if (g_eco_qos == 1 || (g_eco_qos == 2 && w->cpu >= 0 && w->cpu < 16)) {
        apply_thread_eco_qos(1);
    }
#endif

    if (g_ab_mode) {
        rx_vm_group *grp[2];
        int K[2];
        uint8_t blobs[RX_MULTI_MAX_LANES][76];
        uint8_t outs_[RX_MULTI_MAX_LANES][32];
        const void *in[RX_MULTI_MAX_LANES];
        void *out[RX_MULTI_MAX_LANES];
        size_t sz[RX_MULTI_MAX_LANES];
        uint32_t gn = 0;
        for (int l = 0; l < RX_MULTI_MAX_LANES; l++) {
            memset(blobs[l], 0, 76);
            blobs[l][0] = 0x10; blobs[l][3] = (uint8_t)w->tid; blobs[l][4] = (uint8_t)l;
            in[l] = blobs[l]; out[l] = outs_[l]; sz[l] = 76;
        }
        rx_vm *single[2] = { NULL, NULL };   /* lanes=0: original single-VM path */
        for (int c = 0; c < 2; c++) {
            K[c] = g_ab[c].lanes;
            grp[c] = NULL;
            if (K[c] == 0) {
                int ab_flags = RX_FLAG_JIT | (w->cpu >= 16 ? RX_FLAG_CFROUND_GUARD : 0);
                single[c] = rx_create_vm(ab_flags, w->cache, w->dataset);
                if (!single[c]) { fprintf(stderr, "VM alloc failed\n"); exit(3); }
                rx_calculate_hash_first(single[c], in[0], sz[0]);
                continue;
            }
            grp[c] = rx_create_vm_group(K[c], RX_FLAG_DEFAULT, w->cache, w->dataset);
            if (!grp[c]) { fprintf(stderr, "group alloc failed\n"); exit(3); }
            rx_group_hash_first(grp[c], in, sz);
        }
        for (int r = 0; r < g_ab_rounds; r++) {
            for (int k = 0; k < 2; k++) {
                int c = (r & 1) ? 1 - k : k;   /* ABBA ordering */
                barrier_wait();
                if (w->tid == 0) apply_knobs(g_ab[c].knobs);
                barrier_wait();
                /* one warm-up hash per slice (JIT/knob change) */
                int step = K[c] ? K[c] : 1;
                gn++; for (int l = 0; l < step; l++) memcpy(blobs[l] + 39, &gn, 4);
                if (single[c]) rx_calculate_hash_next(single[c], in[0], sz[0], out[0]);
                else rx_group_hash_next(grp[c], in, sz, out);
                double t0 = now_sec();
                for (int i = 0; i < w->hashes; i += step) {
                    gn++;
                    for (int l = 0; l < step; l++) memcpy(blobs[l] + 39, &gn, 4);
                    if (single[c]) rx_calculate_hash_next(single[c], in[0], sz[0], out[0]);
                    else rx_group_hash_next(grp[c], in, sz, out);
                }
                double dt = now_sec() - t0;
                int done = ((w->hashes + step - 1) / step) * step;
                g_ab_time[c][r * g_barrier_total + w->tid] = dt / done;
            }
        }
        rx_destroy_vm_group(grp[0]);
        rx_destroy_vm_group(grp[1]);
        rx_destroy_vm(single[0]);
        rx_destroy_vm(single[1]);
#ifdef _WIN32
        return 0;
#else
        return NULL;
#endif
    }
    if (w->full_mode == 6) {
        int is_pcore = (w->cpu < 16) ? 1 : 0;
        rx_jit *jit = rx_jit_create();
        if (!jit) { fprintf(stderr, "JIT alloc failed\n"); exit(3); }
        if (!is_pcore) rx_jit_set_cfround_guard(jit, 1);

        pe_slot_t *cur = &g_pe_slots[w->tid];
        w->sp_kind = cur->vm->sp_page_kind;

        uint32_t saved_mxcsr = _mm_getcsr();
        _mm_setcsr(RX_MXCSR_DEFAULT);
        uint32_t cur_rm = 0;
        pe_stats_t *st = &g_pe_stats[w->tid];

        /* Multi-threaded bit-exact verification phase (if enabled) */
        barrier_wait();
        if (BAR_LOAD(&g_pe_verify_active)) {
            while (BAR_LOAD(&g_pe_verify_idx) < PE_VERIFY_COUNT) {
                cur = pe_route_slot(cur, is_pcore, w->cpu, st);
                pe_exec_one_chain(cur, jit, &cur_rm, is_pcore, w->cpu, st);
            }
            barrier_wait();
            if (w->tid == 0) g_pe_verify_active = 0;
            barrier_wait();
        }

        /* Warm-up 16 chains */
        for (int i = 0; i < 16; i++) {
            cur = pe_route_slot(cur, is_pcore, w->cpu, st);
            pe_exec_one_chain(cur, jit, &cur_rm, is_pcore, w->cpu, st);
        }

        for (int r = 0; r < w->repeats; r++) {
            barrier_wait();
            if (w->tid == 0) {
                g_pe_hashes_done = 0;
                memset(g_pe_stats, 0, sizeof(g_pe_stats));
                rapl_sample_start(r);
            }
            barrier_wait();
            double t0 = now_sec();
            while (BAR_LOAD(&g_pe_hashes_done) < g_pe_hashes_target) {
                cur = pe_route_slot(cur, is_pcore, w->cpu, st);
                pe_exec_one_chain(cur, jit, &cur_rm, is_pcore, w->cpu, st);
            }
            w->seconds[r] = now_sec() - t0;
            barrier_wait();
            if (w->tid == 0) {
                rapl_sample_end(r, BAR_LOAD(&g_pe_hashes_done));
            }
            barrier_wait();
        }

        _mm_setcsr(saved_mxcsr);
        rx_jit_destroy(jit);
#ifdef _WIN32
        return 0;
#else
        return NULL;
#endif
    }

    if (w->full_mode == 3 || ((w->full_mode == 4 || w->full_mode == 5) && w->lanes > 1)) {
        rx_vm_group *g = rx_create_vm_group(w->lanes, RX_FLAG_DEFAULT, w->cache, w->dataset);
        if (!g) { fprintf(stderr, "group alloc failed (lanes=%d)\n", w->lanes); exit(3); }
        w->sp_kind = rx_vm_group_vm(g, 0)->sp_page_kind;
        int K = w->lanes;
        uint8_t blobs[RX_MULTI_MAX_LANES][76];
        uint8_t outs_[RX_MULTI_MAX_LANES][32];
        const void *in[RX_MULTI_MAX_LANES];
        void *out[RX_MULTI_MAX_LANES];
        size_t sz[RX_MULTI_MAX_LANES];
        uint32_t gn = 0;
        for (int l = 0; l < K; l++) {
            memset(blobs[l], 0, 76);
            blobs[l][0] = 0x10; blobs[l][1] = 0x03; blobs[l][2] = 0xe3;
            blobs[l][3] = (uint8_t)w->tid; blobs[l][4] = (uint8_t)l;
            in[l] = blobs[l]; out[l] = outs_[l]; sz[l] = 76;
        }
        rx_group_hash_first(g, in, sz);
        for (int i = 0; i < 2; i++) {
            gn++;
            for (int l = 0; l < K; l++) memcpy(blobs[l] + 39, &gn, 4);
            rx_group_hash_next(g, in, sz, out);
        }
        for (int r = 0; r < w->repeats; r++) {
            barrier_wait();
            double t0 = now_sec();
            for (int i = 0; i < w->hashes; i += K) {
                gn++;
                for (int l = 0; l < K; l++) memcpy(blobs[l] + 39, &gn, 4);
                rx_group_hash_next(g, in, sz, out);
            }
            w->seconds[r] = now_sec() - t0;
            barrier_wait();
        }
        rx_destroy_vm_group(g);
#ifdef _WIN32
        return 0;
#else
        return NULL;
#endif
    }
    int vm_flags = RX_FLAG_JIT | (w->cfround_guard ? RX_FLAG_CFROUND_GUARD : 0);
    rx_vm *vm = rx_create_vm(vm_flags, w->cache, w->dataset);
    rx_vm *vm2 = w->full_mode == 2 ? rx_create_vm(vm_flags, w->cache, w->dataset) : NULL;
    if (!vm || (w->full_mode == 2 && !vm2)) { fprintf(stderr, "VM alloc failed\n"); exit(3); }
    w->sp_kind = vm->sp_page_kind;

    uint8_t blob[76];
    memset(blob, 0, sizeof(blob));
    blob[0] = 0x10; blob[1] = 0x03; blob[2] = 0xe3;
    for (int i = 3; i < 7; i++) blob[i] = (uint8_t)(w->tid * 17 + i);
    uint32_t nonce = 0;
    uint8_t hash[32];

    memcpy(blob + 39, &nonce, 4);
    rx_calculate_hash_first(vm, blob, sizeof(blob));
    for (int i = 0; i < 3; i++) { /* warm-up: JIT, TLB, caches */
        nonce++; memcpy(blob + 39, &nonce, 4);
        rx_calculate_hash_next(vm, blob, sizeof(blob), hash);
    }

    for (int r = 0; r < w->repeats; r++) {
        barrier_wait();
        double t0 = now_sec();
        if (w->full_mode == 2) {
            uint8_t blob2[76], hash2[32];
            memcpy(blob2, blob, sizeof(blob2));
            blob2[5] ^= 0x80;
            for (int i = 0; i < w->hashes; i += 2) {
                nonce++; memcpy(blob + 39, &nonce, 4); memcpy(blob2 + 39, &nonce, 4);
                rx_calculate_hash_dual(vm, vm2, blob, sizeof(blob), blob2, sizeof(blob2), hash, hash2);
            }
        } else if (w->full_mode == 1) {
            for (int i = 0; i < w->hashes; i++) {
                nonce++; memcpy(blob + 39, &nonce, 4);
                rx_calculate_hash(vm, blob, sizeof(blob), hash);
            }
        } else {
            for (int i = 0; i < w->hashes; i++) {
                nonce++; memcpy(blob + 39, &nonce, 4);
                rx_calculate_hash_next(vm, blob, sizeof(blob), hash);
            }
        }
        w->seconds[r] = now_sec() - t0;
        barrier_wait();
    }
    memcpy(w->last_hash, hash, 32);
    rx_destroy_vm(vm);
    rx_destroy_vm(vm2);
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

static int cmp_double(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return x < y ? -1 : x > y;
}

static int verify(rx_cache *cache, rx_dataset *dataset) {
    static const uint8_t expected[32] = {
        0x63, 0x91, 0x83, 0xaa, 0xe1, 0xbf, 0x4c, 0x9a,
        0x35, 0x88, 0x4c, 0xb4, 0x6b, 0x09, 0xca, 0xd9,
        0x17, 0x5f, 0x04, 0xef, 0xd7, 0x68, 0x4e, 0x72,
        0x62, 0xa0, 0xac, 0x1c, 0x2f, 0x0b, 0x4e, 0x3f
    };
    int ok = 1;
    rx_vm *jit = rx_create_vm(RX_FLAG_JIT, cache, dataset);
    rx_vm *interp = rx_create_vm(RX_FLAG_DEFAULT, cache, dataset);
    uint8_t h[32], ref[32];
    const char *in = "This is a test";
    rx_calculate_hash(jit, in, strlen(in), h);
    if (memcmp(h, expected, 32) != 0) { printf("  [FAIL] official vector (JIT)\n"); ok = 0; }
    else printf("  [PASS] official test vector (JIT, full dataset)\n");

    /* batch pipeline vs single-shot JIT vs interpreter */
    uint8_t blob[76];
    memset(blob, 0x5c, sizeof(blob));
    uint32_t n = 0;
    memcpy(blob + 39, &n, 4);
    rx_calculate_hash_first(jit, blob, sizeof(blob));
    int batch_ok = 1;
    for (n = 1; n <= 4; n++) {
        uint8_t prev[76];
        memcpy(prev, blob, 76);
        memcpy(blob + 39, &n, 4);
        rx_calculate_hash_next(jit, blob, sizeof(blob), h);
        rx_calculate_hash(interp, prev, sizeof(prev), ref);
        if (memcmp(h, ref, 32) != 0) batch_ok = 0;
    }
    printf("  [%s] batch pipeline == interpreter (4 nonces)\n", batch_ok ? "PASS" : "FAIL");
    ok &= batch_ok;
    rx_destroy_vm(jit);
    rx_destroy_vm(interp);
    return ok;
}

int main(int argc, char **argv) {
    int threads = num_cpus();
    int hashes = 200;
    int repeats = 5;
    int pages = 2;
    int full_mode = 0;
    int lanes = 1;
    int check = 1;
    int cpu_list[MAX_THREADS];
    int cpu_list_n = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-t") && i + 1 < argc) threads = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-n") && i + 1 < argc) hashes = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-r") && i + 1 < argc) repeats = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-p") && i + 1 < argc) pages = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--no-pin")) g_pin = 0;
        else if (!strcmp(argv[i], "--full")) full_mode = 1;
        else if (!strcmp(argv[i], "--dual")) full_mode = 2;
        else if (!strcmp(argv[i], "--lanes") && i + 1 < argc) { lanes = atoi(argv[++i]); full_mode = 3; }
        else if (!strcmp(argv[i], "--hetero") && i + 1 < argc) { lanes = atoi(argv[++i]); full_mode = 4; }
        else if (!strcmp(argv[i], "--waterfill") && i + 1 < argc) { lanes = atoi(argv[++i]); full_mode = 5; }
        else if (!strcmp(argv[i], "--pe-route") && i + 1 < argc) { g_pe_extra_vms = atoi(argv[++i]); full_mode = 6; }
        else if (!strcmp(argv[i], "--gran") && i + 1 < argc) g_mjit_granularity = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--eco") && i + 1 < argc) g_eco_qos = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--mxskip")) g_mjit_mxcsr_skip = 1;
        else if (!strcmp(argv[i], "--ab") && i + 2 < argc) {
            g_ab_mode = 1;
            snprintf(g_ab[0].knobs, sizeof(g_ab[0].knobs), "%s", argv[++i]);
            snprintf(g_ab[1].knobs, sizeof(g_ab[1].knobs), "%s", argv[++i]);
            g_ab[0].lanes = knob_lanes(g_ab[0].knobs);
            g_ab[1].lanes = knob_lanes(g_ab[1].knobs);
        }
        else if (!strcmp(argv[i], "--set") && i + 1 < argc) {
            /* --set name=value for experiment knobs */
            char name[64]; int val;
            if (sscanf(argv[++i], "%63[^=]=%d", name, &val) == 2) {
                if (!strcmp(name, "rcp_pool")) g_mjit_rcp_pool = val;
                else if (!strcmp(name, "prefetch")) g_mjit_prefetch_mode = val;
                else if (!strcmp(name, "vaes")) g_aes_use_vaes = val;
                else if (!strcmp(name, "aes_up")) g_aes_hash_fill_upstream = val;
                else if (!strcmp(name, "aes_pf")) g_aes_hash_fill_prefetch = val;
                else if (!strcmp(name, "warmsp")) g_vm_warm_sp = val;
                else if (!strcmp(name, "j_nrcp")) g_jit_near_rcp_pool = val;
                else if (!strcmp(name, "j_ircp")) g_jit_inline_rcp_pool = val;
                else if (!strcmp(name, "j_srcp")) g_jit_stack_rcp_pool = val;
                else if (!strcmp(name, "j_sppf")) g_jit_sp_prefetch_hint = val;
                else if (!strcmp(name, "j_iswap")) g_jit_iswap_mov = val;
                else if (!strcmp(name, "j_fadd")) g_jit_fast_iadd_rs = val;
                else if (!strcmp(name, "j_mulx")) g_jit_bmi2_mulx = val;
                else if (!strcmp(name, "j_dspf")) g_jit_ds_prefetch_hint = val;
                else { printf("unknown knob %s\n", name); return 2; }
            }
        }
        else if (!strcmp(argv[i], "--no-check")) check = 0;
        else if (!strcmp(argv[i], "-c") && i + 1 < argc) {
            char *s = argv[++i];
            while (*s && cpu_list_n < MAX_THREADS) {
                cpu_list[cpu_list_n++] = (int)strtol(s, &s, 10);
                if (*s == ',') s++;
            }
        } else {
            printf("usage: %s [-t threads] [-n hashes] [-r repeats] [-p 0|1|2] "
                   "[--no-pin] [--full] [--no-check] [-c cpu,list]\n", argv[0]);
            return 2;
        }
    }
    if (threads < 1) threads = 1;
    if (threads > MAX_THREADS) threads = MAX_THREADS;
    if (repeats < 1) repeats = 1;

    printf("bench_rx: threads=%d hashes/thread=%d repeats=%d pages=%d lanes=%d gran=%d mode=%s pin=%d\n",
           threads, hashes, repeats, pages, lanes, g_mjit_granularity,
           full_mode == 6 ? "pe-route" : full_mode == 5 ? "waterfill" : full_mode == 4 ? "hetero" :
           full_mode == 3 ? "group" : full_mode == 2 ? "dual" : full_mode ? "full" : "batch", g_pin);

    g_rapl_ok = (msr_init() == 0);
    if (g_rapl_ok) {
        double e0 = 0, e1 = 0;
        double ts = now_sec();
        msr_read_package_energy(&e0);
#ifdef _WIN32
        Sleep(500);
#else
        usleep(500000);
#endif
        msr_read_package_energy(&e1);
        double dt = now_sec() - ts;
        if (dt > 0.1 && e1 >= e0) g_idle_watts = (e1 - e0) / dt;
        printf("  power: RAPL/EMI active (pre-load baseline %.1f W)\n", g_idle_watts);
    }

    const char key[] = "test key 000";
    double t0 = now_sec();
    rx_cache *cache = rx_alloc_cache(pages > 0);
    rx_init_cache(cache, key, sizeof(key) - 1);
    rx_dataset *dataset = rx_alloc_dataset(pages);
    if (!cache || !dataset) { printf("allocation failed\n"); return 1; }
    rx_init_dataset_cached(dataset, cache, 0, RX_DATASET_ITEMS + RX_DATASET_EXTRA_ITEMS,
                           num_cpus(), num_cpus());
    printf("  init: %.1f s, dataset pages: %s\n", now_sec() - t0, vmem_kind_name(dataset->page_kind));

    if (check && !verify(cache, dataset)) {
        printf("CORRECTNESS FAILURE - aborting\n");
        return 1;
    }

    if (full_mode == 6) {
        if (g_pe_extra_vms < 0) g_pe_extra_vms = 0;
        if (threads + g_pe_extra_vms > PE_MAX_VMS) g_pe_extra_vms = PE_MAX_VMS - threads;
        int total_vms = threads + g_pe_extra_vms;
        memset(g_pe_q, 0, sizeof(g_pe_q));
        g_pe_lock = 0;
        g_pe_nonce_gen = total_vms;
        g_pe_hashes_target = (long)threads * (long)hashes;
        g_pe_verify_idx = 0;
        g_pe_verify_active = check ? 1 : 0;
        for (int i = 0; i < total_vms; i++) {
            g_pe_slots[i].vm = rx_create_vm(RX_FLAG_DEFAULT, cache, dataset);
            if (!g_pe_slots[i].vm) { printf("pe-route VM alloc failed (%d)\n", i); return 1; }
            pe_init_slot(&g_pe_slots[i], (uint32_t)(i + 1));
            if (i >= threads) {
                int b = pe_bucket(g_pe_slots[i].cf_count);
                g_pe_q[b].items[g_pe_q[b].count++] = &g_pe_slots[i];
            }
        }
        printf("  pe-route: total_vms=%d (threads=%d + extra=%d, %.0f MB scratchpads)\n",
               total_vms, threads, g_pe_extra_vms, total_vms * 2.0);
    }

    if (g_ab_mode) {
        g_ab_rounds = repeats;
        g_ab_time[0] = (double *)calloc((size_t)repeats * threads, sizeof(double));
        g_ab_time[1] = (double *)calloc((size_t)repeats * threads, sizeof(double));
        printf("  A/B: A=\"%s\" (lanes %d)  B=\"%s\" (lanes %d)  rounds=%d\n",
               g_ab[0].knobs, g_ab[0].lanes, g_ab[1].knobs, g_ab[1].lanes, repeats);
    }
    worker_t *w = (worker_t *)calloc(threads, sizeof(worker_t));
    g_barrier_total = threads;
    int ncpu = num_cpus();
    for (int i = 0; i < threads; i++) {
        w[i].tid = i;
        w[i].cpu = cpu_list_n ? cpu_list[i % cpu_list_n] : i % ncpu;
        w[i].hashes = hashes;
        w[i].repeats = repeats;
        w[i].full_mode = full_mode;
        if (full_mode == 5) {
            /* waterfill: first `lanes` P-cores get 2 lanes, remaining P-cores 1 lane, E-cores 1 lane + cfguard */
            w[i].lanes = (w[i].cpu < 16 && i < lanes) ? 2 : 1;
            w[i].cfround_guard = (w[i].cpu >= 16) ? 1 : 0;
        } else {
            w[i].lanes = (full_mode == 4) ? ((w[i].cpu < 16) ? lanes : 1) : lanes;
            w[i].cfround_guard = (full_mode == 4 && w[i].cpu >= 16) ? 1 : 0;
        }
        w[i].cache = cache;
        w[i].dataset = dataset;
        w[i].seconds = (double *)calloc(repeats, sizeof(double));
    }
#ifdef _WIN32
    HANDLE *th = (HANDLE *)calloc(threads, sizeof(HANDLE));
    for (int i = 0; i < threads; i++) th[i] = CreateThread(NULL, 0, worker_main, &w[i], 0, NULL);
    WaitForMultipleObjects(threads, th, TRUE, INFINITE);
#else
    pthread_t *th = (pthread_t *)calloc(threads, sizeof(pthread_t));
    for (int i = 0; i < threads; i++) pthread_create(&th[i], NULL, worker_main, &w[i]);
    for (int i = 0; i < threads; i++) pthread_join(th[i], NULL);
#endif

    if (g_ab_mode) {
        double *ratio = (double *)calloc(repeats, sizeof(double));
        double *ha = (double *)calloc(repeats, sizeof(double));
        double *hb = (double *)calloc(repeats, sizeof(double));
        for (int r = 0; r < repeats; r++) {
            double ra = 0, rb = 0;
            for (int t = 0; t < threads; t++) {
                ra += 1.0 / g_ab_time[0][r * threads + t];
                rb += 1.0 / g_ab_time[1][r * threads + t];
            }
            ha[r] = ra; hb[r] = rb; ratio[r] = rb / ra;
        }
        qsort(ratio, repeats, sizeof(double), cmp_double);
        qsort(ha, repeats, sizeof(double), cmp_double);
        qsort(hb, repeats, sizeof(double), cmp_double);
        int q1 = repeats / 4, q3 = (3 * repeats) / 4;
        if (q3 >= repeats) q3 = repeats - 1;
        printf("ABRESULT A=%.1f H/s B=%.1f H/s  B/A median=%+.2f%%  IQR=[%+.2f%%, %+.2f%%]\n",
               ha[repeats / 2], hb[repeats / 2], (ratio[repeats / 2] - 1) * 100,
               (ratio[q1] - 1) * 100, (ratio[q3] - 1) * 100);
        return 0;
    }
    if (full_mode == 6) {
        if (check) {
            rx_vm *interp = rx_create_vm(RX_FLAG_DEFAULT, cache, dataset);
            int pass = 0, fail = 0;
            uint8_t ref[32];
            for (int i = 0; i < PE_VERIFY_COUNT; i++) {
                rx_calculate_hash(interp, g_pe_verify_blobs[i], 76, ref);
                if (memcmp(ref, g_pe_verify_hashes[i], 32) == 0) pass++;
                else fail++;
            }
            rx_destroy_vm(interp);
            printf("  [%s] pe-route multi-thread vs interpreter (%d/%d)\n",
                   fail == 0 ? "PASS" : "FAIL", pass, PE_VERIFY_COUNT);
            if (fail > 0) { printf("PE-ROUTE CORRECTNESS FAILURE - aborting\n"); return 1; }
        }
        printf("  scratchpad pages: %s\n", vmem_kind_name(w[0].sp_kind));
        double *rates = (double *)calloc(repeats, sizeof(double));
        double *watts_arr = (double *)calloc(repeats, sizeof(double));
        double *hw_arr = (double *)calloc(repeats, sizeof(double));
        for (int r = 0; r < repeats; r++) {
            double total = (g_run_dt[r] > 0) ? ((double)g_run_hashes[r] / g_run_dt[r]) : 0.0;
            double watts = (g_rapl_ok && g_run_dt[r] > 0) ? ((g_run_e1[r] - g_run_e0[r]) / g_run_dt[r]) : 0.0;
            double hw = (watts > 0.1) ? (total / watts) : 0.0;
            double dw = watts - g_idle_watts;
            double hdw = (dw > 0.5) ? (total / dw) : 0.0;
            rates[r] = total;
            watts_arr[r] = watts;
            hw_arr[r] = hw;
            if (g_rapl_ok) {
                printf("  run %d: %9.1f H/s | %5.1f W | %6.2f H/W (dW=%4.1f W, %6.1f H/dW) [%ld H in %.2fs]\n",
                       r + 1, total, watts, hw, dw, hdw, g_run_hashes[r], g_run_dt[r]);
            } else {
                printf("  run %d: %9.1f H/s [%ld H in %.2fs]\n", r + 1, total, g_run_hashes[r], g_run_dt[r]);
            }
        }
        /* Print P/E chain CFROUND routing distribution from last repeat */
        uint64_t p_cf[3] = {0}, e_cf[3] = {0}, p_sw = 0, p_kp = 0, e_sw = 0, e_kp = 0;
        for (int i = 0; i < threads; i++) {
            int is_p = (w[i].cpu < 16);
            for (int b = 0; b < 3; b++) {
                if (is_p) p_cf[b] += g_pe_stats[i].chains_cf[b];
                else e_cf[b] += g_pe_stats[i].chains_cf[b];
            }
            if (is_p) { p_sw += g_pe_stats[i].swaps; p_kp += g_pe_stats[i].keeps; }
            else { e_sw += g_pe_stats[i].swaps; e_kp += g_pe_stats[i].keeps; }
        }
        uint64_t pt = p_cf[0] + p_cf[1] + p_cf[2];
        uint64_t et = e_cf[0] + e_cf[1] + e_cf[2];
        if (pt > 0) printf("  P-cores chains: %llu (cf=0: %.1f%%, cf=1: %.1f%%, cf>=2: %.1f%%) swaps=%.1f%%\n",
                           (unsigned long long)pt, 100.0*p_cf[0]/pt, 100.0*p_cf[1]/pt, 100.0*p_cf[2]/pt,
                           100.0*p_sw/(p_sw+p_kp+1));
        if (et > 0) printf("  E-cores chains: %llu (cf=0: %.1f%%, cf=1: %.1f%%, cf>=2: %.1f%%) swaps=%.1f%%\n",
                           (unsigned long long)et, 100.0*e_cf[0]/et, 100.0*e_cf[1]/et, 100.0*e_cf[2]/et,
                           100.0*e_sw/(e_sw+e_kp+1));

        qsort(rates, repeats, sizeof(double), cmp_double);
        qsort(watts_arr, repeats, sizeof(double), cmp_double);
        qsort(hw_arr, repeats, sizeof(double), cmp_double);
        double median = rates[repeats / 2];
        double best = rates[repeats - 1];
        double med_w = watts_arr[repeats / 2];
        double med_hw = hw_arr[repeats / 2];
        if (g_rapl_ok) {
            printf("RESULT threads=%d extra=%d median=%.1f H/s best=%.1f H/s med_W=%.1f W med_H/W=%.2f H/W\n",
                   threads, g_pe_extra_vms, median, best, med_w, med_hw);
        } else {
            printf("RESULT threads=%d extra=%d median=%.1f H/s best=%.1f H/s per_thread=%.1f H/s\n",
                   threads, g_pe_extra_vms, median, best, median / threads);
        }
        for (int i = 0; i < threads + g_pe_extra_vms; i++) rx_destroy_vm(g_pe_slots[i].vm);
        if (g_rapl_ok) msr_destroy();
        return 0;
    }
    printf("  scratchpad pages: %s\n", vmem_kind_name(w[0].sp_kind));
    double *rates = (double *)calloc(repeats, sizeof(double));
    for (int r = 0; r < repeats; r++) {
        double total = 0.0;
        for (int i = 0; i < threads; i++) total += hashes / w[i].seconds[r];
        rates[r] = total;
        printf("  run %d: %9.1f H/s\n", r + 1, total);
    }
    qsort(rates, repeats, sizeof(double), cmp_double);
    double median = rates[repeats / 2];
    double best = rates[repeats - 1];
    printf("RESULT threads=%d median=%.1f H/s best=%.1f H/s per_thread=%.1f H/s\n",
           threads, median, best, median / threads);
    if (g_rapl_ok) msr_destroy();
    return 0;
}
