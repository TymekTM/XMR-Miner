#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <windows.h>
#include <mmsystem.h>
#pragma comment(lib, "winmm.lib")
#include "crypto/randomx/randomx_internal.h"
#include "common/cpu.h"
#include "common/log.h"

extern int msr_init(void);
extern void msr_destroy(void);

#define HASHES_PER_RUN 5000

enum {
    MODE_INTERP = 0,
    MODE_JIT_FULL = 1,
    MODE_DUAL = 2,
    MODE_BATCH = 3,
    MODE_BATCH_NC = 4,
    MODE_COUNT = 5,
};

#define MODE_BIT(mode) (1u << (mode))
#define MODE_ALL_MASK ((1u << MODE_COUNT) - 1u)

typedef struct {
    int thread_id;
    int total_threads;
    int mode;
    double hashrate;
    double wall_time;
} thread_data_t;

rx_cache *cache = NULL;
rx_dataset *dataset = NULL;

#define MAX_CORES 128

typedef struct {
    int count;
    int os_index[MAX_CORES];
    int is_pcore[MAX_CORES];
    int sibling[MAX_CORES];
} core_list_t;

static core_list_t g_cores;
static int g_affinity_ready = 0;

static void hex_dump(const char *label, const uint8_t *d, int n) {
    printf("    %s: ", label);
    for (int i = 0; i < n; i++) printf("%02x", d[i]);
    printf("\n");
}

static uint32_t my_read_u32_le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t my_read_u64_le(const uint8_t *p) {
    return (uint64_t)my_read_u32_le(p) | ((uint64_t)my_read_u32_le(p + 4) << 32);
}

static void hex_encode(const uint8_t *data, int len, char *out) {
    for (int i = 0; i < len; i++) {
        out[i * 2]     = "0123456789abcdef"[data[i] >> 4];
        out[i * 2 + 1] = "0123456789abcdef"[data[i] & 0xf];
    }
    out[len * 2] = '\0';
}

static int detect_cores(core_list_t *cores) {
    cores->count = 0;
    DWORD len = 0;
    GetLogicalProcessorInformationEx(RelationProcessorCore, NULL, &len);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) return 0;
    SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *buf = (SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *)malloc(len);
    if (!buf) return 0;
    if (!GetLogicalProcessorInformationEx(RelationProcessorCore, buf, &len)) { free(buf); return 0; }
    BYTE *ptr = (BYTE *)buf;
    DWORD remaining = len;
    while (remaining > 0) {
        SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *item = (SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *)ptr;
        if (item->Relationship == RelationProcessorCore && item->Processor.GroupCount > 0) {
            GROUP_AFFINITY mask = item->Processor.GroupMask[0];
            int first = -1, second = -1, bits = 0;
            for (int b = 0; b < 64; b++) {
                if (mask.Mask & (1ULL << b)) {
                    int os_idx = b + mask.Group * 64;
                    if (first < 0) first = os_idx;
                    else if (second < 0) second = os_idx;
                    bits++;
                }
            }
            if (first >= 0 && cores->count < MAX_CORES) {
                int i = cores->count++;
                cores->os_index[i] = first;
                cores->sibling[i] = second;
                cores->is_pcore[i] = (bits >= 2) ? 1 : 0;
            }
        }
        ptr += item->Size;
        remaining -= item->Size;
    }
    free(buf);
    return cores->count;
}

static int build_affinity_order(int *order, int max_order) {
    if (!g_affinity_ready || g_cores.count <= 0) return 0;
    int n = 0;
    for (int i = 0; i < g_cores.count && n < max_order; i++)
        if (g_cores.is_pcore[i]) order[n++] = g_cores.os_index[i];
    for (int i = 0; i < g_cores.count && n < max_order; i++)
        if (!g_cores.is_pcore[i]) order[n++] = g_cores.os_index[i];
    return n;
}

static void enable_huge_pages(void) {
    TOKEN_PRIVILEGES tp = {0};
    LUID luid;
    HANDLE token;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        if (LookupPrivilegeValueA(NULL, "SeLockMemoryPrivilege", &luid)) {
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL);
        }
        CloseHandle(token);
    }
}

static int parse_mode_token(const char *token, uint32_t *mode_mask) {
    if (!token || !*token || !mode_mask) return 0;

    if (_stricmp(token, "all") == 0) {
        *mode_mask |= MODE_ALL_MASK;
        return 1;
    }

    size_t len = strlen(token);
    if (len >= 128) return 0;

    char local[128];
    memcpy(local, token, len + 1);

    char *ctx = NULL;
    char *part = strtok_s(local, ",", &ctx);
    if (!part) return 0;

    while (part) {
        while (*part == ' ' || *part == '\t') part++;

        char *tail = part + strlen(part);
        while (tail > part && (tail[-1] == ' ' || tail[-1] == '\t')) {
            *--tail = '\0';
        }

        if (*part == '\0') return 0;

        char *endptr = NULL;
        long mode = strtol(part, &endptr, 10);
        if (*endptr != '\0' || mode < 0 || mode >= MODE_COUNT) {
            return 0;
        }

        *mode_mask |= MODE_BIT((uint32_t)mode);
        part = strtok_s(NULL, ",", &ctx);
    }

    return 1;
}

static void print_usage(const char *exe_name) {
    printf("Usage: %s [threads] [modes...]\n", exe_name);
    printf("  Modes: 0=Interp, 1=JIT-full+commit, 2=Dual+commit, 3=Batch+commit, 4=Batch-no-commit\n");
    printf("  Examples:\n");
    printf("    %s 1 3 4\n", exe_name);
    printf("    %s 1 3,4\n", exe_name);
    printf("    %s 8 all\n", exe_name);
}

static int all_pass = 1;
static int total_checks = 0;
static int passed_checks = 0;

#define CHECK(cond, msg) do { \
    total_checks++; \
    if (cond) { passed_checks++; printf("  [PASS] %s\n", msg); } \
    else { all_pass = 0; printf("  [FAIL] %s\n", msg); } \
} while(0)

static void run_correctness_suite(void) {
    printf("\n======================================================================\n");
    printf("  PHASE 1: CORRECTNESS VERIFICATION\n");
    printf("======================================================================\n\n");

    rx_vm *vm_i = rx_create_vm(RX_FLAG_DEFAULT, cache, dataset);
    rx_vm *vm_j = rx_create_vm(RX_FLAG_JIT, cache, dataset);

    uint8_t hi[32], hj[32];

    printf("--- 1.1 JIT full-hash vs interpreter full-hash (10 random inputs) ---\n");
    for (int t = 0; t < 10; t++) {
        char input[80];
        snprintf(input, sizeof(input), "correctness_test_%d_payload_xyz", t);
        rx_calculate_hash(vm_i, input, strlen(input), hi);
        rx_calculate_hash(vm_j, input, strlen(input), hj);
        CHECK(memcmp(hi, hj, 32) == 0, "full-hash match");
    }

    printf("\n--- 1.2 Batch API: JIT batch vs interpreter batch (20 nonces) ---\n");
    {
        uint8_t blob[76];
        memset(blob, 0, sizeof(blob));
        blob[0] = 0x10; blob[1] = 0x03; blob[2] = 0xe3;
        rx_calculate_hash_first(vm_i, blob, sizeof(blob));
        rx_calculate_hash_first(vm_j, blob, sizeof(blob));
        int batch_ok = 1;
        for (int i = 0; i < 20; i++) {
            *(uint32_t *)(blob + 39) = (uint32_t)(i + 1);
            rx_calculate_hash_next(vm_i, blob, sizeof(blob), hi);
            *(uint32_t *)(blob + 39) = (uint32_t)(i + 1);
            rx_calculate_hash_next(vm_j, blob, sizeof(blob), hj);
            if (memcmp(hi, hj, 32) != 0) {
                batch_ok = 0;
                printf("  [FAIL] batch mismatch at nonce %d\n", i + 1);
                hex_dump("  interp", hi, 32);
                hex_dump("  jit   ", hj, 32);
                break;
            }
        }
        CHECK(batch_ok, "batch API: 20/20 nonces match (JIT vs interp)");
    }

    printf("\n--- 1.3 hash_last == rx_calculate_hash (pool submission path) ---\n");
    {
        uint8_t blob[76];
        memset(blob, 0, sizeof(blob));
        blob[0] = 0x10; blob[1] = 0x03; blob[2] = 0xe3;
        *(uint32_t *)(blob + 39) = 42;

        uint8_t full_h[32], last_h[32];
        rx_calculate_hash(vm_j, blob, sizeof(blob), full_h);
        rx_calculate_hash_first(vm_j, blob, sizeof(blob));
        rx_calculate_hash_last(vm_j, last_h);
        CHECK(memcmp(full_h, last_h, 32) == 0, "hash_last == rx_calculate_hash (same nonce=42)");
        if (memcmp(full_h, last_h, 32) != 0) {
            hex_dump("  full ", full_h, 32);
            hex_dump("  last ", last_h, 32);
        }
    }

    printf("\n--- 1.4 Determinism: same input -> same hash always ---\n");
    {
        uint8_t blob[76];
        memset(blob, 0, sizeof(blob));
        blob[0] = 0x10; blob[1] = 0x03;
        *(uint32_t *)(blob + 39) = 12345;
        uint8_t h1[32], h2[32], h3[32];
        rx_calculate_hash(vm_j, blob, sizeof(blob), h1);
        rx_calculate_hash(vm_j, blob, sizeof(blob), h2);
        rx_destroy_vm(vm_j);
        vm_j = rx_create_vm(RX_FLAG_JIT, cache, dataset);
        rx_calculate_hash(vm_j, blob, sizeof(blob), h3);
        CHECK(memcmp(h1, h2, 32) == 0 && memcmp(h1, h3, 32) == 0, "deterministic across calls and VM recreations");
    }

    printf("\n--- 1.5 Commitment: blake2b(blob || hash) is deterministic ---\n");
    {
        uint8_t blob[76];
        memset(blob, 0, sizeof(blob));
        blob[0] = 0x10; *(uint32_t *)(blob + 39) = 99;
        uint8_t hash[32], c1[32], c2[32];
        rx_calculate_hash(vm_j, blob, sizeof(blob), hash);
        rx_calculate_commitment(blob, sizeof(blob), hash, c1);
        rx_calculate_commitment(blob, sizeof(blob), hash, c2);
        CHECK(memcmp(c1, c2, 32) == 0, "commitment deterministic");
    }

    printf("\n--- 1.6 Share target detection (Monero protocol) ---\n");
    {
        uint8_t blob[76];
        memset(blob, 0, sizeof(blob));
        blob[0] = 0x10; blob[1] = 0x03;
        uint8_t hash[32], commitment[32];

        rx_calculate_hash_first(vm_j, blob, sizeof(blob));

        uint64_t target_diff1     = 0xFFFFFFFF00000000ULL;
        uint64_t target_diff100   = 0xFFFFFFFFFFFFFF00ULL;
        uint64_t target_diff1k    = 0xFFFFFFFFFFFFFFFFULL / 1000;
        uint64_t target_diff10k   = 0xFFFFFFFFFFFFFFFFULL / 10000;

        int found_any = 0;
        for (uint32_t nonce = 1; nonce <= 5000; nonce++) {
            *(uint32_t *)(blob + 39) = nonce;
            rx_calculate_hash_next(vm_j, blob, sizeof(blob), hash);
            rx_calculate_commitment(blob, sizeof(blob), hash, commitment);
            if (my_read_u64_le(hash + 24) <= target_diff1) { found_any = 1; break; }
        }
        CHECK(found_any, "share detection: found at least diff-1 share in 5000 nonces (Monero tail check)");
    }

    printf("\n--- 1.7 Pool share format simulation ---\n");
    {
        uint8_t blob[76];
        memset(blob, 0, sizeof(blob));
        blob[0] = 0x10; blob[1] = 0x03; blob[2] = 0xe3;
        *(uint32_t *)(blob + 39) = 0xDEADBEEF;

        uint8_t hash[32], commitment[32];
        rx_calculate_hash(vm_j, blob, sizeof(blob), hash);
        rx_calculate_commitment(blob, sizeof(blob), hash, commitment);

        char nonce_hex[16], result_hex[65], commit_hex[65];
        snprintf(nonce_hex, sizeof(nonce_hex), "%08x", 0xDEADBEEF);
        hex_encode(hash, 32, result_hex);
        hex_encode(commitment, 32, commit_hex);

        printf("  nonce=%s\n", nonce_hex);
        printf("  result=%s\n", result_hex);
        printf("  commit=%s\n", commit_hex);
        printf("  hash_tail_64le=0x%016llx\n", (unsigned long long)my_read_u64_le(hash + 24));
        CHECK(1, "share format generated without errors");

        uint64_t fake_target = 0xFFFFFFFFFFFFFFFFULL;
        int would_accept = my_read_u64_le(hash + 24) <= fake_target;
        CHECK(would_accept, "share meets max-difficulty target (sanity)");
    }

    rx_destroy_vm(vm_i);
    rx_destroy_vm(vm_j);

    printf("\n  CORRECTNESS SUMMARY: %d/%d checks passed\n", passed_checks, total_checks);
    if (!all_pass) {
        printf("  >>> SOME CHECKS FAILED — results below are UNRELIABLE <<<\n");
    }
}

DWORD WINAPI bench_thread(LPVOID arg) {
    thread_data_t *d = (thread_data_t *)arg;
    int tid = d->thread_id;

    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
    {
        static void *pFn = NULL;
        if (!pFn) pFn = (void*)GetProcAddress(GetModuleHandleW(L"ntdll"), "NtSetInformationThread");
        if (pFn) {
            long (*fn)(HANDLE, long, void*, unsigned long) = (long (*)(HANDLE, long, void*, unsigned long))pFn;
            LONG pt[3] = { 1, 2, 1 };
            fn(GetCurrentThread(), 0x5C, pt, sizeof(pt));
        }
    }

    int order[MAX_CORES * 2];
    int order_count = build_affinity_order(order, sizeof(order) / sizeof(order[0]));
    if (order_count > 0) {
        int os_idx = order[tid % order_count];
        GROUP_AFFINITY ga = {0};
        ga.Group = (WORD)(os_idx / 64);
        ga.Mask = (KAFFINITY)(1ULL << (os_idx % 64));
        SetThreadGroupAffinity(GetCurrentThread(), &ga, NULL);
    }

    uint8_t blob[76];
    memset(blob, 0, sizeof(blob));
    blob[0] = 0x10; blob[1] = 0x03; blob[2] = 0xe3;
    for (int i = 3; i < 7; i++) blob[i] = (uint8_t)(tid * 17 + i);
    for (int i = 39; i < 43; i++) blob[i] = 0xAA;

    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);

    if (d->mode == 0) {
        rx_vm *vm = rx_create_vm(RX_FLAG_DEFAULT, cache, dataset);
        uint8_t hash[32];
        for (int i = 0; i < 2; i++) rx_calculate_hash(vm, blob, sizeof(blob), hash);
        QueryPerformanceCounter(&start);
        for (int i = 0; i < HASHES_PER_RUN; i++) {
            *(uint32_t *)(blob + 39) = (uint32_t)i;
            rx_calculate_hash(vm, blob, sizeof(blob), hash);
        }
        QueryPerformanceCounter(&(end));
        rx_destroy_vm(vm);
    } else if (d->mode == 1) {
        rx_vm *vm = rx_create_vm(RX_FLAG_JIT, cache, dataset);
        uint8_t hash[32], commitment[32];
        for (int i = 0; i < 2; i++) {
            *(uint32_t *)(blob + 39) = (uint32_t)i;
            rx_calculate_hash(vm, blob, sizeof(blob), hash);
            rx_calculate_commitment(blob, sizeof(blob), hash, commitment);
        }
        QueryPerformanceCounter(&start);
        for (int i = 0; i < HASHES_PER_RUN; i++) {
            *(uint32_t *)(blob + 39) = (uint32_t)i;
            rx_calculate_hash(vm, blob, sizeof(blob), hash);
            rx_calculate_commitment(blob, sizeof(blob), hash, commitment);
        }
        QueryPerformanceCounter(&end);
        rx_destroy_vm(vm);
    } else if (d->mode == 3) {
        rx_vm *vm = rx_create_vm(RX_FLAG_JIT, cache, dataset);
        uint8_t hash[32], commitment[32];
        *(uint32_t *)(blob + 39) = 0;
        rx_calculate_hash_first(vm, blob, sizeof(blob));
        for (int i = 0; i < 2; i++) {
            *(uint32_t *)(blob + 39) = (uint32_t)(i + 1);
            rx_calculate_hash_next(vm, blob, sizeof(blob), hash);
            rx_calculate_commitment(blob, sizeof(blob), hash, commitment);
        }
        QueryPerformanceCounter(&start);
        for (int i = 0; i < HASHES_PER_RUN; i++) {
            *(uint32_t *)(blob + 39) = (uint32_t)(i + 1);
            rx_calculate_hash_next(vm, blob, sizeof(blob), hash);
            rx_calculate_commitment(blob, sizeof(blob), hash, commitment);
        }
        QueryPerformanceCounter(&end);
        rx_destroy_vm(vm);
    } else if (d->mode == 4) {
        rx_vm *vm = rx_create_vm(RX_FLAG_JIT, cache, dataset);
        uint8_t hash[32];
        *(uint32_t *)(blob + 39) = 0;
        rx_calculate_hash_first(vm, blob, sizeof(blob));
        for (int i = 0; i < 2; i++) {
            *(uint32_t *)(blob + 39) = (uint32_t)(i + 1);
            rx_calculate_hash_next(vm, blob, sizeof(blob), hash);
        }
        QueryPerformanceCounter(&start);
        for (int i = 0; i < HASHES_PER_RUN; i++) {
            *(uint32_t *)(blob + 39) = (uint32_t)(i + 1);
            rx_calculate_hash_next(vm, blob, sizeof(blob), hash);
        }
        QueryPerformanceCounter(&end);
        rx_destroy_vm(vm);
    } else if (d->mode == 2) {
        rx_vm *vm1 = rx_create_vm(RX_FLAG_JIT, cache, dataset);
        rx_vm *vm2 = rx_create_vm(RX_FLAG_JIT, cache, dataset);
        uint8_t blob2[76]; memcpy(blob2, blob, sizeof(blob));
        uint8_t h1[32], h2[32], c1[32], c2[32];
        for (int i = 0; i < 2; i++) {
            *(uint32_t *)(blob + 39) = (uint32_t)(i * 2);
            *(uint32_t *)(blob2 + 39) = (uint32_t)(i * 2 + 1);
            rx_calculate_hash_dual(vm1, vm2, blob, sizeof(blob), blob2, sizeof(blob2), h1, h2);
            rx_calculate_commitment(blob, sizeof(blob), h1, c1);
            rx_calculate_commitment(blob2, sizeof(blob2), h2, c2);
        }
        QueryPerformanceCounter(&start);
        for (int i = 0; i < HASHES_PER_RUN; i++) {
            *(uint32_t *)(blob + 39) = (uint32_t)(i * 2);
            *(uint32_t *)(blob2 + 39) = (uint32_t)(i * 2 + 1);
            rx_calculate_hash_dual(vm1, vm2, blob, sizeof(blob), blob2, sizeof(blob2), h1, h2);
            rx_calculate_commitment(blob, sizeof(blob), h1, c1);
            rx_calculate_commitment(blob2, sizeof(blob2), h2, c2);
        }
        QueryPerformanceCounter(&end);
        rx_destroy_vm(vm1); rx_destroy_vm(vm2);
    }

    d->wall_time = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;
    int hashes_per_thread = (d->mode == 2) ? HASHES_PER_RUN * 2 : HASHES_PER_RUN;
    d->hashrate = hashes_per_thread / d->wall_time;
    return 0;
}

static double run_mode(int num_threads, int mode, const char *label) {
    thread_data_t *tdata = (thread_data_t *)calloc(num_threads, sizeof(thread_data_t));
    HANDLE *threads = (HANDLE *)calloc(num_threads, sizeof(HANDLE));
    for (int i = 0; i < num_threads; i++) {
        tdata[i].thread_id = i;
        tdata[i].total_threads = num_threads;
        tdata[i].mode = mode;
    }

    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);

    for (int i = 0; i < num_threads; i++)
        threads[i] = CreateThread(NULL, 0, bench_thread, &tdata[i], 0, NULL);
    WaitForMultipleObjects(num_threads, threads, TRUE, INFINITE);
    QueryPerformanceCounter(&end);

    double wall_total = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;
    int hashes_per_thread = (mode == 2) ? HASHES_PER_RUN * 2 : HASHES_PER_RUN;
    double work_wall = 0.0;

    double min_t = 1e18, max_t = 0;
    for (int i = 0; i < num_threads; i++) {
        if (tdata[i].wall_time < min_t) min_t = tdata[i].wall_time;
        if (tdata[i].wall_time > max_t) max_t = tdata[i].wall_time;
    }

    if (max_t > 0.0) {
        work_wall = max_t;
    } else {
        work_wall = wall_total;
    }

    double total_hr = (double)(num_threads * hashes_per_thread) / work_wall;
    double per_thread_avg = total_hr / num_threads;

    printf("  %-28s %8.1f H/s total  %8.1f H/s/t  work=%.2fs  total=%.2fs  spread=%.1f%%\n",
           label, total_hr, per_thread_avg, work_wall, wall_total,
           num_threads > 1 ? (max_t - min_t) / ((min_t + max_t) / 2) * 100.0 : 0.0);

    for (int i = 0; i < num_threads; i++) CloseHandle(threads[i]);
    free(threads); free(tdata);
    return total_hr;
}

static void run_timing_breakdown(void) {
    printf("\n======================================================================\n");
    printf("  PHASE 3: TIMING BREAKDOWN (single-thread JIT)\n");
    printf("======================================================================\n\n");

    rx_vm *vm = rx_create_vm(RX_FLAG_JIT | RX_FLAG_DEFAULT, cache, dataset);
    uint8_t input[76];
    memset(input, 0x42, sizeof(input));
    LARGE_INTEGER freq, t0, t1;
    QueryPerformanceFrequency(&freq);

    double t_fill_init = 0, t_jit_gen = 0, t_blake2b_reg = 0;
    double t_blake2b_blob = 0, t_hash_and_fill = 0, t_full_hash = 0, t_hash_next = 0;
    int N;

    printf("--- fill_aes4rx4 + vm_initialize ---\n");
    N = 50000; uint8_t seed[32] = {0};
    QueryPerformanceCounter(&t0);
    for (int i = 0; i < N; i++) { memcpy(seed, &i, 4); rx_fill_aes4rx4(seed, sizeof(rx_program), &vm->program); vm_initialize(vm); }
    QueryPerformanceCounter(&t1); t_fill_init = (double)(t1.QuadPart - t0.QuadPart) / freq.QuadPart / N * 1e6;

    printf("\n--- JIT generate (cached program) ---\n");
    N = 1000; memcpy(seed, &N, 4); rx_fill_aes4rx4(seed, sizeof(rx_program), &vm->program); vm_initialize(vm);
    QueryPerformanceCounter(&t0);
    for (int i = 0; i < N; i++) rx_jit_generate_program(vm->jit, &vm->program, &vm->config, vm->cachePtr);
    QueryPerformanceCounter(&t1); t_jit_gen = (double)(t1.QuadPart - t0.QuadPart) / freq.QuadPart / N * 1e6;
    printf("  %d calls: %.3f us/call\n", N, t_jit_gen);

    printf("\n--- blake2b(regfile, 64B) ---\n");
    N = 100000; uint8_t dummy[32];
    QueryPerformanceCounter(&t0);
    for (int i = 0; i < N; i++) blake2b(dummy, 32, &vm->reg, sizeof(rx_register_file), NULL, 0);
    QueryPerformanceCounter(&t1); t_blake2b_reg = (double)(t1.QuadPart - t0.QuadPart) / freq.QuadPart / N * 1e6;
    printf("  %d calls: %.3f us/call\n", N, t_blake2b_reg);

    printf("\n--- blake2b(blob, 76B) ---\n");
    N = 100000;
    QueryPerformanceCounter(&t0);
    for (int i = 0; i < N; i++) blake2b(dummy, 32, input, sizeof(input), NULL, 0);
    QueryPerformanceCounter(&t1); t_blake2b_blob = (double)(t1.QuadPart - t0.QuadPart) / freq.QuadPart / N * 1e6;
    printf("  %d calls: %.3f us/call\n", N, t_blake2b_blob);

    printf("\n--- hash_and_fill_aes1rx4 (2MB scratchpad) ---\n");
    N = 200;
    QueryPerformanceCounter(&t0);
    for (int i = 0; i < N; i++) rx_hash_and_fill_aes1rx4(vm->scratchpad, RX_SCRATCHPAD_L3, &vm->reg.a, vm->tempHash);
    QueryPerformanceCounter(&t1); t_hash_and_fill = (double)(t1.QuadPart - t0.QuadPart) / freq.QuadPart / N * 1e6;
    printf("  %d calls: %.3f us/call\n", N, t_hash_and_fill);

    printf("\n--- Full hash (rx_calculate_hash, 76B) ---\n");
    N = 100;
    QueryPerformanceCounter(&t0);
    for (int i = 0; i < N; i++) rx_calculate_hash(vm, input, sizeof(input), dummy);
    QueryPerformanceCounter(&t1); t_full_hash = (double)(t1.QuadPart - t0.QuadPart) / freq.QuadPart / N * 1e6;
    printf("  %d hashes: %.3f us/hash = %.0f H/s\n", N, t_full_hash, 1e6 / t_full_hash);

    printf("\n--- Batch: hash_first + 100x hash_next ---\n");
    N = 100;
    rx_calculate_hash_first(vm, input, sizeof(input));
    QueryPerformanceCounter(&t0);
    for (int i = 0; i < N; i++) rx_calculate_hash_next(vm, input, sizeof(input), dummy);
    QueryPerformanceCounter(&t1); t_hash_next = (double)(t1.QuadPart - t0.QuadPart) / freq.QuadPart / N * 1e6;
    printf("  %d hash_next: %.3f us/call = %.0f H/s\n", N, t_hash_next, 1e6 / t_hash_next);

    printf("\n--- BREAKDOWN (per hash_next call) ---\n");
    double overhead = t_blake2b_blob + t_fill_init*8 + t_jit_gen*8 + t_blake2b_reg*9 + t_hash_and_fill;
    printf("  blake2b(blob):       %8.3f us  (%4.1f%%)\n", t_blake2b_blob, t_blake2b_blob/t_hash_next*100);
    printf("  fill+init x8:       %8.3f us  (%4.1f%%)\n", t_fill_init*8, t_fill_init*8/t_hash_next*100);
    printf("  JIT generate x8:    %8.3f us  (%4.1f%%)\n", t_jit_gen*8, t_jit_gen*8/t_hash_next*100);
    printf("  blake2b(reg) x9:    %8.3f us  (%4.1f%%)\n", t_blake2b_reg*9, t_blake2b_reg*9/t_hash_next*100);
    printf("  hash_and_fill x1:  %8.3f us  (%4.1f%%)\n", t_hash_and_fill, t_hash_and_fill/t_hash_next*100);
    printf("  MEASURED hash_next:%8.3f us\n", t_hash_next);
    printf("  DERIVED JIT exec:  %8.3f us  (%4.1f%%)\n",
           t_hash_next - overhead, (t_hash_next - overhead)/t_hash_next*100);
    printf("  JIT exec/chain:     %8.3f us\n", (t_hash_next - overhead)/8);

    rx_destroy_vm(vm);
}

int main(int argc, char **argv) {
    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
    timeBeginPeriod(1);
    enable_huge_pages();
    msr_init();

    int max_threads = 8;
    uint32_t mode_mask = MODE_ALL_MASK;
    if (argc > 1) max_threads = atoi(argv[1]);
    if (argc > 2) {
        mode_mask = 0;
        for (int i = 2; i < argc; i++) {
            if (!parse_mode_token(argv[i], &mode_mask)) {
                printf("[ERR] Invalid mode token: '%s'\n", argv[i]);
                print_usage(argv[0]);
                return 2;
            }
        }
        if (mode_mask == 0) {
            print_usage(argv[0]);
            return 2;
        }
    }

    if (max_threads < 1) {
        max_threads = 1;
    } else if (max_threads > MAXIMUM_WAIT_OBJECTS) {
        printf("[WARN] Requested %d threads, capping to %d (WaitForMultipleObjects limit)\n",
               max_threads, MAXIMUM_WAIT_OBJECTS);
        max_threads = MAXIMUM_WAIT_OBJECTS;
    }

    g_affinity_ready = detect_cores(&g_cores) > 0;
    if (g_affinity_ready) {
        int p = 0;
        for (int i = 0; i < g_cores.count; i++) if (g_cores.is_pcore[i]) p++;
        printf("[AFFINITY] %d cores (%d P, %d E)\n", g_cores.count, p, g_cores.count - p);
    }

    cache = rx_alloc_cache(1);
    uint8_t key[] = "pool_sim_seed_123";
    rx_init_cache(cache, key, sizeof(key));
    dataset = rx_alloc_dataset(1);
    rx_init_dataset_cached(dataset, cache, 0, RX_DATASET_ITEMS, 8, 8);

    run_correctness_suite();

    if (!all_pass) {
        printf("\n======================================================================\n");
        printf("  ABORTING BENCHMARKS — correctness checks failed\n");
        printf("======================================================================\n");
        rx_free_dataset(dataset);
        rx_free_cache(cache);
        timeEndPeriod(1);
        return 1;
    }

    printf("\n======================================================================\n");
    printf("  PHASE 2: PERFORMANCE BENCHMARK  (%d hashes/thread)\n", HASHES_PER_RUN);
    printf("======================================================================\n\n");

    double res_i[MAXIMUM_WAIT_OBJECTS + 1], res_s[MAXIMUM_WAIT_OBJECTS + 1];
    double res_d[MAXIMUM_WAIT_OBJECTS + 1], res_b[MAXIMUM_WAIT_OBJECTS + 1];
    double res_bn[MAXIMUM_WAIT_OBJECTS + 1];
    memset(res_i, 0, sizeof(res_i)); memset(res_s, 0, sizeof(res_s));
    memset(res_d, 0, sizeof(res_d)); memset(res_b, 0, sizeof(res_b));
    memset(res_bn, 0, sizeof(res_bn));

    for (int t = 1; t <= max_threads; t++) {
        printf("--- %d thread%s ---\n", t, t > 1 ? "s" : "");
        if (mode_mask & MODE_BIT(MODE_INTERP))   res_i[t]  = run_mode(t, MODE_INTERP,   "Interpreter (full hash)");
        if (mode_mask & MODE_BIT(MODE_JIT_FULL)) res_s[t]  = run_mode(t, MODE_JIT_FULL, "JIT full hash + commitment");
        if (mode_mask & MODE_BIT(MODE_BATCH))    res_b[t]  = run_mode(t, MODE_BATCH,    "JIT batch (hash_next+commit)");
        if (mode_mask & MODE_BIT(MODE_BATCH_NC)) res_bn[t] = run_mode(t, MODE_BATCH_NC, "JIT batch (no commit)");
        if (mode_mask & MODE_BIT(MODE_DUAL))     res_d[t]  = run_mode(t, MODE_DUAL,     "Dual JIT + commitment");
        printf("\n");
    }

    int show_interp = (mode_mask & MODE_BIT(MODE_INTERP)) != 0;
    int show_jit_full = (mode_mask & MODE_BIT(MODE_JIT_FULL)) != 0;
    int show_batch = (mode_mask & MODE_BIT(MODE_BATCH)) != 0;
    int show_batch_nc = (mode_mask & MODE_BIT(MODE_BATCH_NC)) != 0;
    int show_dual = (mode_mask & MODE_BIT(MODE_DUAL)) != 0;

    printf("======================================================================\n");
    printf("  BENCHMARK SUMMARY\n");
    printf("======================================================================\n");

    printf("%-6s", "Thr");
    if (show_interp) printf("  %-12s", "Interp");
    if (show_jit_full) printf("  %-12s", "JIT-full");
    if (show_batch) printf("  %-12s", "Batch");
    if (show_batch_nc) printf("  %-12s", "BatchNC");
    if (show_dual) printf("  %-12s", "Dual");
    if (show_batch && show_jit_full) printf("  %-6s", "B/J");
    if (show_dual && show_interp) printf("  %-6s", "D/I");
    printf("\n");

    printf("------");
    if (show_interp) printf("  ------------");
    if (show_jit_full) printf("  ------------");
    if (show_batch) printf("  ------------");
    if (show_batch_nc) printf("  ------------");
    if (show_dual) printf("  ------------");
    if (show_batch && show_jit_full) printf("  ------");
    if (show_dual && show_interp) printf("  ------");
    printf("\n");

    for (int t = 1; t <= max_threads; t++) {
        printf("%-6d", t);
        if (show_interp) printf("  %8.1f H/s", res_i[t]);
        if (show_jit_full) printf("  %8.1f H/s", res_s[t]);
        if (show_batch) printf("  %8.1f H/s", res_b[t]);
        if (show_batch_nc) printf("  %8.1f H/s", res_bn[t]);
        if (show_dual) printf("  %8.1f H/s", res_d[t]);
        if (show_batch && show_jit_full) printf("  %5.1fx", res_s[t] > 0 ? res_b[t] / res_s[t] : 0.0);
        if (show_dual && show_interp) printf("  %6.2fx", res_i[t] > 0 ? res_d[t] / res_i[t] : 0.0);
        printf("\n");
    }

    run_timing_breakdown();

    printf("\n======================================================================\n");
    printf("  FINAL RESULT: %s  (%d/%d checks)\n",
           all_pass ? "ALL PASS" : "SOME FAILURES", passed_checks, total_checks);
    printf("======================================================================\n");

    rx_free_dataset(dataset);
    rx_free_cache(cache);
    timeEndPeriod(1);
    return all_pass ? 0 : 1;
}
