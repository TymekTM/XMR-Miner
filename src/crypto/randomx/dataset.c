#include "randomx_internal.h"
#include "crypto/blake2/blake2_generator.h"
#include "crypto/argon2/argon2.h"
#include "common/log.h"
#include <string.h>
#include <stdlib.h>

static const uint64_t ssMul0 = 6364136223846793005ULL;
static const uint64_t ssAdd1 = 9298411001130361340ULL;
static const uint64_t ssAdd2 = 12065312585734608966ULL;
static const uint64_t ssAdd3 = 9306329213124626780ULL;
static const uint64_t ssAdd4 = 5281919268842080866ULL;
static const uint64_t ssAdd5 = 10536153434571861004ULL;
static const uint64_t ssAdd6 = 3398623926847679864ULL;
static const uint64_t ssAdd7 = 9549104520008361294ULL;

#define DS_CACHE_MASK ((uint32_t)(RX_CACHE_SIZE / RX_CACHE_LINE_SIZE - 1))

static void ss_execute(uint64_t r[8], const rx_superscalar_program *prog, const uint64_t *reciprocals) {
    uint32_t size = prog->size;
    const rx_instruction *buf = prog->buffer;

    for (uint32_t i = 0; i < size; i++) {
        const rx_instruction *instr = &buf[i];
        int dst = instr->dst % 8;
        int src = instr->src % 8;

        switch (instr->opcode) {
        case RX_SS_ISUB_R:
            r[dst] -= r[src];
            break;
        case RX_SS_IXOR_R:
            r[dst] ^= r[src];
            break;
        case RX_SS_IADD_RS:
            r[dst] += r[src] << ((instr->mod >> 2) & 3);
            break;
        case RX_SS_IMUL_R:
            r[dst] *= r[src];
            break;
        case RX_SS_IROR_C: {
            uint32_t imm = instr->imm32;
            r[dst] = rx_rotr(r[dst], imm);
            break;
        }
        case RX_SS_IADD_C7:
        case RX_SS_IADD_C8:
        case RX_SS_IADD_C9: {
            uint32_t imm = instr->imm32;
            r[dst] += (uint64_t)(int64_t)(int32_t)imm;
            break;
        }
        case RX_SS_IXOR_C7:
        case RX_SS_IXOR_C8:
        case RX_SS_IXOR_C9: {
            uint32_t imm = instr->imm32;
            r[dst] ^= (uint64_t)(int64_t)(int32_t)imm;
            break;
        }
        case RX_SS_IMULH_R:
            r[dst] = rx_mulh(r[dst], r[src]);
            break;
        case RX_SS_ISMULH_R:
            r[dst] = (uint64_t)rx_smulh(rx_u64_to_s64(r[dst]), rx_u64_to_s64(r[src]));
            break;
        case RX_SS_IMUL_RCP: {
            uint32_t idx = instr->imm32;
            uint64_t rcp = reciprocals ? reciprocals[idx] : 0;
            r[dst] *= rcp;
            break;
        }
        }
    }
}

void rx_init_cache_internal(rx_cache *cache, const void *key, size_t key_size) {
    argon2_hash(ARGON2_D, RX_ARGON_ITERATIONS, RX_ARGON_MEMORY, RX_ARGON_LANES,
                 key, key_size, RX_ARGON_SALT, RX_ARGON_SALT_LEN,
                 NULL, 0, NULL, 0,
                 NULL, 0, cache->memory);

    blake2_gen gen;
    blake2_gen_init(&gen, key, key_size);

    int total_rcp = 0;
    for (int i = 0; i < RX_CACHE_ACCESSES; i++) {
        generate_superscalar(&cache->programs[i], &gen);
        for (uint32_t j = 0; j < cache->programs[i].size; j++) {
            if (cache->programs[i].buffer[j].opcode == RX_SS_IMUL_RCP) {
                total_rcp++;
            }
        }
    }

    if (total_rcp > 0) {
        cache->reciprocalCache = (uint64_t *)malloc((size_t)total_rcp * sizeof(uint64_t));
        cache->reciprocalCapacity = total_rcp;
        cache->reciprocalCount = 0;
        for (int i = 0; i < RX_CACHE_ACCESSES; i++) {
            for (uint32_t j = 0; j < cache->programs[i].size; j++) {
                if (cache->programs[i].buffer[j].opcode == RX_SS_IMUL_RCP) {
                    uint32_t imm = cache->programs[i].buffer[j].imm32;
                    cache->reciprocalCache[cache->reciprocalCount++] = rx_reciprocal(imm);
                    cache->programs[i].buffer[j].imm32 = (u32)(cache->reciprocalCount - 1);
                }
            }
        }
    }
}

void rx_init_dataset_item(rx_cache *cache, uint8_t *out, uint64_t item_number) {
    uint64_t rl[8];
    uint64_t base = (item_number + 1) * ssMul0;
    rl[0] = base;
    rl[1] = base ^ ssAdd1;
    rl[2] = base ^ ssAdd2;
    rl[3] = base ^ ssAdd3;
    rl[4] = base ^ ssAdd4;
    rl[5] = base ^ ssAdd5;
    rl[6] = base ^ ssAdd6;
    rl[7] = base ^ ssAdd7;

    uint64_t reg_val = item_number;
    for (int i = 0; i < RX_CACHE_ACCESSES; i++) {
        uint8_t *mix_block = cache->memory + ((reg_val & DS_CACHE_MASK) << 6);
        _mm_prefetch((const char *)mix_block, _MM_HINT_NTA);

        rx_superscalar_program *prog = &cache->programs[i];
        uint64_t r[8];
        memcpy(r, rl, 64);
        ss_execute(r, prog, cache->reciprocalCache);

        const uint64_t *ml = (const uint64_t *)mix_block;
        r[0] ^= ml[0]; r[1] ^= ml[1]; r[2] ^= ml[2]; r[3] ^= ml[3];
        r[4] ^= ml[4]; r[5] ^= ml[5]; r[6] ^= ml[6]; r[7] ^= ml[7];
        memcpy(rl, r, 64);

        reg_val = rl[prog->addrReg];
    }
    memcpy(out, rl, RX_CACHE_LINE_SIZE);
}

typedef struct {
    rx_dataset *ds;
    rx_cache *cache;
    uint32_t start;
    uint32_t count;
} ds_thread_arg_t;

static DWORD WINAPI ds_init_thread(LPVOID param) {
    ds_thread_arg_t *arg = (ds_thread_arg_t *)param;
    uint8_t *ptr = arg->ds->memory + (size_t)arg->start * RX_CACHE_LINE_SIZE;
    for (uint32_t i = 0; i < arg->count; i++, ptr += RX_CACHE_LINE_SIZE) {
        rx_init_dataset_item(arg->cache, ptr, arg->start + i);
    }
    return 0;
}

void rx_init_dataset_internal(rx_dataset *ds, rx_cache *cache, uint32_t start_item, uint32_t count, int num_threads) {
    if (num_threads < 1) num_threads = 1;

    if (num_threads <= 1) {
        uint8_t *ptr = ds->memory + (size_t)start_item * RX_CACHE_LINE_SIZE;
        uint32_t report_interval = count / 20;
        if (report_interval == 0) report_interval = 1;
        for (uint32_t i = 0; i < count; i++, ptr += RX_CACHE_LINE_SIZE) {
            rx_init_dataset_item(cache, ptr, start_item + i);
            if (report_interval > 0 && (i % report_interval) == 0) {
                LOG_INFO("[DATASET] Initializing... %u/%u (%.0f%%)", i, count, 100.0 * i / count);
            }
        }
    } else {
        LOG_INFO("[DATASET] Initializing with %d threads...", num_threads);

        HANDLE *threads = (HANDLE *)malloc(num_threads * sizeof(HANDLE));
        ds_thread_arg_t *args = (ds_thread_arg_t *)malloc(num_threads * sizeof(ds_thread_arg_t));

        uint32_t per_thread = count / num_threads;
        uint32_t remainder = count % num_threads;
        uint32_t offset = start_item;

        for (int t = 0; t < num_threads; t++) {
            args[t].ds = ds;
            args[t].cache = cache;
            args[t].start = offset;
            args[t].count = per_thread + (t < remainder ? 1 : 0);
            offset += args[t].count;
            threads[t] = CreateThread(NULL, 0, ds_init_thread, &args[t], 0, NULL);
        }

        uint32_t report_interval = count / 20;
        if (report_interval == 0) report_interval = 1;
        DWORD start_tick = GetTickCount();
        uint32_t last_reported = 0;

        while (1) {
            DWORD elapsed = GetTickCount() - start_tick;
            if (elapsed < 2000) {
                Sleep(500);
            } else {
                double items_per_ms = (double)(count) / elapsed;
                uint32_t estimated_done = (uint32_t)(items_per_ms * elapsed);
                if (estimated_done > count) estimated_done = count;
                if (estimated_done - last_reported >= report_interval) {
                    LOG_INFO("[DATASET] Initializing... ~%u/%u (%.0f%%)", estimated_done, count, 100.0 * estimated_done / count);
                    last_reported = estimated_done;
                }
                Sleep(1000);
            }
            DWORD wait_result = WaitForMultipleObjects(num_threads, threads, TRUE, 0);
            if (wait_result != WAIT_TIMEOUT) break;
        }

        WaitForMultipleObjects(num_threads, threads, TRUE, 60000);

        for (int t = 0; t < num_threads; t++)
            CloseHandle(threads[t]);
        free(threads);
        free(args);
    }

    LOG_INFO("[DATASET] Initialization complete: %u items", count);
}
