#include "worker.h"
#include "miner.h"
#include "stratum/stratum.h"
#include "crypto/randomx/randomx.h"
#include "crypto/keccak/keccak.h"
#include "common/log.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

static void hex_decode(const char *hex, uint8_t *out, int max_bytes) {
    int hex_len = (int)strlen(hex);
    int byte_len = hex_len / 2;
    if (byte_len > max_bytes) byte_len = max_bytes;
    for (int i = 0; i < byte_len; i++) {
        char h[3] = { hex[i * 2], hex[i * 2 + 1], 0 };
        out[i] = (uint8_t)strtoul(h, NULL, 16);
    }
}

static void hex_encode(const uint8_t *data, int len, char *out) {
    for (int i = 0; i < len; i++)
        snprintf(out + i * 2, 3, "%02x", data[i]);
    out[len * 2] = '\0';
}

static int hex_decode_seed(const char *hex, uint8_t *out) {
    int hex_len = (int)strlen(hex);
    if (hex_len != 64) return -1;
    for (int i = 0; i < 32; i++) {
        char h[3] = { hex[i * 2], hex[i * 2 + 1], 0 };
        out[i] = (uint8_t)strtoul(h, NULL, 16);
    }
    return 0;
}

static int encode_varint(uint64_t val, uint8_t *out) {
    int i = 0;
    do {
        uint8_t byte = val & 0x7F;
        val >>= 7;
        if (val > 0) byte |= 0x80;
        out[i++] = byte;
    } while (val > 0);
    return i;
}

#define BLOB_MAX_SIZE 256
#define NONCE_OFFSET 39

static int build_hashing_blob(stratum_job_t *job, uint8_t *blob, uint32_t nonce) {
    memset(blob, 0, 76);

    uint8_t version_bytes[8] = {0};
    int version_hex_len = (int)strlen(job->version_hex) / 2;
    if (version_hex_len > 2) version_hex_len = 2;
    hex_decode(job->version_hex, version_bytes, version_hex_len);

    uint8_t ntime_bytes[4] = {0};
    hex_decode(job->ntime_hex, ntime_bytes, 4);
    uint32_t timestamp = (uint32_t)ntime_bytes[3]
                       | ((uint32_t)ntime_bytes[2] << 8)
                       | ((uint32_t)ntime_bytes[1] << 16)
                       | ((uint32_t)ntime_bytes[0] << 24);

    uint8_t timestamp_varint[8];
    int tlen = encode_varint(timestamp, timestamp_varint);

    int pos = 0;
    blob[pos++] = version_bytes[0];
    blob[pos++] = version_bytes[1];

    for (int i = 0; i < tlen; i++)
        blob[pos++] = timestamp_varint[i];

    hex_decode(job->prev_hash, blob + pos, 32);
    pos += 32;

    blob[pos++] = (uint8_t)(nonce & 0xFF);
    blob[pos++] = (uint8_t)((nonce >> 8) & 0xFF);
    blob[pos++] = (uint8_t)((nonce >> 16) & 0xFF);
    blob[pos++] = (uint8_t)((nonce >> 24) & 0xFF);

    int coinb1_len = (int)strlen(job->coinb1) / 2;
    int en1_len = (int)strlen(job->extranonce1) / 2;
    int en2_len = job->extranonce2_size;
    int coinb2_len = (int)strlen(job->coinb2) / 2;
    int prefix_len = coinb1_len + en1_len + en2_len;

    uint8_t *coinbase_tx = (uint8_t *)calloc(prefix_len + coinb2_len + 16, 1);
    if (!coinbase_tx) return -1;

    int tx_pos = 0;
    hex_decode(job->coinb1, coinbase_tx + tx_pos, coinb1_len);
    tx_pos += coinb1_len;
    hex_decode(job->extranonce1, coinbase_tx + tx_pos, en1_len);
    tx_pos += en1_len;
    memset(coinbase_tx + tx_pos, 0, en2_len);
    tx_pos += en2_len;
    hex_decode(job->coinb2, coinbase_tx + tx_pos, coinb2_len);
    tx_pos += coinb2_len;

    int full_tx_len = tx_pos;
    if (full_tx_len < 2) { free(coinbase_tx); return -1; }

    uint8_t prefix_hash[32];
    keccak256(coinbase_tx, prefix_len, prefix_hash);

    uint8_t rct_type_hash[32];
    uint8_t rct_type_byte[1] = { coinbase_tx[prefix_len] };
    keccak256(rct_type_byte, 1, rct_type_hash);

    uint8_t combined[96];
    memcpy(combined, prefix_hash, 32);
    memcpy(combined + 32, rct_type_hash, 32);
    memset(combined + 64, 0, 32);

    uint8_t tree_hash[32];
    keccak256(combined, 96, tree_hash);
    free(coinbase_tx);

    memcpy(blob + pos, tree_hash, 32);
    pos += 32;
    blob[pos++] = 0x01;

    if (pos != 76) {
        LOG_ERR("[W] hashing blob size %d != 76", pos);
        return -1;
    }
    return 0;
}

void worker_run(worker_t *w) {
    rx_vm *vm = (rx_vm *)w->vm;
    stratum_ctx_t *stratum = w->stratum;
    miner_ctx_t *miner = w->miner;

    LOG_INFO("[W%d] Started", w->id);
    w->start_time = GetTickCount64();

    uint8_t blob[BLOB_MAX_SIZE];
    int blob_len = 0;
    uint32_t nonce = 0;
    char current_job_id[128] = {0};
    uint64_t current_target = 0;
    int got_job = 0;
    char current_seed[65] = {0};
    strncpy(current_seed, w->initial_seed, sizeof(current_seed) - 1);
    int is_monero_proto = 0;
    char saved_ntime[64] = {0};
    int saved_en2_size = 4;
    int need_first = 1;

    uint64_t last_report_hashes = 0;
    uint64_t last_report_time = 0;
    uint64_t total_shares = 0;

    stratum_job_t job_copy;
    memset(&job_copy, 0, sizeof(job_copy));

    while (!w->should_stop) {
        stratum_free_job_copy(&job_copy);
        stratum_copy_job(stratum, &job_copy);
        stratum_job_t *job = &job_copy;
        int proto = stratum_get_protocol(stratum);

        if (!job || !job->job_id) {
            Sleep(100);
            continue;
        }

        if (proto == STRATUM_PROTO_MONERO) {
            if (!job->blob || !job->blob[0]) { Sleep(100); continue; }
        } else {
            if (!job->prev_hash || !job->coinb1 || !job->coinb2) { Sleep(100); continue; }
        }

        if (job->target_u64 == 0 && job->difficulty > 0) {
            if (job->difficulty >= 1.0)
                job->target_u64 = (uint64_t)(4294967296.0 / job->difficulty);
            else
                job->target_u64 = 0xFFFFFFFF;
        }
        if (job->target_u64 == 0) { Sleep(100); continue; }

        if (job->seed_hash && job->seed_hash[0] &&
            strcmp(job->seed_hash, current_seed) != 0) {
            strncpy(current_seed, job->seed_hash, sizeof(current_seed) - 1);

            uint8_t seed_bytes[32];
            if (hex_decode_seed(job->seed_hash, seed_bytes) == 0) {
                LOG_INFO("[W%d] Seed changed: %s - reinitializing cache...", w->id, job->seed_hash);
                miner_reinit_cache(miner, seed_bytes, 32);
                vm = (rx_vm *)miner_get_vm(miner, w->id);
                w->vm = vm;
                if (!vm) {
                    LOG_ERR("[W%d] No VM after reinit", w->id);
                    Sleep(1000);
                    continue;
                }
            } else {
                LOG_WARN("[W%d] Invalid seed_hash: %s", w->id, job->seed_hash);
            }
            got_job = 0;
            need_first = 1;
        }

        if (strcmp(job->job_id, current_job_id) != 0) {
            is_monero_proto = (proto == STRATUM_PROTO_MONERO);

            if (is_monero_proto) {
                int hex_len = (int)strlen(job->blob);
                blob_len = hex_len / 2;
                if (blob_len > BLOB_MAX_SIZE) blob_len = BLOB_MAX_SIZE;
                if (blob_len < NONCE_OFFSET + 4) {
                    LOG_ERR("[W%d] Blob too short: %d", w->id, blob_len);
                    Sleep(500);
                    continue;
                }
                hex_decode(job->blob, blob, blob_len);
                nonce = *(uint32_t *)(blob + NONCE_OFFSET);
                nonce += w->nonce_offset;
            } else {
                char *safe_id = _strdup(job->job_id);
                char *safe_coinb1 = _strdup(job->coinb1);
                char *safe_coinb2 = _strdup(job->coinb2);
                char *safe_en1 = _strdup(job->extranonce1 ? job->extranonce1 : "");
                char *safe_prev = _strdup(job->prev_hash);
                char *safe_ntime = _strdup(job->ntime_hex ? job->ntime_hex : "");
                char *safe_version = _strdup(job->version_hex ? job->version_hex : "");

                if (!safe_id || !safe_coinb1 || !safe_coinb2) {
                    free(safe_id); free(safe_coinb1); free(safe_coinb2);
                    free(safe_en1); free(safe_prev); free(safe_ntime); free(safe_version);
                    Sleep(100);
                    continue;
                }

                stratum_job_t safe_job;
                memset(&safe_job, 0, sizeof(safe_job));
                safe_job.job_id = safe_id;
                safe_job.coinb1 = safe_coinb1;
                safe_job.coinb2 = safe_coinb2;
                safe_job.extranonce1 = safe_en1;
                safe_job.prev_hash = safe_prev;
                safe_job.ntime_hex = safe_ntime;
                safe_job.version_hex = safe_version;
                safe_job.extranonce2_size = job->extranonce2_size;

                if (build_hashing_blob(&safe_job, blob, 0) != 0) {
                    LOG_ERR("[W%d] Failed to build blob", w->id);
                    free(safe_id); free(safe_coinb1); free(safe_coinb2);
                    free(safe_en1); free(safe_prev); free(safe_ntime); free(safe_version);
                    Sleep(500);
                    continue;
                }
                blob_len = 76;
                nonce = w->nonce_offset;
                saved_en2_size = job->extranonce2_size;
                strncpy(saved_ntime, safe_ntime, sizeof(saved_ntime) - 1);

                char dbg[256];
                hex_encode(blob, 76, dbg);
                LOG_DEBUG("[W%d] BLOB: %s", w->id, dbg);

                free(safe_id); free(safe_coinb1); free(safe_coinb2);
                free(safe_en1); free(safe_prev); free(safe_ntime); free(safe_version);
            }

            strncpy(current_job_id, job->job_id, sizeof(current_job_id) - 1);
            current_target = job->target_u64;
            got_job = 1;
            need_first = 1;

            LOG_INFO("[W%d] New job: %s blob_len=%d target=%016llx proto=%s",
                     w->id, current_job_id, blob_len, (unsigned long long)current_target,
                     is_monero_proto ? "Monero" : "Standard");
        }

        if (!got_job) { Sleep(10); continue; }

        if (w->hashes == 0) {
            LOG_INFO("[W%d] Starting to mine with blob_len=%d vm=%p", w->id, blob_len, w->vm);
        }

        memcpy(blob + NONCE_OFFSET, &nonce, 4);

        if (need_first) {
            rx_calculate_hash_first(vm, blob, (size_t)blob_len);
            need_first = 0;
        }

        uint8_t hash[32];
        rx_calculate_hash_next(vm, blob, (size_t)blob_len, hash);

        uint64_t hash_val = read_u64_le(hash);
        if (hash_val < current_target) {
            char nonce_hex[16];
            snprintf(nonce_hex, sizeof(nonce_hex), "%08x", nonce);
            char result_hex[65];
            hex_encode(hash, 32, result_hex);

            char en2_hex[32];
            int en2_size = saved_en2_size * 2;
            for (int i = en2_size - 1; i >= 0; i--) {
                int nibble = (int)(w->extranonce2_counter >> (i * 4)) & 0xf;
                en2_hex[en2_size - 1 - i] = "0123456789abcdef"[nibble];
            }
            en2_hex[en2_size] = '\0';
            w->extranonce2_counter++;

            LOG_INFO("[W%d] SHARE! nonce=%s hash=%s", w->id, nonce_hex, result_hex);
            total_shares++;

            stratum_submit_share(stratum, current_job_id, nonce_hex,
                                 result_hex, en2_hex, saved_ntime);
        }

        nonce++;
        w->hashes++;
        w->loop_count++;

        if (w->loop_count % 1000 == 0) {
            uint64_t now = GetTickCount64();
            uint64_t elapsed_ms = now - w->start_time;
            if (now - last_report_time >= 10000) {
                uint64_t delta_h = w->hashes - last_report_hashes;
                double hr = (double)delta_h / ((now - last_report_time) / 1000.0);
                double avg_hr = elapsed_ms > 0 ? (double)w->hashes / (elapsed_ms / 1000.0) : 0;
                LOG_INFO("[W%d] %llu H/s (avg %.1f) | %llu hashes | %llu shares",
                         w->id, (unsigned long long)(hr + 0.5), avg_hr,
                         w->hashes, total_shares);
                last_report_time = now;
                last_report_hashes = w->hashes;
            }
        }
    }

    u64 elapsed = (GetTickCount64() - w->start_time) / 1000;
    if (elapsed > 0) {
        LOG_INFO("[W%d] Stopped: %llu hashes in %llu s (%.1f H/s)",
             w->id, w->hashes, elapsed, (double)w->hashes / elapsed);
    }
}
