#include "stratum.h"
#include "json.h"
#include "../common/log.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib, "ws2_32.lib")

struct stratum_ctx {
    stratum_config_t cfg;
    SOCKET sock;
    int connected;
    int running;
    int protocol;
    int id_counter;
    char session_id[128];
    char extranonce1[STRATUM_MAX_EXTRANONCE1 + 1];
    int extranonce2_size;
    char send_buf[STRATUM_BUF_SIZE];
    char recv_buf[STRATUM_BUF_SIZE];
    int recv_len;
    stratum_job_t job;
    CRITICAL_SECTION lock;
};

static int send_line(stratum_ctx_t *ctx, const char *msg) {
    int len = (int)strlen(msg);
    if (len + 2 > STRATUM_BUF_SIZE) return -1;
    memcpy(ctx->send_buf, msg, len);
    ctx->send_buf[len] = '\n';
    ctx->send_buf[len + 1] = '\0';
    LOG_DEBUG("[STRATUM] > %s", msg);
    int sent = send(ctx->sock, ctx->send_buf, len + 1, 0);
    if (sent != len + 1) {
        LOG_ERR("[STRATUM] send failed: %d", WSAGetLastError());
        return -1;
    }
    return 0;
}

static char *recv_line(stratum_ctx_t *ctx) {
    char *start = ctx->recv_buf;
    char *end = ctx->recv_buf + ctx->recv_len;
    char *nl = memchr(start, '\n', end - start);
    if (!nl) return NULL;
    *nl = '\0';
    int line_len = (int)(nl - start);
    ctx->recv_len -= line_len + 1;
    if (ctx->recv_len > 0)
        memmove(ctx->recv_buf, nl + 1, ctx->recv_len);
    return start;
}

static int recv_more(stratum_ctx_t *ctx) {
    if (!ctx->connected) return -1;
    int avail = STRATUM_BUF_SIZE - ctx->recv_len - 1;
    if (avail < 1024) return -1;
    int n = recv(ctx->sock, ctx->recv_buf + ctx->recv_len, avail, 0);
    if (n <= 0) return -1;
    ctx->recv_len += n;
    ctx->recv_buf[ctx->recv_len] = '\0';
    return 0;
}

static void extract_string(const json_token_t *t, char *out, int max_len) {
    if (!t) { out[0] = '\0'; return; }
    int len = (int)(t->end - t->start);
    if (len >= max_len) len = max_len - 1;
    memcpy(out, t->start, len);
    out[len] = '\0';
}

static uint64_t parse_target_le(const char *hex) {
    uint8_t buf[8] = {0};
    int len = (int)strlen(hex);
    int bytes = len / 2;
    if (bytes > 8) bytes = 8;
    for (int i = 0; i < bytes; i++) {
        char h[3] = { hex[i * 2], hex[i * 2 + 1], 0 };
        buf[i] = (uint8_t)strtoul(h, NULL, 16);
    }
    return (uint64_t)buf[0] | ((uint64_t)buf[1] << 8) |
           ((uint64_t)buf[2] << 16) | ((uint64_t)buf[3] << 24) |
           ((uint64_t)buf[4] << 32) | ((uint64_t)buf[5] << 40) |
           ((uint64_t)buf[6] << 48) | ((uint64_t)buf[7] << 56);
}

static void free_job_fields(stratum_job_t *job) {
    free(job->job_id);
    free(job->blob);
    free(job->target);
    free(job->seed_hash);
    free(job->algo);
    free(job->prev_hash);
    free(job->coinb1);
    free(job->coinb2);
    free(job->version_hex);
    free(job->ntime_hex);
    free(job->extranonce1);
    memset(job, 0, sizeof(*job));
}

static void parse_monero_job(stratum_ctx_t *ctx, const json_parser_t *jp,
                              const json_token_t *job_obj) {
    char job_id[128] = {0};
    char blob[4096] = {0};
    char target[128] = {0};
    char seed_hash[128] = {0};
    char algo[32] = {0};

    extract_string(json_get_in(jp, job_obj, "job_id"), job_id, sizeof(job_id));
    extract_string(json_get_in(jp, job_obj, "blob"), blob, sizeof(blob));
    extract_string(json_get_in(jp, job_obj, "target"), target, sizeof(target));
    extract_string(json_get_in(jp, job_obj, "seed_hash"), seed_hash, sizeof(seed_hash));
    extract_string(json_get_in(jp, job_obj, "algo"), algo, sizeof(algo));

    const json_token_t *height_tok = json_get_in(jp, job_obj, "height");

    if (!job_id[0] || !blob[0]) {
        LOG_WARN("[STRATUM] Monero job missing job_id or blob");
        return;
    }

    EnterCriticalSection(&ctx->lock);
    double saved_diff = ctx->job.difficulty;
    free_job_fields(&ctx->job);
    ctx->job.difficulty = saved_diff;

    ctx->job.job_id = _strdup(job_id);
    ctx->job.blob = _strdup(blob);
    ctx->job.target = _strdup(target);
    ctx->job.seed_hash = _strdup(seed_hash);
    ctx->job.algo = _strdup(algo);
    ctx->job.height = 0;
    if (height_tok && height_tok->type == JSON_INT) {
        char buf[32];
        extract_string(height_tok, buf, sizeof(buf));
        ctx->job.height = (uint64_t)_strtoui64(buf, NULL, 10);
    }
    ctx->job.target_u64 = parse_target_le(target);
    ctx->job.has_blob = 1;

    LOG_INFO("[STRATUM] [Monero] Job: %s algo=%s target=%s seed=%s blob_len=%d",
             job_id, algo[0] ? algo : "?", target,
             seed_hash[0] ? seed_hash : "(none)", (int)strlen(blob));

    LeaveCriticalSection(&ctx->lock);
}

static void parse_standard_job(stratum_ctx_t *ctx, const json_parser_t *jp,
                                const json_token_t *params) {
    char job_id[128] = {0};
    char prev_hash[128] = {0};
    char coinb1[8192] = {0};
    char coinb2[8192] = {0};
    char version_hex[32] = {0};
    char nbits_hex[32] = {0};
    char ntime_hex[32] = {0};
    char seed_hash[128] = {0};

    extract_string(json_child(jp, params, 0), job_id, sizeof(job_id));
    extract_string(json_child(jp, params, 1), prev_hash, sizeof(prev_hash));
    extract_string(json_child(jp, params, 2), coinb1, sizeof(coinb1));
    extract_string(json_child(jp, params, 3), coinb2, sizeof(coinb2));
    extract_string(json_child(jp, params, 5), version_hex, sizeof(version_hex));
    extract_string(json_child(jp, params, 6), nbits_hex, sizeof(nbits_hex));
    extract_string(json_child(jp, params, 7), ntime_hex, sizeof(ntime_hex));

    if (params->size > 9) {
        extract_string(json_child(jp, params, 9), seed_hash, sizeof(seed_hash));
    }

    if (!job_id[0]) {
        LOG_WARN("[STRATUM] Standard job missing job_id");
        return;
    }

    EnterCriticalSection(&ctx->lock);
    double saved_diff = ctx->job.difficulty;
    free_job_fields(&ctx->job);
    ctx->job.difficulty = saved_diff;

    ctx->job.job_id = _strdup(job_id);
    ctx->job.prev_hash = _strdup(prev_hash);
    ctx->job.coinb1 = _strdup(coinb1);
    ctx->job.coinb2 = _strdup(coinb2);
    ctx->job.version_hex = _strdup(version_hex);
    ctx->job.ntime_hex = _strdup(ntime_hex);

    ctx->job.seed_hash = seed_hash[0] ? _strdup(seed_hash) : NULL;
    ctx->job.extranonce1 = _strdup(ctx->extranonce1);
    ctx->job.extranonce2_size = ctx->extranonce2_size;
    ctx->job.has_blob = 0;

    if (ctx->job.difficulty > 0) {
        if (ctx->job.difficulty >= 1.0)
            ctx->job.target_u64 = (uint32_t)(4294967295.0 / ctx->job.difficulty);
        else
            ctx->job.target_u64 = 0xFFFFFFFF;
    }

    LOG_INFO("[STRATUM] [Standard] Job: %s version=%s ntime=%s diff=%.1f target=%016llx",
             job_id, version_hex, ntime_hex, ctx->job.difficulty, (unsigned long long)ctx->job.target_u64);
    if (seed_hash[0]) {
        LOG_INFO("[STRATUM] [Standard] seed_hash from params[9]: %s", seed_hash);
    } else {
        LOG_WARN("[STRATUM] [Standard] NO seed_hash in mining.notify!");
    }

    LeaveCriticalSection(&ctx->lock);
}

stratum_ctx_t *stratum_create(const stratum_config_t *cfg) {
    stratum_ctx_t *ctx = (stratum_ctx_t *)calloc(1, sizeof(stratum_ctx_t));
    if (!ctx) return NULL;
    ctx->sock = INVALID_SOCKET;
    ctx->connected = 0;
    ctx->running = 0;
    ctx->protocol = -1;
    ctx->id_counter = 1;
    ctx->recv_len = 0;
    ctx->extranonce2_size = STRATUM_EXTRANONCE2_SIZE;
    ctx->job.difficulty = 1.0;
    InitializeCriticalSection(&ctx->lock);

    ctx->cfg.pool_url = _strdup(cfg->pool_url);
    ctx->cfg.pool_port = cfg->pool_port;
    ctx->cfg.wallet = _strdup(cfg->wallet);
    ctx->cfg.worker_name = _strdup(cfg->worker_name);
    ctx->cfg.password = _strdup(cfg->password);
    return ctx;
}

void stratum_destroy(stratum_ctx_t *ctx) {
    if (!ctx) return;
    stratum_disconnect(ctx);
    DeleteCriticalSection(&ctx->lock);
    free(ctx->cfg.pool_url);
    free(ctx->cfg.wallet);
    free(ctx->cfg.worker_name);
    free(ctx->cfg.password);
    free_job_fields(&ctx->job);
    free(ctx);
}

int stratum_connect(stratum_ctx_t *ctx) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        LOG_ERR("[STRATUM] WSAStartup failed: %d", WSAGetLastError());
        return -1;
    }

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", ctx->cfg.pool_port);

    struct addrinfo hints, *result;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    LOG_INFO("[STRATUM] Resolving %s:%d...", ctx->cfg.pool_url, ctx->cfg.pool_port);

    int gai_err = getaddrinfo(ctx->cfg.pool_url, port_str, &hints, &result);
    if (gai_err != 0) {
        LOG_ERR("[STRATUM] DNS resolve failed: %s", gai_strerror(gai_err));
        WSACleanup();
        return -1;
    }

    ctx->sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (ctx->sock == INVALID_SOCKET) {
        LOG_ERR("[STRATUM] socket() failed: %d", WSAGetLastError());
        freeaddrinfo(result);
        WSACleanup();
        return -1;
    }

    LOG_INFO("[STRATUM] Connecting to %s:%d...", ctx->cfg.pool_url, ctx->cfg.pool_port);

    if (connect(ctx->sock, result->ai_addr, (int)result->ai_addrlen) != 0) {
        LOG_ERR("[STRATUM] connect() failed: %d", WSAGetLastError());
        closesocket(ctx->sock);
        ctx->sock = INVALID_SOCKET;
        freeaddrinfo(result);
        WSACleanup();
        return -1;
    }

    freeaddrinfo(result);

    DWORD timeout = 300000;
    setsockopt(ctx->sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
    setsockopt(ctx->sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));

    ctx->connected = 1;
    ctx->recv_len = 0;
    LOG_INFO("[STRATUM] Connected");
    return 0;
}

void stratum_disconnect(stratum_ctx_t *ctx) {
    if (ctx->sock != INVALID_SOCKET) {
        closesocket(ctx->sock);
        ctx->sock = INVALID_SOCKET;
    }
    ctx->connected = 0;
}

static int try_monero_login(stratum_ctx_t *ctx) {
    char user[256];
    snprintf(user, sizeof(user), "%s.%s", ctx->cfg.wallet, ctx->cfg.worker_name);

    char msg[1024];
    int id = ctx->id_counter++;
    snprintf(msg, sizeof(msg),
        "{\"id\":%d,\"method\":\"login\",\"params\":{\"login\":\"%s\",\"pass\":\"%s\",\"agent\":\"xmr-miner/0.1.0\"}}",
        id, user, ctx->cfg.password);
    if (send_line(ctx, msg) != 0) return -1;

    DWORD deadline = GetTickCount() + 3000;
    while (GetTickCount() < deadline) {
        char *line;
        while ((line = recv_line(ctx)) != NULL) {
            LOG_INFO("[STRATUM] < %s", line);

            json_parser_t jp;
            if (json_parse(&jp, line, strlen(line)) != 0) continue;

            const json_token_t *result = json_get(&jp, "result");
            if (!result || result->type != JSON_OBJECT) continue;

            const json_token_t *status = json_get_in(&jp, result, "status");
            char status_buf[64] = {0};
            if (status) extract_string(status, status_buf, sizeof(status_buf));

            if (strcmp(status_buf, "OK") == 0) {
                const json_token_t *sid = json_get_in(&jp, result, "id");
                if (sid) extract_string(sid, ctx->session_id, sizeof(ctx->session_id));

                const json_token_t *job_obj = json_get_in(&jp, result, "job");
                if (job_obj && job_obj->type == JSON_OBJECT) {
                    parse_monero_job(ctx, &jp, job_obj);
                }

                ctx->protocol = STRATUM_PROTO_MONERO;
                LOG_INFO("[STRATUM] Monero protocol login OK, session=%s",
                         ctx->session_id);
                return 0;
            }

            if (status_buf[0]) {
                LOG_INFO("[STRATUM] Monero login rejected: %s (trying standard...)", status_buf);
                return -1;
            }
        }
        if (recv_more(ctx) != 0) break;
    }
    return -1;
}

static int try_standard_login(stratum_ctx_t *ctx) {
    char msg[512];
    int id = ctx->id_counter++;
    snprintf(msg, sizeof(msg),
        "{\"id\":%d,\"method\":\"mining.subscribe\",\"params\":[]}", id);
    if (send_line(ctx, msg) != 0) return -1;

    int found = 0;
    for (int att = 0; att < 30 && !found; att++) {
        char *line;
        while ((line = recv_line(ctx)) != NULL) {
            LOG_INFO("[STRATUM] < %s", line);

            json_parser_t jp;
            if (json_parse(&jp, line, strlen(line)) != 0) continue;

            const json_token_t *result = json_get(&jp, "result");
            if (result && result->type == JSON_ARRAY && result->size >= 3) {
                const json_token_t *en1_tok = json_child(&jp, result, 1);
                if (en1_tok) {
                    extract_string(en1_tok, ctx->extranonce1, sizeof(ctx->extranonce1));
                }
                const json_token_t *en2_size_tok = json_child(&jp, result, 2);
                if (en2_size_tok) {
                    char buf[16];
                    extract_string(en2_size_tok, buf, sizeof(buf));
                    ctx->extranonce2_size = atoi(buf);
                }
                ctx->job.extranonce2_size = ctx->extranonce2_size;
                LOG_INFO("[STRATUM] Subscribed: extranonce1='%s' size=%d",
                         ctx->extranonce1, ctx->extranonce2_size);
                found = 1;
                break;
            }
        }
        if (!found) {
            if (recv_more(ctx) != 0) Sleep(100);
        }
    }

    char user[256];
    snprintf(user, sizeof(user), "%s.%s", ctx->cfg.wallet, ctx->cfg.worker_name);
    id = ctx->id_counter++;
    char auth_msg[1024];
    snprintf(auth_msg, sizeof(auth_msg),
        "{\"id\":%d,\"method\":\"mining.authorize\",\"params\":[\"%s\",\"%s\"]}",
        id, user, ctx->cfg.password);
    if (send_line(ctx, auth_msg) != 0) return -1;

    found = 0;
    for (int att = 0; att < 30 && !found; att++) {
        char *line;
        while ((line = recv_line(ctx)) != NULL) {
            LOG_INFO("[STRATUM] < %s", line);

            json_parser_t jp;
            if (json_parse(&jp, line, strlen(line)) != 0) continue;

            const json_token_t *method = json_get(&jp, "method");
            if (method) continue;

            const json_token_t *result = json_get(&jp, "result");
            if (result) {
                char status[64] = {0};
                extract_string(result, status, sizeof(status));
                if (strcmp(status, "true") == 0 || strcmp(status, "OK") == 0) {
                    ctx->protocol = STRATUM_PROTO_STANDARD;
                    LOG_INFO("[STRATUM] Standard stratum authorized as '%s'", user);
                    return 0;
                }
                LOG_ERR("[STRATUM] Authorization failed: %s", status);
                return -1;
            }

            const json_token_t *err = json_get(&jp, "error");
            if (err && err->type == JSON_ARRAY && err->size >= 1) {
                char msg_buf[256];
                extract_string(json_child(&jp, err, 0), msg_buf, sizeof(msg_buf));
                LOG_ERR("[STRATUM] Authorization error: %s", msg_buf);
                return -1;
            }
        }
        if (recv_more(ctx) != 0) Sleep(100);
    }
    return -1;
}

int stratum_login(stratum_ctx_t *ctx) {
    DWORD old_timeout = 30000;
    int optlen = sizeof(old_timeout);
    getsockopt(ctx->sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&old_timeout, &optlen);

    DWORD probe_timeout = 3000;
    setsockopt(ctx->sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&probe_timeout, sizeof(probe_timeout));

    int ret = try_monero_login(ctx);

    setsockopt(ctx->sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&old_timeout, sizeof(old_timeout));

    if (ret == 0) return 0;
    LOG_INFO("[STRATUM] Monero protocol not supported, reconnecting for standard stratum...");
    stratum_disconnect(ctx);
    Sleep(500);
    if (stratum_connect(ctx) != 0) {
        LOG_ERR("[STRATUM] Reconnect failed");
        return -1;
    }
    return try_standard_login(ctx);
}

int stratum_submit_share(stratum_ctx_t *ctx, const char *job_id,
                         const char *nonce_hex, const char *result_hex,
                         const char *en2_hex, const char *ntime_hex) {
    char msg[2048];
    int id = ctx->id_counter++;

    if (ctx->protocol == STRATUM_PROTO_MONERO) {
        snprintf(msg, sizeof(msg),
            "{\"id\":%d,\"method\":\"submit\",\"params\":"
            "{\"id\":\"%s\",\"job_id\":\"%s\",\"nonce\":\"%s\",\"result\":\"%s\"}}",
            id, ctx->session_id, job_id, nonce_hex, result_hex);
    } else {
        char user[256];
        snprintf(user, sizeof(user), "%s.%s", ctx->cfg.wallet, ctx->cfg.worker_name);
        snprintf(msg, sizeof(msg),
            "{\"id\":%d,\"method\":\"mining.submit\",\"params\":"
            "[\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"]}",
            id, user, job_id, en2_hex ? en2_hex : "00000000",
            ntime_hex ? ntime_hex : "00000000", nonce_hex);
    }
    if (send_line(ctx, msg) != 0) return -1;
    return 0;
}

stratum_job_t *stratum_get_job(stratum_ctx_t *ctx) {
    return &ctx->job;
}

int stratum_get_protocol(stratum_ctx_t *ctx) {
    return ctx->protocol;
}

int stratum_recv(stratum_ctx_t *ctx) {
    if (!ctx->connected) return -1;

    int avail = STRATUM_BUF_SIZE - ctx->recv_len - 1;
    if (avail < 1024) return -1;

    int n = recv(ctx->sock, ctx->recv_buf + ctx->recv_len, avail, 0);
    if (n <= 0) {
        LOG_WARN("[STRATUM] recv returned %d", n);
        return -1;
    }
    ctx->recv_len += n;
    ctx->recv_buf[ctx->recv_len] = '\0';

    char *line;
    while ((line = recv_line(ctx)) != NULL) {
        LOG_DEBUG("[STRATUM] < %s", line);

        json_parser_t jp;
        if (json_parse(&jp, line, strlen(line)) != 0) continue;

        const json_token_t *id_tok = json_get(&jp, "id");
        if (id_tok && id_tok->type == JSON_INT && !(json_get(&jp, "method"))) {
            const json_token_t *result = json_get(&jp, "result");
            const json_token_t *err = json_get(&jp, "error");
            if (err && err->type == JSON_ARRAY && err->size >= 2) {
                const json_token_t *code = json_child(&jp, err, 0);
                const json_token_t *msg_tok = json_child(&jp, err, 1);
                char code_buf[16], msg_buf[256];
                extract_string(code, code_buf, sizeof(code_buf));
                extract_string(msg_tok, msg_buf, sizeof(msg_buf));
                LOG_WARN("[STRATUM] Share rejected: [%s] %s", code_buf, msg_buf);
            } else if (result) {
                LOG_INFO("[STRATUM] Share accepted!");
            }
            continue;
        }

        const json_token_t *method = json_get(&jp, "method");
        if (!method || method->type != JSON_STRING) continue;

        char method_name[64];
        extract_string(method, method_name, sizeof(method_name));

        const json_token_t *params = json_get(&jp, "params");

        if (strcmp(method_name, "job") == 0 && params && params->type == JSON_OBJECT) {
            parse_monero_job(ctx, &jp, params);
        } else if (strcmp(method_name, "mining.notify") == 0 &&
                   params && params->type == JSON_ARRAY) {
            parse_standard_job(ctx, &jp, params);
        } else if (strcmp(method_name, "mining.set_difficulty") == 0 &&
                   params && params->type == JSON_ARRAY && params->size >= 1) {
            const json_token_t *diff_tok = json_child(&jp, params, 0);
            if (diff_tok) {
                char buf[32];
                extract_string(diff_tok, buf, sizeof(buf));
                double new_diff = atof(buf);
                EnterCriticalSection(&ctx->lock);
                ctx->job.difficulty = new_diff;
                if (new_diff >= 1.0)
                    ctx->job.target_u64 = (uint32_t)(4294967295.0 / new_diff);
                else
                    ctx->job.target_u64 = 0xFFFFFFFF;
                LeaveCriticalSection(&ctx->lock);
                LOG_INFO("[STRATUM] Difficulty: %.1f (target=%016llx)", new_diff, (unsigned long long)ctx->job.target_u64);
            }
        } else if (strcmp(method_name, "mining.set_seed_hash") == 0 &&
                   params && params->type == JSON_ARRAY && params->size >= 1) {
            const json_token_t *seed_tok = json_child(&jp, params, 0);
            if (seed_tok) {
                char seed[128];
                extract_string(seed_tok, seed, sizeof(seed));
                EnterCriticalSection(&ctx->lock);
                free(ctx->job.seed_hash);
                ctx->job.seed_hash = _strdup(seed);
                LeaveCriticalSection(&ctx->lock);
                LOG_INFO("[STRATUM] Seed hash (set_seed_hash): %s", seed);
            }
        } else if (strcmp(method_name, "mining.set_target") == 0 &&
                   params && params->type == JSON_ARRAY && params->size >= 1) {
            const json_token_t *target_tok = json_child(&jp, params, 0);
            if (target_tok) {
                char target[128];
                extract_string(target_tok, target, sizeof(target));
                EnterCriticalSection(&ctx->lock);
                ctx->job.target_u64 = parse_target_le(target);
                LeaveCriticalSection(&ctx->lock);
                LOG_INFO("[STRATUM] Target: %s (%016llx)", target, (unsigned long long)ctx->job.target_u64);
            }
        }
    }
    return 0;
}

int stratum_running(const stratum_ctx_t *ctx) {
    return ctx->running;
}

void stratum_set_running(stratum_ctx_t *ctx, int val) {
    ctx->running = val;
}
