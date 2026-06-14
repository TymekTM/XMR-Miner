#include "blob.h"
#include "crypto/keccak/keccak.h"
#include "crypto/randomx/randomx.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

void hex_decode(const char *hex, uint8_t *out, int max_bytes) {
    int hex_len = (int)strlen(hex);
    int byte_len = hex_len / 2;
    if (byte_len > max_bytes) byte_len = max_bytes;
    for (int i = 0; i < byte_len; i++) {
        char h[3] = { hex[i * 2], hex[i * 2 + 1], 0 };
        out[i] = (uint8_t)strtoul(h, NULL, 16);
    }
}

void hex_encode(const uint8_t *data, int len, char *out) {
    for (int i = 0; i < len; i++)
        snprintf(out + i * 2, 3, "%02x", data[i]);
    out[len * 2] = '\0';
}

void hex_encode_rev(const uint8_t *data, int len, char *out) {
    for (int i = 0; i < len; i++)
        snprintf(out + i * 2, 3, "%02x", data[len - 1 - i]);
    out[len * 2] = '\0';
}

int hex_decode_seed(const char *hex, uint8_t *out) {
    int hex_len = (int)strlen(hex);
    if (hex_len != 64) return -1;
    for (int i = 0; i < 32; i++) {
        char h[3] = { hex[i * 2], hex[i * 2 + 1], 0 };
        out[i] = (uint8_t)strtoul(h, NULL, 16);
    }
    return 0;
}

int algo_to_rx_flags(const char *algo) {
    if (algo && (strcmp(algo, "rx/1") == 0 || strcmp(algo, "rx/v2") == 0))
        return RX_FLAG_V2;
    return RX_FLAG_DEFAULT;
}

int encode_varint(uint64_t val, uint8_t *out) {
    int i = 0;
    do {
        uint8_t byte = val & 0x7F;
        val >>= 7;
        if (val > 0) byte |= 0x80;
        out[i++] = byte;
    } while (val > 0);
    return i;
}

int decode_varint(const uint8_t *p, int max_bytes) {
    int val = 0, shift = 0, i;
    for (i = 0; i < max_bytes && i < 9; i++) {
        val |= (p[i] & 0x7F) << shift;
        if (!(p[i] & 0x80)) return i + 1;
        shift += 7;
    }
    return -1;
}

int get_monero_nonce_offset(const uint8_t *blob, int blob_len) {
    if (blob_len < 43) return -1;
    int ts_len = decode_varint(blob + 2, blob_len - 2);
    if (ts_len < 1) return -1;
    return 2 + ts_len + 32;
}

void format_nonce_hex(uint32_t nonce, int is_monero, char *out, size_t out_size) {
    if (is_monero) {
        snprintf(out, out_size, "%02x%02x%02x%02x",
                 (unsigned)(nonce & 0xFF),
                 (unsigned)((nonce >> 8) & 0xFF),
                 (unsigned)((nonce >> 16) & 0xFF),
                 (unsigned)((nonce >> 24) & 0xFF));
    } else {
        snprintf(out, out_size, "%08x", nonce);
    }
}

int share_meets_target(const uint8_t *hash, uint64_t target, int is_monero) {
    if (is_monero) {
        return read_u64_le(hash + 24) <= target;
    }
    return read_u32_le(hash) <= (uint32_t)target;
}

int build_hashing_blob(stratum_job_t *job, uint8_t *blob, uint32_t nonce) {
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
    keccak256(coinbase_tx, full_tx_len, prefix_hash);

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
        return -1;
    }
    return 0;
}
