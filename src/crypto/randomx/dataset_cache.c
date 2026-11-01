#include "randomx_internal.h"
#include "common/log.h"
#ifdef _WIN32
#include <windows.h>
#endif
#include <string.h>
#include <stdio.h>

#define DS_CACHE_MAGIC 0x58524443
#define DS_CACHE_VERSION 1

#pragma pack(push, 1)
typedef struct {
    uint32_t magic;
    uint32_t version;
    uint8_t seed[64];
    uint32_t start_item;
    uint32_t count;
    uint64_t checksum;
} ds_cache_header_t;
#pragma pack(pop)

static uint64_t compute_checksum(const uint8_t *data, size_t len) {
    uint64_t hash = 14695981039346656037ULL;
    for (size_t i = 0; i < len; i += 64) {
        size_t chunk = (i + 64 <= len) ? 64 : (len - i);
        for (size_t j = 0; j < chunk; j++) {
            hash ^= data[i + j];
            hash *= 1099511628211ULL;
        }
    }
    return hash;
}

#ifdef _WIN32
static void get_cache_path(const uint8_t *seed, size_t seed_len, char *out, size_t out_size) {
    char seed_hex[65];
    for (size_t i = 0; i < seed_len && i < 32; i++)
        snprintf(seed_hex + i * 2, 3, "%02x", seed[i]);
    seed_hex[seed_len * 2 < 64 ? seed_len * 2 : 64] = '\0';

    char app_data[MAX_PATH];
    DWORD len = GetEnvironmentVariableA("APPDATA", app_data, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) {
        GetTempPathA(MAX_PATH, app_data);
    }

    snprintf(out, out_size, "%s\\xmrig-dataset-cache", app_data);
    CreateDirectoryA(out, NULL);
    snprintf(out, out_size, "%s\\xmrig-dataset-cache\\dataset_%s.bin", app_data, seed_hex);
}

int rx_try_load_dataset_cache(rx_dataset *ds, const uint8_t *seed, size_t seed_len,
                                uint32_t start_item, uint32_t count) {
    char path[MAX_PATH * 2];
    get_cache_path(seed, seed_len, path, sizeof(path));

    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                                OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 0;

    ds_cache_header_t header;
    DWORD bytesRead;
    if (!ReadFile(hFile, &header, sizeof(header), &bytesRead, NULL) || bytesRead != sizeof(header)) {
        CloseHandle(hFile);
        return 0;
    }

    if (header.magic != DS_CACHE_MAGIC || header.version != DS_CACHE_VERSION) {
        CloseHandle(hFile);
        return 0;
    }

    uint8_t expected_seed[64];
    memset(expected_seed, 0, sizeof(expected_seed));
    memcpy(expected_seed, seed, seed_len < 64 ? seed_len : 64);

    if (memcmp(header.seed, expected_seed, 64) != 0 ||
        header.start_item != start_item || header.count != count) {
        CloseHandle(hFile);
        return 0;
    }

    size_t data_size = (size_t)count * RX_CACHE_LINE_SIZE;
    LOG_INFO("[DATASET] Loading cached dataset from disk (%.1f MB)...", (double)data_size / (1024.0 * 1024.0));

    LARGE_INTEGER file_size;
    GetFileSizeEx(hFile, &file_size);
    size_t expected = sizeof(header) + data_size;
    if ((size_t)file_size.QuadPart != expected) {
        LOG_WARN("[DATASET] Cache file size mismatch (expected %zu, got %lld)", expected, file_size.QuadPart);
        CloseHandle(hFile);
        return 0;
    }

    size_t total_read = 0;
    uint64_t running_checksum = 14695981039346656037ULL;
    uint8_t *ptr = ds->memory;

    while (total_read < data_size) {
        DWORD to_read = (data_size - total_read > 16 * 1024 * 1024) ? 16 * 1024 * 1024 : (DWORD)(data_size - total_read);
        if (!ReadFile(hFile, ptr + total_read, to_read, &bytesRead, NULL) || bytesRead == 0) {
            LOG_WARN("[DATASET] Failed to read cached dataset");
            CloseHandle(hFile);
            return 0;
        }
        for (DWORD i = 0; i < bytesRead; i++) {
            running_checksum ^= ptr[total_read + i];
            running_checksum *= 1099511628211ULL;
        }
        total_read += bytesRead;
    }

    CloseHandle(hFile);

    if (running_checksum != header.checksum) {
        LOG_WARN("[DATASET] Cached dataset checksum mismatch, regenerating");
        return 0;
    }

    LOG_INFO("[DATASET] Cached dataset loaded successfully");
    return 1;
}

int rx_save_dataset_cache(rx_dataset *ds, const uint8_t *seed, size_t seed_len,
                            uint32_t start_item, uint32_t count) {
    char path[MAX_PATH * 2];
    get_cache_path(seed, seed_len, path, sizeof(path));

    size_t data_size = (size_t)count * RX_CACHE_LINE_SIZE;

    LOG_INFO("[DATASET] Computing checksum for cache save...");
    uint64_t checksum = compute_checksum(ds->memory, data_size);

    ds_cache_header_t header;
    memset(&header, 0, sizeof(header));
    header.magic = DS_CACHE_MAGIC;
    header.version = DS_CACHE_VERSION;
    memset(header.seed, 0, sizeof(header.seed));
    memcpy(header.seed, seed, seed_len < 64 ? seed_len : 64);
    header.start_item = start_item;
    header.count = count;
    header.checksum = checksum;

    HANDLE hFile = CreateFileA(path, GENERIC_WRITE, 0, NULL,
                                CREATE_ALWAYS, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        LOG_WARN("[DATASET] Cannot create cache file: %s", path);
        return 0;
    }

    DWORD bytesWritten;
    if (!WriteFile(hFile, &header, sizeof(header), &bytesWritten, NULL) || bytesWritten != sizeof(header)) {
        CloseHandle(hFile);
        return 0;
    }

    size_t total_written = 0;
    while (total_written < data_size) {
        DWORD to_write = (data_size - total_written > 16 * 1024 * 1024) ? 16 * 1024 * 1024 : (DWORD)(data_size - total_written);
        if (!WriteFile(hFile, ds->memory + total_written, to_write, &bytesWritten, NULL) || bytesWritten == 0) {
            CloseHandle(hFile);
            return 0;
        }
        total_written += bytesWritten;
    }

    FlushFileBuffers(hFile);
    CloseHandle(hFile);

    LOG_INFO("[DATASET] Cached dataset saved to disk (%.1f MB)", (double)data_size / (1024.0 * 1024.0));
    return 1;
}

void rx_cleanup_old_dataset_caches(void) {
    char dir_path[MAX_PATH];
    char app_data[MAX_PATH];
    DWORD len = GetEnvironmentVariableA("APPDATA", app_data, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) return;

    snprintf(dir_path, sizeof(dir_path), "%s\\xmrig-dataset-cache", app_data);

    WIN32_FIND_DATAA fd;
    char search_path[MAX_PATH];
    snprintf(search_path, sizeof(search_path), "%s\\dataset_*.bin", dir_path);

    HANDLE hFind = FindFirstFileA(search_path, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        char full_path[MAX_PATH * 2];
        snprintf(full_path, sizeof(full_path), "%s\\%s", dir_path, fd.cFileName);
        DeleteFileA(full_path);
    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);
}

#else /* POSIX */

#include <stdlib.h>
#include <sys/stat.h>
#include <errno.h>

static int get_cache_dir(char *out, size_t out_size) {
    const char *dir = getenv("RX_DATASET_CACHE_DIR");
    if (dir && *dir) {
        snprintf(out, out_size, "%s", dir);
    } else {
        const char *xdg = getenv("XDG_CACHE_HOME");
        const char *home = getenv("HOME");
        if (xdg && *xdg) snprintf(out, out_size, "%s/xmr-miner-dataset-cache", xdg);
        else if (home && *home) snprintf(out, out_size, "%s/.cache/xmr-miner-dataset-cache", home);
        else snprintf(out, out_size, "/tmp/xmr-miner-dataset-cache");
    }
    return 1;
}

static void get_cache_path(const uint8_t *seed, size_t seed_len, char *out, size_t out_size) {
    char seed_hex[65];
    size_t n = seed_len < 32 ? seed_len : 32;
    for (size_t i = 0; i < n; i++)
        snprintf(seed_hex + i * 2, 3, "%02x", seed[i]);
    seed_hex[n * 2] = '\0';
    char dir[1024];
    get_cache_dir(dir, sizeof(dir));
    /* create parent (~/.cache) and the cache directory itself */
    char parent[1024];
    snprintf(parent, sizeof(parent), "%s", dir);
    char *slash = strrchr(parent, '/');
    if (slash && slash != parent) { *slash = 0; mkdir(parent, 0755); }
    mkdir(dir, 0755);
    snprintf(out, out_size, "%s/dataset_%s.bin", dir, seed_hex);
}

static int cache_disabled(void) {
    const char *v = getenv("RX_NO_DATASET_CACHE");
    return v && *v && *v != '0';
}

int rx_try_load_dataset_cache(rx_dataset *ds, const uint8_t *seed, size_t seed_len,
                                uint32_t start_item, uint32_t count) {
    if (cache_disabled()) return 0;
    char path[2048];
    get_cache_path(seed, seed_len, path, sizeof(path));
    FILE *f = fopen(path, "rb");
    if (!f) return 0;

    ds_cache_header_t header;
    if (fread(&header, sizeof(header), 1, f) != 1 ||
        header.magic != DS_CACHE_MAGIC || header.version != DS_CACHE_VERSION) {
        fclose(f);
        return 0;
    }
    uint8_t expected_seed[64];
    memset(expected_seed, 0, sizeof(expected_seed));
    memcpy(expected_seed, seed, seed_len < 64 ? seed_len : 64);
    if (memcmp(header.seed, expected_seed, 64) != 0 ||
        header.start_item != start_item || header.count != count) {
        fclose(f);
        return 0;
    }
    size_t data_size = (size_t)count * RX_CACHE_LINE_SIZE;
    LOG_INFO("[DATASET] Loading cached dataset from disk (%.1f MB)...", (double)data_size / (1024.0 * 1024.0));
    uint8_t *dst = ds->memory + (size_t)start_item * RX_CACHE_LINE_SIZE;
    size_t total = 0;
    while (total < data_size) {
        size_t chunk = data_size - total > (64u << 20) ? (64u << 20) : data_size - total;
        size_t got = fread(dst + total, 1, chunk, f);
        if (got == 0) break;
        total += got;
    }
    fclose(f);
    if (total != data_size) {
        LOG_WARN("[DATASET] Cache file truncated");
        return 0;
    }
    if (compute_checksum(dst, data_size) != header.checksum) {
        LOG_WARN("[DATASET] Cached dataset checksum mismatch, regenerating");
        return 0;
    }
    LOG_INFO("[DATASET] Cached dataset loaded successfully");
    return 1;
}

int rx_save_dataset_cache(rx_dataset *ds, const uint8_t *seed, size_t seed_len,
                            uint32_t start_item, uint32_t count) {
    if (cache_disabled()) return 0;
    char path[2048], tmp[2100];
    get_cache_path(seed, seed_len, path, sizeof(path));
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    size_t data_size = (size_t)count * RX_CACHE_LINE_SIZE;
    const uint8_t *src = ds->memory + (size_t)start_item * RX_CACHE_LINE_SIZE;

    ds_cache_header_t header;
    memset(&header, 0, sizeof(header));
    header.magic = DS_CACHE_MAGIC;
    header.version = DS_CACHE_VERSION;
    memcpy(header.seed, seed, seed_len < 64 ? seed_len : 64);
    header.start_item = start_item;
    header.count = count;
    header.checksum = compute_checksum(src, data_size);

    FILE *f = fopen(tmp, "wb");
    if (!f) {
        LOG_WARN("[DATASET] Cannot create cache file: %s", tmp);
        return 0;
    }
    int ok = fwrite(&header, sizeof(header), 1, f) == 1 &&
             fwrite(src, 1, data_size, f) == data_size;
    ok = (fclose(f) == 0) && ok;
    if (!ok || rename(tmp, path) != 0) {
        remove(tmp);
        return 0;
    }
    LOG_INFO("[DATASET] Cached dataset saved to %s (%.1f MB)", path, (double)data_size / (1024.0 * 1024.0));
    return 1;
}

void rx_cleanup_old_dataset_caches(void) {}

#endif
