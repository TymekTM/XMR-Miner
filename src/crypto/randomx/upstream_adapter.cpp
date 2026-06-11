#include "crypto/randomx/randomx.h"

#include <algorithm>
#include <new>
#include <thread>
#include <vector>

#include <randomx.h>

struct rx_cache {
    randomx_cache *impl;
    int large_pages;
};

struct rx_dataset {
    randomx_dataset *impl;
    int large_pages;
};

struct rx_vm {
    randomx_vm *impl;
};

extern "C" {
int g_jit_sp_prefetch_hint = 0;
int g_jit_bmi2_mulx = 0;
int g_jit_cfround_elim = 0;
int g_jit_large_pages = 0;
int g_jit_jcc_align = 0;
int g_jit_near_rcp_pool = 0;
int g_aes_hash_fill_prefetch = 0;
int g_jit_double_buffer = 0;
int g_jit_inline_rcp_pool = 0;
int g_jit_rorx = 0;
int g_jit_stack_rcp_pool = 0;
int g_jit_cfround_rorx = 0;
int g_aes_hash_fill_upstream = 0;
}

static randomx_flags cache_flags(int large_pages) {
    int flags = static_cast<int>(randomx_get_flags());
    flags |= RANDOMX_FLAG_JIT;
    flags &= RANDOMX_FLAG_JIT | RANDOMX_FLAG_ARGON2;
    if (large_pages)
        flags |= RANDOMX_FLAG_LARGE_PAGES;
    return static_cast<randomx_flags>(flags);
}

extern "C" rx_cache *rx_alloc_cache(int large_pages) {
    rx_cache *cache = new (std::nothrow) rx_cache{};
    if (!cache)
        return nullptr;
    cache->large_pages = large_pages;
    cache->impl = randomx_alloc_cache(cache_flags(large_pages));
    if (!cache->impl) {
        delete cache;
        return nullptr;
    }
    return cache;
}

extern "C" void rx_init_cache(rx_cache *cache, const void *key, size_t key_size) {
    randomx_init_cache(cache->impl, key, key_size);
}

extern "C" void *rx_get_cache_memory(rx_cache *cache) {
    return randomx_get_cache_memory(cache->impl);
}

extern "C" void rx_free_cache(rx_cache *cache) {
    if (!cache)
        return;
    randomx_release_cache(cache->impl);
    delete cache;
}

extern "C" rx_dataset *rx_alloc_dataset(int large_pages) {
    rx_dataset *dataset = new (std::nothrow) rx_dataset{};
    if (!dataset)
        return nullptr;
    dataset->large_pages = large_pages;
    randomx_flags flags = large_pages ? RANDOMX_FLAG_LARGE_PAGES : RANDOMX_FLAG_DEFAULT;
    dataset->impl = randomx_alloc_dataset(flags);
    if (!dataset->impl) {
        delete dataset;
        return nullptr;
    }
    return dataset;
}

extern "C" void rx_init_dataset(rx_dataset *dataset, rx_cache *cache,
                                  uint32_t start, uint32_t count,
                                  int num_threads, int) {
    const int threads = std::max(1, num_threads);
    std::vector<std::thread> workers;
    workers.reserve(threads);
    for (int i = 0; i < threads; ++i) {
        const uint32_t begin = start + static_cast<uint32_t>(
            (static_cast<uint64_t>(count) * i) / threads);
        const uint32_t end = start + static_cast<uint32_t>(
            (static_cast<uint64_t>(count) * (i + 1)) / threads);
        workers.emplace_back([=]() {
            randomx_init_dataset(dataset->impl, cache->impl, begin, end - begin);
        });
    }
    for (auto &worker : workers)
        worker.join();
}

extern "C" void rx_init_dataset_cached(rx_dataset *dataset, rx_cache *cache,
                                         uint32_t start, uint32_t count,
                                         int num_threads, int physical_cores) {
    rx_init_dataset(dataset, cache, start, count, num_threads, physical_cores);
}

extern "C" void *rx_get_dataset_memory(rx_dataset *dataset) {
    return randomx_get_dataset_memory(dataset->impl);
}

extern "C" void rx_free_dataset(rx_dataset *dataset) {
    if (!dataset)
        return;
    randomx_release_dataset(dataset->impl);
    delete dataset;
}

static randomx_flags vm_flags(int flags, const rx_cache *cache,
                              const rx_dataset *dataset) {
    int out = RANDOMX_FLAG_HARD_AES;
    if (flags & RX_FLAG_JIT)
        out |= RANDOMX_FLAG_JIT;
    if (flags & RX_FLAG_SECURE)
        out |= RANDOMX_FLAG_SECURE;
    if (flags & RX_FLAG_V2)
        out |= RANDOMX_FLAG_V2;
    if (dataset)
        out |= RANDOMX_FLAG_FULL_MEM;
    if ((dataset && dataset->large_pages) || (!dataset && cache && cache->large_pages))
        out |= RANDOMX_FLAG_LARGE_PAGES;
    return static_cast<randomx_flags>(out);
}

extern "C" rx_vm *rx_create_vm(int flags, rx_cache *cache, rx_dataset *dataset) {
    rx_vm *vm = new (std::nothrow) rx_vm{};
    if (!vm)
        return nullptr;
    vm->impl = randomx_create_vm(vm_flags(flags, cache, dataset),
        cache ? cache->impl : nullptr, dataset ? dataset->impl : nullptr);
    if (!vm->impl) {
        delete vm;
        return nullptr;
    }
    return vm;
}

extern "C" void rx_destroy_vm(rx_vm *vm) {
    if (!vm)
        return;
    randomx_destroy_vm(vm->impl);
    delete vm;
}

extern "C" void rx_calculate_hash(rx_vm *vm, const void *input,
                                    size_t input_size, void *output) {
    randomx_calculate_hash(vm->impl, input, input_size, output);
}

extern "C" void rx_calculate_hash_first(rx_vm *vm, const void *input,
                                          size_t input_size) {
    randomx_calculate_hash_first(vm->impl, input, input_size);
}

extern "C" void rx_calculate_hash_next(rx_vm *vm, const void *input,
                                         size_t input_size, void *output) {
    randomx_calculate_hash_next(vm->impl, input, input_size, output);
}

extern "C" void rx_calculate_hash_last(rx_vm *vm, void *output) {
    randomx_calculate_hash_last(vm->impl, output);
}

extern "C" void rx_calculate_hash_dual(rx_vm *vm1, rx_vm *vm2,
                                         const void *input1, size_t input_size1,
                                         const void *input2, size_t input_size2,
                                         void *output1, void *output2) {
    randomx_calculate_hash(vm1->impl, input1, input_size1, output1);
    randomx_calculate_hash(vm2->impl, input2, input_size2, output2);
}

extern "C" void rx_calculate_commitment(const void *input, size_t input_size,
                                          const void *hash_in, void *output) {
    randomx_calculate_commitment(input, input_size, hash_in, output);
}
