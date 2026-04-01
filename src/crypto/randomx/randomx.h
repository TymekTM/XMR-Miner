#ifndef RX_RANDOMX_H
#define RX_RANDOMX_H

#include <stddef.h>
#include <stdint.h>

#define RX_HASH_SIZE 32
#define RX_DATASET_ITEM_SIZE 64

#define RX_FLAG_DEFAULT     0
#define RX_FLAG_JIT         1
#define RX_FLAG_V2          16
#define RX_FLAG_SECURE      32

#define RX_DATASET_BASE_SIZE  2147483648ULL
#define RX_DATASET_EXTRA_SIZE 33554368ULL
#define RX_DATASET_ITEMS      (RX_DATASET_BASE_SIZE / 64)
#define RX_DATASET_EXTRA_ITEMS (RX_DATASET_EXTRA_SIZE / 64)

typedef struct rx_cache rx_cache;
typedef struct rx_dataset rx_dataset;
typedef struct rx_vm rx_vm;

rx_cache *rx_alloc_cache(int large_pages);
void rx_init_cache(rx_cache *cache, const void *key, size_t key_size);
void *rx_get_cache_memory(rx_cache *cache);
void rx_free_cache(rx_cache *cache);

rx_dataset *rx_alloc_dataset(int large_pages);
void rx_init_dataset(rx_dataset *ds, rx_cache *cache, uint32_t start, uint32_t count, int num_threads, int num_physical_cores);
void rx_init_dataset_cached(rx_dataset *ds, rx_cache *cache, uint32_t start, uint32_t count, int num_threads, int num_physical_cores);
void *rx_get_dataset_memory(rx_dataset *ds);
void rx_free_dataset(rx_dataset *ds);
void rx_init_dataset_item(rx_cache *cache, uint8_t *out, uint64_t item_number);

rx_vm *rx_create_vm(int flags, rx_cache *cache, rx_dataset *dataset);
void rx_destroy_vm(rx_vm *vm);
void rx_calculate_hash(rx_vm *vm, const void *input, size_t input_size, void *output);
void rx_calculate_hash_dual(rx_vm *vm1, rx_vm *vm2,
    const void *input1, size_t input1_size,
    const void *input2, size_t input2_size,
    void *output1, void *output2);
void rx_calculate_hash_first(rx_vm *vm, const void *input, size_t input_size);
void rx_calculate_hash_next(rx_vm *vm, const void *next_input, size_t next_input_size, void *output);
void rx_calculate_hash_last(rx_vm *vm, void *output);
void rx_vm_run_n(rx_vm *vm, void *seed, uint32_t iterations);
void rx_calculate_commitment(const void *input, size_t input_size, const void *hash_in, void *com_out);

#endif
