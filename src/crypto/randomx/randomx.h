#ifndef RX_RANDOMX_H
#define RX_RANDOMX_H

#include <stddef.h>
#include <stdint.h>

#define RX_HASH_SIZE 32
#define RX_DATASET_ITEM_SIZE 64

typedef struct rx_cache rx_cache;
typedef struct rx_dataset rx_dataset;
typedef struct rx_vm rx_vm;

rx_cache *rx_alloc_cache(int large_pages);
void rx_init_cache(rx_cache *cache, const void *key, size_t key_size);
void *rx_get_cache_memory(rx_cache *cache);
void rx_free_cache(rx_cache *cache);

rx_dataset *rx_alloc_dataset(int large_pages);
void rx_init_dataset(rx_dataset *ds, rx_cache *cache, uint32_t start, uint32_t count);
void *rx_get_dataset_memory(rx_dataset *ds);
void rx_free_dataset(rx_dataset *ds);

rx_vm *rx_create_vm(int full_mem, rx_cache *cache, rx_dataset *dataset);
void rx_destroy_vm(rx_vm *vm);
void rx_calculate_hash(rx_vm *vm, const void *input, size_t input_size, void *output);
void rx_calculate_hash_first(rx_vm *vm, const void *input, size_t input_size);
void rx_calculate_hash_next(rx_vm *vm, const void *next_input, size_t next_input_size, void *output);
void rx_calculate_hash_last(rx_vm *vm, void *output);

#endif
