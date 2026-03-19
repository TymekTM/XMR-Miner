#pragma once

#include "osdep.h"

void *memory_alloc_large(size_t size);
void *memory_alloc_huge_pages(size_t size);
void memory_free_large(void *ptr, size_t size);
void memory_free_huge_pages(void *ptr, size_t size);
void memory_flush_instruction_cache(void *ptr, size_t size);
