#include "crypto/randomx/randomx_internal.h"
#include <stdio.h>
#include <windows.h>
#include <stdlib.h>

int main() {
    uint8_t* mem = _aligned_malloc(2097152, 64);
    uint8_t hash[64];
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    
    for (int i = 0; i < 1000; i++) {
        rx_hash_aes1rx4(mem, 2097152, hash);
    }
    
    QueryPerformanceCounter(&end);
    double time = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;
    printf("1000 AES Scratchpad hashes took %.5f s\n", time);
    _aligned_free(mem);
    return 0;
}
