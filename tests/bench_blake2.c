#include "crypto/blake2/blake2.h"
#include <stdio.h>
#include <windows.h>

int main() {
    uint8_t input[256];
    uint8_t output[64];
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    
    for (int i = 0; i < 100000; i++) {
        blake2b(output, 64, input, 256, NULL, 0);
    }
    
    QueryPerformanceCounter(&end);
    double time = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;
    printf("100000 blake2b hashes took %.5f s\n", time);
    return 0;
}
