#include "crypto/blake2/blake2b.h"
#include <stdio.h>
#include <string.h>

static void dump(const char *label, const u8 *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) printf("%02x", data[i]);
    printf("\n");
}

int main(void) {
    u8 hash[64];

    blake2b(hash, 64, "", 0, NULL, 0);
    dump("blake2b(\"\")", hash, 64);

    blake2b(hash, 64, "abc", 3, NULL, 0);
    dump("blake2b(\"abc\")", hash, 64);

    u8 input[61];
    int pos = 0;

    u32 v = 1; memcpy(input+pos, &v, 4); pos += 4;
    v = 0; memcpy(input+pos, &v, 4); pos += 4;
    v = 262144; memcpy(input+pos, &v, 4); pos += 4;
    v = 3; memcpy(input+pos, &v, 4); pos += 4;
    v = 0x13; memcpy(input+pos, &v, 4); pos += 4;
    v = 0; memcpy(input+pos, &v, 4); pos += 4;
    v = 12; memcpy(input+pos, &v, 4); pos += 4;
    memcpy(input+pos, "test key 000", 12); pos += 12;
    v = 8; memcpy(input+pos, &v, 4); pos += 4;
    memcpy(input+pos, "RandomX\x03", 8); pos += 8;
    v = 0; memcpy(input+pos, &v, 4); pos += 4;
    v = 0; memcpy(input+pos, &v, 4); pos += 4;

    printf("Input length: %d\n", pos);
    dump("Input bytes", input, pos);

    blake2b(hash, 64, input, pos, NULL, 0);
    dump("H0 (standalone)", hash, 64);

    blake2b_state S;
    blake2b_init(&S, 64);
    printf("Our blake2b state h[0..3] after init = ");
    for (int i = 0; i < 4; i++) printf("%016llx", (unsigned long long)S.h[i]);
    printf("\n");

    {
        typedef struct {
            u8 digest_length;
            u8 key_length;
            u8 fanout;
            u8 depth;
            u32 leaf_length;
            u32 node_offset;
            u32 xof_length;
            u8 node_depth;
            u8 inner_length;
            u8 reserved[14];
            u8 salt[16];
            u8 personal[16];
        } test_param;
        test_param P2;
        memset(&P2, 0, sizeof(P2));
        P2.digest_length = 64;
        P2.fanout = 1;
        P2.depth = 1;
        printf("Our param bytes: ");
        for (int i = 0; i < 64; i++) printf("%02x", ((u8*)&P2)[i]);
        printf("\n");
        printf("sizeof(test_param) = %d\n", (int)sizeof(P2));
    }
    blake2b_update(&S, input, pos);
    blake2b_final(&S, hash, 64);
    dump("H0 (incremental)", hash, 64);

    printf("\nExpected: 340575f85795c20ed0e07f7356a02cf55018567f6ad34f24590ff8f8b12ffaaad9348a3070f3f589e4a2b4187cd267fc0498080fb1e077c4fc2206732d0c14b2\n");

    return 0;
}
