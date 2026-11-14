// The cryptographic extension: AES-128 both ways over the FIPS-197 example,
// SHA-256 of "abc" through the four SHA-256 instructions, and the
// polynomial multiplies, on bytes and on doublewords, against one worked
// out a bit at a time. The kernel reports all of it in AT_HWCAP.
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/auxv.h>

#define CRYPTO __attribute__((target("aes,sha2"), noinline))

typedef uint8_t u8x16 __attribute__((vector_size(16)));
typedef uint32_t u32x4 __attribute__((vector_size(16)));
typedef uint64_t u64x2 __attribute__((vector_size(16)));

// The FIPS-197 appendix C.1 round keys for 000102...0f.
static const uint8_t rk[11][16] = {
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
    {0xd6, 0xaa, 0x74, 0xfd, 0xd2, 0xaf, 0x72, 0xfa, 0xda, 0xa6, 0x78, 0xf1, 0xd6, 0xab, 0x76, 0xfe},
    {0xb6, 0x92, 0xcf, 0x0b, 0x64, 0x3d, 0xbd, 0xf1, 0xbe, 0x9b, 0xc5, 0x00, 0x68, 0x30, 0xb3, 0xfe},
    {0xb6, 0xff, 0x74, 0x4e, 0xd2, 0xc2, 0xc9, 0xbf, 0x6c, 0x59, 0x0c, 0xbf, 0x04, 0x69, 0xbf, 0x41},
    {0x47, 0xf7, 0xf7, 0xbc, 0x95, 0x35, 0x3e, 0x03, 0xf9, 0x6c, 0x32, 0xbc, 0xfd, 0x05, 0x8d, 0xfd},
    {0x3c, 0xaa, 0xa3, 0xe8, 0xa9, 0x9f, 0x9d, 0xeb, 0x50, 0xf3, 0xaf, 0x57, 0xad, 0xf6, 0x22, 0xaa},
    {0x5e, 0x39, 0x0f, 0x7d, 0xf7, 0xa6, 0x92, 0x96, 0xa7, 0x55, 0x3d, 0xc1, 0x0a, 0xa3, 0x1f, 0x6b},
    {0x14, 0xf9, 0x70, 0x1a, 0xe3, 0x5f, 0xe2, 0x8c, 0x44, 0x0a, 0xdf, 0x4d, 0x4e, 0xa9, 0xc0, 0x26},
    {0x47, 0x43, 0x87, 0x35, 0xa4, 0x1c, 0x65, 0xb9, 0xe0, 0x16, 0xba, 0xf4, 0xae, 0xbf, 0x7a, 0xd2},
    {0x54, 0x99, 0x32, 0xd1, 0xf0, 0x85, 0x57, 0x68, 0x10, 0x93, 0xed, 0x9c, 0xbe, 0x2c, 0x97, 0x4e},
    {0x13, 0x11, 0x1d, 0x7f, 0xe3, 0x94, 0x4a, 0x17, 0xf3, 0x07, 0xa7, 0x8b, 0x4d, 0x2b, 0x30, 0xc5},
};
static const u8x16 plain = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
static const u8x16 cipher = {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a};

static u8x16 key(int r) {
    u8x16 k;
    memcpy(&k, rk[r], 16);
    return k;
}

CRYPTO static u8x16 encrypt(u8x16 s) {
    for (int r = 0; r < 9; r++) {
        u8x16 k = key(r);
        __asm__("aese %0.16b, %1.16b\n\taesmc %0.16b, %0.16b" : "+w"(s) : "w"(k));
    }
    u8x16 k9 = key(9);
    __asm__("aese %0.16b, %1.16b" : "+w"(s) : "w"(k9));
    return s ^ key(10);
}

// The equivalent inverse cipher: the middle round keys through aesimc.
CRYPTO static u8x16 decrypt(u8x16 s) {
    u8x16 k = key(10);
    __asm__("aesd %0.16b, %1.16b\n\taesimc %0.16b, %0.16b" : "+w"(s) : "w"(k));
    for (int r = 9; r >= 2; r--) {
        k = key(r);
        __asm__("aesimc %1.16b, %1.16b\n\taesd %0.16b, %1.16b\n\taesimc %0.16b, %0.16b" : "+w"(s), "+w"(k));
    }
    k = key(1);
    __asm__("aesimc %1.16b, %1.16b\n\taesd %0.16b, %1.16b" : "+w"(s), "+w"(k));
    return s ^ key(0);
}

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

// One block into the state, four rounds an iteration.
CRYPTO static void sha256_block(uint32_t h[8], const uint32_t w[16]) {
    u32x4 abcd, efgh, m[4];
    memcpy(&abcd, h, 16);
    memcpy(&efgh, h + 4, 16);
    memcpy(m, w, 64);
    u32x4 a0 = abcd, e0 = efgh;
    for (int i = 0; i < 16; i++) {
        if (i >= 4) {
            u32x4 x = m[i & 3], n1 = m[(i + 1) & 3], n2 = m[(i + 2) & 3], n3 = m[(i + 3) & 3];
            __asm__("sha256su0 %0.4s, %1.4s\n\tsha256su1 %0.4s, %2.4s, %3.4s" : "+w"(x) : "w"(n1), "w"(n2), "w"(n3));
            m[i & 3] = x;
        }
        u32x4 k;
        memcpy(&k, K + 4 * i, 16);
        u32x4 wk = m[i & 3] + k, before = abcd;
        __asm__("sha256h %q0, %q1, %2.4s" : "+w"(abcd) : "w"(efgh), "w"(wk));
        __asm__("sha256h2 %q0, %q1, %2.4s" : "+w"(efgh) : "w"(before), "w"(wk));
    }
    abcd += a0;
    efgh += e0;
    memcpy(h, &abcd, 16);
    memcpy(h + 4, &efgh, 16);
}

// Carry-less multiply, a bit at a time: the low and high halves of a 64 by
// 64, and an 8 by 8.
static void clmul64(uint64_t a, uint64_t b, uint64_t out[2]) {
    out[0] = out[1] = 0;
    for (int i = 0; i < 64; i++)
        if (b >> i & 1) {
            out[0] ^= a << i;
            if (i) out[1] ^= a >> (64 - i);
        }
}
static uint16_t clmul8(uint8_t a, uint8_t b) {
    uint16_t r = 0;
    for (int i = 0; i < 8; i++)
        if (b >> i & 1) r ^= (uint16_t)a << i;
    return r;
}

CRYPTO static int pmull_ok(u8x16 a, u8x16 b) {
    u8x16 lo, hi;
    u64x2 q, q2, a64 = (u64x2)a, b64 = (u64x2)b;
    __asm__("pmull %0.8h, %1.8b, %2.8b" : "=w"(lo) : "w"(a), "w"(b));
    __asm__("pmull2 %0.8h, %1.16b, %2.16b" : "=w"(hi) : "w"(a), "w"(b));
    __asm__("pmull %0.1q, %1.1d, %2.1d" : "=w"(q) : "w"(a), "w"(b));
    __asm__("pmull2 %0.1q, %1.2d, %2.2d" : "=w"(q2) : "w"(a), "w"(b));
    for (int i = 0; i < 8; i++) {
        uint16_t l, h;
        memcpy(&l, (uint8_t *)&lo + 2 * i, 2);
        memcpy(&h, (uint8_t *)&hi + 2 * i, 2);
        if (l != clmul8(a[i], b[i]) || h != clmul8(a[i + 8], b[i + 8])) return 0;
    }
    uint64_t want[2];
    clmul64(a64[0], b64[0], want);
    if (q[0] != want[0] || q[1] != want[1]) return 0;
    clmul64(a64[1], b64[1], want);
    return q2[0] == want[0] && q2[1] == want[1];
}

int main(void) {
    int status = 0;
    // AES, PMULL, SHA1 and SHA2.
    if ((getauxval(AT_HWCAP) & 0x78) != 0x78) status |= 1;

    u8x16 c = encrypt(plain), p = decrypt(cipher);
    if (memcmp(&c, &cipher, 16)) status |= 2;
    if (memcmp(&p, &plain, 16)) status |= 4;

    uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    uint32_t block[16] = {0x61626380, [15] = 0x18};
    static const uint32_t abc[8] = {0xba7816bf, 0x8f01cfea, 0x414140de, 0x5dae2223, 0xb00361a3, 0x96177a9c, 0xb410ff61, 0xf20015ad};
    sha256_block(h, block);
    if (memcmp(h, abc, 32)) status |= 8;

    uint64_t seed = 0x9e3779b97f4a7c15ull;
    for (int i = 0; i < 2000 && !(status & 16); i++) {
        u64x2 a, b;
        for (int j = 0; j < 2; j++) {
            seed = seed * 6364136223846793005ull + 1442695040888963407ull;
            a[j] = seed ^ seed >> 29;
            seed = seed * 6364136223846793005ull + 1442695040888963407ull;
            b[j] = seed ^ seed >> 31;
        }
        if (!pmull_ok((u8x16)a, (u8x16)b)) status |= 16;
    }
    u8x16 ones = (u8x16)(u64x2){~0ull, ~0ull};
    if (!pmull_ok(ones, ones) || !pmull_ok((u8x16){0}, ones)) status |= 32;

    if (status) {
        printf("crypto %d\n", status);
        return 1;
    }
    printf("crypto ok\n");
    return 0;
}
