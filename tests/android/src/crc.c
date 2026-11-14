// crc32{b,h,w,x} and crc32c{b,h,w,x} against the checksums worked out a bit
// at a time, over many inputs, and against the standard check values. The
// kernel reports the instructions in AT_HWCAP.
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/auxv.h>

#define CRC __attribute__((target("crc"), noinline))

static uint32_t by_bit(uint32_t acc, uint64_t data, int bits, uint32_t poly) {
    for (int i = 0; i < bits; i++) {
        acc ^= (uint32_t)(data >> i) & 1;
        acc = (acc >> 1) ^ (poly & -(acc & 1));
    }
    return acc;
}

// One instruction, by its mnemonic and its data register's width.
#define ONE(name, reg)                                                              \
    CRC static uint32_t name(uint32_t acc, uint64_t data) {                         \
        uint32_t out;                                                               \
        __asm__(#name " %w0, %w1, %" reg "2" : "=r"(out) : "r"(acc), "r"(data)); \
        return out;                                                                 \
    }
ONE(crc32b, "w")
ONE(crc32h, "w")
ONE(crc32w, "w")
ONE(crc32x, "x")
ONE(crc32cb, "w")
ONE(crc32ch, "w")
ONE(crc32cw, "w")
ONE(crc32cx, "x")

static uint32_t crc(int castagnoli, int bits, uint32_t acc, uint64_t data) {
    switch (bits + castagnoli) {
    case 8: return crc32b(acc, data);
    case 16: return crc32h(acc, data);
    case 32: return crc32w(acc, data);
    case 64: return crc32x(acc, data);
    case 9: return crc32cb(acc, data);
    case 17: return crc32ch(acc, data);
    case 33: return crc32cw(acc, data);
    default: return crc32cx(acc, data);
    }
}

// The whole checksum of a buffer, eight bytes at a time then the rest.
static uint32_t whole(int castagnoli, const void *buf, size_t n) {
    const uint8_t *p = buf;
    uint32_t c = ~0u;
    for (; n >= 8; n -= 8, p += 8) {
        uint64_t v;
        memcpy(&v, p, 8);
        c = crc(castagnoli, 64, c, v);
    }
    for (; n; n--, p++) c = crc(castagnoli, 8, c, *p);
    return ~c;
}

int main(void) {
    int status = 0;
    if (!(getauxval(AT_HWCAP) & (1 << 7))) status |= 1;
    if (whole(0, "123456789", 9) != 0xcbf43926u) status |= 2;
    if (whole(1, "123456789", 9) != 0xe3069283u) status |= 4;
    uint64_t seed = 0x9e3779b97f4a7c15ull;
    for (int i = 0; i < 20000 && !(status & 8); i++) {
        seed = seed * 6364136223846793005ull + 1442695040888963407ull;
        uint32_t acc = (uint32_t)(seed >> 32);
        uint64_t data = (seed << 17 | seed >> 47) ^ seed >> 7;
        for (int c = 0; c < 2; c++)
            for (int bits = 8; bits <= 64; bits *= 2)
                if (crc(c, bits, acc, data) != by_bit(acc, data, bits, c ? 0x82f63b78u : 0xedb88320u)) status |= 8;
    }
    // The edges: nothing set, everything set.
    for (int c = 0; c < 2; c++)
        for (int bits = 8; bits <= 64; bits *= 2) {
            uint32_t poly = c ? 0x82f63b78u : 0xedb88320u;
            if (crc(c, bits, 0, 0) != 0 || crc(c, bits, ~0u, ~0ull) != by_bit(~0u, ~0ull, bits, poly)) status |= 16;
        }
    if (status) {
        printf("crc %d\n", status);
        return 1;
    }
    printf("crc ok\n");
    return 0;
}
