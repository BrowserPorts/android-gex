// The top byte of a data address is ignored by every kind of access, not
// only a plain load or store: pairs, register-offset and vector forms,
// exclusives, the LSE atomics, and dc zva, which bionic's memset zeroes
// with. Three tags: the one Android's allocator puts on its own header
// pointers, the one bionic puts on heap pointers, and all ones.
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define TAG(p, t) ((void *)(((uintptr_t)(p) & 0x00ffffffffffffffull) | ((uintptr_t)(t) << 56)))
#define LSE __attribute__((target("lse"), noinline))
LSE static uint64_t cas(uint64_t *p, uint64_t want, uint64_t with) {
    __asm__ volatile("casal %0, %1, [%2]" : "+r"(want) : "r"(with), "r"(p) : "memory");
    return want;
}
LSE static uint64_t ldadd(uint64_t *p, uint64_t by) {
    uint64_t old;
    __asm__ volatile("ldaddal %1, %0, [%2]" : "=&r"(old) : "r"(by), "r"(p) : "memory");
    return old;
}
LSE static uint64_t swp(uint64_t *p, uint64_t v) {
    uint64_t old;
    __asm__ volatile("swpal %1, %0, [%2]" : "=&r"(old) : "r"(v), "r"(p) : "memory");
    return old;
}
int main(void) {
    for (int t = 0; t < 3; t++) {
        int tag = (int[]){0x02, 0xb4, 0xff}[t], bad = 0;
        uint64_t *raw = TAG(aligned_alloc(64, 1024), 0);
        uint64_t *p = TAG(raw, tag);
        memset(raw, 0xff, 1024);
        __asm__ volatile("dc zva, %0" : : "r"(p + 8) : "memory");
        for (int i = 0; i < 8; i++) if (raw[8 + i] != 0) bad |= 1;
        if (raw[7] != ~0ull || raw[16] != ~0ull) bad |= 1;
        uint64_t a = 1, b = 2, c = 0, d = 0;
        __asm__ volatile("stp %0, %1, [%2]" : : "r"(a), "r"(b), "r"(p) : "memory");
        __asm__ volatile("ldp %0, %1, [%2]" : "=&r"(c), "=&r"(d) : "r"(p) : "memory");
        if (raw[0] != 1 || raw[1] != 2 || c != 1 || d != 2) bad |= 2;
        uint64_t idx = 1, v = 0;
        __asm__ volatile("ldr %0, [%1, %2, lsl #3]" : "=&r"(v) : "r"(p), "r"(idx) : "memory");
        if (v != 2) bad |= 4;
        __asm__ volatile("ldr q0, [%0]\n\tstr q0, [%0, #128]\n\tld1 {v1.16b}, [%0]\n\tst1 {v1.16b}, [%1]" : : "r"(p), "r"(p + 20) : "v0", "v1", "memory");
        if (raw[16] != 1 || raw[17] != 2 || raw[20] != 1 || raw[21] != 2) bad |= 8;
        uint64_t x = 0;
        uint32_t st = 9;
        __asm__ volatile("ldxr %0, [%2]\n\tadd %0, %0, #1\n\tstxr %w1, %0, [%2]" : "=&r"(x), "=&r"(st) : "r"(p + 1) : "memory");
        if (st != 0 || raw[1] != 3) bad |= 16;
        _Atomic uint64_t *at = (void *)(p + 4);
        atomic_store(at, 5);
        uint64_t e = 5;
        if (!atomic_compare_exchange_strong(at, &e, 6) || atomic_fetch_add(at, 10) != 6 || atomic_exchange(at, 3) != 16 || atomic_load(at) != 3 || raw[4] != 3) bad |= 32;
        raw[5] = 5;
        if (cas(p + 5, 5, 6) != 5 || raw[5] != 6 || cas(p + 5, 5, 7) != 6 || raw[5] != 6) bad |= 64;
        if (ldadd(p + 5, 10) != 6 || raw[5] != 16 || swp(p + 5, 3) != 16 || raw[5] != 3) bad |= 128;
        memcpy(p + 30, "hello", 6);
        if (strcmp((char *)raw + 240, "hello") || ((char *)p)[241] != 'e') bad |= 256;
        char *big = TAG(calloc(1, 8192), 0);
        memset(TAG(big, tag), 0x55, 8192);
        memset(TAG(big, tag), 0, 8192);
        for (int i = 0; i < 8192; i++) if (big[i]) bad |= 512;
        if (bad) { printf("tag %#x bad %d\n", tag, bad); return 1; }
    }
    printf("tbi ok\n");
    return 0;
}
