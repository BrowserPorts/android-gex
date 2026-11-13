// SADDLV and UADDLV: every lane widened to twice its size and summed, for
// each arrangement the instructions have (8B, 16B, 4H, 8H, 4S). clang makes
// UADDLV of a population count, which is how bionic meets it.
#include <arm_neon.h>
#include <stdint.h>
#include <stdio.h>

#define CHECK(c)                                          \
    do {                                                  \
        if (!(c)) {                                       \
            printf("%s:%d: %s\n", __FILE__, __LINE__, #c); \
            return 1;                                     \
        }                                                 \
    } while (0)

// Inputs the compiler cannot see through.
static volatile uint8_t bytes[16] = {0xff, 0x80, 0x7f, 1, 0, 0xfe, 0x55, 0xaa, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static volatile uint16_t halves[8] = {0xffff, 0x8000, 0x7fff, 1, 0xffff, 0xffff, 0xffff, 0xfffe};
static volatile uint32_t words[4] = {0xffffffffu, 0x80000000u, 0x7fffffffu, 0xfffffffeu};

int main(void) {
    uint8_t b[16];
    uint16_t h[8];
    uint32_t w[4];
    for (int i = 0; i < 16; i++) b[i] = bytes[i];
    for (int i = 0; i < 8; i++) h[i] = halves[i];
    for (int i = 0; i < 4; i++) w[i] = words[i];

    uint32_t ub8 = 0, ub16 = 0, uh4 = 0, uh8 = 0;
    int32_t sb8 = 0, sb16 = 0, sh4 = 0, sh8 = 0;
    uint64_t uw = 0;
    int64_t sw = 0;
    for (int i = 0; i < 16; i++) {
        ub16 += b[i];
        sb16 += (int8_t)b[i];
        if (i < 8) ub8 += b[i], sb8 += (int8_t)b[i];
    }
    for (int i = 0; i < 8; i++) {
        uh8 += h[i];
        sh8 += (int16_t)h[i];
        if (i < 4) uh4 += h[i], sh4 += (int16_t)h[i];
    }
    for (int i = 0; i < 4; i++) uw += w[i], sw += (int32_t)w[i];

    CHECK(vaddlv_u8(vld1_u8(b)) == (uint16_t)ub8);
    CHECK(vaddlvq_u8(vld1q_u8(b)) == (uint16_t)ub16);
    CHECK(vaddlv_s8(vld1_s8((int8_t *)b)) == (int16_t)sb8);
    CHECK(vaddlvq_s8(vld1q_s8((int8_t *)b)) == (int16_t)sb16);
    CHECK(vaddlv_u16(vld1_u16(h)) == uh4);
    CHECK(vaddlvq_u16(vld1q_u16(h)) == uh8);
    CHECK(vaddlv_s16(vld1_s16((int16_t *)h)) == sh4);
    CHECK(vaddlvq_s16(vld1q_s16((int16_t *)h)) == sh8);
    CHECK(vaddlvq_u32(vld1q_u32(w)) == uw);
    CHECK(vaddlvq_s32(vld1q_s32((int32_t *)w)) == sw);

    // The destination is one lane; the rest of the register is zero,
    // whatever it held.
    register uint8x16_t src __asm__("v1") = vld1q_u8(b);
    register uint64x2_t dst __asm__("v0") = vdupq_n_u64(~0ull);
    __asm__("uaddlv h0, v1.16b" : "+w"(dst) : "w"(src));
    CHECK(vgetq_lane_u64(dst, 0) == ub16 && vgetq_lane_u64(dst, 1) == 0);
    dst = vdupq_n_u64(~0ull);
    __asm__("saddlv h0, v1.16b" : "+w"(dst) : "w"(src));
    CHECK(vgetq_lane_u64(dst, 0) == (uint16_t)sb16 && vgetq_lane_u64(dst, 1) == 0);

    volatile uint64_t x = 0xf0f0f0f0f0f0f0f0ull;
    CHECK(__builtin_popcountll(x) == 32);

    printf("simd ok\n");
    return 0;
}
