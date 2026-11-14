// SADDLV and UADDLV: every lane widened to twice its size and summed, for
// each arrangement the instructions have (8B, 16B, 4H, 8H, 4S). clang makes
// UADDLV of a population count, which is how bionic meets it.
//
// And the scalar floating-point multiplies by a vector's element (fmla,
// fmls, fmul, fmulx), the accumulating ones fused.
#include <arm_neon.h>
#include <math.h>
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

    // The scalar multiplies by one lane of a vector. fmla and fmls round
    // once, as fma does: with these operands a product rounded first loses
    // the whole answer. The result is a scalar, the register's rest zero.
    volatile double da = 1.0 + 0x1p-30, db = 1.0 - 0x1p-30, dacc = -1.0;
    register float64x2_t vd __asm__("v4") = vdupq_n_f64(dacc);
    register float64x2_t vn __asm__("v2") = vdupq_n_f64(da);
    register float64x2_t vm __asm__("v3") = vsetq_lane_f64(db, vdupq_n_f64(99.0), 1);
    vd = vsetq_lane_f64(7.0, vd, 1);
    __asm__("fmla d4, d2, v3.d[1]" : "+w"(vd) : "w"(vn), "w"(vm));
    CHECK(vgetq_lane_f64(vd, 0) == fma(da, db, dacc) && vgetq_lane_f64(vd, 0) == -0x1p-60 && vgetq_lane_f64(vd, 1) == 0);
    vd = vdupq_n_f64(1.0);
    __asm__("fmls d4, d2, v3.d[1]" : "+w"(vd) : "w"(vn), "w"(vm));
    CHECK(vgetq_lane_f64(vd, 0) == fma(-da, db, 1.0) && vgetq_lane_f64(vd, 0) == 0x1p-60 && vgetq_lane_f64(vd, 1) == 0);
    vd = vdupq_n_f64(5.0);
    __asm__("fmul d4, d2, v3.d[0]" : "+w"(vd) : "w"(vn), "w"(vm));
    CHECK(vgetq_lane_f64(vd, 0) == da * 99.0 && vgetq_lane_f64(vd, 1) == 0);
    volatile float fa = 1.0f + 0x1p-12f, fb = 1.0f - 0x1p-12f;
    register float32x4_t wd __asm__("v4") = vdupq_n_f32(-1.0f);
    register float32x4_t wn __asm__("v2") = vdupq_n_f32(fa);
    register float32x4_t wm __asm__("v3") = vsetq_lane_f32(fb, vdupq_n_f32(3.0f), 3);
    __asm__("fmla s4, s2, v3.s[3]" : "+w"(wd) : "w"(wn), "w"(wm));
    CHECK(vgetq_lane_f32(wd, 0) == fmaf(fa, fb, -1.0f) && vgetq_lane_f32(wd, 0) == -0x1p-24f && vgetq_lane_f32(wd, 1) == 0 && vgetq_lane_f32(wd, 3) == 0);
    wd = vdupq_n_f32(2.0f);
    __asm__("fmulx s4, s2, v3.s[0]" : "+w"(wd) : "w"(wn), "w"(wm));
    CHECK(vgetq_lane_f32(wd, 0) == fa * 3.0f && vgetq_lane_f32(wd, 2) == 0);

    printf("simd ok\n");
    return 0;
}
