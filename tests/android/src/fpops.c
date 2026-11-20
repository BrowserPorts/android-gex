// AArch64's floating-point instructions, each run over the same inputs
// (bit patterns at random, ordinary numbers, and zeros, infinities, NaNs,
// subnormals and the extremes), with a hash of what each gives. The hashes
// are Linux 7.0's, on the oracle's arm64 CPU; a difference names the
// instruction. A NaN counts only as a NaN (its sign and payload are not
// compared: wasm does not keep them). The rounding mode is the default.
//
// Found for it: system_server's PathInterpolator threw "The Path cannot loop
// back on itself" from points libhwui computed, which a cubic with its
// control points in [0, 1] cannot give.
//
// `fpops print` prints the table instead of checking it.
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define N 4096

static uint32_t S[N], T[N], U[N];
static uint64_t D[N], E[N], F[N];

static uint64_t rng = 0x9e3779b97f4a7c15ull;
static uint64_t next(void) {
    rng ^= rng << 13;
    rng ^= rng >> 7;
    rng ^= rng << 17;
    return rng;
}

static float fs(uint32_t b) {
    float f;
    memcpy(&f, &b, 4);
    return f;
}
static uint32_t bs(float f) {
    uint32_t b;
    memcpy(&b, &f, 4);
    return b;
}
static double fd(uint64_t b) {
    double f;
    memcpy(&f, &b, 8);
    return f;
}
static uint64_t bd(double f) {
    uint64_t b;
    memcpy(&b, &f, 8);
    return b;
}

static const uint32_t SPECIAL_S[] = {0, 0x80000000, 0x7f800000, 0xff800000, 0x7fc00000, 0x7fa00000, 0x00000001, 0x807fffff, 0x00800000, 0x7f7fffff, 0x3f800000, 0xbf800000, 0x3f000000, 0x4f000000, 0xcf000000, 0x5f000000, 0x3effffff, 0x4b000001};
static const uint64_t SPECIAL_D[] = {0, 0x8000000000000000ull, 0x7ff0000000000000ull, 0xfff0000000000000ull, 0x7ff8000000000000ull, 0x7ff4000000000000ull, 1, 0x800fffffffffffffull, 0x0010000000000000ull, 0x7fefffffffffffffull, 0x3ff0000000000000ull, 0xbff0000000000000ull, 0x3fe0000000000000ull, 0x41e0000000000000ull, 0xc1e0000000000000ull, 0x43e0000000000000ull, 0x3fdfffffffffffffull, 0x4330000000000001ull};

// One input: a special value, an ordinary number in (-4, 4), or any bits.
static uint32_t one_s(void) {
    uint64_t r = next();
    switch (r % 4) {
    case 0:
        return SPECIAL_S[(r >> 8) % (sizeof SPECIAL_S / 4)];
    case 1:
    case 2:
        return bs(((float)(int32_t)(r >> 32) / 2147483648.0f) * 4.0f);
    default:
        return (uint32_t)(r >> 16);
    }
}
static uint64_t one_d(void) {
    uint64_t r = next();
    switch (r % 4) {
    case 0:
        return SPECIAL_D[(r >> 8) % (sizeof SPECIAL_D / 8)];
    case 1:
    case 2:
        return bd(((double)(int64_t)next() / 9223372036854775808.0) * 4.0);
    default:
        return next();
    }
}

static uint64_t h;
static void mix(uint64_t v) {
    for (int i = 0; i < 8; i++) {
        h ^= (v >> (i * 8)) & 0xff;
        h *= 0x100000001b3ull;
    }
}
static void mix_s(uint32_t b) {
    mix(isnan(fs(b)) ? 0x7fc00000 : b);
}
static void mix_d(uint64_t b) {
    mix(isnan(fd(b)) ? 0x7ff8000000000000ull : b);
}

// Scalar single and double: binary, unary, ternary, to integer, compares.
#define BIN(name, insn)                                                                         \
    static uint64_t name(void) {                                                                \
        h = 0xcbf29ce484222325ull;                                                              \
        for (int i = 0; i < N; i++) {                                                           \
            float r, x = fs(S[i]), y = fs(T[i]);                                                \
            asm volatile(insn " %s0, %s1, %s2" : "=w"(r) : "w"(x), "w"(y));                    \
            mix_s(bs(r));                                                                       \
            double q, a = fd(D[i]), b = fd(E[i]);                                               \
            asm volatile(insn " %d0, %d1, %d2" : "=w"(q) : "w"(a), "w"(b));                    \
            mix_d(bd(q));                                                                       \
        }                                                                                       \
        return h;                                                                               \
    }
#define UN(name, insn)                                                                          \
    static uint64_t name(void) {                                                                \
        h = 0xcbf29ce484222325ull;                                                              \
        for (int i = 0; i < N; i++) {                                                           \
            float r, x = fs(S[i]);                                                              \
            asm volatile(insn " %s0, %s1" : "=w"(r) : "w"(x));                                  \
            mix_s(bs(r));                                                                       \
            double q, a = fd(D[i]);                                                             \
            asm volatile(insn " %d0, %d1" : "=w"(q) : "w"(a));                                  \
            mix_d(bd(q));                                                                       \
        }                                                                                       \
        return h;                                                                               \
    }
#define TER(name, insn)                                                                         \
    static uint64_t name(void) {                                                                \
        h = 0xcbf29ce484222325ull;                                                              \
        for (int i = 0; i < N; i++) {                                                           \
            float r, x = fs(S[i]), y = fs(T[i]), z = fs(U[i]);                                  \
            asm volatile(insn " %s0, %s1, %s2, %s3" : "=w"(r) : "w"(x), "w"(y), "w"(z));       \
            mix_s(bs(r));                                                                       \
            double q, a = fd(D[i]), b = fd(E[i]), c = fd(F[i]);                                 \
            asm volatile(insn " %d0, %d1, %d2, %d3" : "=w"(q) : "w"(a), "w"(b), "w"(c));       \
            mix_d(bd(q));                                                                       \
        }                                                                                       \
        return h;                                                                               \
    }
#define TOINT(name, insn)                                                                       \
    static uint64_t name(void) {                                                                \
        h = 0xcbf29ce484222325ull;                                                              \
        for (int i = 0; i < N; i++) {                                                           \
            uint64_t w, x;                                                                      \
            float a = fs(S[i]);                                                                 \
            double b = fd(D[i]);                                                                \
            asm volatile(insn " %w0, %s2\n" insn " %x1, %d3" : "=&r"(w), "=r"(x) : "w"(a), "w"(b)); \
            mix(w & 0xffffffff);                                                                \
            mix(x);                                                                             \
            asm volatile(insn " %x0, %s2\n" insn " %w1, %d3" : "=&r"(w), "=r"(x) : "w"(a), "w"(b)); \
            mix(w);                                                                             \
            mix(x & 0xffffffff);                                                                \
        }                                                                                       \
        return h;                                                                               \
    }
#define FROMINT(name, insn)                                                                     \
    static uint64_t name(void) {                                                                \
        h = 0xcbf29ce484222325ull;                                                              \
        for (int i = 0; i < N; i++) {                                                           \
            float r, r2;                                                                        \
            double q, q2;                                                                       \
            uint64_t x = D[i], w = S[i];                                                        \
            asm volatile(insn " %s0, %w2\n" insn " %d1, %x3" : "=&w"(r), "=w"(q) : "r"(w), "r"(x)); \
            asm volatile(insn " %s0, %x2\n" insn " %d1, %w3" : "=&w"(r2), "=w"(q2) : "r"(x), "r"(w)); \
            mix_s(bs(r));                                                                       \
            mix_d(bd(q));                                                                       \
            mix_s(bs(r2));                                                                      \
            mix_d(bd(q2));                                                                      \
        }                                                                                       \
        return h;                                                                               \
    }
// Four lanes of single, two of double.
#define VBIN(name, insn)                                                                        \
    static uint64_t name(void) {                                                                \
        h = 0xcbf29ce484222325ull;                                                              \
        for (int i = 0; i + 4 <= N; i += 4) {                                                   \
            __attribute__((vector_size(16))) float r, x, y;                                     \
            __attribute__((vector_size(16))) double q, a, b;                                    \
            memcpy(&x, &S[i], 16);                                                              \
            memcpy(&y, &T[i], 16);                                                              \
            asm volatile(insn " %0.4s, %1.4s, %2.4s" : "=w"(r) : "w"(x), "w"(y));              \
            memcpy(&a, &D[i], 16);                                                              \
            memcpy(&b, &E[i], 16);                                                              \
            asm volatile(insn " %0.2d, %1.2d, %2.2d" : "=w"(q) : "w"(a), "w"(b));              \
            for (int l = 0; l < 4; l++) mix_s(bs(r[l]));                                        \
            for (int l = 0; l < 2; l++) mix_d(bd(q[l]));                                        \
        }                                                                                       \
        return h;                                                                               \
    }
#define VACC(name, insn)                                                                        \
    static uint64_t name(void) {                                                                \
        h = 0xcbf29ce484222325ull;                                                              \
        for (int i = 0; i + 4 <= N; i += 4) {                                                   \
            __attribute__((vector_size(16))) float r, x, y;                                     \
            __attribute__((vector_size(16))) double q, a, b;                                    \
            memcpy(&r, &U[i], 16);                                                              \
            memcpy(&x, &S[i], 16);                                                              \
            memcpy(&y, &T[i], 16);                                                              \
            asm volatile(insn " %0.4s, %1.4s, %2.4s" : "+w"(r) : "w"(x), "w"(y));              \
            memcpy(&q, &F[i], 16);                                                              \
            memcpy(&a, &D[i], 16);                                                              \
            memcpy(&b, &E[i], 16);                                                              \
            asm volatile(insn " %0.2d, %1.2d, %2.2d" : "+w"(q) : "w"(a), "w"(b));              \
            for (int l = 0; l < 4; l++) mix_s(bs(r[l]));                                        \
            for (int l = 0; l < 2; l++) mix_d(bd(q[l]));                                        \
        }                                                                                       \
        return h;                                                                               \
    }
#define VUN(name, insn)                                                                         \
    static uint64_t name(void) {                                                                \
        h = 0xcbf29ce484222325ull;                                                              \
        for (int i = 0; i + 4 <= N; i += 4) {                                                   \
            __attribute__((vector_size(16))) float r, x;                                        \
            __attribute__((vector_size(16))) double q, a;                                       \
            memcpy(&x, &S[i], 16);                                                              \
            asm volatile(insn " %0.4s, %1.4s" : "=w"(r) : "w"(x));                              \
            memcpy(&a, &D[i], 16);                                                              \
            asm volatile(insn " %0.2d, %1.2d" : "=w"(q) : "w"(a));                              \
            for (int l = 0; l < 4; l++) mix_s(bs(r[l]));                                        \
            for (int l = 0; l < 2; l++) mix_d(bd(q[l]));                                        \
        }                                                                                       \
        return h;                                                                               \
    }

BIN(fadd_, "fadd")
BIN(fsub_, "fsub")
BIN(fmul_, "fmul")
BIN(fnmul_, "fnmul")
BIN(fdiv_, "fdiv")
BIN(fmax_, "fmax")
BIN(fmin_, "fmin")
BIN(fmaxnm_, "fmaxnm")
BIN(fminnm_, "fminnm")
BIN(fabd_, "fabd")
BIN(fmulx_, "fmulx")
BIN(frecps_, "frecps")
BIN(frsqrts_, "frsqrts")
UN(fsqrt_, "fsqrt")
UN(fneg_, "fneg")
UN(fabs_, "fabs")
UN(fmov_, "fmov")
UN(frintn_, "frintn")
UN(frinta_, "frinta")
UN(frintp_, "frintp")
UN(frintm_, "frintm")
UN(frintz_, "frintz")
UN(frintx_, "frintx")
UN(frinti_, "frinti")
UN(frecpe_, "frecpe")
UN(frsqrte_, "frsqrte")
UN(frecpx_, "frecpx")
TER(fmadd_, "fmadd")
TER(fmsub_, "fmsub")
TER(fnmadd_, "fnmadd")
TER(fnmsub_, "fnmsub")
TOINT(fcvtzs_, "fcvtzs")
TOINT(fcvtzu_, "fcvtzu")
TOINT(fcvtns_, "fcvtns")
TOINT(fcvtnu_, "fcvtnu")
TOINT(fcvtas_, "fcvtas")
TOINT(fcvtau_, "fcvtau")
TOINT(fcvtms_, "fcvtms")
TOINT(fcvtmu_, "fcvtmu")
TOINT(fcvtps_, "fcvtps")
TOINT(fcvtpu_, "fcvtpu")
FROMINT(scvtf_, "scvtf")
FROMINT(ucvtf_, "ucvtf")
VBIN(vfadd_, "fadd")
VBIN(vfsub_, "fsub")
VBIN(vfmul_, "fmul")
VBIN(vfdiv_, "fdiv")
VBIN(vfmax_, "fmax")
VBIN(vfmin_, "fmin")
VBIN(vfmaxnm_, "fmaxnm")
VBIN(vfminnm_, "fminnm")
VBIN(vfabd_, "fabd")
VBIN(vfaddp_, "faddp")
VBIN(vfmaxp_, "fmaxp")
VBIN(vfminp_, "fminp")
VBIN(vfcmeq_, "fcmeq")
VBIN(vfcmge_, "fcmge")
VBIN(vfcmgt_, "fcmgt")
VBIN(vfacge_, "facge")
VBIN(vfrecps_, "frecps")
VBIN(vfrsqrts_, "frsqrts")
VACC(vfmla_, "fmla")
VACC(vfmls_, "fmls")
VUN(vfsqrt_, "fsqrt")
VUN(vfneg_, "fneg")
VUN(vfabs_, "fabs")
VUN(vfrintn_, "frintn")
VUN(vfrinta_, "frinta")
VUN(vfrintm_, "frintm")
VUN(vfrintp_, "frintp")
VUN(vfrintz_, "frintz")
VUN(vfrecpe_, "frecpe")
VUN(vfrsqrte_, "frsqrte")
VUN(vfcvtzs_, "fcvtzs")
VUN(vfcvtns_, "fcvtns")
VUN(vscvtf_, "scvtf")

// Compares: the flags they set, and the selects and conditional compares
// that read them.
static uint64_t fcmp_(void) {
    h = 0xcbf29ce484222325ull;
    for (int i = 0; i < N; i++) {
        uint64_t f1, f2, f3, f4;
        float x = fs(S[i]), y = fs(T[i]), z = fs(U[i]);
        double a = fd(D[i]), b = fd(E[i]);
        asm volatile("fcmp %s1, %s2\nmrs %0, nzcv" : "=r"(f1) : "w"(x), "w"(y) : "cc");
        asm volatile("fcmpe %d1, %d2\nmrs %0, nzcv" : "=r"(f2) : "w"(a), "w"(b) : "cc");
        asm volatile("fcmp %s1, #0.0\nmrs %0, nzcv" : "=r"(f3) : "w"(x) : "cc");
        asm volatile("fcmp %s1, %s2\nfccmp %s3, %s1, #6, ge\nmrs %0, nzcv" : "=r"(f4) : "w"(x), "w"(y), "w"(z) : "cc");
        mix(f1 | f2 << 4 | f3 << 8 | f4 << 12);
        float r;
        double q;
        asm volatile("fcmp %s1, %s2\nfcsel %s0, %s3, %s2, gt" : "=w"(r) : "w"(x), "w"(y), "w"(z) : "cc");
        asm volatile("fcmp %d1, %d2\nfcsel %d0, %d1, %d2, mi" : "=w"(q) : "w"(a), "w"(b) : "cc");
        mix_s(bs(r));
        mix_d(bd(q));
        uint64_t c;
        asm volatile("fcmp %s1, %s2\ncset %w0, ls" : "=r"(c) : "w"(x), "w"(y) : "cc");
        mix(c);
        asm volatile("fcmp %d1, %d2\ncset %w0, vs" : "=r"(c) : "w"(a), "w"(b) : "cc");
        mix(c);
    }
    return h;
}

// Between widths: single to double and back, and half.
static uint64_t fcvt_(void) {
    h = 0xcbf29ce484222325ull;
    for (int i = 0; i < N; i++) {
        double q;
        float r;
        asm volatile("fcvt %d0, %s1" : "=w"(q) : "w"(fs(S[i])));
        mix_d(bd(q));
        asm volatile("fcvt %s0, %d1" : "=w"(r) : "w"(fd(D[i])));
        mix_s(bs(r));
        uint16_t half;
        __fp16 hv;
        asm volatile("fcvt %h0, %s1" : "=w"(hv) : "w"(fs(S[i])));
        memcpy(&half, &hv, 2);
        mix(half);
        asm volatile("fcvt %s0, %h1" : "=w"(r) : "w"(hv));
        mix_s(bs(r));
    }
    return h;
}

// Reductions across a vector.
static uint64_t vreduce_(void) {
    h = 0xcbf29ce484222325ull;
    for (int i = 0; i + 4 <= N; i += 4) {
        __attribute__((vector_size(16))) float x;
        memcpy(&x, &S[i], 16);
        float a, b, c, d;
        asm volatile("fmaxv %s0, %1.4s" : "=w"(a) : "w"(x));
        asm volatile("fminv %s0, %1.4s" : "=w"(b) : "w"(x));
        asm volatile("fmaxnmv %s0, %1.4s" : "=w"(c) : "w"(x));
        asm volatile("fminnmv %s0, %1.4s" : "=w"(d) : "w"(x));
        mix_s(bs(a));
        mix_s(bs(b));
        mix_s(bs(c));
        mix_s(bs(d));
    }
    return h;
}

struct op {
    const char *name;
    uint64_t (*run)(void);
};

static struct op ops[] = {
#define OP(n) {#n, n##_},
    OP(fadd) OP(fsub) OP(fmul) OP(fnmul) OP(fdiv) OP(fmax) OP(fmin) OP(fmaxnm) OP(fminnm) OP(fabd) OP(fmulx) OP(frecps) OP(frsqrts)
    OP(fsqrt) OP(fneg) OP(fabs) OP(fmov) OP(frintn) OP(frinta) OP(frintp) OP(frintm) OP(frintz) OP(frintx) OP(frinti) OP(frecpe) OP(frsqrte) OP(frecpx)
    OP(fmadd) OP(fmsub) OP(fnmadd) OP(fnmsub)
    OP(fcvtzs) OP(fcvtzu) OP(fcvtns) OP(fcvtnu) OP(fcvtas) OP(fcvtau) OP(fcvtms) OP(fcvtmu) OP(fcvtps) OP(fcvtpu) OP(scvtf) OP(ucvtf)
    OP(vfadd) OP(vfsub) OP(vfmul) OP(vfdiv) OP(vfmax) OP(vfmin) OP(vfmaxnm) OP(vfminnm) OP(vfabd) OP(vfaddp) OP(vfmaxp) OP(vfminp)
    OP(vfcmeq) OP(vfcmge) OP(vfcmgt) OP(vfacge) OP(vfrecps) OP(vfrsqrts) OP(vfmla) OP(vfmls)
    OP(vfsqrt) OP(vfneg) OP(vfabs) OP(vfrintn) OP(vfrinta) OP(vfrintm) OP(vfrintp) OP(vfrintz) OP(vfrecpe) OP(vfrsqrte) OP(vfcvtzs) OP(vfcvtns) OP(vscvtf)
    OP(fcmp) OP(fcvt) OP(vreduce)
#undef OP
};

// What each gives on Linux 7.0 (`fpops print` there).
static const struct {
    const char *name;
    uint64_t hash;
} WANT[] = {
#include "fpops.want"
};

int main(int argc, char **argv) {
    for (int i = 0; i < N; i++) {
        S[i] = one_s();
        T[i] = one_s();
        U[i] = one_s();
        D[i] = one_d();
        E[i] = one_d();
        F[i] = one_d();
    }
    int print = argc > 1 && !strcmp(argv[1], "print");
    int bad = 0;
    for (size_t i = 0; i < sizeof ops / sizeof ops[0]; i++) {
        uint64_t got = ops[i].run();
        if (print) {
            printf("    {\"%s\", 0x%016llxull},\n", ops[i].name, (unsigned long long)got);
            continue;
        }
        uint64_t want = 0;
        for (size_t j = 0; j < sizeof WANT / sizeof WANT[0]; j++)
            if (!strcmp(WANT[j].name, ops[i].name)) want = WANT[j].hash;
        if (got != want) {
            printf("fpops: %s differs (0x%016llx, Linux 0x%016llx)\n", ops[i].name, (unsigned long long)got, (unsigned long long)want);
            bad = 1;
        }
    }
    if (print) return 0;
    if (bad) return 1;
    printf("fpops ok\n");
    return 0;
}
