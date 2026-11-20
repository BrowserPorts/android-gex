// AArch64's integer Advanced SIMD instructions, each run over the same
// inputs (random bits, with lanes at their extremes mixed in), with a hash
// of what each gives, in the shape of fpops.c. The hashes are Linux 7.0's,
// on the oracle's arm64 CPU; a difference names the instruction and its
// arrangement.
//
// `simdops print` prints the table instead of checking it; `simdops dump
// NAME` and `simdops inputs` print one case's results and the inputs.
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define N 2048

typedef __attribute__((vector_size(16))) uint8_t v16;

static v16 A[N], B[N], C[N];

static uint64_t rng = 0x2545f4914f6cdd1dull;
static uint64_t next(void) {
    rng ^= rng << 13;
    rng ^= rng >> 7;
    rng ^= rng << 17;
    return rng;
}

// Lanes at random, with some bytes, halves, words and doublewords set to
// the values saturating and shifting operations turn on: 0, all ones, the
// top bit alone, and the top bit clear with the rest set.
static v16 one(void) {
    uint64_t w[2] = {next(), next()};
    uint64_t r = next();
    static const uint64_t edges[] = {0, ~0ull, 0x8080808080808080ull, 0x7f7f7f7f7f7f7f7full, 0x8000800080008000ull, 0x7fff7fff7fff7fffull, 0x8000000080000000ull, 0x7fffffff7fffffffull, 0x8000000000000000ull, 0x7fffffffffffffffull, 0x0101010101010101ull, 0x00ff00ff00ff00ffull};
    if (r % 3 == 0) w[0] = edges[(r >> 8) % 12];
    if (r % 5 == 0) w[1] = edges[(r >> 16) % 12];
    if (r % 7 == 0) w[0] &= 0x0f0f0f0f0f0f0f0full;
    v16 v;
    memcpy(&v, w, 16);
    return v;
}

static uint64_t h;
static int dump;
static void mix(v16 v) {
    unsigned char b[16];
    memcpy(b, &v, 16);
    if (dump) {
        for (int i = 0; i < 16; i++) printf("%02x", b[i]);
        printf("\n");
    }
    for (int i = 0; i < 16; i++) {
        h ^= b[i];
        h *= 0x100000001b3ull;
    }
}

// Three-register: d = op(a, b), at one arrangement.
#define V3(name, insn, arr)                                                          \
    static uint64_t name(void) {                                                     \
        h = 0xcbf29ce484222325ull;                                                   \
        for (int i = 0; i < N; i++) {                                                \
            v16 r;                                                                   \
            asm volatile(insn " %0." arr ", %1." arr ", %2." arr : "=w"(r) : "w"(A[i]), "w"(B[i])); \
            mix(r);                                                                  \
        }                                                                            \
        return h;                                                                    \
    }
// Accumulating: d = op(d, a, b).
#define VACC(name, insn, darr, sarr)                                                 \
    static uint64_t name(void) {                                                     \
        h = 0xcbf29ce484222325ull;                                                   \
        for (int i = 0; i < N; i++) {                                                \
            v16 r = C[i];                                                            \
            asm volatile(insn " %0." darr ", %1." sarr ", %2." sarr : "+w"(r) : "w"(A[i]), "w"(B[i])); \
            mix(r);                                                                  \
        }                                                                            \
        return h;                                                                    \
    }
// Widening or narrowing three-register: the arrangements differ.
#define VW(name, insn, darr, aarr, barr)                                             \
    static uint64_t name(void) {                                                     \
        h = 0xcbf29ce484222325ull;                                                   \
        for (int i = 0; i < N; i++) {                                                \
            v16 r;                                                                   \
            asm volatile(insn " %0." darr ", %1." aarr ", %2." barr : "=w"(r) : "w"(A[i]), "w"(B[i])); \
            mix(r);                                                                  \
        }                                                                            \
        return h;                                                                    \
    }
// Two-register: d = op(a).
#define V2(name, insn, darr, sarr)                                                   \
    static uint64_t name(void) {                                                     \
        h = 0xcbf29ce484222325ull;                                                   \
        for (int i = 0; i < N; i++) {                                                \
            v16 r;                                                                   \
            asm volatile(insn " %0." darr ", %1." sarr : "=w"(r) : "w"(A[i]));       \
            mix(r);                                                                  \
        }                                                                            \
        return h;                                                                    \
    }
// Narrowing into the upper half (the `2` forms): d keeps its lower half.
#define V2HI(name, insn, darr, sarr)                                                 \
    static uint64_t name(void) {                                                     \
        h = 0xcbf29ce484222325ull;                                                   \
        for (int i = 0; i < N; i++) {                                                \
            v16 r = C[i];                                                            \
            asm volatile(insn " %0." darr ", %1." sarr : "+w"(r) : "w"(A[i]));       \
            mix(r);                                                                  \
        }                                                                            \
        return h;                                                                    \
    }
// Shift by an immediate.
#define VSH(name, insn, darr, sarr, imm)                                             \
    static uint64_t name(void) {                                                     \
        h = 0xcbf29ce484222325ull;                                                   \
        for (int i = 0; i < N; i++) {                                                \
            v16 r = C[i];                                                            \
            asm volatile(insn " %0." darr ", %1." sarr ", #" #imm : "+w"(r) : "w"(A[i])); \
            mix(r);                                                                  \
        }                                                                            \
        return h;                                                                    \
    }
// Across all lanes, to a scalar.
#define VACR(name, insn, dreg, sarr)                                                 \
    static uint64_t name(void) {                                                     \
        h = 0xcbf29ce484222325ull;                                                   \
        for (int i = 0; i < N; i++) {                                                \
            v16 r = {0};                                                             \
            asm volatile(insn " %" dreg "0, %1." sarr : "=w"(r) : "w"(A[i]));        \
            mix(r);                                                                  \
        }                                                                            \
        return h;                                                                    \
    }
// By element: d = op(a, b[lane]).
#define VEL(name, insn, arr, earr, lane)                                             \
    static uint64_t name(void) {                                                     \
        h = 0xcbf29ce484222325ull;                                                   \
        for (int i = 0; i < N; i++) {                                                \
            v16 r = C[i];                                                            \
            asm volatile(insn " %0." arr ", %1." arr ", %2." earr "[" #lane "]" : "+w"(r) : "w"(A[i]), "x"(B[i])); \
            mix(r);                                                                  \
        }                                                                            \
        return h;                                                                    \
    }

V3(add_16b, "add", "16b") V3(add_2d, "add", "2d") V3(sub_8h, "sub", "8h") V3(mul_16b, "mul", "16b") V3(mul_4s, "mul", "4s")
V3(sqadd_16b, "sqadd", "16b") V3(uqadd_8h, "uqadd", "8h") V3(sqsub_4s, "sqsub", "4s") V3(uqsub_2d, "uqsub", "2d")
V3(sqdmulh_8h, "sqdmulh", "8h") V3(sqrdmulh_4s, "sqrdmulh", "4s")
V3(shadd_16b, "shadd", "16b") V3(uhadd_8h, "uhadd", "8h") V3(srhadd_4s, "srhadd", "4s") V3(urhadd_16b, "urhadd", "16b") V3(shsub_8h, "shsub", "8h") V3(uhsub_4s, "uhsub", "4s")
V3(sabd_16b, "sabd", "16b") V3(uabd_8h, "uabd", "8h") V3(sabd_4s, "sabd", "4s")
V3(smax_16b, "smax", "16b") V3(umin_8h, "umin", "8h") V3(smaxp_4s, "smaxp", "4s") V3(uminp_16b, "uminp", "16b") V3(addp_8h, "addp", "8h") V3(addp_2d, "addp", "2d")
V3(sshl_16b, "sshl", "16b") V3(ushl_8h, "ushl", "8h") V3(sshl_2d, "sshl", "2d") V3(srshl_4s, "srshl", "4s") V3(urshl_16b, "urshl", "16b")
V3(sqshl_8h, "sqshl", "8h") V3(uqshl_4s, "uqshl", "4s") V3(sqrshl_16b, "sqrshl", "16b") V3(uqrshl_2d, "uqrshl", "2d")
V3(cmeq_16b, "cmeq", "16b") V3(cmge_8h, "cmge", "8h") V3(cmgt_4s, "cmgt", "4s") V3(cmhi_2d, "cmhi", "2d") V3(cmhs_16b, "cmhs", "16b") V3(cmtst_8h, "cmtst", "8h")
V3(and_16b, "and", "16b") V3(orn_16b, "orn", "16b") V3(bic_16b, "bic", "16b") V3(eor_16b, "eor", "16b")
V3(pmul_16b, "pmul", "16b")
V3(zip1_16b, "zip1", "16b") V3(zip2_8h, "zip2", "8h") V3(uzp1_4s, "uzp1", "4s") V3(uzp2_16b, "uzp2", "16b") V3(trn1_8h, "trn1", "8h") V3(trn2_2d, "trn2", "2d")
VACC(mla_16b, "mla", "16b", "16b") VACC(mls_4s, "mls", "4s", "4s") VACC(saba_8h, "saba", "8h", "8h") VACC(uaba_16b, "uaba", "16b", "16b")
VACC(bsl_16b, "bsl", "16b", "16b") VACC(bit_16b, "bit", "16b", "16b") VACC(bif_16b, "bif", "16b", "16b")
VACC(smlal_8h, "smlal", "8h", "8b") VACC(umlal2_4s, "umlal2", "4s", "8h") VACC(sqdmlal_2d, "sqdmlal", "2d", "2s") VACC(sabal_8h, "sabal", "8h", "8b") VACC(uabal2_4s, "uabal2", "4s", "8h")
VW(smull_8h, "smull", "8h", "8b", "8b") VW(umull2_4s, "umull2", "4s", "8h", "8h") VW(sqdmull_4s, "sqdmull", "4s", "4h", "4h") VW(pmull_8h, "pmull", "8h", "8b", "8b")
VW(saddl_8h, "saddl", "8h", "8b", "8b") VW(uaddl2_4s, "uaddl2", "4s", "8h", "8h") VW(ssubl_2d, "ssubl", "2d", "2s", "2s") VW(usubl2_8h, "usubl2", "8h", "16b", "16b")
VW(saddw_8h, "saddw", "8h", "8h", "8b") VW(uaddw2_4s, "uaddw2", "4s", "4s", "8h") VW(sabdl_8h, "sabdl", "8h", "8b", "8b") VW(uabdl2_2d, "uabdl2", "2d", "4s", "4s")
VW(addhn_8b, "addhn", "8b", "8h", "8h") VW(raddhn_4h, "raddhn", "4h", "4s", "4s") VW(subhn_2s, "subhn", "2s", "2d", "2d") VW(rsubhn_8b, "rsubhn", "8b", "8h", "8h")
V2(abs_16b, "abs", "16b", "16b") V2(neg_8h, "neg", "8h", "8h") V2(sqabs_4s, "sqabs", "4s", "4s") V2(sqneg_2d, "sqneg", "2d", "2d") V2(abs_2d, "abs", "2d", "2d")
V2(cnt_16b, "cnt", "16b", "16b") V2(clz_8h, "clz", "8h", "8h") V2(cls_4s, "cls", "4s", "4s") V2(clz_16b, "clz", "16b", "16b") V2(not_16b, "not", "16b", "16b") V2(rbit_16b, "rbit", "16b", "16b")
V2(rev16_16b, "rev16", "16b", "16b") V2(rev32_8h, "rev32", "8h", "8h") V2(rev64_4s, "rev64", "4s", "4s")
V2(cmeq0_16b, "cmeq", "16b", "16b, #0") V2(cmlt0_8h, "cmlt", "8h", "8h, #0")
V2(xtn_8b, "xtn", "8b", "8h") V2(sqxtn_4h, "sqxtn", "4h", "4s") V2(uqxtn_2s, "uqxtn", "2s", "2d") V2(sqxtun_8b, "sqxtun", "8b", "8h")
V2HI(xtn2_16b, "xtn2", "16b", "8h") V2HI(sqxtn2_8h, "sqxtn2", "8h", "4s") V2HI(uqxtn2_4s, "uqxtn2", "4s", "2d")
V2(saddlp_8h, "saddlp", "8h", "16b") V2(uaddlp_4s, "uaddlp", "4s", "8h") V2(uaddlp_2d, "uaddlp", "2d", "4s")
V2HI(sadalp_8h, "sadalp", "8h", "16b") V2HI(uadalp_2d, "uadalp", "2d", "4s")
V2(urecpe_4s, "urecpe", "4s", "4s") V2(ursqrte_4s, "ursqrte", "4s", "4s")
V2HI(suqadd_16b, "suqadd", "16b", "16b") V2HI(usqadd_8h, "usqadd", "8h", "8h")
VSH(shl_16b, "shl", "16b", "16b", 3) VSH(shl_2d, "shl", "2d", "2d", 63) VSH(sshr_8h, "sshr", "8h", "8h", 16) VSH(ushr_4s, "ushr", "4s", "4s", 1) VSH(ushr_2d, "ushr", "2d", "2d", 64)
VSH(srshr_16b, "srshr", "16b", "16b", 5) VSH(urshr_8h, "urshr", "8h", "8h", 16) VSH(ssra_4s, "ssra", "4s", "4s", 31) VSH(ursra_2d, "ursra", "2d", "2d", 33)
VSH(sri_16b, "sri", "16b", "16b", 3) VSH(sli_8h, "sli", "8h", "8h", 15) VSH(sqshl_i_4s, "sqshl", "4s", "4s", 7) VSH(uqshl_i_16b, "uqshl", "16b", "16b", 2) VSH(sqshlu_8h, "sqshlu", "8h", "8h", 9)
VSH(shrn_8b, "shrn", "8b", "8h", 3) VSH(rshrn_4h, "rshrn", "4h", "4s", 16) VSH(sqshrn_2s, "sqshrn", "2s", "2d", 31) VSH(uqshrn_8b, "uqshrn", "8b", "8h", 1)
VSH(sqrshrn_4h, "sqrshrn", "4h", "4s", 9) VSH(uqrshrn_2s, "uqrshrn", "2s", "2d", 32) VSH(sqshrun_8b, "sqshrun", "8b", "8h", 4) VSH(sqrshrun_4h, "sqrshrun", "4h", "4s", 1)
VSH(shrn2_16b, "shrn2", "16b", "8h", 7) VSH(sqrshrn2_8h, "sqrshrn2", "8h", "4s", 11)
VSH(sshll_8h, "sshll", "8h", "8b", 3) VSH(ushll2_4s, "ushll2", "4s", "8h", 15) VSH(sshll_2d, "sshll", "2d", "2s", 0)
VACR(addv_16b, "addv", "b", "16b") VACR(addv_4s, "addv", "s", "4s") VACR(smaxv_8h, "smaxv", "h", "8h") VACR(uminv_16b, "uminv", "b", "16b")
VACR(saddlv_16b, "saddlv", "h", "16b") VACR(uaddlv_8h, "uaddlv", "s", "8h") VACR(uaddlv_4s, "uaddlv", "d", "4s")
VEL(mul_e_8h, "mul", "8h", "h", 5) VEL(mla_e_4s, "mla", "4s", "s", 3) VEL(sqdmulh_e_8h, "sqdmulh", "8h", "h", 7) VEL(sqrdmulh_e_4s, "sqrdmulh", "4s", "s", 1)

// `ext` with a byte offset between the two sources, and `tbl`/`tbx` with
// two and four table registers and indices past the table.
static uint64_t ext_tbl_(void) {
    h = 0xcbf29ce484222325ull;
    for (int i = 0; i < N; i++) {
        v16 r;
        asm volatile("ext %0.16b, %1.16b, %2.16b, #7" : "=w"(r) : "w"(A[i]), "w"(B[i]));
        mix(r);
        asm volatile("tbl %0.16b, {%1.16b}, %2.16b" : "=w"(r) : "w"(B[i]), "w"(A[i]));
        mix(r);
        v16 idx = A[i] & (v16){63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63};
        register v16 t0 asm("v20") = B[i], t1 asm("v21") = C[i], t2 asm("v22") = A[(i + 1) % N], t3 asm("v23") = B[(i + 1) % N];
        asm volatile("tbl %0.16b, {%1.16b, %2.16b}, %3.16b" : "=w"(r) : "w"(t0), "w"(t1), "w"(idx));
        mix(r);
        asm volatile("tbl %0.16b, {%1.16b, %2.16b, %3.16b, %4.16b}, %5.16b" : "=w"(r) : "w"(t0), "w"(t1), "w"(t2), "w"(t3), "w"(A[i]));
        mix(r);
        r = C[i];
        asm volatile("tbx %0.16b, {%1.16b, %2.16b}, %3.16b" : "+w"(r) : "w"(t0), "w"(t1), "w"(A[i]));
        mix(r);
    }
    return h;
}

// Moving between lanes and general registers, and duplicating.
static uint64_t moves_(void) {
    h = 0xcbf29ce484222325ull;
    for (int i = 0; i < N; i++) {
        uint64_t x, y, z;
        asm volatile("smov %x0, %3.b[13]\nsmov %w1, %3.h[5]\numov %w2, %3.h[6]" : "=r"(x), "=r"(y), "=r"(z) : "w"(A[i]));
        v16 r;
        memcpy(&r, (uint64_t[2]){x, y ^ z << 32}, 16);
        mix(r);
        asm volatile("dup %0.8h, %1.h[3]" : "=w"(r) : "w"(A[i]));
        mix(r);
        r = C[i];
        asm volatile("ins %0.s[2], %1.s[1]" : "+w"(r) : "w"(A[i]));
        mix(r);
        asm volatile("dup %0.16b, %w1" : "=w"(r) : "r"((uint32_t)x));
        mix(r);
    }
    return h;
}

// The scalar forms of saturating and shifting operations, on d and s.
static uint64_t scalar_(void) {
    h = 0xcbf29ce484222325ull;
    for (int i = 0; i < N; i++) {
        v16 r = {0}, s = {0}, t = {0}, u = {0};
        asm volatile("sqadd %d0, %d1, %d2" : "=w"(r) : "w"(A[i]), "w"(B[i]));
        asm volatile("uqsub %s0, %s1, %s2" : "=w"(s) : "w"(A[i]), "w"(B[i]));
        asm volatile("sqdmulh %s0, %s1, %s2" : "=w"(t) : "w"(A[i]), "w"(B[i]));
        asm volatile("sqrshl %d0, %d1, %d2" : "=w"(u) : "w"(A[i]), "w"(B[i]));
        mix(r);
        mix(s);
        mix(t);
        mix(u);
        asm volatile("sqxtn %h0, %s1" : "=w"(r) : "w"(A[i]));
        asm volatile("ushr %d0, %d1, #17" : "=w"(s) : "w"(A[i]));
        asm volatile("sqshl %b0, %b1, #3" : "=w"(t) : "w"(A[i]));
        asm volatile("cmgt %d0, %d1, %d2" : "=w"(u) : "w"(A[i]), "w"(B[i]));
        mix(r);
        mix(s);
        mix(t);
        mix(u);
    }
    return h;
}

struct op {
    const char *name;
    uint64_t (*run)(void);
};

static struct op ops[] = {
#define OP(n) {#n, n},
    OP(add_16b) OP(add_2d) OP(sub_8h) OP(mul_16b) OP(mul_4s) OP(sqadd_16b) OP(uqadd_8h) OP(sqsub_4s) OP(uqsub_2d) OP(sqdmulh_8h) OP(sqrdmulh_4s)
    OP(shadd_16b) OP(uhadd_8h) OP(srhadd_4s) OP(urhadd_16b) OP(shsub_8h) OP(uhsub_4s) OP(sabd_16b) OP(uabd_8h) OP(sabd_4s)
    OP(smax_16b) OP(umin_8h) OP(smaxp_4s) OP(uminp_16b) OP(addp_8h) OP(addp_2d)
    OP(sshl_16b) OP(ushl_8h) OP(sshl_2d) OP(srshl_4s) OP(urshl_16b) OP(sqshl_8h) OP(uqshl_4s) OP(sqrshl_16b) OP(uqrshl_2d)
    OP(cmeq_16b) OP(cmge_8h) OP(cmgt_4s) OP(cmhi_2d) OP(cmhs_16b) OP(cmtst_8h) OP(and_16b) OP(orn_16b) OP(bic_16b) OP(eor_16b) OP(pmul_16b)
    OP(zip1_16b) OP(zip2_8h) OP(uzp1_4s) OP(uzp2_16b) OP(trn1_8h) OP(trn2_2d)
    OP(mla_16b) OP(mls_4s) OP(saba_8h) OP(uaba_16b) OP(bsl_16b) OP(bit_16b) OP(bif_16b)
    OP(smlal_8h) OP(umlal2_4s) OP(sqdmlal_2d) OP(sabal_8h) OP(uabal2_4s)
    OP(smull_8h) OP(umull2_4s) OP(sqdmull_4s) OP(pmull_8h) OP(saddl_8h) OP(uaddl2_4s) OP(ssubl_2d) OP(usubl2_8h) OP(saddw_8h) OP(uaddw2_4s) OP(sabdl_8h) OP(uabdl2_2d)
    OP(addhn_8b) OP(raddhn_4h) OP(subhn_2s) OP(rsubhn_8b)
    OP(abs_16b) OP(neg_8h) OP(sqabs_4s) OP(sqneg_2d) OP(abs_2d) OP(cnt_16b) OP(clz_8h) OP(cls_4s) OP(clz_16b) OP(not_16b) OP(rbit_16b)
    OP(rev16_16b) OP(rev32_8h) OP(rev64_4s) OP(cmeq0_16b) OP(cmlt0_8h)
    OP(xtn_8b) OP(sqxtn_4h) OP(uqxtn_2s) OP(sqxtun_8b) OP(xtn2_16b) OP(sqxtn2_8h) OP(uqxtn2_4s)
    OP(saddlp_8h) OP(uaddlp_4s) OP(uaddlp_2d) OP(sadalp_8h) OP(uadalp_2d) OP(urecpe_4s) OP(ursqrte_4s) OP(suqadd_16b) OP(usqadd_8h)
    OP(shl_16b) OP(shl_2d) OP(sshr_8h) OP(ushr_4s) OP(ushr_2d) OP(srshr_16b) OP(urshr_8h) OP(ssra_4s) OP(ursra_2d)
    OP(sri_16b) OP(sli_8h) OP(sqshl_i_4s) OP(uqshl_i_16b) OP(sqshlu_8h)
    OP(shrn_8b) OP(rshrn_4h) OP(sqshrn_2s) OP(uqshrn_8b) OP(sqrshrn_4h) OP(uqrshrn_2s) OP(sqshrun_8b) OP(sqrshrun_4h) OP(shrn2_16b) OP(sqrshrn2_8h)
    OP(sshll_8h) OP(ushll2_4s) OP(sshll_2d)
    OP(addv_16b) OP(addv_4s) OP(smaxv_8h) OP(uminv_16b) OP(saddlv_16b) OP(uaddlv_8h) OP(uaddlv_4s)
    OP(mul_e_8h) OP(mla_e_4s) OP(sqdmulh_e_8h) OP(sqrdmulh_e_4s)
    OP(ext_tbl_) OP(moves_) OP(scalar_)
#undef OP
};

// What each gives on Linux 7.0 (`simdops print` there).
static const struct {
    const char *name;
    uint64_t hash;
} WANT[] = {
#include "simdops.want"
};

int main(int argc, char **argv) {
    for (int i = 0; i < N; i++) {
        A[i] = one();
        B[i] = one();
        C[i] = one();
    }
    // `dump NAME`: each result of one case, its bytes in order; `inputs`:
    // the inputs. For checking a case against a model of the architecture.
    if (argc > 2 && !strcmp(argv[1], "dump")) {
        dump = 1;
        for (size_t i = 0; i < sizeof ops / sizeof ops[0]; i++)
            if (!strcmp(ops[i].name, argv[2])) ops[i].run();
        return 0;
    }
    if (argc > 1 && !strcmp(argv[1], "inputs")) {
        dump = 1;
        for (int i = 0; i < N; i++) {
            mix(A[i]);
            mix(B[i]);
            mix(C[i]);
        }
        return 0;
    }
    if (argc > 2 && !strcmp(argv[1], "only")) {
        for (size_t i = 0; i < sizeof ops / sizeof ops[0]; i++)
            if (!strcmp(ops[i].name, argv[2])) printf("    {\"%s\", 0x%016llxull},\n", ops[i].name, (unsigned long long)ops[i].run());
        return 0;
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
            printf("simdops: %s differs (0x%016llx, Linux 0x%016llx)\n", ops[i].name, (unsigned long long)got, (unsigned long long)want);
            bad = 1;
        }
    }
    if (print) return 0;
    if (bad) return 1;
    printf("simdops ok\n");
    return 0;
}
