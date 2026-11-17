// Running BPF programs: BPF_PROG_TEST_RUN of many small ones, each a
// line with what it returned (and what it left in its packet, context or
// maps), so the arithmetic, branches, stack, atomics, calls, maps, packet
// loads and context fields are the kernel's. Prints an answer a line and
// checks them against Linux 7.0's. As root.
#define _GNU_SOURCE
#include <errno.h>
#include <linux/bpf.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static long sys_bpf(int cmd, union bpf_attr *attr, unsigned size) {
    long r = syscall(__NR_bpf, cmd, attr, size);
    return r < 0 ? -errno : r;
}

// What Linux 7.0 printed.
static const char expected[] =
    "constant: 0 0x2a\n"
    "add sub mul: 0 0x8c\n"
    "div mod: 0 0xe02\n"
    "div by zero: 0 0\n"
    "mod by zero: 0 0x64\n"
    "32-bit mod by zero, the top: 0 0\n"
    "32-bit add zeroes the top: 0 0x1\n"
    "arsh: 0 0xfffffffc\n"
    "arsh32: 0 0xf8000000\n"
    "shift by 65: 0 0x2\n"
    "32-bit shift by 33: 0 0x2\n"
    "neg: 0 0xfffffffb\n"
    "be32: 0 0x78563412\n"
    "be16: 0 0x7856\n"
    "le16: 0 0x5678\n"
    "bswap64, the bottom: 0 0x44332211\n"
    "64-bit constant: 0 0x12345678\n"
    "movsx8: 0 0xffffff80\n"
    "sdiv: 0 0xfffffff2\n"
    "smod: 0 0xfffffffe\n"
    "unsigned and signed: 0 0x2\n"
    "jmp32: 0 0x9\n"
    "jset jle jslt: 0 0x27\n"
    "stack: 0 0x334488\n"
    "st sign-extends: 0 0xfffffffd\n"
    "atomic add and fetch: 0 0x120f\n"
    "xchg cmpxchg: 0 0xa634d\n"
    "atomic or fetch, 32 bits: 0 0xe06\n"
    "a call: 0 0x411\n"
    "hash update and lookup: 0 0x63\n"
    "the value written through the pointer: 0 123\n"
    "delete twice: 0 0xfffffe00\n"
    "array lookup and atomic add: 0 0x4d3\n"
    "the array's value: 0 1235\n"
    "array lookup out of range: 0 0\n"
    "for each, without BTF: load -22\n"
    "for each: 0 0xa04\n"
    "one record for two functions: -22\n"
    "the callback global: -22\n"
    "for each, stopping at 2, without BTF: load -22\n"
    "for each, stopping at 2: 0 0x603\n"
    "ld_abs: 0 0x162e11\n"
    "ld_abs word: 0 0xa000001\n"
    "ld_ind: 0 0x4d2\n"
    "ld_abs past the end: 0 0\n"
    "skb_load_bytes: 0 0x21216968\n"
    "skb_load_bytes past the end: 0 0xfffffff2\n"
    "len protocol ifindex pkt_type: 0 0x1000820\n"
    "mark and cb: 0 0x1107, cb[1] after 0x22, wire_len 32, ifindex 1\n"
    "a context with len: -22\n"
    "a context with an interface not there: -19\n"
    "five runs: 0 5, cb[0] after 5\n"
    "the packet back: 0, 46 bytes, the link header zeroed 1, the rest as it was 1\n"
    "a packet of 13: -22\n"
    "a packet of 3648: 0\n"
    "room for 10: -28, size 46\n"
    "classifier: 0 0x2e08, 46 bytes back, the first 0xaa\n"
    "cgroup skb: 0 0x1\n"
    "a socket program run: -524\n"
;

static char out_buf[16384];
static size_t used;

static void SAY(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    char line[512];
    int n = vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    fputs(line, stdout);
    if (n > 0 && used + (size_t)n < sizeof out_buf) {
        memcpy(out_buf + used, line, (size_t)n);
        used += (size_t)n;
    }
}

#define I(c, d, s, o, i) ((struct bpf_insn){.code = (c), .dst_reg = (d), .src_reg = (s), .off = (o), .imm = (i)})
#define MOV64(d, i) I(BPF_ALU64 | BPF_MOV | BPF_K, d, 0, 0, i)
#define MOV32(d, i) I(BPF_ALU | BPF_MOV | BPF_K, d, 0, 0, i)
#define MOVR(d, s) I(BPF_ALU64 | BPF_MOV | BPF_X, d, s, 0, 0)
#define A64(op, d, i) I(BPF_ALU64 | (op) | BPF_K, d, 0, 0, i)
#define A64R(op, d, s) I(BPF_ALU64 | (op) | BPF_X, d, s, 0, 0)
#define A32(op, d, i) I(BPF_ALU | (op) | BPF_K, d, 0, 0, i)
#define A32R(op, d, s) I(BPF_ALU | (op) | BPF_X, d, s, 0, 0)
#define EXIT I(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)
#define LDDW(d, v) I(BPF_LD | BPF_DW | BPF_IMM, d, 0, 0, (int32_t)(uint32_t)(v)), I(0, 0, 0, 0, (int32_t)((uint64_t)(v) >> 32))
#define LDMAP(d, fd) I(BPF_LD | BPF_DW | BPF_IMM, d, BPF_PSEUDO_MAP_FD, 0, fd), I(0, 0, 0, 0, 0)
#define LDX(sz, d, s, o) I(BPF_LDX | BPF_MEM | (sz), d, s, o, 0)
#define STX(sz, d, s, o) I(BPF_STX | BPF_MEM | (sz), d, s, o, 0)
#define ST(sz, d, o, i) I(BPF_ST | BPF_MEM | (sz), d, 0, o, i)
#define J(op, d, i, o) I(BPF_JMP | (op) | BPF_K, d, 0, o, i)
#define JR(op, d, s, o) I(BPF_JMP | (op) | BPF_X, d, s, o, 0)
#define J32(op, d, i, o) I(BPF_JMP32 | (op) | BPF_K, d, 0, o, i)
#define CALL(f) I(BPF_JMP | BPF_CALL, 0, 0, 0, f)
#define N(a) (int)(sizeof(a) / sizeof(a[0]))

// Ethernet, IPv4 10.0.0.1 to 10.0.0.2, UDP 1234 to 5678, "hi!!".
static unsigned char pkt[46] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x08, 0x00, 0x45, 0x00, 0x00, 0x20, 0x12, 0x34, 0x40, 0x00, 0x40,
                                0x11, 0x00, 0x00, 10, 0, 0, 1, 10, 0, 0, 2, 0x04, 0xd2, 0x16, 0x2e, 0x00, 0x0c, 0x00, 0x00, 'h', 'i', '!', '!'};

static long load(int type, const struct bpf_insn *insns, int n) {
    union bpf_attr a;
    memset(&a, 0, sizeof a);
    a.prog_type = type;
    a.insns = (uintptr_t)insns;
    a.insn_cnt = n;
    a.license = (uintptr_t) "GPL";
    return sys_bpf(BPF_PROG_LOAD, &a, sizeof a);
}

static struct __sk_buff ctx_out;
static unsigned char data_out[128];

// Run once: the result, the return value in *ret.
static long run(long fd, const void *data, unsigned len, struct __sk_buff *ctx, unsigned repeat, uint32_t *ret, unsigned *out_len) {
    union bpf_attr a;
    memset(&a, 0, sizeof a);
    memset(&ctx_out, 0, sizeof ctx_out);
    memset(data_out, 0, sizeof data_out);
    a.test.prog_fd = fd;
    a.test.data_in = (uintptr_t)data;
    a.test.data_size_in = len;
    a.test.data_out = (uintptr_t)data_out;
    a.test.data_size_out = sizeof data_out;
    a.test.repeat = repeat;
    if (ctx) {
        a.test.ctx_in = (uintptr_t)ctx;
        a.test.ctx_size_in = sizeof *ctx;
        a.test.ctx_out = (uintptr_t)&ctx_out;
        a.test.ctx_size_out = sizeof ctx_out;
    }
    long r = sys_bpf(BPF_PROG_TEST_RUN, &a, sizeof a);
    if (ret) *ret = a.test.retval;
    if (out_len) *out_len = a.test.data_size_out;
    return r;
}

static void one(const char *what, int type, const struct bpf_insn *insns, int n) {
    long fd = load(type, insns, n);
    if (fd < 0) {
        SAY("%s: load %ld\n", what, fd);
        return;
    }
    uint32_t ret = 0;
    long r = run(fd, pkt, sizeof pkt, NULL, 1, &ret, NULL);
    SAY("%s: %ld %#x\n", what, r, ret);
    close(fd);
}

static long map(int type, int key, int value, int max) {
    union bpf_attr a;
    memset(&a, 0, sizeof a);
    a.map_type = type;
    a.key_size = key;
    a.value_size = value;
    a.max_entries = max;
    return sys_bpf(BPF_MAP_CREATE, &a, sizeof a);
}

static long elem(int cmd, int fd, const void *k, void *v) {
    union bpf_attr a;
    memset(&a, 0, sizeof a);
    a.map_fd = fd;
    a.key = (uintptr_t)k;
    a.value = (uintptr_t)v;
    return sys_bpf(cmd, &a, sizeof a);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    int SF = BPF_PROG_TYPE_SOCKET_FILTER;
    {
        struct bpf_insn p[] = {MOV64(0, 42), EXIT};
        one("constant", SF, p, N(p));
    }
    {
        struct bpf_insn p[] = {MOV64(0, 7), A64(BPF_MUL, 0, 6), A64(BPF_SUB, 0, 2), A64(BPF_ADD, 0, 100), EXIT};
        one("add sub mul", SF, p, N(p));
    }
    {
        struct bpf_insn p[] = {MOV64(0, 100), MOV64(1, 7), A64R(BPF_DIV, 0, 1), A64(BPF_LSH, 0, 8), MOV64(2, 100), A64R(BPF_MOD, 2, 1),
                               A64R(BPF_OR, 0, 2), EXIT};
        one("div mod", SF, p, N(p));
    }
    {
        struct bpf_insn p[] = {MOV64(0, 100), MOV64(1, 0), A64R(BPF_DIV, 0, 1), EXIT};
        one("div by zero", SF, p, N(p));
    }
    {
        struct bpf_insn p[] = {MOV64(0, 100), MOV64(1, 0), A64R(BPF_MOD, 0, 1), EXIT};
        one("mod by zero", SF, p, N(p));
    }
    {
        struct bpf_insn p[] = {LDDW(0, 0xffffffff00000064ull), MOV64(1, 0), A32R(BPF_MOD, 0, 1), A64(BPF_RSH, 0, 32), EXIT};
        one("32-bit mod by zero, the top", SF, p, N(p));
    }
    {
        struct bpf_insn p[] = {MOV64(0, -1), A32(BPF_ADD, 0, 2), MOVR(1, 0), A64(BPF_RSH, 1, 32), A64(BPF_LSH, 1, 8), A64R(BPF_OR, 0, 1), EXIT};
        one("32-bit add zeroes the top", SF, p, N(p));
    }
    {
        struct bpf_insn p[] = {MOV64(0, -16), A64(BPF_ARSH, 0, 2), EXIT};
        one("arsh", SF, p, N(p));
    }
    {
        struct bpf_insn p[] = {MOV32(0, (int)0x80000000), A32(BPF_ARSH, 0, 4), EXIT};
        one("arsh32", SF, p, N(p));
    }
    {
        struct bpf_insn p[] = {MOV64(0, 1), MOV64(1, 65), A64R(BPF_LSH, 0, 1), EXIT};
        one("shift by 65", SF, p, N(p));
    }
    {
        struct bpf_insn p[] = {MOV64(0, 1), MOV64(1, 33), A32R(BPF_LSH, 0, 1), EXIT};
        one("32-bit shift by 33", SF, p, N(p));
    }
    {
        struct bpf_insn p[] = {MOV64(0, 5), I(BPF_ALU64 | BPF_NEG, 0, 0, 0, 0), EXIT};
        one("neg", SF, p, N(p));
    }
    {
        struct bpf_insn p[] = {MOV32(0, 0x12345678), I(BPF_ALU | BPF_END | BPF_TO_BE, 0, 0, 0, 32), EXIT};
        one("be32", SF, p, N(p));
    }
    {
        struct bpf_insn p[] = {MOV32(0, 0x12345678), I(BPF_ALU | BPF_END | BPF_TO_BE, 0, 0, 0, 16), EXIT};
        one("be16", SF, p, N(p));
    }
    {
        struct bpf_insn p[] = {MOV32(0, 0x12345678), I(BPF_ALU | BPF_END | BPF_TO_LE, 0, 0, 0, 16), EXIT};
        one("le16", SF, p, N(p));
    }
    {
        struct bpf_insn p[] = {LDDW(0, 0x1122334455667788ull), I(BPF_ALU64 | BPF_END | BPF_TO_LE, 0, 0, 0, 64), EXIT};
        one("bswap64, the bottom", SF, p, N(p));
    }
    {
        struct bpf_insn p[] = {LDDW(0, 0x123456789abcdef0ull), A64(BPF_RSH, 0, 32), EXIT};
        one("64-bit constant", SF, p, N(p));
    }
    {
        struct bpf_insn p[] = {MOV64(1, 0x80), I(BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 8, 0), EXIT};
        one("movsx8", SF, p, N(p));
    }
    {
        struct bpf_insn p[] = {MOV64(0, -100), MOV64(1, 7), I(BPF_ALU64 | BPF_DIV | BPF_X, 0, 1, 1, 0), EXIT};
        one("sdiv", SF, p, N(p));
    }
    {
        struct bpf_insn p[] = {MOV64(0, -100), MOV64(1, 7), I(BPF_ALU64 | BPF_MOD | BPF_X, 0, 1, 1, 0), EXIT};
        one("smod", SF, p, N(p));
    }
    {
        struct bpf_insn p[] = {MOV64(1, -1), MOV64(0, 0), J(BPF_JGT, 1, 5, 1), MOV64(0, 1), J(BPF_JSGT, 1, 5, 1), A64(BPF_ADD, 0, 2), EXIT};
        one("unsigned and signed", SF, p, N(p));
    }
    {
        struct bpf_insn p[] = {LDDW(1, 0x100000005ull), MOV64(0, 0), J32(BPF_JEQ, 1, 5, 1), EXIT, MOV64(0, 9), J(BPF_JEQ, 1, 5, 1), EXIT,
                               MOV64(0, 8), EXIT};
        one("jmp32", SF, p, N(p));
    }
    {
        struct bpf_insn p[] = {MOV64(1, 6), MOV64(0, 0), JR(BPF_JSET, 1, 1, 0), MOV64(2, 1), MOV64(0, 3), J(BPF_JSET, 1, 1, 1),
                               A64(BPF_ADD, 0, 4), J(BPF_JLE, 1, 6, 1), A64(BPF_ADD, 0, 16), J(BPF_JSLT, 1, -1, 1), A64(BPF_ADD, 0, 32), EXIT};
        one("jset jle jslt", SF, p, N(p));
    }
    {
        struct bpf_insn p[] = {LDDW(1, 0x1122334455667788ull), STX(BPF_DW, 10, 1, -8), LDX(BPF_B, 0, 10, -8), LDX(BPF_H, 2, 10, -4),
                               A64(BPF_LSH, 2, 8), A64R(BPF_OR, 0, 2), EXIT};
        one("stack", SF, p, N(p));
    }
    {
        struct bpf_insn p[] = {ST(BPF_W, 10, -4, -2), LDX(BPF_W, 0, 10, -4), ST(BPF_DW, 10, -16, -2), LDX(BPF_DW, 1, 10, -16),
                               A64(BPF_RSH, 1, 32), A64R(BPF_ADD, 0, 1), EXIT};
        one("st sign-extends", SF, p, N(p));
    }
    {
        struct bpf_insn p[] = {ST(BPF_DW, 10, -8, 10), MOV64(1, 5), I(BPF_STX | BPF_ATOMIC | BPF_DW, 10, 1, -8, BPF_ADD),
                               MOV64(2, 3), I(BPF_STX | BPF_ATOMIC | BPF_DW, 10, 2, -8, BPF_ADD | BPF_FETCH), LDX(BPF_DW, 0, 10, -8),
                               A64(BPF_LSH, 0, 8), A64R(BPF_OR, 0, 2), EXIT};
        one("atomic add and fetch", SF, p, N(p));
    }
    {
        struct bpf_insn p[] = {ST(BPF_DW, 10, -8, 10), MOV64(1, 77), I(BPF_STX | BPF_ATOMIC | BPF_DW, 10, 1, -8, BPF_XCHG),
                               MOV64(0, 77), MOV64(2, 99), I(BPF_STX | BPF_ATOMIC | BPF_DW, 10, 2, -8, BPF_CMPXCHG), LDX(BPF_DW, 3, 10, -8),
                               A64(BPF_LSH, 3, 8), A64R(BPF_OR, 0, 3), A64(BPF_LSH, 1, 16), A64R(BPF_OR, 0, 1), EXIT};
        one("xchg cmpxchg", SF, p, N(p));
    }
    {
        struct bpf_insn p[] = {ST(BPF_W, 10, -4, 6), MOV64(1, 12), I(BPF_STX | BPF_ATOMIC | BPF_W, 10, 1, -4, BPF_OR | BPF_FETCH),
                               LDX(BPF_W, 0, 10, -4), A64(BPF_LSH, 0, 8), A64R(BPF_OR, 0, 1), EXIT};
        one("atomic or fetch, 32 bits", SF, p, N(p));
    }
    {
        struct bpf_insn p[] = {MOV64(1, 20), MOV64(6, 1000), I(BPF_JMP | BPF_CALL, 0, BPF_PSEUDO_CALL, 0, 3), A64R(BPF_ADD, 0, 6),
                               A64(BPF_ADD, 0, 1), EXIT, ST(BPF_DW, 10, -8, 5), MOVR(0, 1), A64(BPF_MUL, 0, 2), MOV64(6, 7), EXIT};
        one("a call", SF, p, N(p));
    }
    // A hash map: update, look up, delete.
    long h = map(BPF_MAP_TYPE_HASH, 4, 8, 4);
    {
        struct bpf_insn p[] = {ST(BPF_W, 10, -4, 7), ST(BPF_DW, 10, -16, 99), LDMAP(1, (int)h), MOVR(2, 10), A64(BPF_ADD, 2, -4),
                               MOVR(3, 10), A64(BPF_ADD, 3, -16), MOV64(4, BPF_ANY), CALL(BPF_FUNC_map_update_elem), MOVR(6, 0),
                               LDMAP(1, (int)h), MOVR(2, 10), A64(BPF_ADD, 2, -4), CALL(BPF_FUNC_map_lookup_elem), J(BPF_JEQ, 0, 0, 3),
                               LDX(BPF_DW, 1, 0, 0), ST(BPF_DW, 0, 0, 123), MOVR(0, 1), A64(BPF_LSH, 6, 16), A64R(BPF_OR, 0, 6), EXIT};
        one("hash update and lookup", SF, p, N(p));
        uint32_t k = 7;
        uint64_t v = 0;
        SAY("the value written through the pointer: %ld %llu\n", elem(BPF_MAP_LOOKUP_ELEM, (int)h, &k, &v), (unsigned long long)v);
    }
    {
        struct bpf_insn p[] = {ST(BPF_W, 10, -4, 7), LDMAP(1, (int)h), MOVR(2, 10), A64(BPF_ADD, 2, -4), CALL(BPF_FUNC_map_delete_elem),
                               MOVR(6, 0), LDMAP(1, (int)h), MOVR(2, 10), A64(BPF_ADD, 2, -4), CALL(BPF_FUNC_map_delete_elem),
                               A64(BPF_LSH, 0, 8), A64R(BPF_OR, 0, 6), EXIT};
        one("delete twice", SF, p, N(p));
    }
    long arr = map(BPF_MAP_TYPE_ARRAY, 4, 4, 4);
    {
        uint32_t k = 2, v = 1234;
        elem(BPF_MAP_UPDATE_ELEM, (int)arr, &k, &v);
        struct bpf_insn p[] = {ST(BPF_W, 10, -4, 2), LDMAP(1, (int)arr), MOVR(2, 10), A64(BPF_ADD, 2, -4), CALL(BPF_FUNC_map_lookup_elem),
                               J(BPF_JEQ, 0, 0, 4), MOV64(1, 1), I(BPF_STX | BPF_ATOMIC | BPF_W, 0, 1, 0, BPF_ADD), LDX(BPF_W, 0, 0, 0), EXIT,
                               MOV64(0, 0), EXIT};
        one("array lookup and atomic add", SF, p, N(p));
        v = 0;
        SAY("the array's value: %ld %u\n", elem(BPF_MAP_LOOKUP_ELEM, (int)arr, &k, &v), v);
        struct bpf_insn q[] = {ST(BPF_W, 10, -4, 9), LDMAP(1, (int)arr), MOVR(2, 10), A64(BPF_ADD, 2, -4), CALL(BPF_FUNC_map_lookup_elem),
                               EXIT};
        one("array lookup out of range", SF, q, N(q));
    }
    // A callback for each element (bpf_for_each_map_elem): the sum of an
    // array's values and how many it was given; one that stops at key 2.
    {
        long sums = map(BPF_MAP_TYPE_ARRAY, 4, 4, 4);
        for (uint32_t k = 0; k < 4; k++) {
            uint32_t v = k + 1;
            elem(BPF_MAP_UPDATE_ELEM, (int)sums, &k, &v);
        }
        for (int stop = 0; stop < 2; stop++) {
            struct bpf_insn p[] = {ST(BPF_DW, 10, -8, 0), LDMAP(1, (int)sums), I(BPF_LD | BPF_DW | BPF_IMM, 2, BPF_PSEUDO_FUNC, 0, 9),
                                   I(0, 0, 0, 0, 0), MOVR(3, 10), A64(BPF_ADD, 3, -8), MOV64(4, 0), CALL(BPF_FUNC_for_each_map_elem),
                                   LDX(BPF_DW, 1, 10, -8), A64(BPF_LSH, 1, 8), A64R(BPF_OR, 0, 1), EXIT,
                                   // The callback: (map, key, value, ctx).
                                   LDX(BPF_W, 6, 3, 0), LDX(BPF_DW, 7, 4, 0), A64R(BPF_ADD, 7, 6), STX(BPF_DW, 4, 7, 0), MOV64(0, 0),
                                   LDX(BPF_W, 8, 2, 0), J(BPF_JNE, 8, 2, 1), MOV64(0, stop), EXIT};
            // Described in BTF, the callback static (as the verifier holds a
            // function whose address is taken to): a prototype, "main"
            // global, "cb" static.
            unsigned char btf[24 + 36 + 9];
            memset(btf, 0, sizeof btf);
            uint16_t magic = 0xeb9f;
            memcpy(btf, &magic, 2);
            btf[2] = 1;
            uint32_t h[] = {24, 0, 36, 36, 9};
            memcpy(btf + 4, h, sizeof h);
            uint32_t t[] = {0, 13u << 24, 0, 1, (12u << 24) | 1, 1, 6, 12u << 24, 1};
            memcpy(btf + 24, t, sizeof t);
            memcpy(btf + 60, "\0main\0cb\0", 9);
            union bpf_attr a;
            memset(&a, 0, sizeof a);
            a.btf = (uintptr_t)btf;
            a.btf_size = sizeof btf;
            long bfd = sys_bpf(BPF_BTF_LOAD, &a, sizeof a);
            uint32_t finfo[] = {0, 2, 13, 3};
            for (int with = 0; with < 2; with++) {
                memset(&a, 0, sizeof a);
                a.prog_type = SF;
                a.insns = (uintptr_t)p;
                a.insn_cnt = N(p);
                a.license = (uintptr_t) "GPL";
                if (with) {
                    a.prog_btf_fd = bfd;
                    a.func_info_rec_size = 8;
                    a.func_info = (uintptr_t)finfo;
                    a.func_info_cnt = 2;
                }
                long fd = sys_bpf(BPF_PROG_LOAD, &a, sizeof a);
                const char *what = stop ? "for each, stopping at 2" : "for each";
                if (fd < 0) {
                    SAY("%s, %s BTF: load %ld\n", what, with ? "with" : "without", fd);
                    continue;
                }
                uint32_t ret = 0;
                long r = run(fd, pkt, sizeof pkt, NULL, 1, &ret, NULL);
                SAY("%s: %ld %#x\n", what, r, ret);
                close(fd);
            }
            if (!stop) {
                // A record too few, and the callback global.
                memset(&a, 0, sizeof a);
                a.prog_type = SF;
                a.insns = (uintptr_t)p;
                a.insn_cnt = N(p);
                a.license = (uintptr_t) "GPL";
                a.prog_btf_fd = bfd;
                a.func_info_rec_size = 8;
                a.func_info = (uintptr_t)finfo;
                a.func_info_cnt = 1;
                SAY("one record for two functions: %ld\n", sys_bpf(BPF_PROG_LOAD, &a, sizeof a));
                uint32_t global[] = {0, 2, 13, 2};
                a.func_info = (uintptr_t)global;
                a.func_info_cnt = 2;
                SAY("the callback global: %ld\n", sys_bpf(BPF_PROG_LOAD, &a, sizeof a));
            }
        }
    }
    // The packet: the old loads, from the network header.
    {
        struct bpf_insn p[] = {MOVR(6, 1), I(BPF_LD | BPF_ABS | BPF_B, 0, 0, 0, 9), MOVR(7, 0), I(BPF_LD | BPF_ABS | BPF_H, 0, 0, 0, 22),
                               A64(BPF_LSH, 0, 8), A64R(BPF_OR, 0, 7), EXIT};
        one("ld_abs", SF, p, N(p));
    }
    {
        struct bpf_insn p[] = {MOVR(6, 1), I(BPF_LD | BPF_ABS | BPF_W, 0, 0, 0, 12), EXIT};
        one("ld_abs word", SF, p, N(p));
    }
    {
        struct bpf_insn p[] = {MOVR(6, 1), MOV64(2, 20), I(BPF_LD | BPF_IND | BPF_H, 0, 2, 0, 0), EXIT};
        one("ld_ind", SF, p, N(p));
    }
    {
        struct bpf_insn p[] = {MOVR(6, 1), MOV64(0, 99), I(BPF_LD | BPF_ABS | BPF_B, 0, 0, 0, 1000), MOV64(0, 55), EXIT};
        one("ld_abs past the end", SF, p, N(p));
    }
    {
        struct bpf_insn p[] = {MOVR(6, 1), MOVR(1, 6), MOV64(2, 28), MOVR(3, 10), A64(BPF_ADD, 3, -4), MOV64(4, 4),
                               CALL(BPF_FUNC_skb_load_bytes), MOVR(7, 0), LDX(BPF_W, 0, 10, -4), EXIT};
        one("skb_load_bytes", SF, p, N(p));
    }
    {
        struct bpf_insn p[] = {MOVR(6, 1), MOVR(1, 6), MOV64(2, 30), MOVR(3, 10), A64(BPF_ADD, 3, -8), MOV64(4, 8),
                               CALL(BPF_FUNC_skb_load_bytes), EXIT};
        one("skb_load_bytes past the end", SF, p, N(p));
    }
    // The context.
    {
        struct bpf_insn p[] = {LDX(BPF_W, 0, 1, offsetof(struct __sk_buff, len)), LDX(BPF_W, 2, 1, offsetof(struct __sk_buff, protocol)),
                               A64(BPF_LSH, 2, 8), A64R(BPF_OR, 0, 2), LDX(BPF_W, 2, 1, offsetof(struct __sk_buff, ifindex)),
                               A64(BPF_LSH, 2, 24), A64R(BPF_OR, 0, 2), LDX(BPF_W, 2, 1, offsetof(struct __sk_buff, pkt_type)),
                               A64(BPF_LSH, 2, 28), A64R(BPF_OR, 0, 2), EXIT};
        one("len protocol ifindex pkt_type", SF, p, N(p));
    }
    {
        struct bpf_insn p[] = {LDX(BPF_W, 0, 1, offsetof(struct __sk_buff, mark)), LDX(BPF_W, 2, 1, offsetof(struct __sk_buff, cb[0])),
                               A64(BPF_LSH, 2, 8), A64R(BPF_OR, 0, 2), ST(BPF_W, 1, offsetof(struct __sk_buff, cb[1]), 0x22), EXIT};
        long fd = load(SF, p, N(p));
        struct __sk_buff c;
        memset(&c, 0, sizeof c);
        c.mark = 7;
        c.cb[0] = 0x11;
        uint32_t ret = 0;
        long r = run(fd, pkt, sizeof pkt, &c, 1, &ret, NULL);
        SAY("mark and cb: %ld %#x, cb[1] after %#x, wire_len %u, ifindex %u\n", r, ret, ctx_out.cb[1], ctx_out.wire_len, ctx_out.ifindex);
        c.len = 5;
        SAY("a context with len: %ld\n", run(fd, pkt, sizeof pkt, &c, 1, &ret, NULL));
        c.len = 0;
        c.ifindex = 77;
        SAY("a context with an interface not there: %ld\n", run(fd, pkt, sizeof pkt, &c, 1, &ret, NULL));
        close(fd);
    }
    {
        struct bpf_insn p[] = {LDX(BPF_W, 2, 1, offsetof(struct __sk_buff, cb[0])), A64(BPF_ADD, 2, 1),
                               STX(BPF_W, 1, 2, offsetof(struct __sk_buff, cb[0])), MOVR(0, 2), EXIT};
        long fd = load(SF, p, N(p));
        struct __sk_buff c;
        memset(&c, 0, sizeof c);
        uint32_t ret = 0;
        long r = run(fd, pkt, sizeof pkt, &c, 5, &ret, NULL);
        SAY("five runs: %ld %u, cb[0] after %u\n", r, ret, ctx_out.cb[0]);
        unsigned outlen = 0;
        r = run(fd, pkt, sizeof pkt, NULL, 1, &ret, &outlen);
        SAY("the packet back: %ld, %u bytes, the link header zeroed %d, the rest as it was %d\n", r, outlen, data_out[12] == 0,
            memcmp(data_out + 14, pkt + 14, 32) == 0);
        SAY("a packet of 13: %ld\n", run(fd, pkt, 13, NULL, 1, &ret, NULL));
        static unsigned char big[4096];
        memcpy(big, pkt, sizeof pkt);
        // (The most 6.18 takes on arm64, a page less an skb's room; 7.0
        // takes far more, so the size past it is not asked.)
        SAY("a packet of 3648: %ld\n", run(fd, big, 3648, NULL, 1, &ret, NULL) == -ENOSPC ? 0 : -1L);
        union bpf_attr a;
        memset(&a, 0, sizeof a);
        a.test.prog_fd = fd;
        a.test.data_in = (uintptr_t)pkt;
        a.test.data_size_in = sizeof pkt;
        a.test.data_out = (uintptr_t)data_out;
        a.test.data_size_out = 10;
        r = sys_bpf(BPF_PROG_TEST_RUN, &a, sizeof a);
        SAY("room for 10: %ld, size %u\n", r, a.test.data_size_out);
        close(fd);
    }
    // A classifier sees the link layer's header and may write the packet.
    {
        struct bpf_insn p[] = {LDX(BPF_W, 5, 1, offsetof(struct __sk_buff, len)), LDX(BPF_W, 2, 1, offsetof(struct __sk_buff, data)),
                               LDX(BPF_W, 3, 1, offsetof(struct __sk_buff, data_end)), MOVR(4, 2), A64(BPF_ADD, 4, 14), MOV64(0, 0),
                               JR(BPF_JGT, 4, 3, 2), LDX(BPF_B, 0, 2, 12), ST(BPF_B, 2, 0, 0xaa), A64(BPF_LSH, 5, 8), A64R(BPF_OR, 0, 5), EXIT};
        long fd = load(BPF_PROG_TYPE_SCHED_CLS, p, N(p));
        uint32_t ret = 0;
        unsigned outlen = 0;
        long r = run(fd, pkt, sizeof pkt, NULL, 1, &ret, &outlen);
        SAY("classifier: %ld %#x, %u bytes back, the first %#x\n", r, ret, outlen, data_out[0]);
        close(fd);
    }
    // A cgroup skb program: the socket's family and address.
    {
        struct bpf_insn p[] = {LDX(BPF_W, 2, 1, offsetof(struct __sk_buff, family)), LDX(BPF_W, 3, 1, offsetof(struct __sk_buff, local_ip4)),
                               MOV64(0, 0), J(BPF_JNE, 2, 2, 2), J(BPF_JNE, 3, 0x0100000a, 1), MOV64(0, 1), EXIT};
        one("cgroup skb", BPF_PROG_TYPE_CGROUP_SKB, p, N(p));
    }
    {
        struct bpf_insn p[] = {MOV64(0, 1), EXIT};
        union bpf_attr a;
        memset(&a, 0, sizeof a);
        a.prog_type = BPF_PROG_TYPE_CGROUP_SOCK;
        a.expected_attach_type = BPF_CGROUP_INET_SOCK_CREATE;
        a.insns = (uintptr_t)p;
        a.insn_cnt = N(p);
        a.license = (uintptr_t) "GPL";
        long fd = sys_bpf(BPF_PROG_LOAD, &a, sizeof a);
        uint32_t ret = 0;
        SAY("a socket program run: %ld\n", run(fd, pkt, sizeof pkt, NULL, 1, &ret, NULL));
        close(fd);
    }

    if (expected[0] && strcmp(out_buf, expected) != 0) {
        printf("bpfrun: not what Linux shows\n");
        return 1;
    }
    printf(expected[0] ? "bpfrun ok\n" : "bpfrun done\n");
    return 0;
}
