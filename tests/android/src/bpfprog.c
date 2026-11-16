// BPF_PROG_LOAD as libbpf and netbpfload use it: a program is checked and
// kept, and is a descriptor, an id, a pin. What is refused is what the
// kernel refuses of a program's form: an instruction it does not know, a
// jump out of the program or into the middle of a 64-bit load, no exit, an
// instruction nothing reaches, the frame pointer written, a register read
// before it is written, a division by zero, a map that is not one, a
// helper that is not one or is GPL-only for a program that is not, an
// attach type its program type does not take. Prints an answer a line and
// checks them against what Linux 7.0 gave. As root.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static long sys_bpf(int cmd, union bpf_attr *attr, unsigned size) {
    long r = syscall(__NR_bpf, cmd, attr, size);
    return r < 0 ? -errno : r;
}

// What Linux 7.0 printed.
static const char expected[] =
    "the least program: loaded\n"
    "its info: 0 type 1 name gex_prog xlated 16\n"
    "no instructions: -7\n"
    "type 999: -22\n"
    "an unknown instruction: -22\n"
    "a jump out of the program: -22\n"
    "the frame pointer written: -13\n"
    "no exit: -22\n"
    "an instruction never reached: -22\n"
    "r0 never written: -13\n"
    "r2 read before written: -13\n"
    "a division by zero: -22\n"
    "a shift by 64: -22\n"
    "a jump into a 64-bit load: -22\n"
    "a 64-bit load's second half not empty: -22\n"
    "helper 9999: -22\n"
    "a GPL-only helper, not GPL: -22\n"
    "a map's lookup: loaded\n"
    "a map by a descriptor not open: -9\n"
    "a map by a pipe: -22\n"
    "a map value's address, two elements: -524\n"
    "a map value's address: loaded\n"
    "a map value's address past it: -22\n"
    "cgroup sock, none: loaded\n"
    "cgroup sock, ingress: loaded\n"
    "cgroup sock_addr, none: -22\n"
    "cgroup sock_addr, connect4: loaded\n"
    "cgroup skb, egress: loaded\n"
    "cgroup skb, sock create: -22\n"
    "bad name: -22\n"
    "program ids: ours there 1, ended -2\n"
    "by id: loaded\n"
    "pin: 0\n"
    "get: loaded\n"
    "with a log: loaded\n"
    "it says: processed 2 insns \n"
;

static char out_buf[8192];
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
#define MOV_K(d, i) I(BPF_ALU64 | BPF_MOV | BPF_K, d, 0, 0, i)
#define MOV_X(d, s) I(BPF_ALU64 | BPF_MOV | BPF_X, d, s, 0, 0)
#define EXIT I(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)
#define JA(o) I(BPF_JMP | BPF_JA, 0, 0, o, 0)
#define CALL(n) I(BPF_JMP | BPF_CALL, 0, 0, 0, n)

static long load_as(int type, int attach, const struct bpf_insn *insns, int n, const char *license, const char *name) {
    union bpf_attr a;
    memset(&a, 0, sizeof a);
    a.prog_type = type;
    a.insns = (uintptr_t)insns;
    a.insn_cnt = n;
    a.license = (uintptr_t)license;
    a.expected_attach_type = attach;
    if (name) strncpy(a.prog_name, name, sizeof a.prog_name - 1);
    return sys_bpf(BPF_PROG_LOAD, &a, sizeof a);
}

static long load(const struct bpf_insn *insns, int n) {
    return load_as(BPF_PROG_TYPE_SOCKET_FILTER, 0, insns, n, "GPL", NULL);
}

#define N(a) ((int)(sizeof(a) / sizeof(a[0])))
#define SHOW(what, r) SAY("%s: %s\n", what, (r) >= 0 ? "loaded" : (snprintf(err, sizeof err, "%ld", (long)(r)), err))
static char err[32];

int main(void) {
    struct bpf_insn ok[] = {MOV_K(0, 0), EXIT};
    long p = load_as(BPF_PROG_TYPE_SOCKET_FILTER, 0, ok, N(ok), "GPL", "gex_prog");
    SHOW("the least program", p);
    struct bpf_prog_info info;
    memset(&info, 0, sizeof info);
    union bpf_attr ia;
    memset(&ia, 0, sizeof ia);
    ia.info.bpf_fd = p;
    ia.info.info_len = sizeof info;
    ia.info.info = (uintptr_t)&info;
    long ir = sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &ia, sizeof ia);
    SAY("its info: %ld type %u name %s xlated %u\n", ir, info.type, info.name, info.xlated_prog_len);

    SHOW("no instructions", load(ok, 0));
    SHOW("type 999", load_as(999, 0, ok, N(ok), "GPL", NULL));
    struct bpf_insn badop[] = {I(0xff, 0, 0, 0, 0), MOV_K(0, 0), EXIT};
    SHOW("an unknown instruction", load(badop, N(badop)));
    struct bpf_insn far[] = {JA(5), MOV_K(0, 0), EXIT};
    SHOW("a jump out of the program", load(far, N(far)));
    struct bpf_insn fp[] = {MOV_K(10, 0), MOV_K(0, 0), EXIT};
    SHOW("the frame pointer written", load(fp, N(fp)));
    struct bpf_insn noexit[] = {MOV_K(0, 0)};
    SHOW("no exit", load(noexit, N(noexit)));
    struct bpf_insn unreached[] = {MOV_K(0, 0), JA(1), MOV_K(0, 1), EXIT};
    SHOW("an instruction never reached", load(unreached, N(unreached)));
    struct bpf_insn r0[] = {EXIT};
    SHOW("r0 never written", load(r0, N(r0)));
    struct bpf_insn r2[] = {MOV_X(0, 2), EXIT};
    SHOW("r2 read before written", load(r2, N(r2)));
    struct bpf_insn div0[] = {MOV_K(0, 1), I(BPF_ALU64 | BPF_DIV | BPF_K, 0, 0, 0, 0), EXIT};
    SHOW("a division by zero", load(div0, N(div0)));
    struct bpf_insn shift[] = {MOV_K(0, 1), I(BPF_ALU64 | BPF_LSH | BPF_K, 0, 0, 0, 64), EXIT};
    SHOW("a shift by 64", load(shift, N(shift)));
    struct bpf_insn mid[] = {JA(1), I(BPF_LD | BPF_IMM | BPF_DW, 0, 0, 0, 1), I(0, 0, 0, 0, 0), EXIT};
    SHOW("a jump into a 64-bit load", load(mid, N(mid)));
    struct bpf_insn bad_ld[] = {I(BPF_LD | BPF_IMM | BPF_DW, 0, 0, 0, 1), I(0, 1, 0, 0, 0), EXIT};
    SHOW("a 64-bit load's second half not empty", load(bad_ld, N(bad_ld)));
    struct bpf_insn unk[] = {CALL(9999), MOV_K(0, 0), EXIT};
    SHOW("helper 9999", load(unk, N(unk)));
    struct bpf_insn printk[] = {CALL(BPF_FUNC_trace_printk), MOV_K(0, 0), EXIT};
    SHOW("a GPL-only helper, not GPL", load_as(BPF_PROG_TYPE_SOCKET_FILTER, 0, printk, N(printk), "Proprietary", NULL));

    // A map, by its descriptor.
    union bpf_attr ma;
    memset(&ma, 0, sizeof ma);
    ma.map_type = BPF_MAP_TYPE_ARRAY;
    ma.key_size = 4;
    ma.value_size = 8;
    ma.max_entries = 2;
    long map = sys_bpf(BPF_MAP_CREATE, &ma, sizeof ma);
    struct bpf_insn lookup[] = {
        I(BPF_LD | BPF_IMM | BPF_DW, 1, BPF_PSEUDO_MAP_FD, 0, (int)map), I(0, 0, 0, 0, 0),
        I(BPF_ST | BPF_MEM | BPF_W, 10, 0, -4, 0),
        MOV_X(2, 10),
        I(BPF_ALU64 | BPF_ADD | BPF_K, 2, 0, 0, -4),
        CALL(BPF_FUNC_map_lookup_elem),
        MOV_K(0, 0),
        EXIT,
    };
    SHOW("a map's lookup", load(lookup, N(lookup)));
    lookup[0].imm = 9999;
    SHOW("a map by a descriptor not open", load(lookup, N(lookup)));
    int pipes[2];
    pipe(pipes);
    lookup[0].imm = pipes[0];
    SHOW("a map by a pipe", load(lookup, N(lookup)));
    struct bpf_insn value[] = {I(BPF_LD | BPF_IMM | BPF_DW, 1, BPF_PSEUDO_MAP_VALUE, 0, (int)map), I(0, 0, 0, 0, 4), MOV_K(0, 0), EXIT};
    SHOW("a map value's address, two elements", load(value, N(value)));
    ma.max_entries = 1;
    long map1 = sys_bpf(BPF_MAP_CREATE, &ma, sizeof ma);
    value[0].imm = (int)map1;
    SHOW("a map value's address", load(value, N(value)));
    value[1].imm = 8;
    SHOW("a map value's address past it", load(value, N(value)));

    // What a program expects to be attached to.
    SHOW("cgroup sock, none", load_as(BPF_PROG_TYPE_CGROUP_SOCK, 0, ok, N(ok), "GPL", NULL));
    SHOW("cgroup sock, ingress", load_as(BPF_PROG_TYPE_CGROUP_SOCK, BPF_CGROUP_INET_INGRESS, ok, N(ok), "GPL", NULL));
    struct bpf_insn one[] = {MOV_K(0, 1), EXIT};
    SHOW("cgroup sock_addr, none", load_as(BPF_PROG_TYPE_CGROUP_SOCK_ADDR, 0, one, N(one), "GPL", NULL));
    SHOW("cgroup sock_addr, connect4", load_as(BPF_PROG_TYPE_CGROUP_SOCK_ADDR, BPF_CGROUP_INET4_CONNECT, one, N(one), "GPL", NULL));
    SHOW("cgroup skb, egress", load_as(BPF_PROG_TYPE_CGROUP_SKB, BPF_CGROUP_INET_EGRESS, one, N(one), "GPL", NULL));
    SHOW("cgroup skb, sock create", load_as(BPF_PROG_TYPE_CGROUP_SKB, BPF_CGROUP_INET_SOCK_CREATE, one, N(one), "GPL", NULL));
    SHOW("bad name", load_as(BPF_PROG_TYPE_SOCKET_FILTER, 0, ok, N(ok), "GPL", "no-dash!"));

    // Its id, and a pin.
    uint32_t id = 0, ours = info.id;
    int found = 0;
    long rr;
    for (;;) {
        union bpf_attr na;
        memset(&na, 0, sizeof na);
        na.start_id = id;
        rr = sys_bpf(BPF_PROG_GET_NEXT_ID, &na, sizeof na);
        if (rr) break;
        if (na.next_id == ours) found = 1;
        id = na.next_id;
    }
    SAY("program ids: ours there %d, ended %ld\n", found, rr);
    union bpf_attr fa;
    memset(&fa, 0, sizeof fa);
    fa.prog_id = ours;
    SHOW("by id", sys_bpf(BPF_PROG_GET_FD_BY_ID, &fa, sizeof fa));
    char dir[] = "/tmp/bpfprog.XXXXXX";
    mkdtemp(dir);
    mount("bpf", dir, "bpf", 0, NULL);
    char path[96];
    snprintf(path, sizeof path, "%s/prog", dir);
    union bpf_attr pa;
    memset(&pa, 0, sizeof pa);
    pa.bpf_fd = p;
    pa.pathname = (uintptr_t)path;
    SAY("pin: %ld\n", sys_bpf(BPF_OBJ_PIN, &pa, sizeof pa));
    memset(&pa, 0, sizeof pa);
    pa.pathname = (uintptr_t)path;
    SHOW("get", sys_bpf(BPF_OBJ_GET, &pa, sizeof pa));
    umount2(dir, MNT_DETACH);
    rmdir(dir);

    // The log.
    static char log[4096];
    union bpf_attr la;
    memset(&la, 0, sizeof la);
    la.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    la.insns = (uintptr_t)ok;
    la.insn_cnt = N(ok);
    la.license = (uintptr_t)"GPL";
    la.log_buf = (uintptr_t)log;
    la.log_size = sizeof log;
    la.log_level = 1;
    SHOW("with a log", sys_bpf(BPF_PROG_LOAD, &la, sizeof la));
    SAY("it says: %.18s\n", log);

    if (expected[0] && strcmp(out_buf, expected) != 0) {
        printf("bpfprog: not what Linux shows\n");
        return 1;
    }
    printf(expected[0] ? "bpfprog ok\n" : "bpfprog done\n");
    return 0;
}
