// BPF programs at a cgroup's getsockopt and setsockopt: one that answers
// an option of its own (and refuses too small a buffer with
// bpf_set_retval), one that answers a setsockopt itself (length -1),
// changes another's value before the kernel takes it, and refuses a
// third. Prints an answer a line and checks them against Linux 7.0's. As
// root.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static long sys_bpf(int cmd, union bpf_attr *attr, unsigned size) {
    long r = syscall(__NR_bpf, cmd, attr, size);
    return r < 0 ? -errno : r;
}

// What Linux 7.0 printed.
static const char expected[] =
    "loaded: 1 1\n"
    "attached: 0 0\n"
    "its own option: 0, 0x77, 8 bytes\n"
    "into seven bytes: -22\n"
    "SO_TYPE, untouched: 0 2 4\n"
    "set 0x4321, answered by the program: 0\n"
    "set SO_MARK 5: 0, the mark 9\n"
    "set 0x5555, refused: -1\n"
    "detached: 0 0\n"
    "its own option without it: -92\n"
    "away: 0\n"
;

static char out_buf[4096];
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
#define MOVR(d, s) I(BPF_ALU64 | BPF_MOV | BPF_X, d, s, 0, 0)
#define EXIT I(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)
#define LDX(sz, d, s, o) I(BPF_LDX | BPF_MEM | (sz), d, s, o, 0)
#define ST(sz, d, o, i) I(BPF_ST | BPF_MEM | (sz), d, 0, o, i)
#define JNE(d, i, o) I(BPF_JMP | BPF_JNE | BPF_K, d, 0, o, i)
#define JEQ(d, i, o) I(BPF_JMP | BPF_JEQ | BPF_K, d, 0, o, i)
#define N(a) (int)(sizeof(a) / sizeof(a[0]))
#define OFF(f) offsetof(struct bpf_sockopt, f)

static long load(int expected_attach, const struct bpf_insn *p, int n) {
    union bpf_attr a;
    memset(&a, 0, sizeof a);
    a.prog_type = BPF_PROG_TYPE_CGROUP_SOCKOPT;
    a.expected_attach_type = expected_attach;
    a.insns = (uintptr_t)p;
    a.insn_cnt = n;
    a.license = (uintptr_t) "GPL";
    return sys_bpf(BPF_PROG_LOAD, &a, sizeof a);
}

static long attach(int cg, int prog, int type) {
    union bpf_attr a;
    memset(&a, 0, sizeof a);
    a.target_fd = cg;
    a.attach_bpf_fd = prog;
    a.attach_type = type;
    return sys_bpf(BPF_PROG_ATTACH, &a, sizeof a);
}

static long detach(int cg, int prog, int type) {
    union bpf_attr a;
    memset(&a, 0, sizeof a);
    a.target_fd = cg;
    a.attach_bpf_fd = prog;
    a.attach_type = type;
    return sys_bpf(BPF_PROG_DETACH, &a, sizeof a);
}

static void into(const char *procs) {
    int fd = open(procs, O_WRONLY);
    write(fd, "0", 1);
    close(fd);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    const char *base = "/tmp/gexcg4";
    mkdir(base, 0755);
    if (mount("none", base, "cgroup2", 0, NULL) != 0) {
        printf("sockopt: no mount: %s\n", strerror(errno));
        return 1;
    }
    rmdir("/tmp/gexcg4/gexopt");
    mkdir("/tmp/gexcg4/gexopt", 0755);
    int cg = open("/tmp/gexcg4/gexopt", O_RDONLY | O_DIRECTORY);
    into("/tmp/gexcg4/gexopt/cgroup.procs");

    // getsockopt(SOL_SOCKET, 0x1234): eight bytes of 0x77, or EINVAL for
    // less room.
    struct bpf_insn get[] = {
        MOVR(6, 1), LDX(BPF_W, 2, 6, OFF(level)), JNE(2, SOL_SOCKET, 16), LDX(BPF_W, 2, 6, OFF(optname)), JNE(2, 0x1234, 14),
        LDX(BPF_DW, 2, 6, OFF(optval)), LDX(BPF_DW, 3, 6, OFF(optval_end)), MOVR(4, 2), I(BPF_ALU64 | BPF_ADD | BPF_K, 4, 0, 0, 8),
        I(BPF_JMP | BPF_JGT | BPF_X, 4, 3, 5, 0), ST(BPF_DW, 2, 0, 0x77), ST(BPF_W, 6, OFF(optlen), 8), ST(BPF_W, 6, OFF(retval), 0), MOV64(0, 1), EXIT,
        MOV64(1, -EINVAL), I(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_set_retval), MOV64(0, 0), EXIT,
        MOV64(0, 1), EXIT};
    // setsockopt: 0x4321 answered here; SO_MARK's value made 9; 0x5555
    // refused.
    struct bpf_insn set[] = {
        MOVR(6, 1), LDX(BPF_W, 2, 6, OFF(optname)), JNE(2, 0x4321, 3), ST(BPF_W, 6, OFF(optlen), -1), MOV64(0, 1), EXIT,
        JEQ(2, 0x5555, 9), JNE(2, SO_MARK, 6), LDX(BPF_DW, 3, 6, OFF(optval)), LDX(BPF_DW, 4, 6, OFF(optval_end)), MOVR(5, 3),
        I(BPF_ALU64 | BPF_ADD | BPF_K, 5, 0, 0, 4), I(BPF_JMP | BPF_JGT | BPF_X, 5, 4, 1, 0), ST(BPF_W, 3, 0, 9), MOV64(0, 1), EXIT,
        MOV64(0, 0), EXIT};
    long pg = load(BPF_CGROUP_GETSOCKOPT, get, N(get)), ps = load(BPF_CGROUP_SETSOCKOPT, set, N(set));
    SAY("loaded: %d %d\n", pg > 0, ps > 0);
    SAY("attached: %ld %ld\n", attach(cg, (int)pg, BPF_CGROUP_GETSOCKOPT), attach(cg, (int)ps, BPF_CGROUP_SETSOCKOPT));

    int s = socket(AF_INET, SOCK_DGRAM, 0);
    uint64_t v = 0;
    socklen_t l = sizeof v;
    int r = getsockopt(s, SOL_SOCKET, 0x1234, &v, &l);
    SAY("its own option: %d, %#llx, %u bytes\n", r == 0 ? 0 : -errno, (unsigned long long)v, l);
    l = 7;
    r = getsockopt(s, SOL_SOCKET, 0x1234, &v, &l);
    SAY("into seven bytes: %d\n", r == 0 ? 0 : -errno);
    int ty = 0;
    l = sizeof ty;
    r = getsockopt(s, SOL_SOCKET, SO_TYPE, &ty, &l);
    SAY("SO_TYPE, untouched: %d %d %u\n", r == 0 ? 0 : -errno, ty, l);
    int one = 1;
    SAY("set 0x4321, answered by the program: %d\n", setsockopt(s, SOL_SOCKET, 0x4321, &one, 4) == 0 ? 0 : -errno);
    int five = 5;
    r = setsockopt(s, SOL_SOCKET, SO_MARK, &five, 4);
    int mark = 0;
    l = sizeof mark;
    getsockopt(s, SOL_SOCKET, SO_MARK, &mark, &l);
    SAY("set SO_MARK 5: %d, the mark %d\n", r == 0 ? 0 : -errno, mark);
    SAY("set 0x5555, refused: %d\n", setsockopt(s, SOL_SOCKET, 0x5555, &one, 4) == 0 ? 0 : -errno);
    SAY("detached: %ld %ld\n", detach(cg, (int)pg, BPF_CGROUP_GETSOCKOPT), detach(cg, (int)ps, BPF_CGROUP_SETSOCKOPT));
    l = sizeof v;
    SAY("its own option without it: %d\n", getsockopt(s, SOL_SOCKET, 0x1234, &v, &l) == 0 ? 0 : -errno);
    close(s);

    into("/tmp/gexcg4/cgroup.procs");
    close(cg);
    SAY("away: %d\n", rmdir("/tmp/gexcg4/gexopt") == 0 ? 0 : -errno);
    umount(base);
    if (expected[0] && strcmp(out_buf, expected) != 0) {
        printf("sockopt: not what Linux shows\n");
        return 1;
    }
    printf(expected[0] ? "sockopt ok\n" : "sockopt done\n");
    return 0;
}
