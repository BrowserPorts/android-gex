// BPF programs run where a process in a cgroup makes a socket
// (BPF_CGROUP_INET_SOCK_CREATE): one that keeps the socket's cookie and
// its maker's ids in socket storage, marks a TCP socket and refuses a UDP
// one (EPERM); inherited by a group under it; several at once, one saying
// no; a socket that is not an internet one untouched. And SO_COOKIE,
// SO_MARK, SO_PRIORITY. Prints an answer a line and checks them against
// Linux 7.0's. As root.
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
#include <sys/wait.h>
#include <unistd.h>

#ifndef SO_COOKIE
#define SO_COOKIE 57
#endif

static long sys_bpf(int cmd, union bpf_attr *attr, unsigned size) {
    long r = syscall(__NR_bpf, cmd, attr, size);
    return r < 0 ? -errno : r;
}

// What Linux 7.0 printed.
static const char expected[] =
    "storage: 1\n"
    "loaded: 1, attached: 0\n"
    "tcp: 0\n"
    "its mark 0x55, priority 0, a cookie 1\n"
    "kept: 0, the cookie 1, the ids 0\n"
    "udp: -1\n"
    "unix: 0, a cookie of its own 1\n"
    "the same cookie asked again: 1\n"
    "set mark 7: 0, priority 3: 0, read 7 3\n"
    "a cookie into 4 bytes: -22\n"
    "a user's socket: 1, kept 0, the ids 0x4d2000010e1\n"
    "udp in the group under it: -1\n"
    "detached: 0, udp: 1\n"
    "two attached: 0 0, tcp: -1\n"
    "the one saying no away: 0, tcp: 1\n"
    "away: 0 0\n"
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
#define MOV64(d, i) I(BPF_ALU64 | BPF_MOV | BPF_K, d, 0, 0, i)
#define MOVR(d, s) I(BPF_ALU64 | BPF_MOV | BPF_X, d, s, 0, 0)
#define EXIT I(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)
#define LDMAP(d, fd) I(BPF_LD | BPF_DW | BPF_IMM, d, BPF_PSEUDO_MAP_FD, 0, fd), I(0, 0, 0, 0, 0)
#define CALL(f) I(BPF_JMP | BPF_CALL, 0, 0, 0, f)
#define N(a) (int)(sizeof(a) / sizeof(a[0]))

static long load(const struct bpf_insn *p, int n) {
    union bpf_attr a;
    memset(&a, 0, sizeof a);
    a.prog_type = BPF_PROG_TYPE_CGROUP_SOCK;
    a.expected_attach_type = BPF_CGROUP_INET_SOCK_CREATE;
    a.insns = (uintptr_t)p;
    a.insn_cnt = n;
    a.license = (uintptr_t) "GPL";
    return sys_bpf(BPF_PROG_LOAD, &a, sizeof a);
}

static long attach(int cg, int prog, unsigned flags) {
    union bpf_attr a;
    memset(&a, 0, sizeof a);
    a.target_fd = cg;
    a.attach_bpf_fd = prog;
    a.attach_type = BPF_CGROUP_INET_SOCK_CREATE;
    a.attach_flags = flags;
    return sys_bpf(BPF_PROG_ATTACH, &a, sizeof a);
}

static long detach(int cg, int prog) {
    union bpf_attr a;
    memset(&a, 0, sizeof a);
    a.target_fd = cg;
    a.attach_bpf_fd = prog;
    a.attach_type = BPF_CGROUP_INET_SOCK_CREATE;
    return sys_bpf(BPF_PROG_DETACH, &a, sizeof a);
}

static char base[] = "/tmp/gexcg3";

static void into(const char *group) {
    char p[256];
    snprintf(p, sizeof p, "%s/%s/cgroup.procs", base, group);
    int fd = open(p, O_WRONLY);
    write(fd, "0", 1);
    close(fd);
}

static long sock(int domain, int type) {
    int s = socket(domain, type, 0);
    return s < 0 ? -errno : s;
}

static uint32_t opt32(int s, int name) {
    uint32_t v = 0;
    socklen_t l = sizeof v;
    getsockopt(s, SOL_SOCKET, name, &v, &l);
    return v;
}

static uint64_t cookie(int s) {
    uint64_t c = 0;
    socklen_t l = sizeof c;
    if (getsockopt(s, SOL_SOCKET, SO_COOKIE, &c, &l) != 0) return 0;
    return c;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    mkdir(base, 0755);
    if (mount("none", base, "cgroup2", 0, NULL) != 0) {
        printf("sockhook: no mount: %s\n", strerror(errno));
        return 1;
    }
    char g[256], c[256];
    snprintf(g, sizeof g, "%s/gexsock", base);
    snprintf(c, sizeof c, "%s/gexsock/c", base);
    rmdir(c);
    rmdir(g);
    mkdir(g, 0755);
    mkdir(c, 0755);
    int gfd = open(g, O_RDONLY | O_DIRECTORY);
    into("gexsock");

    // Socket storage: a key of an int, a value of 16 bytes (an int of 128
    // bits, to the BTF).
    unsigned char btf[24 + 32 + 7];
    memset(btf, 0, sizeof btf);
    uint16_t magic = 0xeb9f;
    memcpy(btf, &magic, 2);
    btf[2] = 1;
    uint32_t h[] = {24, 0, 32, 32, 7};
    memcpy(btf + 4, h, sizeof h);
    uint32_t t[] = {1, 1u << 24, 4, 0x01000020, 5, 1u << 24, 16, 128};
    memcpy(btf + 24, t, sizeof t);
    memcpy(btf + 56, "\0int\0v", 7);
    union bpf_attr a;
    memset(&a, 0, sizeof a);
    a.btf = (uintptr_t)btf;
    a.btf_size = sizeof btf;
    long bfd = sys_bpf(BPF_BTF_LOAD, &a, sizeof a);
    memset(&a, 0, sizeof a);
    a.map_type = BPF_MAP_TYPE_SK_STORAGE;
    a.key_size = 4;
    a.value_size = 16;
    a.map_flags = BPF_F_NO_PREALLOC;
    a.btf_fd = bfd;
    a.btf_key_type_id = 1;
    a.btf_value_type_id = 2;
    long st = sys_bpf(BPF_MAP_CREATE, &a, sizeof a);
    SAY("storage: %d\n", st > 0);

    struct bpf_insn keep[] = {
        MOVR(6, 1), LDMAP(1, (int)st), MOVR(2, 6), MOV64(3, 0), MOV64(4, 1), CALL(BPF_FUNC_sk_storage_get), I(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 6, 0),
        MOVR(7, 0), MOVR(1, 6), CALL(BPF_FUNC_get_socket_cookie), I(BPF_STX | BPF_MEM | BPF_DW, 7, 0, 0, 0), CALL(BPF_FUNC_get_current_uid_gid),
        I(BPF_STX | BPF_MEM | BPF_DW, 7, 0, 8, 0), I(BPF_LDX | BPF_MEM | BPF_W, 2, 6, offsetof(struct bpf_sock, type), 0),
        I(BPF_JMP | BPF_JEQ | BPF_K, 2, 0, 3, SOCK_DGRAM), I(BPF_ST | BPF_MEM | BPF_W, 6, 0, offsetof(struct bpf_sock, mark), 0x55), MOV64(0, 1), EXIT,
        MOV64(0, 0), EXIT};
    long p = load(keep, N(keep));
    SAY("loaded: %d, attached: %ld\n", p > 0, attach(gfd, (int)p, 0));

    long tcp = sock(AF_INET, SOCK_STREAM);
    SAY("tcp: %d\n", tcp > 0 ? 0 : (int)tcp);
    uint64_t ck = cookie((int)tcp);
    SAY("its mark %#x, priority %u, a cookie %d\n", opt32((int)tcp, SO_MARK), opt32((int)tcp, SO_PRIORITY), ck != 0);
    uint64_t v[2] = {0, 0};
    int key = (int)tcp;
    memset(&a, 0, sizeof a);
    a.map_fd = st;
    a.key = (uintptr_t)&key;
    a.value = (uintptr_t)v;
    long r = sys_bpf(BPF_MAP_LOOKUP_ELEM, &a, sizeof a);
    SAY("kept: %ld, the cookie %d, the ids %#llx\n", r, v[0] == ck, (unsigned long long)v[1]);
    SAY("udp: %ld\n", sock(AF_INET, SOCK_DGRAM));
    long un = sock(AF_UNIX, SOCK_STREAM);
    SAY("unix: %d, a cookie of its own %d\n", un > 0 ? 0 : (int)un, cookie((int)un) != 0 && cookie((int)un) != ck);
    SAY("the same cookie asked again: %d\n", cookie((int)tcp) == ck);
    uint32_t seven = 7, three = 3;
    SAY("set mark 7: %d, priority 3: %d, read %u %u\n", setsockopt((int)tcp, SOL_SOCKET, SO_MARK, &seven, 4),
        setsockopt((int)tcp, SOL_SOCKET, SO_PRIORITY, &three, 4), opt32((int)tcp, SO_MARK), opt32((int)tcp, SO_PRIORITY));
    char small[4];
    socklen_t sl = sizeof small;
    SAY("a cookie into 4 bytes: %d\n", getsockopt((int)tcp, SOL_SOCKET, SO_COOKIE, small, &sl) == 0 ? 0 : -errno);

    // A user's process: its ids.
    int pp[2];
    pipe(pp);
    pid_t kid = fork();
    if (kid == 0) {
        if (setgid(1234) != 0 || setuid(4321) != 0) _exit(1);
        int s = socket(AF_INET, SOCK_STREAM, 0);
        uint64_t w[2] = {0, 0};
        union bpf_attr b;
        memset(&b, 0, sizeof b);
        b.map_fd = st;
        b.key = (uintptr_t)&s;
        b.value = (uintptr_t)w;
        long rr = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &b, sizeof b);
        dprintf(pp[1], "a user's socket: %d, kept %ld, the ids %#llx\n", s > 0, rr, (unsigned long long)w[1]);
        _exit(0);
    }
    close(pp[1]);
    char line[256] = {0};
    if (read(pp[0], line, sizeof line - 1) <= 0) strcpy(line, "a user's socket: nothing\n");
    waitpid(kid, NULL, 0);
    SAY("%s", line);

    // A group under it: the program is still its.
    into("gexsock/c");
    SAY("udp in the group under it: %ld\n", sock(AF_INET, SOCK_DGRAM));
    into("gexsock");
    SAY("detached: %ld, udp: %d\n", detach(gfd, (int)p), sock(AF_INET, SOCK_DGRAM) > 0);

    // Two at once, one saying no.
    struct bpf_insn yes[] = {MOV64(0, 1), EXIT}, no[] = {MOV64(0, 0), EXIT};
    long py = load(yes, N(yes)), pn = load(no, N(no));
    SAY("two attached: %ld %ld, tcp: %ld\n", attach(gfd, (int)py, BPF_F_ALLOW_MULTI), attach(gfd, (int)pn, BPF_F_ALLOW_MULTI),
        sock(AF_INET, SOCK_STREAM));
    SAY("the one saying no away: %ld, tcp: %d\n", detach(gfd, (int)pn), sock(AF_INET, SOCK_STREAM) > 0);
    detach(gfd, (int)py);

    // Out, and away.
    int rfd = open("/tmp/gexcg3/cgroup.procs", O_WRONLY);
    write(rfd, "0", 1);
    close(rfd);
    close(gfd);
    SAY("away: %d %d\n", rmdir(c) == 0 ? 0 : -errno, rmdir(g) == 0 ? 0 : -errno);
    umount(base);

    if (expected[0] && strcmp(out_buf, expected) != 0) {
        printf("sockhook: not what Linux shows\n");
        return 1;
    }
    printf(expected[0] ? "sockhook ok\n" : "sockhook done\n");
    return 0;
}
