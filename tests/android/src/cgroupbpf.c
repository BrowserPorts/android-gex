// BPF programs attached to cgroup v2 groups: one replacing another, an
// ancestor's program letting its descendants have their own or not
// (BPF_F_ALLOW_OVERRIDE), several at once (BPF_F_ALLOW_MULTI, and
// BPF_F_REPLACE among them), what runs for a group (BPF_F_QUERY_EFFECTIVE),
// the count of changes, detaching, and what is refused. Prints an answer a
// line and checks them against Linux 7.0's. As root.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
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
    "loaded: 1 1 1 1\n"
    "nothing yet: 0, flags 0, count 0, revision 1, programs\n"
    "p0 on the parent: 0\n"
    "the parent: 0, flags 0, count 1, revision 2, programs p0\n"
    "p1 on the parent, replacing it: 0\n"
    "the parent: 0, flags 0, count 1, revision 3, programs p1\n"
    "p2 on the child, under one that allows no other: -1\n"
    "p1 on the parent again, allowing override: -1\n"
    "detach the parent's: 0\n"
    "p1 on the parent, allowing override: 0\n"
    "p2 on the child: 0\n"
    "what runs for the child: 0, flags 0, count 1, revision 0, programs p2\n"
    "detach the child's, then the parent's: 0 0\n"
    "what runs for the child: 0, flags 0, count 0, revision 0, programs\n"
    "detach again: -2\n"
    "override and multi at once: -22\n"
    "replace without multi: -22\n"
    "p0, p1 on the parent, several: 0 0\n"
    "p0 again: -22\n"
    "p2 on the parent with other flags: -1\n"
    "p2 on the child, several: 0\n"
    "the parent: 0, flags 2, count 2, revision 8, programs p0 p1\n"
    "what runs for the child: 0, flags 0, count 3, revision 0, programs p2 p0 p1\n"
    "room for one: -28, flags 0, count 3, revision 0, programs p2\n"
    "p2 in place of p0 on the parent: 0\n"
    "p0 in place of p0, not there: -2\n"
    "the parent: 0, flags 2, count 2, revision 9, programs p2 p1\n"
    "detach with no program among several: -22\n"
    "detach one not there: -2\n"
    "detach p2, p1, the child's p2: 0 0 0\n"
    "the parent: 0, flags 0, count 0, revision 11, programs\n"
    "a socket program at another attach type: -22\n"
    "a socket program at its own: 0, detached: 0\n"
    "an skb program as a socket one: -22\n"
    "to a directory that is no group: -9\n"
    "to no descriptor: -9\n"
    "no program: -9\n"
    "an unknown attach type: -22\n"
    "unknown flags: -22\n"
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

static long load(int type, int expected_attach) {
    struct bpf_insn insns[] = {{.code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = 0, .imm = 1}, {.code = BPF_JMP | BPF_EXIT}};
    union bpf_attr a;
    memset(&a, 0, sizeof a);
    a.prog_type = type;
    a.expected_attach_type = expected_attach;
    a.insns = (uintptr_t)insns;
    a.insn_cnt = 2;
    a.license = (uintptr_t) "GPL";
    return sys_bpf(BPF_PROG_LOAD, &a, sizeof a);
}

static long attach(int cg, int prog, int type, unsigned flags, int replace) {
    union bpf_attr a;
    memset(&a, 0, sizeof a);
    a.target_fd = cg;
    a.attach_bpf_fd = prog;
    a.attach_type = type;
    a.attach_flags = flags;
    a.replace_bpf_fd = replace;
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

static uint32_t id_of(int fd) {
    struct bpf_prog_info i;
    memset(&i, 0, sizeof i);
    union bpf_attr a;
    memset(&a, 0, sizeof a);
    a.info.bpf_fd = fd;
    a.info.info_len = sizeof i;
    a.info.info = (uintptr_t)&i;
    sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &a, sizeof a);
    return i.id;
}

static int fds[8], nfds;

// A program's number among those this test loaded, or its id.
static int which(uint32_t id) {
    for (int k = 0; k < nfds; k++)
        if (id_of(fds[k]) == id) return k;
    return -1;
}

static void query(const char *what, int cg, int type, unsigned qflags, unsigned room) {
    uint32_t ids[8] = {0};
    // As 6.18's union has it (the NDK's headers stop before revision).
    unsigned char a[128];
    memset(a, 0, sizeof a);
    uint64_t at = (uintptr_t)ids;
    memcpy(a + 0, &cg, 4);
    memcpy(a + 4, &type, 4);
    memcpy(a + 8, &qflags, 4);
    memcpy(a + 16, &at, 8);
    memcpy(a + 24, &room, 4);
    long r = syscall(__NR_bpf, BPF_PROG_QUERY, a, 64);
    r = r < 0 ? -errno : r;
    uint32_t flags, cnt;
    uint64_t revision;
    memcpy(&flags, a + 12, 4);
    memcpy(&cnt, a + 24, 4);
    memcpy(&revision, a + 56, 8);
    SAY("%s: %ld, flags %u, count %u, revision %llu, programs", what, r, flags, cnt, (unsigned long long)revision);
    for (unsigned k = 0; k < cnt && k < room; k++) SAY(" p%d", which(ids[k]));
    SAY("\n");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    const char *base = "/tmp/gexcg2";
    mkdir(base, 0755);
    if (mount("none", base, "cgroup2", 0, NULL) != 0) {
        printf("cgroupbpf: no mount: %s\n", strerror(errno));
        return 1;
    }
    char parent[256], child[256];
    snprintf(parent, sizeof parent, "%s/gexbpf", base);
    snprintf(child, sizeof child, "%s/gexbpf/c", base);
    rmdir(child);
    rmdir(parent);
    mkdir(parent, 0755);
    mkdir(child, 0755);
    int pg = open(parent, O_RDONLY | O_DIRECTORY), cg = open(child, O_RDONLY | O_DIRECTORY);

    for (nfds = 0; nfds < 3; nfds++) fds[nfds] = (int)load(BPF_PROG_TYPE_CGROUP_SKB, 0);
    fds[nfds++] = (int)load(BPF_PROG_TYPE_CGROUP_SOCK, BPF_CGROUP_INET_SOCK_CREATE);
    SAY("loaded: %d %d %d %d\n", fds[0] > 0, fds[1] > 0, fds[2] > 0, fds[3] > 0);
    int I = BPF_CGROUP_INET_INGRESS;

    query("nothing yet", pg, I, 0, 8);
    SAY("p0 on the parent: %ld\n", attach(pg, fds[0], I, 0, 0));
    query("the parent", pg, I, 0, 8);
    SAY("p1 on the parent, replacing it: %ld\n", attach(pg, fds[1], I, 0, 0));
    query("the parent", pg, I, 0, 8);
    SAY("p2 on the child, under one that allows no other: %ld\n", attach(cg, fds[2], I, 0, 0));
    SAY("p1 on the parent again, allowing override: %ld\n", attach(pg, fds[1], I, BPF_F_ALLOW_OVERRIDE, 0));
    SAY("detach the parent's: %ld\n", detach(pg, 0, I));
    SAY("p1 on the parent, allowing override: %ld\n", attach(pg, fds[1], I, BPF_F_ALLOW_OVERRIDE, 0));
    SAY("p2 on the child: %ld\n", attach(cg, fds[2], I, 0, 0));
    query("what runs for the child", cg, I, BPF_F_QUERY_EFFECTIVE, 8);
    SAY("detach the child's, then the parent's: %ld %ld\n", detach(cg, 0, I), detach(pg, 0, I));
    query("what runs for the child", cg, I, BPF_F_QUERY_EFFECTIVE, 8);
    SAY("detach again: %ld\n", detach(pg, 0, I));

    SAY("override and multi at once: %ld\n", attach(pg, fds[0], I, BPF_F_ALLOW_OVERRIDE | BPF_F_ALLOW_MULTI, 0));
    SAY("replace without multi: %ld\n", attach(pg, fds[0], I, BPF_F_REPLACE, fds[1]));
    SAY("p0, p1 on the parent, several: %ld %ld\n", attach(pg, fds[0], I, BPF_F_ALLOW_MULTI, 0), attach(pg, fds[1], I, BPF_F_ALLOW_MULTI, 0));
    SAY("p0 again: %ld\n", attach(pg, fds[0], I, BPF_F_ALLOW_MULTI, 0));
    SAY("p2 on the parent with other flags: %ld\n", attach(pg, fds[2], I, 0, 0));
    SAY("p2 on the child, several: %ld\n", attach(cg, fds[2], I, BPF_F_ALLOW_MULTI, 0));
    query("the parent", pg, I, 0, 8);
    query("what runs for the child", cg, I, BPF_F_QUERY_EFFECTIVE, 8);
    query("room for one", cg, I, BPF_F_QUERY_EFFECTIVE, 1);
    SAY("p2 in place of p0 on the parent: %ld\n", attach(pg, fds[2], I, BPF_F_ALLOW_MULTI | BPF_F_REPLACE, fds[0]));
    SAY("p0 in place of p0, not there: %ld\n", attach(pg, fds[0], I, BPF_F_ALLOW_MULTI | BPF_F_REPLACE, fds[0]));
    query("the parent", pg, I, 0, 8);
    SAY("detach with no program among several: %ld\n", detach(pg, 0, I));
    SAY("detach one not there: %ld\n", detach(pg, fds[0], I));
    SAY("detach p2, p1, the child's p2: %ld %ld %ld\n", detach(pg, fds[2], I), detach(pg, fds[1], I), detach(cg, fds[2], I));
    query("the parent", pg, I, 0, 8);

    SAY("a socket program at another attach type: %ld\n", attach(pg, fds[3], BPF_CGROUP_INET_SOCK_RELEASE, 0, 0));
    SAY("a socket program at its own: %ld, detached: %ld\n", attach(pg, fds[3], BPF_CGROUP_INET_SOCK_CREATE, 0, 0),
        detach(pg, fds[3], BPF_CGROUP_INET_SOCK_CREATE));
    SAY("an skb program as a socket one: %ld\n", attach(pg, fds[0], BPF_CGROUP_INET_SOCK_CREATE, 0, 0));
    int notcg = open("/tmp", O_RDONLY | O_DIRECTORY);
    SAY("to a directory that is no group: %ld\n", attach(notcg, fds[0], I, 0, 0));
    SAY("to no descriptor: %ld\n", attach(999, fds[0], I, 0, 0));
    SAY("no program: %ld\n", attach(pg, 999, I, 0, 0));
    SAY("an unknown attach type: %ld\n", attach(pg, fds[0], 200, 0, 0));
    SAY("unknown flags: %ld\n", attach(pg, fds[0], I, 1u << 20, 0));

    close(pg);
    close(cg);
    SAY("away: %d %d\n", rmdir(child) == 0 ? 0 : -errno, rmdir(parent) == 0 ? 0 : -errno);
    umount(base);

    if (expected[0] && strcmp(out_buf, expected) != 0) {
        printf("cgroupbpf: not what Linux shows\n");
        return 1;
    }
    printf(expected[0] ? "cgroupbpf ok\n" : "cgroupbpf done\n");
    return 0;
}
