// What BPF_OBJ_GET_INFO_BY_FD says of a program the kernel compiled: its
// tag (exactly Linux's: the SHA-256 of its instructions), its
// instructions as translated, the maps it uses, its compiled image's
// functions, their places and lengths (which differ from an arm64 JIT's
// and are checked for their form: there, added up, distinct), what a
// caller without CAP_BPF is told, what kptr_restrict 2 hides, the record
// sizes it holds a caller to, and a map's info keeping what the kernel
// does not fill. Prints an answer a line and checks them against Linux
// 7.0's. As root.
#define _GNU_SOURCE
#include <errno.h>
#include <linux/bpf.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static long sys_bpf(int cmd, union bpf_attr *attr, unsigned size) {
    long r = syscall(__NR_bpf, cmd, attr, size);
    return r < 0 ? -errno : r;
}

// What Linux 7.0 printed.
static const char expected[] =
    "r0 = 0: 0\n"
    "r0 = 0: info 0, tag 59f4a931744dcdc6, gpl 1\n"
    "r0 = 0: translated 16 bytes\n"
    "r0 = 0: the program's own, a map by its id: 1\n"
    "r0 = 0: maps 0, the one asked for 1\n"
    "r0 = 0: compiled 1, functions 1 1, lengths add up 1, placed apart 1\n"
    "r0 = 0: tags 1, the first the program's 1\n"
    "r0 = 0: loaded before now 1, runs 0 0\n"
    "r0 = 0: verified 2\n"
    "a map named: 0\n"
    "a map named: info 0, tag 6751555a61820a41, gpl 1\n"
    "a map named: translated 32 bytes\n"
    "a map named: the program's own, a map by its id: 1\n"
    "a map named: maps 1, the one asked for 1\n"
    "a map named: compiled 1, functions 1 1, lengths add up 1, placed apart 1\n"
    "a map named: tags 1, the first the program's 1\n"
    "a map named: loaded before now 1, runs 0 0\n"
    "a map named: verified 3\n"
    "two functions: 0\n"
    "two functions: info 0, tag 01ae61b7c6171653, gpl 1\n"
    "two functions: translated 40 bytes\n"
    "two functions: the program's own, a map by its id: 1\n"
    "two functions: maps 0, the one asked for 1\n"
    "two functions: compiled 1, functions 2 2, lengths add up 1, placed apart 1\n"
    "two functions: tags 2, the first the program's 1\n"
    "two functions: loaded before now 1, runs 0 0\n"
    "two functions: verified 5\n"
    "a jump into another function: -22\n"
    "a function running on into the next: -22\n"
    "func records of 4: -22\n"
    "line records of 8: -22\n"
    "record sizes: 8 16 8\n"
    "hidden: 0, compiled 1, image given 0, places given 0, functions 2\n"
    "unprivileged: 0, compiled 0, translated 0, functions 0, id 1\n"
    "map info: ifindex 42, btf 77, key 4\n"
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

static long load(const struct bpf_insn *insns, int n) {
    union bpf_attr a;
    memset(&a, 0, sizeof a);
    a.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    a.insns = (uintptr_t)insns;
    a.insn_cnt = n;
    a.license = (uintptr_t) "GPL";
    return sys_bpf(BPF_PROG_LOAD, &a, sizeof a);
}

static long info_of(int fd, void *info, unsigned len) {
    union bpf_attr a;
    memset(&a, 0, sizeof a);
    a.info.bpf_fd = fd;
    a.info.info_len = len;
    a.info.info = (uintptr_t)info;
    return sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &a, sizeof a);
}

static void hex(char *out, const uint8_t *b, int n) {
    for (int i = 0; i < n; i++) sprintf(out + 2 * i, "%02x", b[i]);
}

// What a program's info says, in the terms that hold on any kernel.
static void describe(const char *what, int fd, const struct bpf_insn *insns, int n, int map_id) {
    struct bpf_prog_info i;
    uint64_t ksyms[4] = {0};
    uint32_t lens[4] = {0}, ids[4] = {0};
    uint8_t tags[4][8], image[65536];
    struct bpf_insn xl[64];
    memset(&i, 0, sizeof i);
    memset(tags, 0, sizeof tags);
    i.nr_jited_ksyms = 4;
    i.jited_ksyms = (uintptr_t)ksyms;
    i.nr_jited_func_lens = 4;
    i.jited_func_lens = (uintptr_t)lens;
    i.nr_map_ids = 4;
    i.map_ids = (uintptr_t)ids;
    i.nr_prog_tags = 4;
    i.prog_tags = (uintptr_t)tags;
    i.xlated_prog_len = sizeof xl;
    i.xlated_prog_insns = (uintptr_t)xl;
    i.jited_prog_len = sizeof image;
    i.jited_prog_insns = (uintptr_t)image;
    long r = info_of(fd, &i, sizeof i);
    char tag[17];
    hex(tag, i.tag, 8);
    SAY("%s: info %ld, tag %s, gpl %u\n", what, r, tag, i.gpl_compatible);
    SAY("%s: translated %u bytes\n", what, i.xlated_prog_len);
    if (i.xlated_prog_len == (unsigned)n * 8) {
        int same = 1;
        for (int k = 0; k < n; k++) {
            struct bpf_insn want = insns[k];
            if (want.code == (BPF_LD | BPF_IMM | BPF_DW) && want.src_reg == BPF_PSEUDO_MAP_FD) want.imm = map_id;
            if (want.code == (BPF_JMP | BPF_CALL)) continue;
            same &= memcmp(&xl[k], &want, sizeof want) == 0;
        }
        SAY("%s: the program's own, a map by its id: %d\n", what, same);
    }
    SAY("%s: maps %u, the one asked for %d\n", what, i.nr_map_ids, i.nr_map_ids ? ids[0] == (uint32_t)map_id : 1);
    uint32_t sum = 0;
    int placed = 1;
    for (unsigned k = 0; k < i.nr_jited_func_lens && k < 4; k++) sum += lens[k];
    for (unsigned k = 0; k < i.nr_jited_ksyms && k < 4; k++) {
        placed &= ksyms[k] != 0;
        for (unsigned j = 0; j < k; j++) placed &= ksyms[j] != ksyms[k];
    }
    SAY("%s: compiled %d, functions %u %u, lengths add up %d, placed apart %d\n", what, i.jited_prog_len > 0, i.nr_jited_ksyms,
        i.nr_jited_func_lens, sum == i.jited_prog_len, placed);
    char t0[17];
    hex(t0, tags[0], 8);
    SAY("%s: tags %u, the first the program's %d\n", what, i.nr_prog_tags, i.nr_prog_tags == 1 ? strcmp(t0, tag) == 0 : 1);
    struct timespec now;
    clock_gettime(CLOCK_BOOTTIME, &now);
    SAY("%s: loaded before now %d, runs %llu %llu\n", what, i.load_time > 0 && i.load_time <= (uint64_t)now.tv_sec * 1000000000ull + now.tv_nsec,
        (unsigned long long)i.run_cnt, (unsigned long long)i.run_time_ns);
    SAY("%s: verified %u\n", what, i.verified_insns);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    struct bpf_insn ret0[] = {I(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0), I(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)};
    long p1 = load(ret0, 2);
    SAY("r0 = 0: %ld\n", p1 < 0 ? p1 : 0);
    describe("r0 = 0", p1, ret0, 2, 0);

    union bpf_attr ma;
    memset(&ma, 0, sizeof ma);
    ma.map_type = BPF_MAP_TYPE_HASH;
    ma.key_size = 4;
    ma.value_size = 8;
    ma.max_entries = 4;
    long map = sys_bpf(BPF_MAP_CREATE, &ma, sizeof ma);
    struct bpf_map_info mi;
    memset(&mi, 0, sizeof mi);
    info_of(map, &mi, sizeof mi);
    struct bpf_insn with_map[] = {I(BPF_LD | BPF_IMM | BPF_DW, 1, BPF_PSEUDO_MAP_FD, 0, (int)map), I(0, 0, 0, 0, 0),
                                  I(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 7), I(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)};
    long p2 = load(with_map, 4);
    SAY("a map named: %ld\n", p2 < 0 ? p2 : 0);
    describe("a map named", p2, with_map, 4, mi.id);

    struct bpf_insn two[] = {I(BPF_JMP | BPF_CALL, 0, BPF_PSEUDO_CALL, 0, 2), I(BPF_ALU64 | BPF_ADD | BPF_K, 0, 0, 0, 1),
                             I(BPF_JMP | BPF_EXIT, 0, 0, 0, 0), I(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 1),
                             I(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)};
    long p3 = load(two, 5);
    SAY("two functions: %ld\n", p3 < 0 ? p3 : 0);
    describe("two functions", p3, two, 5, 0);

    struct bpf_insn out_of[] = {I(BPF_JMP | BPF_CALL, 0, BPF_PSEUDO_CALL, 0, 2), I(BPF_JMP | BPF_JA, 0, 0, 2, 0),
                                I(BPF_JMP | BPF_EXIT, 0, 0, 0, 0), I(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 1),
                                I(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)};
    SAY("a jump into another function: %ld\n", load(out_of, 5));
    struct bpf_insn runs_on[] = {I(BPF_JMP | BPF_CALL, 0, BPF_PSEUDO_CALL, 0, 1), I(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
                                 I(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 1), I(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)};
    SAY("a function running on into the next: %ld\n", load(runs_on, 4));

    // The record sizes a caller is held to.
    struct bpf_prog_info i;
    memset(&i, 0, sizeof i);
    i.nr_func_info = 1;
    i.func_info_rec_size = 4;
    SAY("func records of 4: %ld\n", info_of(p1, &i, sizeof i));
    memset(&i, 0, sizeof i);
    i.line_info_rec_size = 8;
    SAY("line records of 8: %ld\n", info_of(p1, &i, sizeof i));
    memset(&i, 0, sizeof i);
    info_of(p1, &i, sizeof i);
    SAY("record sizes: %u %u %u\n", i.func_info_rec_size, i.line_info_rec_size, i.jited_line_info_rec_size);

    // kptr_restrict 2: lengths, and no image or places.
    char old[8] = "0";
    FILE *f = fopen("/proc/sys/kernel/kptr_restrict", "r");
    if (f) {
        if (!fgets(old, sizeof old, f)) strcpy(old, "0");
        fclose(f);
    }
    f = fopen("/proc/sys/kernel/kptr_restrict", "w");
    if (f) {
        fputs("2", f);
        fclose(f);
    }
    uint64_t ks[2];
    uint8_t img[4096];
    memset(&i, 0, sizeof i);
    i.nr_jited_ksyms = 2;
    i.jited_ksyms = (uintptr_t)ks;
    i.jited_prog_len = sizeof img;
    i.jited_prog_insns = (uintptr_t)img;
    long r = info_of(p3, &i, sizeof i);
    SAY("hidden: %ld, compiled %d, image given %d, places given %d, functions %u\n", r, i.jited_prog_len > 0, i.jited_prog_insns != 0,
        i.jited_ksyms != 0, i.nr_jited_ksyms);
    f = fopen("/proc/sys/kernel/kptr_restrict", "w");
    if (f) {
        fputs(old, f);
        fclose(f);
    }

    // Without CAP_BPF: no lengths.
    int pp[2];
    if (pipe(pp) != 0) return 1;
    pid_t c = fork();
    if (c == 0) {
        if (setuid(65534) != 0) _exit(2);
        struct bpf_prog_info j;
        memset(&j, 0, sizeof j);
        long rr = info_of(p1, &j, sizeof j);
        dprintf(pp[1], "unprivileged: %ld, compiled %u, translated %u, functions %u, id %d\n", rr, j.jited_prog_len, j.xlated_prog_len,
                j.nr_jited_ksyms, j.id != 0);
        _exit(0);
    }
    close(pp[1]);
    char line[256] = {0};
    ssize_t got = read(pp[0], line, sizeof line - 1);
    int st;
    waitpid(c, &st, 0);
    SAY("%s", got > 0 ? line : "unprivileged: nothing\n");

    // A map's info keeps what the kernel does not fill.
    memset(&mi, 0, sizeof mi);
    mi.ifindex = 42;
    mi.btf_id = 77;
    info_of(map, &mi, sizeof mi);
    SAY("map info: ifindex %u, btf %u, key %u\n", mi.ifindex, mi.btf_id, mi.key_size);

    if (expected[0] && strcmp(out_buf, expected) != 0) {
        printf("bpfinfo: not what Linux shows\n");
        return 1;
    }
    printf(expected[0] ? "bpfinfo ok\n" : "bpfinfo done\n");
    return 0;
}
