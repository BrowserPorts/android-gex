// BPF_MAP_FREEZE, as libbpf freezes a program's read-only data after
// filling it: a frozen map is no longer written through the system call
// or a new writable mapping, a map with a writable mapping cannot be
// frozen until every one (a forked child's copy too) is gone, and only a
// descriptor that may write it may freeze it. Prints an answer a line and
// checks them against Linux 7.0's. As root.
#define _GNU_SOURCE
#include <errno.h>
#include <linux/bpf.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef BPF_MAP_FREEZE
#define BPF_MAP_FREEZE 22
#endif

static long sys_bpf(int cmd, union bpf_attr *attr, unsigned size) {
    long r = syscall(__NR_bpf, cmd, attr, size);
    return r < 0 ? -errno : r;
}

// What Linux 7.0 printed.
static const char expected[] =
    "array: 0\n"
    "update: 0\n"
    "freeze: 0\n"
    "update frozen: -1\n"
    "delete frozen: -1\n"
    "lookup frozen: 0 7\n"
    "freeze again: -1\n"
    "map frozen for writing: -1\n"
    "map frozen private: -22\n"
    "map frozen for reading: 0\n"
    "element 0 in it: 7\n"
    "made writable: -13\n"
    "mapped for writing: 0\n"
    "freeze while mapped: -16\n"
    "freeze after unmapping: 0\n"
    "mapped for reading: 0\n"
    "freeze while mapped for reading: 0\n"
    "freeze while a child has it mapped: -16\n"
    "freeze after the child: 0\n"
    "freeze a map user space only reads: -1\n"
    "freeze a map user space only writes: 0\n"
    "freeze no descriptor: -9\n"
    "freeze a pipe: -22\n"
    "freeze with more in the attr: -22\n"
    "hash freeze: 0\n"
    "hash update frozen: -1\n"
    "hash walk frozen: 0 1\n"
    "ring buffer: 0\n"
    "consumer page mapped: 0\n"
    "ring buffer freeze while mapped: -16\n"
    "ring buffer freeze: 0\n"
    "consumer page mapped frozen: -1\n"
    "producer page mapped frozen: 0\n";

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

static long make(int type, int key, int value, int max, int flags) {
    union bpf_attr a;
    memset(&a, 0, sizeof a);
    a.map_type = type;
    a.key_size = key;
    a.value_size = value;
    a.max_entries = max;
    a.map_flags = flags;
    return sys_bpf(BPF_MAP_CREATE, &a, sizeof a);
}

static long elem(int cmd, int fd, const void *key, void *value, uint64_t flags) {
    union bpf_attr a;
    memset(&a, 0, sizeof a);
    a.map_fd = fd;
    a.key = (uintptr_t)key;
    a.value = (uintptr_t)value;
    a.flags = flags;
    return sys_bpf(cmd, &a, sizeof a);
}

static long freeze(int fd) {
    union bpf_attr a;
    memset(&a, 0, sizeof a);
    a.map_fd = fd;
    return sys_bpf(BPF_MAP_FREEZE, &a, sizeof a);
}

static long mapped(int fd, int prot, int flags, off_t off, void **at) {
    void *p = mmap(NULL, 4096, prot, flags, fd, off);
    if (p == MAP_FAILED)
        return -errno;
    if (at)
        *at = p;
    else
        munmap(p, 4096);
    return 0;
}

int main(void) {
    uint32_t k0 = 0, k1 = 1;
    uint64_t v = 7, got = 0;

    // An array, filled and frozen.
    int a = (int)make(BPF_MAP_TYPE_ARRAY, 4, 8, 4, BPF_F_MMAPABLE);
    SAY("array: %d\n", a < 0 ? a : 0);
    SAY("update: %ld\n", elem(BPF_MAP_UPDATE_ELEM, a, &k0, &v, BPF_ANY));
    SAY("freeze: %ld\n", freeze(a));
    v = 8;
    SAY("update frozen: %ld\n", elem(BPF_MAP_UPDATE_ELEM, a, &k1, &v, BPF_ANY));
    SAY("delete frozen: %ld\n", elem(BPF_MAP_DELETE_ELEM, a, &k0, NULL, 0));
    SAY("lookup frozen: %ld %llu\n", elem(BPF_MAP_LOOKUP_ELEM, a, &k0, &got, 0), (unsigned long long)got);
    SAY("freeze again: %ld\n", freeze(a));
    SAY("map frozen for writing: %ld\n", mapped(a, PROT_READ | PROT_WRITE, MAP_SHARED, 0, NULL));
    SAY("map frozen private: %ld\n", mapped(a, PROT_READ, MAP_PRIVATE, 0, NULL));
    void *ro = NULL;
    SAY("map frozen for reading: %ld\n", mapped(a, PROT_READ, MAP_SHARED, 0, &ro));
    if (ro) {
        SAY("element 0 in it: %llu\n", (unsigned long long)((volatile uint64_t *)ro)[0]);
        SAY("made writable: %d\n", mprotect(ro, 4096, PROT_READ | PROT_WRITE) < 0 ? -errno : 0);
        munmap(ro, 4096);
    }

    // A writable mapping holds it unfrozen until it goes.
    int b = (int)make(BPF_MAP_TYPE_ARRAY, 4, 8, 4, BPF_F_MMAPABLE);
    void *rw = NULL;
    SAY("mapped for writing: %ld\n", mapped(b, PROT_READ | PROT_WRITE, MAP_SHARED, 0, &rw));
    SAY("freeze while mapped: %ld\n", freeze(b));
    if (rw)
        munmap(rw, 4096);
    SAY("freeze after unmapping: %ld\n", freeze(b));

    // A read-only mapping does not.
    int c = (int)make(BPF_MAP_TYPE_ARRAY, 4, 8, 4, BPF_F_MMAPABLE);
    void *r2 = NULL;
    SAY("mapped for reading: %ld\n", mapped(c, PROT_READ, MAP_SHARED, 0, &r2));
    SAY("freeze while mapped for reading: %ld\n", freeze(c));
    if (r2)
        munmap(r2, 4096);

    // A forked child's copy of a writable mapping holds it too.
    int d = (int)make(BPF_MAP_TYPE_ARRAY, 4, 8, 4, BPF_F_MMAPABLE);
    void *rw2 = NULL;
    mapped(d, PROT_READ | PROT_WRITE, MAP_SHARED, 0, &rw2);
    int go[2];
    if (pipe(go) != 0)
        return 2;
    pid_t child = fork();
    if (child == 0) {
        char x;
        close(go[1]);
        read(go[0], &x, 1);
        _exit(0);
    }
    close(go[0]);
    if (rw2)
        munmap(rw2, 4096);
    SAY("freeze while a child has it mapped: %ld\n", freeze(d));
    close(go[1]);
    waitpid(child, NULL, 0);
    SAY("freeze after the child: %ld\n", freeze(d));

    // Who may freeze.
    int e = (int)make(BPF_MAP_TYPE_ARRAY, 4, 8, 4, BPF_F_RDONLY);
    SAY("freeze a map user space only reads: %ld\n", freeze(e));
    int f = (int)make(BPF_MAP_TYPE_ARRAY, 4, 8, 4, BPF_F_WRONLY);
    SAY("freeze a map user space only writes: %ld\n", freeze(f));
    SAY("freeze no descriptor: %ld\n", freeze(999));
    int p[2];
    pipe(p);
    SAY("freeze a pipe: %ld\n", freeze(p[0]));
    union bpf_attr t;
    memset(&t, 0, sizeof t);
    t.map_fd = (uint32_t)a;
    ((char *)&t)[4] = 1;
    SAY("freeze with more in the attr: %ld\n", sys_bpf(BPF_MAP_FREEZE, &t, sizeof t));

    // A hash: its elements are still there to read and walk.
    int h = (int)make(BPF_MAP_TYPE_HASH, 4, 8, 4, 0);
    v = 9;
    elem(BPF_MAP_UPDATE_ELEM, h, &k1, &v, BPF_ANY);
    SAY("hash freeze: %ld\n", freeze(h));
    SAY("hash update frozen: %ld\n", elem(BPF_MAP_UPDATE_ELEM, h, &k0, &v, BPF_ANY));
    uint32_t next = 0;
    union bpf_attr n;
    memset(&n, 0, sizeof n);
    n.map_fd = (uint32_t)h;
    n.next_key = (uintptr_t)&next;
    SAY("hash walk frozen: %ld %u\n", sys_bpf(BPF_MAP_GET_NEXT_KEY, &n, sizeof n), next);

    // A ring buffer: its consumer page is the one mapping that writes.
    int rb = (int)make(BPF_MAP_TYPE_RINGBUF, 0, 0, 4096, 0);
    SAY("ring buffer: %d\n", rb < 0 ? rb : 0);
    void *cons = NULL;
    SAY("consumer page mapped: %ld\n", mapped(rb, PROT_READ | PROT_WRITE, MAP_SHARED, 0, &cons));
    SAY("ring buffer freeze while mapped: %ld\n", freeze(rb));
    if (cons)
        munmap(cons, 4096);
    SAY("ring buffer freeze: %ld\n", freeze(rb));
    SAY("consumer page mapped frozen: %ld\n", mapped(rb, PROT_READ | PROT_WRITE, MAP_SHARED, 0, NULL));
    SAY("producer page mapped frozen: %ld\n", mapped(rb, PROT_READ, MAP_SHARED, 4096, NULL));

    if (expected[0] && strcmp(out_buf, expected) != 0) {
        printf("bpffreeze: not what Linux shows\n");
        return 1;
    }
    printf(expected[0] ? "bpffreeze ok\n" : "bpffreeze done\n");
    return 0;
}
