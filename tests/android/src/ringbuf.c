// A BPF ring buffer as user space has it: made with no key or value and a
// size of a power of two pages; no element calls; mapped shared, the
// consumer's page alone for writing; the consumer's position kept as
// written; poll readable while the producer is ahead. Prints an answer a
// line and checks them against Linux 7.0's. As root.
#define _GNU_SOURCE
#include <errno.h>
#include <linux/bpf.h>
#include <poll.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

static long sys_bpf(int cmd, union bpf_attr *attr, unsigned size) {
    long r = syscall(__NR_bpf, cmd, attr, size);
    return r < 0 ? -errno : r;
}

// What Linux 7.0 printed.
static const char expected[] =
    "a key: -22\n"
    "a value: -22\n"
    "3 pages: -22\n"
    "half a page: -22\n"
    "no prealloc: -22\n"
    "read-only: -22\n"
    "two pages: 0\n"
    "lookup with a key: -22\n"
    "lookup: -524\n"
    "lookup flags 4: -22\n"
    "lookup with the lock: -22\n"
    "update with a key: -22\n"
    "update: -524\n"
    "delete with a key: -22\n"
    "delete: -524\n"
    "delete with a value: -22\n"
    "delete with flags: -22\n"
    "next key from a key: -22\n"
    "next key: -524\n"
    "read: -22\n"
    "private: -22\n"
    "consumer page for writing: 0\n"
    "two pages for writing: -1\n"
    "producer page for writing: -1\n"
    "all, reading: 0\n"
    "a page more: -22\n"
    "from the producer on: 0\n"
    "past the end: -22\n"
    "positions: 0 0\n"
    "poll, empty: 0 0\n"
    "poll, the consumer past the producer: 1 0x1\n"
    "its position mapped again: 8\n"
    "made writable again: -13\n"
    "a hash map mapped: -524\n"
    "a hash map polled: 1 0x8\n"
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

#define MADE(r) ((r) >= 0 ? 0 : (r))

static long elem(int cmd, int fd, int with_key, uint64_t flags) {
    char k[8] = {0}, v[8] = {0};
    union bpf_attr a;
    memset(&a, 0, sizeof a);
    a.map_fd = fd;
    a.key = with_key ? (uintptr_t)k : 0;
    // Only the fields the command has: past them must be zero.
    if (cmd != BPF_MAP_DELETE_ELEM) a.value = (uintptr_t)v;
    if (cmd == BPF_MAP_LOOKUP_ELEM || cmd == BPF_MAP_UPDATE_ELEM) a.flags = flags;
    return sys_bpf(cmd, &a, sizeof a);
}

static long map(int fd, size_t len, int prot, int flags, off_t off, void **at) {
    void *p = mmap(NULL, len, prot, flags, fd, off);
    if (p == MAP_FAILED) return -errno;
    if (at) *at = p;
    else munmap(p, len);
    return 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    const long P = 4096;
    SAY("a key: %ld\n", MADE(make(BPF_MAP_TYPE_RINGBUF, 4, 0, P, 0)));
    SAY("a value: %ld\n", MADE(make(BPF_MAP_TYPE_RINGBUF, 0, 4, P, 0)));
    SAY("3 pages: %ld\n", MADE(make(BPF_MAP_TYPE_RINGBUF, 0, 0, 3 * P, 0)));
    SAY("half a page: %ld\n", MADE(make(BPF_MAP_TYPE_RINGBUF, 0, 0, P / 2, 0)));
    SAY("no prealloc: %ld\n", MADE(make(BPF_MAP_TYPE_RINGBUF, 0, 0, P, BPF_F_NO_PREALLOC)));
    SAY("read-only: %ld\n", MADE(make(BPF_MAP_TYPE_RINGBUF, 0, 0, P, BPF_F_RDONLY)));
    long rb = make(BPF_MAP_TYPE_RINGBUF, 0, 0, 2 * P, 0);
    SAY("two pages: %ld\n", MADE(rb));

    // (A key where the map has none is EINVAL first: `__bpf_copy_key`.)
    SAY("lookup with a key: %ld\n", elem(BPF_MAP_LOOKUP_ELEM, rb, 1, 0));
    SAY("lookup: %ld\n", elem(BPF_MAP_LOOKUP_ELEM, rb, 0, 0));
    SAY("lookup flags 4: %ld\n", elem(BPF_MAP_LOOKUP_ELEM, rb, 0, 4));
    SAY("lookup with the lock: %ld\n", elem(BPF_MAP_LOOKUP_ELEM, rb, 0, BPF_F_LOCK));
    SAY("update with a key: %ld\n", elem(BPF_MAP_UPDATE_ELEM, rb, 1, 0));
    SAY("update: %ld\n", elem(BPF_MAP_UPDATE_ELEM, rb, 0, 0));
    // (Not asked: update with flags past BPF_EXIST, which 6.18 hands the
    // map (ENOTSUPP) and 7.0 refuses first, EINVAL.)
    SAY("delete with a key: %ld\n", elem(BPF_MAP_DELETE_ELEM, rb, 1, 0));
    SAY("delete: %ld\n", elem(BPF_MAP_DELETE_ELEM, rb, 0, 0));
    {
        union bpf_attr d;
        memset(&d, 0, sizeof d);
        d.map_fd = rb;
        d.value = 1;
        SAY("delete with a value: %ld\n", sys_bpf(BPF_MAP_DELETE_ELEM, &d, sizeof d));
        d.value = 0;
        d.flags = 1;
        SAY("delete with flags: %ld\n", sys_bpf(BPF_MAP_DELETE_ELEM, &d, sizeof d));
    }
    SAY("next key from a key: %ld\n", elem(BPF_MAP_GET_NEXT_KEY, rb, 1, 0));
    SAY("next key: %ld\n", elem(BPF_MAP_GET_NEXT_KEY, rb, 0, 0));
    char c;
    SAY("read: %ld\n", read(rb, &c, 1) < 0 ? (long)-errno : 0L);

    SAY("private: %ld\n", map(rb, P, PROT_READ, MAP_PRIVATE, 0, NULL));
    SAY("consumer page for writing: %ld\n", map(rb, P, PROT_READ | PROT_WRITE, MAP_SHARED, 0, NULL));
    SAY("two pages for writing: %ld\n", map(rb, 2 * P, PROT_READ | PROT_WRITE, MAP_SHARED, 0, NULL));
    SAY("producer page for writing: %ld\n", map(rb, P, PROT_READ | PROT_WRITE, MAP_SHARED, P, NULL));
    SAY("all, reading: %ld\n", map(rb, 6 * P, PROT_READ, MAP_SHARED, 0, NULL));
    SAY("a page more: %ld\n", map(rb, 7 * P, PROT_READ, MAP_SHARED, 0, NULL));
    SAY("from the producer on: %ld\n", map(rb, 5 * P, PROT_READ, MAP_SHARED, P, NULL));
    SAY("past the end: %ld\n", map(rb, P, PROT_READ, MAP_SHARED, 6 * P, NULL));

    void *cons = NULL, *prod = NULL;
    map(rb, P, PROT_READ | PROT_WRITE, MAP_SHARED, 0, &cons);
    map(rb, 5 * P, PROT_READ, MAP_SHARED, P, &prod);
    SAY("positions: %llu %llu\n", (unsigned long long)*(volatile uint64_t *)cons, (unsigned long long)*(volatile uint64_t *)prod);
    struct pollfd pf = {(int)rb, POLLIN | POLLOUT, 0};
    SAY("poll, empty: %d %#x\n", poll(&pf, 1, 0), pf.revents);
    *(volatile uint64_t *)cons = 8;
    msync(cons, P, MS_SYNC);
    pf.revents = 0;
    SAY("poll, the consumer past the producer: %d %#x\n", poll(&pf, 1, 0), pf.revents);
    munmap(cons, P);
    map(rb, P, PROT_READ, MAP_SHARED, 0, &cons);
    SAY("its position mapped again: %llu\n", (unsigned long long)*(volatile uint64_t *)cons);
    long again = mprotect(cons, P, PROT_READ | PROT_WRITE) < 0 ? (long)-errno : 0L;
    SAY("made writable again: %ld\n", again);
    if (again == 0) *(volatile uint64_t *)cons = 0;
    munmap(cons, P);
    munmap(prod, 5 * P);

    long h = make(BPF_MAP_TYPE_HASH, 4, 4, 4, 0);
    SAY("a hash map mapped: %ld\n", map(h, P, PROT_READ, MAP_SHARED, 0, NULL));
    pf.fd = (int)h;
    pf.revents = 0;
    SAY("a hash map polled: %d %#x\n", poll(&pf, 1, 0), pf.revents);

    if (expected[0] && strcmp(out_buf, expected) != 0) {
        printf("ringbuf: not what Linux shows\n");
        return 1;
    }
    printf(expected[0] ? "ringbuf ok\n" : "ringbuf done\n");
    return 0;
}
