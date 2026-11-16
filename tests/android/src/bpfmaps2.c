// The other map types Android's networking objects use, and the creation
// flags: an LRU hash (full, the least recently used goes), a per-CPU
// array (a value for each possible CPU, as user space sees it), an LPM
// trie (the longest prefix that matches; its own walk order; full is
// ENOSPC), maps read-only or write-only for user space, flags a type does
// not take. Prints an answer a line and checks them against Linux 7.0's.
// As root.
#define _GNU_SOURCE
#include <errno.h>
#include <linux/bpf.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static long sys_bpf(int cmd, union bpf_attr *attr, unsigned size) {
    long r = syscall(__NR_bpf, cmd, attr, size);
    return r < 0 ? -errno : r;
}

// What Linux 7.0 printed.
static const char expected[] =
    "lru: 0\n"
    "lru without its elements made ahead: -524\n"
    "lru a third in two: 0\n"
    "lru holds: 2\n"
    "lru the third there: 0\n"
    "percpu: 0\n"
    "percpu update: 0\n"
    "percpu lookup: 0\n"
    "percpu each cpu's, rounded to 8: 1\n"
    "percpu delete: -22\n"
    "lpm made ahead: -22\n"
    "lpm key of 4: -22\n"
    "lpm: 0\n"
    "lpm 10/8: 0\n"
    "lpm 10.1/16: 0\n"
    "lpm 10.0.3/24: 0\n"
    "lpm a fourth in three: -28\n"
    "lpm /33: -22\n"
    "lpm 10/8 NOEXIST: -17\n"
    "lpm 10.1.2.3: 0 2\n"
    "lpm 10.0.3.9: 0 3\n"
    "lpm 10.9.9.9: 0 1\n"
    "lpm 11.0.0.0: -2\n"
    "lpm 10.1.2.3/12: 0 1\n"
    "lpm walk: 10.0.3.0/24 10.1.0.0/16 10.0.0.0/8 (-2)\n"
    "lpm delete 10.1/16: 0\n"
    "lpm delete it again: -2\n"
    "read-only update: -1\n"
    "read-only lookup: -2\n"
    "write-only update: 0\n"
    "write-only lookup: -1\n"
    "both: -22\n"
    "hash mmapable: -22\n"
    "array no prealloc: -22\n"
    "hash read-only for programs: 0\n"
    "devmap value 6: -22\n"
    "devmap read-only for programs asked: -22\n"
    "devmap: 0\n"
    "devmap flags: 0x80\n"
    "devmap lo: 0\n"
    "devmap ifindex 999: -22\n"
    "devmap ifindex 0: -22\n"
    "devmap EXIST of a missing key: 0\n"
    "devmap NOEXIST of a key there: -17\n"
    "devmap a third: -7\n"
    "devmap lookup: 0 1\n"
    "devmap delete: 0\n"
    "devmap delete again: -2\n"
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

static long elem(int cmd, int fd, const void *key, void *value, uint64_t flags) {
    union bpf_attr a;
    memset(&a, 0, sizeof a);
    a.map_fd = fd;
    a.key = (uintptr_t)key;
    a.value = (uintptr_t)value;
    a.flags = flags;
    return sys_bpf(cmd, &a, sizeof a);
}

static long next_key(int fd, const void *key, void *next) {
    union bpf_attr a;
    memset(&a, 0, sizeof a);
    a.map_fd = fd;
    a.key = (uintptr_t)key;
    a.next_key = (uintptr_t)next;
    return sys_bpf(BPF_MAP_GET_NEXT_KEY, &a, sizeof a);
}

#define MADE(r) ((r) >= 0 ? 0 : (r))

// The number of possible CPUs, as libbpf counts them.
static int possible(void) {
    FILE *f = fopen("/sys/devices/system/cpu/possible", "r");
    int a = 0, b = 0;
    if (!f) return -1;
    if (fscanf(f, "%d-%d", &a, &b) < 2) b = a;
    fclose(f);
    return b + 1;
}

struct lpm4 {
    uint32_t plen;
    uint8_t addr[4];
};

int main(void) {
    // LRU hash.
    long lru = make(BPF_MAP_TYPE_LRU_HASH, 4, 8, 2, 0);
    SAY("lru: %ld\n", MADE(lru));
    SAY("lru without its elements made ahead: %ld\n", MADE(make(BPF_MAP_TYPE_LRU_HASH, 4, 8, 2, BPF_F_NO_PREALLOC)));
    uint32_t k1 = 1, k2 = 2, k3 = 3;
    uint64_t v = 7, out = 0;
    elem(BPF_MAP_UPDATE_ELEM, lru, &k1, &v, BPF_ANY);
    elem(BPF_MAP_UPDATE_ELEM, lru, &k2, &v, BPF_ANY);
    SAY("lru a third in two: %ld\n", elem(BPF_MAP_UPDATE_ELEM, lru, &k3, &v, BPF_ANY));
    int there = 0;
    for (uint32_t k = 1; k <= 3; k++) there += elem(BPF_MAP_LOOKUP_ELEM, lru, &k, &out, 0) == 0;
    SAY("lru holds: %d\n", there);
    SAY("lru the third there: %ld\n", elem(BPF_MAP_LOOKUP_ELEM, lru, &k3, &out, 0));

    // Per-CPU array.
    int n = possible();
    long pc = make(BPF_MAP_TYPE_PERCPU_ARRAY, 4, 4, 2, 0);
    SAY("percpu: %ld\n", MADE(pc));
    uint64_t *vals = calloc(n, 8), *got = calloc(n, 8);
    for (int i = 0; i < n; i++) vals[i] = 100 + i;
    uint32_t k0 = 0;
    SAY("percpu update: %ld\n", elem(BPF_MAP_UPDATE_ELEM, pc, &k0, vals, BPF_ANY));
    SAY("percpu lookup: %ld\n", elem(BPF_MAP_LOOKUP_ELEM, pc, &k0, got, 0));
    int same = 1;
    for (int i = 0; i < n; i++) same &= got[i] == 100 + (uint64_t)i;
    SAY("percpu each cpu's, rounded to 8: %d\n", same);
    SAY("percpu delete: %ld\n", elem(BPF_MAP_DELETE_ELEM, pc, &k0, NULL, 0));

    // LPM trie.
    SAY("lpm made ahead: %ld\n", MADE(make(BPF_MAP_TYPE_LPM_TRIE, 8, 8, 2, 0)));
    SAY("lpm key of 4: %ld\n", MADE(make(BPF_MAP_TYPE_LPM_TRIE, 4, 8, 2, BPF_F_NO_PREALLOC)));
    long t = make(BPF_MAP_TYPE_LPM_TRIE, 8, 8, 3, BPF_F_NO_PREALLOC);
    SAY("lpm: %ld\n", MADE(t));
    struct lpm4 p8 = {8, {10, 0, 0, 0}}, p16 = {16, {10, 1, 0, 0}}, p24 = {24, {10, 0, 3, 0}}, p33 = {33, {10, 0, 0, 0}}, p4 = {4, {192, 0, 0, 0}};
    uint64_t one = 1, two = 2, three = 3;
    SAY("lpm 10/8: %ld\n", elem(BPF_MAP_UPDATE_ELEM, t, &p8, &one, BPF_ANY));
    SAY("lpm 10.1/16: %ld\n", elem(BPF_MAP_UPDATE_ELEM, t, &p16, &two, BPF_ANY));
    SAY("lpm 10.0.3/24: %ld\n", elem(BPF_MAP_UPDATE_ELEM, t, &p24, &three, BPF_ANY));
    SAY("lpm a fourth in three: %ld\n", elem(BPF_MAP_UPDATE_ELEM, t, &p4, &three, BPF_ANY));
    SAY("lpm /33: %ld\n", elem(BPF_MAP_UPDATE_ELEM, t, &p33, &one, BPF_ANY));
    SAY("lpm 10/8 NOEXIST: %ld\n", elem(BPF_MAP_UPDATE_ELEM, t, &p8, &one, BPF_NOEXIST));
    struct lpm4 q = {32, {10, 1, 2, 3}};
    out = 0;
    SAY("lpm 10.1.2.3: %ld %llu\n", elem(BPF_MAP_LOOKUP_ELEM, t, &q, &out, 0), (unsigned long long)out);
    q = (struct lpm4){32, {10, 0, 3, 9}};
    out = 0;
    SAY("lpm 10.0.3.9: %ld %llu\n", elem(BPF_MAP_LOOKUP_ELEM, t, &q, &out, 0), (unsigned long long)out);
    q = (struct lpm4){32, {10, 9, 9, 9}};
    out = 0;
    SAY("lpm 10.9.9.9: %ld %llu\n", elem(BPF_MAP_LOOKUP_ELEM, t, &q, &out, 0), (unsigned long long)out);
    q = (struct lpm4){32, {11, 0, 0, 0}};
    SAY("lpm 11.0.0.0: %ld\n", elem(BPF_MAP_LOOKUP_ELEM, t, &q, &out, 0));
    q = (struct lpm4){12, {10, 1, 2, 3}};
    out = 0;
    SAY("lpm 10.1.2.3/12: %ld %llu\n", elem(BPF_MAP_LOOKUP_ELEM, t, &q, &out, 0), (unsigned long long)out);
    SAY("lpm walk:");
    struct lpm4 cur, nxt;
    long r = next_key(t, NULL, &cur);
    while (r == 0) {
        SAY(" %u.%u.%u.%u/%u", cur.addr[0], cur.addr[1], cur.addr[2], cur.addr[3], cur.plen);
        r = next_key(t, &cur, &nxt);
        cur = nxt;
    }
    SAY(" (%ld)\n", r);
    SAY("lpm delete 10.1/16: %ld\n", elem(BPF_MAP_DELETE_ELEM, t, &p16, NULL, 0));
    SAY("lpm delete it again: %ld\n", elem(BPF_MAP_DELETE_ELEM, t, &p16, NULL, 0));

    // Read-only and write-only for user space.
    long ro = make(BPF_MAP_TYPE_HASH, 4, 8, 2, BPF_F_RDONLY);
    SAY("read-only update: %ld\n", elem(BPF_MAP_UPDATE_ELEM, ro, &k1, &v, BPF_ANY));
    SAY("read-only lookup: %ld\n", elem(BPF_MAP_LOOKUP_ELEM, ro, &k1, &out, 0));
    long wo = make(BPF_MAP_TYPE_HASH, 4, 8, 2, BPF_F_WRONLY);
    SAY("write-only update: %ld\n", elem(BPF_MAP_UPDATE_ELEM, wo, &k1, &v, BPF_ANY));
    SAY("write-only lookup: %ld\n", elem(BPF_MAP_LOOKUP_ELEM, wo, &k1, &out, 0));
    SAY("both: %ld\n", MADE(make(BPF_MAP_TYPE_HASH, 4, 8, 2, BPF_F_RDONLY | BPF_F_WRONLY)));
    SAY("hash mmapable: %ld\n", MADE(make(BPF_MAP_TYPE_HASH, 4, 8, 2, BPF_F_MMAPABLE)));
    SAY("array no prealloc: %ld\n", MADE(make(BPF_MAP_TYPE_ARRAY, 4, 8, 2, BPF_F_NO_PREALLOC)));
    SAY("hash read-only for programs: %ld\n", MADE(make(BPF_MAP_TYPE_HASH, 4, 8, 2, BPF_F_RDONLY_PROG)));

    // A devmap hash: interfaces by key.
    SAY("devmap value 6: %ld\n", MADE(make(BPF_MAP_TYPE_DEVMAP_HASH, 4, 6, 2, 0)));
    SAY("devmap read-only for programs asked: %ld\n", MADE(make(BPF_MAP_TYPE_DEVMAP_HASH, 4, 4, 2, BPF_F_RDONLY_PROG)));
    long dm = make(BPF_MAP_TYPE_DEVMAP_HASH, 4, 4, 2, 0);
    SAY("devmap: %ld\n", MADE(dm));
    struct bpf_map_info mi;
    memset(&mi, 0, sizeof mi);
    union bpf_attr ia;
    memset(&ia, 0, sizeof ia);
    ia.info.bpf_fd = dm;
    ia.info.info_len = sizeof mi;
    ia.info.info = (uintptr_t)&mi;
    sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &ia, sizeof ia);
    SAY("devmap flags: %#x\n", mi.map_flags);
    uint32_t lo = 1, none = 999, zero = 0, got32 = 0;
    SAY("devmap lo: %ld\n", elem(BPF_MAP_UPDATE_ELEM, dm, &k1, &lo, BPF_ANY));
    SAY("devmap ifindex 999: %ld\n", elem(BPF_MAP_UPDATE_ELEM, dm, &k2, &none, BPF_ANY));
    SAY("devmap ifindex 0: %ld\n", elem(BPF_MAP_UPDATE_ELEM, dm, &k2, &zero, BPF_ANY));
    SAY("devmap EXIST of a missing key: %ld\n", elem(BPF_MAP_UPDATE_ELEM, dm, &k2, &lo, BPF_EXIST));
    SAY("devmap NOEXIST of a key there: %ld\n", elem(BPF_MAP_UPDATE_ELEM, dm, &k1, &lo, BPF_NOEXIST));
    SAY("devmap a third: %ld\n", elem(BPF_MAP_UPDATE_ELEM, dm, &k3, &lo, BPF_ANY));
    SAY("devmap lookup: %ld %u\n", elem(BPF_MAP_LOOKUP_ELEM, dm, &k1, &got32, 0), got32);
    SAY("devmap delete: %ld\n", elem(BPF_MAP_DELETE_ELEM, dm, &k1, NULL, 0));
    SAY("devmap delete again: %ld\n", elem(BPF_MAP_DELETE_ELEM, dm, &k1, NULL, 0));

    if (expected[0] && strcmp(out_buf, expected) != 0) {
        printf("bpfmaps2: not what Linux shows\n");
        return 1;
    }
    printf(expected[0] ? "bpfmaps2 ok\n" : "bpfmaps2 done\n");
    return 0;
}
