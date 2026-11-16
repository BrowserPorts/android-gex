// BPF_BTF_LOAD, as libbpf uses it before anything else of a BPF object,
// and maps that name BTF key and value types. A BTF with a type of each
// kind is built by hand and loaded; then the same broken one way at a
// time; maps are made against it with sizes that match and that do not.
// Prints an answer a line and checks them against what Linux 7.0 gave.
// As root.
#define _GNU_SOURCE
#include <errno.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#ifndef BTF_KIND_ENUM64
#define BTF_KIND_ENUM64 19
#endif
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
    "the good one: loaded\n"
    "bad magic: -22\n"
    "version 2: -524\n"
    "flags 1: -524\n"
    "longer header, not zero: -7\n"
    "longer header, zero: loaded\n"
    "header alone: -22\n"
    "kind 25: -22\n"
    "name past the strings: -22\n"
    "a pointer to type 99: -22\n"
    "an int of 3 bytes: -22\n"
    "a pointer with a name: -22\n"
    "typedefs in a circle: -17\n"
    "a func of an int: -22\n"
    "strings not begun empty: -22\n"
    "hash int -> u64_t: made\n"
    "hash value int for 8 bytes: -22\n"
    "hash key long for 4 bytes: -22\n"
    "hash value only: refused\n"
    "hash key only: -22\n"
    "hash with ids and no BTF: -22\n"
    "hash value a func: -22\n"
    "hash value the struct: made\n"
    "info: 0 size the blob's id given\n"
    "a log with no level: -22\n"
    "a log of 64 bytes: -28\n"
    "a log with room: loaded\n"
    "it begins: magic: 0xeb9\n"
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

// A BTF under construction: types and strings.
static uint32_t types[256];
static int ntypes;
static char strs[512];
static int nstrs;

static uint32_t str(const char *s) {
    if (!*s) return 0;
    uint32_t at = nstrs;
    strcpy(strs + nstrs, s);
    nstrs += strlen(s) + 1;
    return at;
}

static void w(uint32_t v) {
    types[ntypes++] = v;
}

static uint32_t info(int kind, int vlen, int kflag) {
    return (uint32_t)kind << 24 | (uint32_t)vlen | (uint32_t)kflag << 31;
}

// The good one: [1] int, [2] ptr, [3] struct, [4] array, [5] proto,
// [6] func, [7] var, [8] datasec, [9] float, [10] long, [11] typedef,
// [12] enum64, [13] decl_tag, [14] type_tag, [15] const.
static void build(void) {
    ntypes = 0;
    nstrs = 1;
    strs[0] = 0;
    w(str("int")); w(info(BTF_KIND_INT, 0, 0)); w(4); w(BTF_INT_SIGNED << 24 | 32);
    w(0); w(info(BTF_KIND_PTR, 0, 0)); w(1);
    w(str("s")); w(info(BTF_KIND_STRUCT, 2, 0)); w(8);
    w(str("a")); w(1); w(0);
    w(str("b")); w(1); w(32);
    w(0); w(info(BTF_KIND_ARRAY, 0, 0)); w(0); w(1); w(1); w(2);
    w(0); w(info(BTF_KIND_FUNC_PROTO, 1, 0)); w(1); w(str("x")); w(1);
    w(str("f")); w(info(BTF_KIND_FUNC, 0, 0)); w(5);
    w(str("v")); w(info(BTF_KIND_VAR, 0, 0)); w(1); w(1);
    w(str(".data")); w(info(BTF_KIND_DATASEC, 1, 0)); w(4); w(7); w(0); w(4);
    w(str("float")); w(info(BTF_KIND_FLOAT, 0, 0)); w(4);
    w(str("long")); w(info(BTF_KIND_INT, 0, 0)); w(8); w(BTF_INT_SIGNED << 24 | 64);
    w(str("u64_t")); w(info(BTF_KIND_TYPEDEF, 0, 0)); w(10);
    w(str("e")); w(info(BTF_KIND_ENUM64, 1, 0)); w(8); w(str("A")); w(1); w(0);
    w(str("tag")); w(info(BTF_KIND_DECL_TAG, 0, 0)); w(3); w((uint32_t)-1);
    w(str("tt")); w(info(BTF_KIND_TYPE_TAG, 0, 0)); w(1);
    w(0); w(info(BTF_KIND_CONST, 0, 0)); w(1);
}

static char blob[4096];

// Header, types, strings, into `blob`; its length.
static int assemble(void) {
    struct btf_header h = {.magic = BTF_MAGIC, .version = BTF_VERSION, .flags = 0, .hdr_len = sizeof h,
                           .type_off = 0, .type_len = ntypes * 4, .str_off = ntypes * 4, .str_len = nstrs};
    memcpy(blob, &h, sizeof h);
    memcpy(blob + sizeof h, types, ntypes * 4);
    memcpy(blob + sizeof h + ntypes * 4, strs, nstrs);
    return sizeof h + ntypes * 4 + nstrs;
}

static long load(const char *b, int len) {
    union bpf_attr a;
    memset(&a, 0, sizeof a);
    a.btf = (uintptr_t)b;
    a.btf_size = len;
    return sys_bpf(BPF_BTF_LOAD, &a, sizeof a);
}

static long map(int btf, int key, int value, int key_id, int value_id) {
    union bpf_attr a;
    memset(&a, 0, sizeof a);
    a.map_type = BPF_MAP_TYPE_HASH;
    a.key_size = key;
    a.value_size = value;
    a.max_entries = 4;
    a.btf_fd = btf;
    a.btf_key_type_id = key_id;
    a.btf_value_type_id = value_id;
    return sys_bpf(BPF_MAP_CREATE, &a, sizeof a);
}

int main(void) {
    build();
    int len = assemble();
    long fd = load(blob, len);
    SAY("the good one: %s\n", fd >= 0 ? "loaded" : "refused");
    if (fd < 0) SAY("  (%ld)\n", fd);

    struct btf_header *h = (struct btf_header *)blob;
    len = assemble(); h->magic = 0x1234; SAY("bad magic: %ld\n", load(blob, len));
    len = assemble(); h->version = 2; SAY("version 2: %ld\n", load(blob, len));
    len = assemble(); h->flags = 1; SAY("flags 1: %ld\n", load(blob, len));
    {
        // A header 8 bytes longer, those 8 not zero.
        char big[4096];
        len = assemble();
        struct btf_header hh;
        memcpy(&hh, blob, sizeof hh);
        hh.hdr_len = sizeof hh + 8;
        memcpy(big, &hh, sizeof hh);
        memset(big + sizeof hh, 0, 8);
        big[sizeof hh] = 1;
        memcpy(big + sizeof hh + 8, blob + sizeof hh, len - sizeof hh);
        SAY("longer header, not zero: %ld\n", load(big, len + 8));
        big[sizeof hh] = 0;
        SAY("longer header, zero: %s\n", load(big, len + 8) >= 0 ? "loaded" : "refused");
    }
    SAY("header alone: %ld\n", load(blob, sizeof(struct btf_header)));
    build(); types[1] = info(25, 0, 0); len = assemble(); SAY("kind 25: %ld\n", load(blob, len));
    build(); types[0] = 400; len = assemble(); SAY("name past the strings: %ld\n", load(blob, len));
    build(); types[6] = 99; len = assemble(); SAY("a pointer to type 99: %ld\n", load(blob, len));
    build(); types[2] = 3; len = assemble(); SAY("an int of 3 bytes: %ld\n", load(blob, len));
    build(); types[4] = str("p"); len = assemble(); SAY("a pointer with a name: %ld\n", load(blob, len));
    build();
    // [11] typedef -> 16, [16] typedef -> 11: round.
    w(str("loop")); w(info(BTF_KIND_TYPEDEF, 0, 0)); w(11);
    for (int i = 0; i < ntypes - 2; i++)
        if (types[i] == info(BTF_KIND_TYPEDEF, 0, 0) && types[i + 1] == 10) types[i + 1] = 16;
    len = assemble(); SAY("typedefs in a circle: %ld\n", load(blob, len));
    build();
    for (int i = 0; i < ntypes - 2; i++)
        if (types[i] == info(BTF_KIND_FUNC, 0, 0)) types[i + 1] = 1;
    len = assemble(); SAY("a func of an int: %ld\n", load(blob, len));
    build(); strs[0] = 'x'; len = assemble(); SAY("strings not begun empty: %ld\n", load(blob, len));

    // Maps against the good one.
    build();
    len = assemble();
    fd = load(blob, len);
    SAY("hash int -> u64_t: %s\n", map(fd, 4, 8, 1, 11) >= 0 ? "made" : "refused");
    SAY("hash value int for 8 bytes: %ld\n", map(fd, 4, 8, 1, 1));
    SAY("hash key long for 4 bytes: %ld\n", map(fd, 4, 8, 10, 11));
    SAY("hash value only: %s\n", map(fd, 4, 8, 0, 11) >= 0 ? "made" : "refused");
    SAY("hash key only: %ld\n", map(fd, 4, 8, 1, 0));
    SAY("hash with ids and no BTF: %ld\n", map(0, 4, 8, 1, 11));
    SAY("hash value a func: %ld\n", map(fd, 4, 8, 1, 6));
    SAY("hash value the struct: %s\n", map(fd, 4, 8, 1, 3) >= 0 ? "made" : "refused");

    // Its description.
    struct bpf_btf_info bi;
    memset(&bi, 0, sizeof bi);
    union bpf_attr ia;
    memset(&ia, 0, sizeof ia);
    ia.info.bpf_fd = fd;
    ia.info.info_len = sizeof bi;
    ia.info.info = (uintptr_t)&bi;
    long ir = sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &ia, sizeof ia);
    SAY("info: %ld size %s id %s\n", ir, bi.btf_size == (uint32_t)len ? "the blob's" : "other", bi.id ? "given" : "none");

    // The log's attributes.
    char log[256];
    union bpf_attr la;
    memset(&la, 0, sizeof la);
    la.btf = (uintptr_t)blob;
    la.btf_size = len;
    la.btf_log_buf = (uintptr_t)log;
    la.btf_log_size = sizeof log;
    SAY("a log with no level: %ld\n", sys_bpf(BPF_BTF_LOAD, &la, sizeof la));
    la.btf_log_level = 1;
    la.btf_log_size = 64;
    SAY("a log of 64 bytes: %ld\n", sys_bpf(BPF_BTF_LOAD, &la, sizeof la));
    static char biglog[8192];
    la.btf_log_buf = (uintptr_t)biglog;
    la.btf_log_size = sizeof biglog;
    SAY("a log with room: %s\n", sys_bpf(BPF_BTF_LOAD, &la, sizeof la) >= 0 ? "loaded" : "refused");
    SAY("it begins: %.12s\n", biglog);

    if (expected[0] && strcmp(out_buf, expected) != 0) {
        printf("btf: not what Linux shows\n");
        return 1;
    }
    printf(expected[0] ? "btf ok\n" : "btf done\n");
    return 0;
}
