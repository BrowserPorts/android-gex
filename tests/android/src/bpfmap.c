// bpf(2)'s maps and bpffs, as Android's netd and its BPF loader use them:
// maps made (array, hash), read and written by key with the update flags,
// walked with GET_NEXT_KEY, pinned in a bpffs (a file a later process
// opens the map by, BPF_OBJ_GET), described (BPF_OBJ_GET_INFO_BY_FD).
// Prints what it sees, one line a question, and checks it against what
// Linux 7.0 printed. As root.
#define _GNU_SOURCE
#include <errno.h>
#include <stdarg.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <unistd.h>

static long sys_bpf(int cmd, union bpf_attr *attr, unsigned size) {
    long r = syscall(__NR_bpf, cmd, attr, size);
    return r < 0 ? -errno : r;
}

static long map_create(int type, int key, int value, int max, int flags, const char *name) {
    union bpf_attr a;
    memset(&a, 0, sizeof a);
    a.map_type = type;
    a.key_size = key;
    a.value_size = value;
    a.max_entries = max;
    a.map_flags = flags;
    if (name) strncpy(a.map_name, name, sizeof a.map_name - 1);
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

static long pin(int fd, const char *path) {
    union bpf_attr a;
    memset(&a, 0, sizeof a);
    a.bpf_fd = fd;
    a.pathname = (uintptr_t)path;
    return sys_bpf(BPF_OBJ_PIN, &a, sizeof a);
}

static long get(const char *path, int flags) {
    union bpf_attr a;
    memset(&a, 0, sizeof a);
    a.pathname = (uintptr_t)path;
    a.file_flags = flags;
    return sys_bpf(BPF_OBJ_GET, &a, sizeof a);
}

// What Linux 7.0 printed.
static const char expected[] =
    "mount bpf: 0\n"
    "magic: cafe4a11\n"
    "mkdir: 0\n"
    "open O_CREAT: -13\n"
    "array: made\n"
    "array lookup 2 (zero): 0 0\n"
    "array update 2: 0\n"
    "array lookup 2: 0 1122334455667788\n"
    "array update 9: -7\n"
    "array update 2 NOEXIST: -17\n"
    "array delete 2: -22\n"
    "array update flags 9: -22\n"
    "array next of none: 0 0\n"
    "array next of 3: -2\n"
    "array next of 9: 0 0\n"
    "hash: made\n"
    "hash lookup 10: -2\n"
    "hash update 10 EXIST: -2\n"
    "hash update 10 NOEXIST: 0\n"
    "hash update 10 NOEXIST again: -17\n"
    "hash update 20: 0\n"
    "hash update 30 (full): -7\n"
    "hash update 20 again (full): 0\n"
    "hash walk: sum 30, ended -2\n"
    "hash next of 99: 0\n"
    "hash delete 10: 0\n"
    "hash delete 10 again: -2\n"
    "array key 8: -22\n"
    "hash max 0: -22\n"
    "hash value 0: -22\n"
    "type 999: -22\n"
    "bad name: -22\n"
    "pin: 0\n"
    "pin again: -17\n"
    "pinned: mode 100600\n"
    "open pinned: -5\n"
    "get: a descriptor\n"
    "lookup 20 through it: 0 1122334455667788\n"
    "update through a read-only one: -1\n"
    "get of a directory: -13\n"
    "get of nothing: -2\n"
    "pin outside bpffs: -1\n"
    "info: 0 type 1 key 4 value 8 max 2 flags 0 name gex_hash len 88\n"
    "attr with a tail: -22\n"
    "command 999: -22\n"
    "unlink pinned: 0\n"
;

static char out_buf[8192];
static size_t used;

// Print, and keep what was printed.
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

int main(void) {
    char dir[] = "/tmp/bpfmap.XXXXXX";
    if (!mkdtemp(dir)) return 1;
    SAY("mount bpf: %d\n", mount("bpf", dir, "bpf", 0, NULL) ? -errno : 0);
    struct statfs sf;
    statfs(dir, &sf);
    SAY("magic: %lx\n", (unsigned long)sf.f_type);
    char path[128];
    snprintf(path, sizeof path, "%s/sub", dir);
    SAY("mkdir: %d\n", mkdir(path, 0755) ? -errno : 0);
    snprintf(path, sizeof path, "%s/file", dir);
    int f = open(path, O_CREAT | O_WRONLY, 0644);
    SAY("open O_CREAT: %d\n", f < 0 ? -errno : 0);

    // An array.
    long arr = map_create(BPF_MAP_TYPE_ARRAY, 4, 8, 4, 0, "gex_array");
    SAY("array: %s\n", arr >= 0 ? "made" : "refused");
    uint32_t k = 2, k9 = 9;
    uint64_t v = 0x1122334455667788ull, out = 1;
    SAY("array lookup 2 (zero): %ld %llx\n", elem(BPF_MAP_LOOKUP_ELEM, arr, &k, &out, 0), (unsigned long long)out);
    SAY("array update 2: %ld\n", elem(BPF_MAP_UPDATE_ELEM, arr, &k, &v, BPF_ANY));
    SAY("array lookup 2: %ld %llx\n", elem(BPF_MAP_LOOKUP_ELEM, arr, &k, &out, 0), (unsigned long long)out);
    SAY("array update 9: %ld\n", elem(BPF_MAP_UPDATE_ELEM, arr, &k9, &v, BPF_ANY));
    SAY("array update 2 NOEXIST: %ld\n", elem(BPF_MAP_UPDATE_ELEM, arr, &k, &v, BPF_NOEXIST));
    SAY("array delete 2: %ld\n", elem(BPF_MAP_DELETE_ELEM, arr, &k, NULL, 0));
    SAY("array update flags 9: %ld\n", elem(BPF_MAP_UPDATE_ELEM, arr, &k, &v, 9));
    uint32_t nk = 77;
    SAY("array next of none: %ld %u\n", next_key(arr, NULL, &nk), nk);
    SAY("array next of 3: %ld\n", next_key(arr, &(uint32_t){3}, &nk));
    SAY("array next of 9: %ld %u\n", next_key(arr, &k9, &nk), nk);

    // A hash.
    long h = map_create(BPF_MAP_TYPE_HASH, 4, 8, 2, 0, "gex_hash");
    SAY("hash: %s\n", h >= 0 ? "made" : "refused");
    uint32_t a1 = 10, a2 = 20, a3 = 30;
    SAY("hash lookup 10: %ld\n", elem(BPF_MAP_LOOKUP_ELEM, h, &a1, &out, 0));
    SAY("hash update 10 EXIST: %ld\n", elem(BPF_MAP_UPDATE_ELEM, h, &a1, &v, BPF_EXIST));
    SAY("hash update 10 NOEXIST: %ld\n", elem(BPF_MAP_UPDATE_ELEM, h, &a1, &v, BPF_NOEXIST));
    SAY("hash update 10 NOEXIST again: %ld\n", elem(BPF_MAP_UPDATE_ELEM, h, &a1, &v, BPF_NOEXIST));
    SAY("hash update 20: %ld\n", elem(BPF_MAP_UPDATE_ELEM, h, &a2, &v, BPF_ANY));
    SAY("hash update 30 (full): %ld\n", elem(BPF_MAP_UPDATE_ELEM, h, &a3, &v, BPF_ANY));
    SAY("hash update 20 again (full): %ld\n", elem(BPF_MAP_UPDATE_ELEM, h, &a2, &v, BPF_ANY));
    int seen = 0;
    uint32_t cur, nxt;
    long r = next_key(h, NULL, &cur);
    while (r == 0) {
        seen += cur;
        r = next_key(h, &cur, &nxt);
        cur = nxt;
    }
    SAY("hash walk: sum %d, ended %ld\n", seen, r);
    SAY("hash next of 99: %ld\n", next_key(h, &(uint32_t){99}, &nxt));
    SAY("hash delete 10: %ld\n", elem(BPF_MAP_DELETE_ELEM, h, &a1, NULL, 0));
    SAY("hash delete 10 again: %ld\n", elem(BPF_MAP_DELETE_ELEM, h, &a1, NULL, 0));

    // Refused shapes.
    SAY("array key 8: %ld\n", map_create(BPF_MAP_TYPE_ARRAY, 8, 8, 4, 0, NULL));
    SAY("hash max 0: %ld\n", map_create(BPF_MAP_TYPE_HASH, 4, 8, 0, 0, NULL));
    SAY("hash value 0: %ld\n", map_create(BPF_MAP_TYPE_HASH, 4, 0, 4, 0, NULL));
    SAY("type 999: %ld\n", map_create(999, 4, 8, 4, 0, NULL));
    SAY("bad name: %ld\n", map_create(BPF_MAP_TYPE_ARRAY, 4, 8, 4, 0, "no-dash!"));

    // Pinned.
    snprintf(path, sizeof path, "%s/sub/map_gex", dir);
    SAY("pin: %ld\n", pin(h, path));
    SAY("pin again: %ld\n", pin(h, path));
    struct stat st;
    stat(path, &st);
    SAY("pinned: mode %o\n", st.st_mode);
    int o = open(path, O_RDONLY);
    SAY("open pinned: %d\n", o < 0 ? -errno : 0);
    long g = get(path, 0);
    SAY("get: %s\n", g >= 0 ? "a descriptor" : "refused");
    SAY("lookup 20 through it: %ld %llx\n", elem(BPF_MAP_LOOKUP_ELEM, g, &a2, &out, 0), (unsigned long long)out);
    long gro = get(path, BPF_F_RDONLY);
    SAY("update through a read-only one: %ld\n", elem(BPF_MAP_UPDATE_ELEM, gro, &a2, &v, BPF_ANY));
    SAY("get of a directory: %ld\n", get(dir, 0));
    snprintf(path, sizeof path, "%s/none", dir);
    SAY("get of nothing: %ld\n", get(path, 0));
    SAY("pin outside bpffs: %ld\n", pin(h, "/tmp/bpfmap-not-bpffs"));

    // Described.
    struct bpf_map_info info;
    memset(&info, 0, sizeof info);
    union bpf_attr ia;
    memset(&ia, 0, sizeof ia);
    ia.info.bpf_fd = g;
    ia.info.info_len = sizeof info;
    ia.info.info = (uintptr_t)&info;
    SAY("info: %ld type %u key %u value %u max %u flags %u name %s len %u\n", sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &ia, sizeof ia), info.type, info.key_size, info.value_size, info.max_entries, info.map_flags, info.name, ia.info.info_len);

    // An attr longer than the kernel's, with something in the tail.
    char big[sizeof(union bpf_attr) + 16];
    memset(big, 0, sizeof big);
    union bpf_attr *ba = (union bpf_attr *)big;
    ba->map_type = BPF_MAP_TYPE_ARRAY;
    ba->key_size = 4;
    ba->value_size = 4;
    ba->max_entries = 1;
    big[sizeof big - 1] = 1;
    SAY("attr with a tail: %ld\n", sys_bpf(BPF_MAP_CREATE, ba, sizeof big));
    SAY("command 999: %ld\n", sys_bpf(999, ba, sizeof(union bpf_attr)));

    snprintf(path, sizeof path, "%s/sub/map_gex", dir);
    SAY("unlink pinned: %d\n", unlink(path) ? -errno : 0);
    umount2(dir, MNT_DETACH);
    rmdir(dir);
    if (strcmp(out_buf, expected) != 0) {
        printf("bpfmap: not what Linux shows\n");
        return 1;
    }
    printf("bpfmap ok\n");
    return 0;
}
