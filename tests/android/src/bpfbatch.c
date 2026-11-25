// bpf(2)'s batch commands, as Android's BpfMap walks and drains its maps
// on kernels from 5.10 (doBulkLookupAndMaybeDelete: BPF_MAP_LOOKUP_BATCH,
// BPF_MAP_LOOKUP_AND_DELETE_BATCH; netd's and the system server's traffic
// statistics):
//
// - a hash gives whole buckets from the one in_batch names, the latest put
//   in a bucket first, and the bucket to go on from in out_batch; ENOSPC if
//   the first bucket will not fit, ENOENT (with what it gave) past the
//   last. With BPF_F_ZERO_SEED a key's bucket is the kernel's jhash of it
//   with seed 0, which this program works out itself, so the order is
//   checked exactly;
// - lookup-and-delete empties what it gives;
// - an array goes key after key (generic_map_lookup_batch), out_batch the
//   last key given, ENOENT at the end; it has an update batch and no delete
//   batch (ENOTSUPP, 524);
// - a delete batch stops at the first key not there, counting the ones it
//   deleted;
// - the checks: flags on a hash's lookup, elem_flags, a short attribute (the
//   rest zero, as bpf(2) copies one: a lookup),
//   a count of 0.
//
// Prints nothing when all is as the source says; as root.
#define _GNU_SOURCE
#include <errno.h>
#include <linux/bpf.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#define ENOTSUPP 524

static int failed;

static long sys_bpf(int cmd, union bpf_attr *attr, unsigned size) {
    long r = syscall(__NR_bpf, cmd, attr, size);
    return r < 0 ? -errno : r;
}

static void want(const char *what, long got, long expect) {
    if (got != expect) {
        printf("bpfbatch: %s: want %ld, got %ld\n", what, expect, got);
        failed = 1;
    }
}

static int map_create(int type, int key, int value, int max, int flags) {
    union bpf_attr a;
    memset(&a, 0, sizeof a);
    a.map_type = type;
    a.key_size = key;
    a.value_size = value;
    a.max_entries = max;
    a.map_flags = flags;
    return (int)sys_bpf(BPF_MAP_CREATE, &a, sizeof a);
}

static long update(int fd, const void *key, const void *value) {
    union bpf_attr a;
    memset(&a, 0, sizeof a);
    a.map_fd = fd;
    a.key = (uintptr_t)key;
    a.value = (uintptr_t)value;
    return sys_bpf(BPF_MAP_UPDATE_ELEM, &a, sizeof a);
}

static long lookup(int fd, const void *key, void *value) {
    union bpf_attr a;
    memset(&a, 0, sizeof a);
    a.map_fd = fd;
    a.key = (uintptr_t)key;
    a.value = (uintptr_t)value;
    return sys_bpf(BPF_MAP_LOOKUP_ELEM, &a, sizeof a);
}

// A batch command; *count in and out.
static long batch(int cmd, int fd, void *in, void *out, void *keys, void *values, uint32_t *count, uint64_t elem_flags, uint64_t flags, unsigned size) {
    union bpf_attr a;
    memset(&a, 0, sizeof a);
    a.batch.in_batch = (uintptr_t)in;
    a.batch.out_batch = (uintptr_t)out;
    a.batch.keys = (uintptr_t)keys;
    a.batch.values = (uintptr_t)values;
    a.batch.count = *count;
    a.batch.map_fd = fd;
    a.batch.elem_flags = elem_flags;
    a.batch.flags = flags;
    long r = sys_bpf(cmd, &a, size);
    *count = a.batch.count;
    return r;
}

// include/linux/jhash.h: jhash_1word, as htab_map_hash takes a 4-byte key.
static uint32_t rol32(uint32_t w, unsigned s) { return (w << s) | (w >> (32 - s)); }

static uint32_t jhash_1word(uint32_t a, uint32_t initval) {
    uint32_t b, c;
    initval += 0xdeadbeef + (1 << 2);
    a += initval;
    b = initval;
    c = initval;
    c ^= b; c -= rol32(b, 14);
    a ^= c; a -= rol32(c, 11);
    b ^= a; b -= rol32(a, 25);
    c ^= b; c -= rol32(b, 16);
    a ^= c; a -= rol32(c, 4);
    b ^= a; b -= rol32(a, 14);
    c ^= b; c -= rol32(b, 24);
    return c;
}

#define N 8

int main(void) {
    // A hash of eight, eight buckets, seed 0; keys 0..7 put in that order,
    // values ten times the key.
    int h = map_create(BPF_MAP_TYPE_HASH, 4, 8, N, BPF_F_ZERO_SEED);
    if (h < 0) {
        printf("bpfbatch: a hash: %d\n", h);
        return 1;
    }
    for (uint32_t k = 0; k < N; k++) {
        uint64_t v = k * 10;
        want("put", update(h, &k, &v), 0);
    }
    // The kernel's order: bucket by bucket, the latest first in each.
    uint32_t expect[N], n = 0, biggest = 0;
    for (uint32_t b = 0; b < N; b++) {
        uint32_t in_bucket = 0;
        for (int k = N - 1; k >= 0; k--) {
            if ((jhash_1word((uint32_t)k, 0) & (N - 1)) == b) {
                expect[n++] = (uint32_t)k;
                in_bucket++;
            }
        }
        if (in_bucket > biggest) biggest = in_bucket;
    }

    // All in one: ENOENT, with all eight, and the bucket past the last.
    uint32_t keys[N * 2], out = 99, count = N * 2;
    uint64_t values[N * 2];
    want("all at once", batch(BPF_MAP_LOOKUP_BATCH, h, NULL, &out, keys, values, &count, 0, 0, sizeof(union bpf_attr)), -ENOENT);
    want("all at once: how many", count, N);
    want("all at once: out_batch", out, N);
    for (uint32_t i = 0; i < count && i < N; i++) {
        want("all at once: key", keys[i], expect[i]);
        want("all at once: value", (long)values[i], expect[i] * 10);
    }

    // One at a time, as BpfMap starts (and grows the room on ENOSPC): the
    // same order, and an ENOSPC for each bucket of more than one.
    uint32_t got[N], have = 0, in = 0, room = 1, nospc = 0;
    int first = 1;
    for (int guard = 0; guard < 64; guard++) {
        count = room;
        long r = batch(BPF_MAP_LOOKUP_BATCH, h, first ? NULL : &in, &in, keys, values, &count, 0, 0, sizeof(union bpf_attr));
        if (r == -ENOSPC) {
            want("ENOSPC: how many", count, 0);
            nospc++;
            room *= 2;
            continue;
        }
        for (uint32_t i = 0; i < count && have < N; i++) got[have++] = keys[i];
        first = 0;
        if (r == -ENOENT) break;
        want("one at a time", r, 0);
        room = 1;
    }
    want("one at a time: how many", have, N);
    for (uint32_t i = 0; i < have; i++) want("one at a time: key", got[i], expect[i]);
    want("one at a time: an ENOSPC only if a bucket has more than one", nospc > 0, biggest > 1);

    // A bucket past the last; nothing asked for; the checks.
    in = N;
    count = 4;
    want("past the last bucket", batch(BPF_MAP_LOOKUP_BATCH, h, &in, &out, keys, values, &count, 0, 0, sizeof(union bpf_attr)), -ENOENT);
    want("past the last bucket: how many", count, 0);
    count = 0;
    want("a count of 0", batch(BPF_MAP_LOOKUP_BATCH, h, NULL, &out, keys, values, &count, 0, 0, sizeof(union bpf_attr)), 0);
    count = 4;
    want("flags", batch(BPF_MAP_LOOKUP_BATCH, h, NULL, &out, keys, values, &count, 0, 1, sizeof(union bpf_attr)), -EINVAL);
    want("elem_flags", batch(BPF_MAP_LOOKUP_BATCH, h, NULL, &out, keys, values, &count, BPF_F_LOCK, 0, sizeof(union bpf_attr)), -EINVAL);
    // A short attribute: the rest is zero (bpf(2)'s copy), so one that
    // stops before flags is a lookup from the start.
    count = 4;
    want("a short attribute", batch(BPF_MAP_LOOKUP_BATCH, h, NULL, &out, keys, values, &count, 0, 0, offsetof(union bpf_attr, batch.flags)), 0);

    // Delete by keys: 1 and 2 go, 99 is not there and stops it.
    uint32_t del[3] = {1, 2, 99};
    count = 3;
    want("delete batch", batch(BPF_MAP_DELETE_BATCH, h, NULL, NULL, del, NULL, &count, 0, 0, sizeof(union bpf_attr)), -ENOENT);
    want("delete batch: how many", count, 2);
    uint64_t v;
    want("deleted", lookup(h, &del[0], &v), -ENOENT);

    // Lookup and delete: what is left, given and gone.
    count = N;
    want("lookup and delete", batch(BPF_MAP_LOOKUP_AND_DELETE_BATCH, h, NULL, &out, keys, values, &count, 0, 0, sizeof(union bpf_attr)), -ENOENT);
    want("lookup and delete: how many", count, N - 2);
    uint32_t zero = 0;
    want("emptied", lookup(h, &zero, &v), -ENOENT);
    close(h);

    // An array of five: three, then the rest and ENOENT.
    int a = map_create(BPF_MAP_TYPE_ARRAY, 4, 4, 5, 0);
    uint32_t ak[5] = {0, 1, 2, 3, 4}, av[5] = {7, 8, 9, 10, 11};
    count = 5;
    want("array update batch", batch(BPF_MAP_UPDATE_BATCH, a, NULL, NULL, ak, av, &count, 0, 0, sizeof(union bpf_attr)), 0);
    want("array update batch: how many", count, 5);
    uint32_t rk[5], rv[5], last = 99;
    count = 3;
    want("array: three", batch(BPF_MAP_LOOKUP_BATCH, a, NULL, &last, rk, rv, &count, 0, 0, sizeof(union bpf_attr)), 0);
    want("array: three: how many", count, 3);
    want("array: three: out_batch", last, 2);
    want("array: three: a value", rv[2], 9);
    count = 3;
    want("array: the rest", batch(BPF_MAP_LOOKUP_BATCH, a, &last, &last, rk, rv, &count, 0, 0, sizeof(union bpf_attr)), -ENOENT);
    want("array: the rest: how many", count, 2);
    want("array: the rest: first key", rk[0], 3);
    want("array: the rest: out_batch", last, 4);
    count = 1;
    want("array: no delete batch", batch(BPF_MAP_DELETE_BATCH, a, NULL, NULL, ak, NULL, &count, 0, 0, sizeof(union bpf_attr)), -ENOTSUPP);
    want("array: no lookup and delete batch", batch(BPF_MAP_LOOKUP_AND_DELETE_BATCH, a, NULL, &last, rk, rv, &count, 0, 0, sizeof(union bpf_attr)), -ENOTSUPP);
    close(a);

    if (!failed) printf("bpfbatch ok\n");
    return failed;
}
