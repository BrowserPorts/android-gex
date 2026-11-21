// A one-way call to a node whose caller lets its last references on the
// node go right after: the call still reaches the node's owner as a call
// to that node (BR_TRANSACTION with the node's pointer and cookie), since a
// call holds its target as Linux's binder holds it, until its buffer is
// given back. (The suspend service aborted with "Calling transact on null
// Binder": a call that reached it naming no node, which is a call to the
// context manager it is not.)
//
// The parent is the context manager and owns the node; the child takes the
// node from a reply, holds it, and once the owner has taken its references
// calls it one way twice (the second waits on the node behind the first)
// and lets it go in the same write.
//
// Needs the device: /dev/binder, or binderfs mounted at /dev/binderfs.
// Without one the program says so and exits 77.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/android/binder.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef BINDER_GET_EXTENDED_ERROR
struct binder_extended_error {
    __u32 id;
    __u32 command;
    __s32 param;
};
#define BINDER_GET_EXTENDED_ERROR _IOWR('b', 17, struct binder_extended_error)
#endif

#define MAP_SIZE (128 * 1024)
#define P1 0x1111
#define K1 0x2222

static int fd;
static int releases, decrefs;
static char *map;
static const char *who;
static pid_t other;

static void die(const char *what, long a, long b) {
    printf("bindernode: %s: %s (%ld, %ld; errno %d)\n", who, what, a, b, errno);
    fflush(stdout);
    if (other > 0) kill(other, SIGKILL);
    exit(1);
}

static int open_device(int flags) {
    int f = open("/dev/binder", O_RDWR | O_CLOEXEC | flags);
    if (f < 0) f = open("/dev/binderfs/binder", O_RDWR | O_CLOEXEC | flags);
    if (f < 0) {
        printf("bindernode: no device (/dev/binder, /dev/binderfs/binder): errno %d\n", errno);
        exit(77);
    }
    return f;
}

static void open_binder(void) {
    fd = open_device(0);
    map = mmap(0, MAP_SIZE, PROT_READ, MAP_PRIVATE | MAP_NORESERVE, fd, 0);
    if (map == MAP_FAILED) die("mmap", 0, 0);
    uint32_t max = 0;
    if (ioctl(fd, BINDER_SET_MAX_THREADS, &max)) die("max threads", 0, 0);
}

static void send(const void *cmds, size_t n) {
    struct binder_write_read bwr = {.write_size = n, .write_buffer = (uintptr_t)cmds};
    if (ioctl(fd, BINDER_WRITE_READ, &bwr) || bwr.write_consumed != n) die("write", bwr.write_consumed, n);
}

static void send_u32(uint32_t cmd, uint32_t arg) {
    uint32_t b[2] = {cmd, arg};
    send(b, sizeof b);
}

static void send_ptr(uint32_t cmd, uint64_t arg) {
    struct {
        uint32_t cmd;
        uint64_t arg;
    } __attribute__((packed)) b = {cmd, arg};
    send(&b, sizeof b);
}

static void transact(uint32_t cmd, uint32_t handle, uint32_t code, uint32_t flags, const void *data, size_t n, int objects) {
    static const binder_size_t first = 0;
    struct {
        uint32_t cmd;
        struct binder_transaction_data t;
    } __attribute__((packed)) b;
    memset(&b, 0, sizeof b);
    b.cmd = cmd;
    b.t.target.handle = handle;
    b.t.code = code;
    b.t.flags = flags;
    b.t.data_size = n;
    b.t.offsets_size = objects ? sizeof first : 0;
    b.t.data.ptr.buffer = (uintptr_t)data;
    b.t.data.ptr.offsets = (uintptr_t)&first;
    send(&b, sizeof b);
}

// Every return the driver gave, in order, for the test to look back at.
static uint32_t seen[256];
static int n_seen;
static char inbox[1024];
static size_t in_at, in_end;

struct event {
    uint32_t cmd;
    struct binder_transaction_data t;
    uint64_t cookie;
};

// The next return that is a call, a reply, a death or an error. A node's
// reference returns are answered on the way, and everything is noted.
static struct event next(void) {
    for (;;) {
        if (in_at == in_end) {
            struct binder_write_read bwr = {.read_size = sizeof inbox, .read_buffer = (uintptr_t)inbox};
            if (ioctl(fd, BINDER_WRITE_READ, &bwr)) die("read", 0, 0);
            in_at = 0;
            in_end = bwr.read_consumed;
            continue;
        }
        struct event e = {0};
        memcpy(&e.cmd, inbox + in_at, 4);
        in_at += 4;
        size_t size = _IOC_SIZE(e.cmd);
        const char *arg = inbox + in_at;
        in_at += size;
        if (n_seen < 256) seen[n_seen++] = e.cmd;
        switch (e.cmd) {
        case BR_NOOP:
        case BR_SPAWN_LOOPER:
        case BR_TRANSACTION_COMPLETE:
            continue;
        case BR_INCREFS:
        case BR_ACQUIRE: {
            struct {
                uint32_t cmd;
                struct binder_ptr_cookie pc;
            } __attribute__((packed)) done = {e.cmd == BR_INCREFS ? BC_INCREFS_DONE : BC_ACQUIRE_DONE};
            memcpy(&done.pc, arg, sizeof done.pc);
            if (done.pc.ptr != P1 || done.pc.cookie != K1) die("a reference return's node", (long)done.pc.ptr, (long)done.pc.cookie);
            send(&done, sizeof done);
            continue;
        }
        case BR_RELEASE:
        case BR_DECREFS: {
            struct binder_ptr_cookie pc;
            memcpy(&pc, arg, sizeof pc);
            if (pc.ptr != P1 || pc.cookie != K1) die("a reference loss's node", (long)pc.ptr, (long)pc.cookie);
            if (e.cmd == BR_RELEASE) releases++;
            else decrefs++;
            continue;
        }
        case BR_TRANSACTION:
        case BR_REPLY:
            memcpy(&e.t, arg, sizeof e.t);
            return e;
        case BR_DEAD_BINDER:
        case BR_CLEAR_DEATH_NOTIFICATION_DONE:
            memcpy(&e.cookie, arg, 8);
            return e;
        default:
            return e;
        }
    }
}

// The child: one call to the manager, the node out of the reply, held,
// and an exit with the references still held.
static int holder(int go) {
    who = "holder";
    open_binder();
    char c;
    if (read(go, &c, 1) != 1) die("the go-ahead", 0, 0);
    uint32_t nothing = 0;
    transact(BC_TRANSACTION, 0, 1, 0, &nothing, sizeof nothing, 0);
    struct event e = next();
    if (e.cmd != BR_REPLY) die("the reply", e.cmd, 0);
    struct flat_binder_object obj;
    if (e.t.data_size < sizeof obj) die("the reply's size", e.t.data_size, 0);
    memcpy(&obj, (const void *)(uintptr_t)e.t.data.ptr.buffer, sizeof obj);
    if (obj.hdr.type != BINDER_TYPE_HANDLE) die("the node as a handle", obj.hdr.type, 0);
    send_u32(BC_INCREFS, obj.handle);
    send_u32(BC_ACQUIRE, obj.handle);
    send_ptr(BC_FREE_BUFFER, e.t.data.ptr.buffer);
    // Once the owner has taken its references: a one-way call to the node,
    // and the node let go at once, in the same write as the call.
    if (read(go, &c, 1) != 1) die("the word to call", 0, 0);
    struct {
        uint32_t cmd;
        struct binder_transaction_data t;
        uint32_t cmd2;
        struct binder_transaction_data t2;
        uint32_t release[2];
        uint32_t decrefs[2];
    } __attribute__((packed)) w;
    memset(&w, 0, sizeof w);
    w.cmd = BC_TRANSACTION;
    w.t.target.handle = obj.handle;
    w.t.code = 7;
    w.t.flags = TF_ONE_WAY;
    w.t.data_size = sizeof nothing;
    w.t.data.ptr.buffer = (uintptr_t)&nothing;
    // A second, which waits on the node behind the first.
    w.cmd2 = BC_TRANSACTION;
    w.t2 = w.t;
    w.t2.code = 8;
    w.release[0] = BC_RELEASE;
    w.release[1] = obj.handle;
    w.decrefs[0] = BC_DECREFS;
    w.decrefs[1] = obj.handle;
    send(&w, sizeof w);
    if (read(go, &c, 1) != 1) die("the word to exit", 0, 0);
    _exit(0);
}

// The owner's side of one holder: its call answered with the node, its
// exit waited for, and then the losses counted until a quiet moment.
static void one_holder(int round) {
    int go[2];
    if (pipe(go)) die("pipe", 0, 0);
    pid_t child = fork();
    if (child == 0) {
        close(go[1]);
        holder(go[0]);
    }
    other = child;
    close(go[0]);
    if (write(go[1], "x", 1) != 1) die("go", 0, 0);
    struct event e = next();
    if (e.cmd != BR_TRANSACTION) die("the call", e.cmd, round);
    struct flat_binder_object obj;
    memset(&obj, 0, sizeof obj);
    obj.hdr.type = BINDER_TYPE_BINDER;
    obj.binder = P1;
    obj.cookie = K1;
    send_ptr(BC_FREE_BUFFER, e.t.data.ptr.buffer);
    transact(BC_REPLY, 0, 0, 0, &obj, sizeof obj, 1);
    // The owner is told of the references the holder takes (BR_INCREFS,
    // BR_ACQUIRE, answered as libbinder answers them) before the holder
    // goes: a node whose references come and go between two of its
    // owner's reads tells it nothing.
    int increfs = 0, acquires = 0;
    while (increfs == 0 || acquires == 0) {
        struct pollfd p = {fd, POLLIN, 0};
        if (poll(&p, 1, 5000) == 0) die("the references the holder takes", increfs, acquires);
        struct binder_write_read bwr = {.read_size = sizeof inbox, .read_buffer = (uintptr_t)inbox};
        if (ioctl(fd, BINDER_WRITE_READ, &bwr)) die("read", 0, 0);
        for (size_t at = 0; at < bwr.read_consumed;) {
            uint32_t cmd;
            memcpy(&cmd, inbox + at, 4);
            struct binder_ptr_cookie pc;
            memcpy(&pc, inbox + at + 4, sizeof pc);
            at += 4 + _IOC_SIZE(cmd);
            if (cmd == BR_NOOP || cmd == BR_TRANSACTION_COMPLETE) continue;
            if (cmd != BR_INCREFS && cmd != BR_ACQUIRE) die("a return besides the references taken", cmd, round);
            if (pc.ptr != P1 || pc.cookie != K1) die("a reference return's node", (long)pc.ptr, (long)pc.cookie);
            struct {
                uint32_t cmd;
                struct binder_ptr_cookie pc;
            } __attribute__((packed)) done = {cmd == BR_INCREFS ? BC_INCREFS_DONE : BC_ACQUIRE_DONE, pc};
            send(&done, sizeof done);
            if (cmd == BR_INCREFS) increfs++;
            else acquires++;
        }
    }
    if (write(go[1], "x", 1) != 1) die("the word to call", 0, 0);
    // Both calls, in order, naming the node, whatever became of the
    // holder's references meanwhile: each call holds the node until its
    // buffer is given back, so the node's losses come after the second.
    for (uint32_t code = 7; code <= 8; code++) {
        e = next();
        if (e.cmd != BR_TRANSACTION) die("the one-way call", e.cmd, round);
        if (e.t.target.ptr != P1 || e.t.cookie != K1) die("the call's node (pointer, cookie)", (long)e.t.target.ptr, (long)e.t.cookie);
        if (e.t.code != code || !(e.t.flags & TF_ONE_WAY)) die("the call's code and flags", e.t.code, e.t.flags);
        if (releases || decrefs) die("the node's losses before its calls were done with", releases, decrefs);
        send_ptr(BC_FREE_BUFFER, e.t.data.ptr.buffer);
    }
    if (write(go[1], "x", 1) != 1) die("the word to exit", 0, 0);
    int st;
    if (waitpid(child, &st, 0) != child || !WIFEXITED(st) || WEXITSTATUS(st)) die("the holder's exit", st, round);
    other = 0;
    close(go[1]);
    // Everything the exit gives the owner, up to a quiet half second: the
    // losses counted, anything else a failure.
    if (in_at != in_end) die("returns left over before the exit", in_at, in_end);
    for (;;) {
        struct pollfd p = {fd, POLLIN, 0};
        if (poll(&p, 1, 500) == 0) break;
        struct binder_write_read bwr = {.read_size = sizeof inbox, .read_buffer = (uintptr_t)inbox};
        if (ioctl(fd, BINDER_WRITE_READ, &bwr)) die("read", 0, 0);
        for (size_t at = 0; at < bwr.read_consumed;) {
            uint32_t cmd;
            memcpy(&cmd, inbox + at, 4);
            struct binder_ptr_cookie pc;
            memcpy(&pc, inbox + at + 4, sizeof pc);
            at += 4 + _IOC_SIZE(cmd);
            // The owner's reply's completion comes first: it had not read since.
            if (cmd == BR_NOOP || cmd == BR_TRANSACTION_COMPLETE) continue;
            if (cmd != BR_RELEASE && cmd != BR_DECREFS) die("a return besides the reference losses", cmd, round);
            if (pc.ptr != P1 || pc.cookie != K1) die("a reference loss's node", (long)pc.ptr, (long)pc.cookie);
            if (cmd == BR_RELEASE) releases++;
            else decrefs++;
        }
    }
}

int main(void) {
    who = "owner";
    open_binder();
    if (ioctl(fd, BINDER_SET_CONTEXT_MGR, 0)) {
        if (errno == EPERM || errno == EBUSY) {
            printf("bindernode: cannot be the context manager (errno %d)\n", errno);
            return 77;
        }
        die("context manager", 0, 0);
    }
    for (int round = 1; round <= 2; round++) {
        releases = decrefs = 0;
        one_holder(round);
        if (releases != 1 || decrefs != 1) die("the losses a holder's exit gives the owner (BR_RELEASE, BR_DECREFS)", releases, decrefs);
    }
    printf("bindernode ok\n");
    return 0;
}
