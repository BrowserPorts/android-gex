// More of the binder driver's protocol between two processes: who is told
// what, and in what order.
//
// - A descriptor opened O_NONBLOCK reads EAGAIN, and nothing, when there is
//   no work (after its thread's first read, which returns BR_NOOP alone);
//   poll says the same until there is.
// - The owner of a node is told of the references it gains (BR_INCREFS,
//   BR_ACQUIRE) before its call completes, and of their loss (BR_RELEASE,
//   BR_DECREFS) by a read it makes out of any call.
// - A handle on the receiver's own node arrives as the node: its pointer
//   and cookie.
// - A death notification taken back is answered with
//   BR_CLEAR_DEATH_NOTIFICATION_DONE.
// - A descriptor sent to a node that takes none fails the call, and the
//   extended error says EPERM; so does a call too large for the target's
//   buffer.
// - The context manager may ask how many references a handle's node has.
// - Two one-way calls to one node: the second is not readable until the
//   first's buffer is given back, and a call that waits, sent after both,
//   is read before it. With room for another thread, the read that takes
//   work asks for one (BR_SPAWN_LOOPER), once.
// - A process that exits in a call: its caller reads the call's completion
//   and BR_DEAD_REPLY, then the death it asked to hear of.
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
static char *map;
static const char *who;
static pid_t other;

static void die(const char *what, long a, long b) {
    printf("binderwork: %s: %s (%ld, %ld; errno %d)\n", who, what, a, b, errno);
    fflush(stdout);
    if (other > 0) kill(other, SIGKILL);
    exit(1);
}

static int open_device(int flags) {
    int f = open("/dev/binder", O_RDWR | O_CLOEXEC | flags);
    if (f < 0) f = open("/dev/binderfs/binder", O_RDWR | O_CLOEXEC | flags);
    if (f < 0) {
        printf("binderwork: no device (/dev/binder, /dev/binderfs/binder): errno %d\n", errno);
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

static void send_handle_cookie(uint32_t cmd, uint32_t handle, uint64_t cookie) {
    struct {
        uint32_t cmd;
        struct binder_handle_cookie hc;
    } __attribute__((packed)) b = {cmd, {handle, cookie}};
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
static int n_seen, looked;
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
        case BR_DECREFS:
            continue;
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

// One read, which must not have to wait, and nothing in it but
// bookkeeping.
static void read_once(void) {
    if (in_at != in_end) die("returns left over before a read", in_at, in_end);
    struct binder_write_read bwr = {.read_size = sizeof inbox, .read_buffer = (uintptr_t)inbox};
    if (ioctl(fd, BINDER_WRITE_READ, &bwr)) die("read", 0, 0);
    for (size_t at = 0; at < bwr.read_consumed;) {
        uint32_t cmd;
        memcpy(&cmd, inbox + at, 4);
        if (n_seen < 256) seen[n_seen++] = cmd;
        if (cmd == BR_TRANSACTION || cmd == BR_REPLY) die("a call or a reply in a read for bookkeeping", cmd, 0);
        at += 4 + _IOC_SIZE(cmd);
    }
}

// The returns since the last look are exactly these.
static void took(const char *what, int n, ...) {
    __builtin_va_list ap;
    __builtin_va_start(ap, n);
    int bad = n_seen - looked != n;
    for (int i = 0; i < n; i++) {
        uint32_t want = __builtin_va_arg(ap, uint32_t);
        if (!bad && seen[looked + i] != want) bad = 1;
    }
    __builtin_va_end(ap);
    if (bad) {
        printf("binderwork: %s: %s: the returns were", who, what);
        for (int i = looked; i < n_seen; i++) printf(" %#x", seen[i]);
        printf("\n");
        die(what, n_seen - looked, n);
    }
    looked = n_seen;
}

static struct event expect(uint32_t cmd, const char *what) {
    struct event e = next();
    if (e.cmd != cmd) die(what, e.cmd, cmd);
    return e;
}

static void done_with(const struct event *e) { send_ptr(BC_FREE_BUFFER, e->t.data.ptr.buffer); }

static void reply_bytes(const struct event *to, const void *data, size_t n, int objects) {
    done_with(to);
    transact(BC_REPLY, 0, 0, 0, data, n, objects);
}

// A call that waits: its reply.
static struct event call(uint32_t handle, uint32_t code, const void *data, size_t n, int objects) {
    transact(BC_TRANSACTION, handle, code, TF_ACCEPT_FDS, data, n, objects);
    return expect(BR_REPLY, "a reply");
}

static int readable(int f, int ms) {
    struct pollfd p = {.fd = f, .events = POLLIN};
    return poll(&p, 1, ms);
}

static int client(int ready) {
    who = "caller";
    other = getppid();
    char c;
    if (read(ready, &c, 1) != 1) die("waiting for the manager", 0, 0);
    open_binder();

    // 1: a node of this process's, strongly. It takes no descriptors. The
    // references it gains are told before the call completes; the reply
    // holds a handle on it, which is the node itself here.
    struct flat_binder_object obj = {.hdr.type = BINDER_TYPE_BINDER, .flags = 0x7f, .binder = P1, .cookie = K1};
    struct event r = call(0, 1, &obj, sizeof obj, 1);
    took("the returns of a call that gave a node", 5, BR_NOOP, BR_INCREFS, BR_ACQUIRE, BR_TRANSACTION_COMPLETE, BR_REPLY);
    struct flat_binder_object back;
    if (r.t.data_size != sizeof back || r.t.offsets_size != sizeof(binder_size_t)) die("the reply's size", r.t.data_size, r.t.offsets_size);
    memcpy(&back, (void *)(uintptr_t)r.t.data.ptr.buffer, sizeof back);
    if (back.hdr.type != BINDER_TYPE_BINDER || back.binder != P1 || back.cookie != K1) die("this process's node as it came back", back.hdr.type, (long)back.binder);
    done_with(&r);

    // 2: the manager lets its references go; out of the call, this
    // process is told.
    r = call(0, 2, "drop", 5, 0);
    done_with(&r);
    took("the returns of a plain call", 3, BR_NOOP, BR_TRANSACTION_COMPLETE, BR_REPLY);
    read_once();
    took("the returns of a read out of the call, once the node's references are gone", 3, BR_NOOP, BR_RELEASE, BR_DECREFS);
    // The node again, for what follows: told of its references anew.
    r = call(0, 3, &obj, sizeof obj, 1);
    done_with(&r);
    took("the returns of a call that gave the node again", 5, BR_NOOP, BR_INCREFS, BR_ACQUIRE, BR_TRANSACTION_COMPLETE, BR_REPLY);

    // 4: too large for the manager's buffer.
    static char big[200 * 1024];
    transact(BC_TRANSACTION, 0, 4, 0, big, sizeof big, 0);
    expect(BR_FAILED_REPLY, "a call too large for the target's buffer");
    took("the returns of a call that is too large", 2, BR_NOOP, BR_FAILED_REPLY);

    // 5: two one-way calls, written together.
    struct {
        uint32_t c1;
        struct binder_transaction_data t1;
        uint32_t c2;
        struct binder_transaction_data t2;
    } __attribute__((packed)) two;
    memset(&two, 0, sizeof two);
    two.c1 = two.c2 = BC_TRANSACTION;
    two.t1.code = 31;
    two.t2.code = 32;
    two.t1.flags = two.t2.flags = TF_ONE_WAY;
    send(&two, sizeof two);
    // Each is complete for its sender at once.
    read_once();
    took("the returns of two one-way calls", 3, BR_NOOP, BR_TRANSACTION_COMPLETE, BR_TRANSACTION_COMPLETE);
    // (and a call that waits, sent after both)
    r = call(0, 6, "sync", 5, 0);
    done_with(&r);
    took("the returns of the call sent after them", 3, BR_NOOP, BR_TRANSACTION_COMPLETE, BR_REPLY);

    // 7: the manager calls this process's node, and this process exits in
    // the call.
    struct event in = expect(BR_TRANSACTION, "the manager's call");
    if (in.t.code != 99 || in.t.target.ptr != P1 || in.t.cookie != K1) die("the manager's call's target", in.t.code, (long)in.t.target.ptr);
    _exit(0);
}

int main(void) {
    // Is there a device at all? Found out before there are two processes.
    close(open_device(0));
    int ready[2];
    if (pipe(ready)) return 2;
    pid_t child = fork();
    if (child == 0) {
        close(ready[1]);
        _exit(client(ready[0]));
    }

    who = "manager";
    other = child;
    open_binder();
    struct flat_binder_object mgr = {.flags = 0x7f | FLAT_BINDER_FLAG_ACCEPTS_FDS};
    if (ioctl(fd, BINDER_SET_CONTEXT_MGR_EXT, &mgr)) die("becoming the context manager", 0, 0);
    uint32_t enter = BC_ENTER_LOOPER;
    send(&enter, sizeof enter);

    // No work: a descriptor that does not wait says so and returns
    // nothing, and poll agrees.
    int nb = open_device(O_NONBLOCK);
    uint32_t out[8];
    // (a thread's first ioctl on a descriptor returns at once: BR_NOOP
    // alone)
    struct binder_write_read bwr = {.read_size = sizeof out, .read_buffer = (uintptr_t)out};
    if (ioctl(nb, BINDER_WRITE_READ, &bwr) || bwr.read_consumed != 4 || out[0] != BR_NOOP) die("a thread's first read", errno, bwr.read_consumed);
    bwr.read_consumed = 0;
    errno = 0;
    if (ioctl(nb, BINDER_WRITE_READ, &bwr) != -1 || errno != EAGAIN || bwr.read_consumed != 0) die("a read with no work on a descriptor that does not wait", errno, bwr.read_consumed);
    if (readable(nb, 20) != 0 || readable(fd, 20) != 0) die("poll with no work", 0, 0);
    close(nb);
    if (write(ready[1], "r", 1) != 1) die("telling the caller", 0, 0);

    // 1: the caller's node, as a handle. Poll saw the call come.
    if (readable(fd, 5000) != 1) die("poll with a call waiting", 0, 0);
    struct event e = expect(BR_TRANSACTION, "the call that gives a node");
    struct flat_binder_object got;
    memcpy(&got, (void *)(uintptr_t)e.t.data.ptr.buffer, sizeof got);
    if (e.t.code != 1 || got.hdr.type != BINDER_TYPE_HANDLE || got.handle != 1) die("the node as it arrived", got.hdr.type, got.handle);
    uint32_t h = got.handle;
    send_u32(BC_INCREFS, h);
    send_u32(BC_ACQUIRE, h);
    // How many references the node has, which the manager may ask: one
    // strong (this process's), and its owner has not been told yet.
    struct binder_node_info_for_ref info = {.handle = h};
    if (ioctl(fd, BINDER_GET_NODE_INFO_FOR_REF, &info) || info.strong_count != 1 || info.weak_count != 0) die("the node's counts", info.strong_count, info.weak_count);
    // A death notification, taken back: answered on this thread.
    send_handle_cookie(BC_REQUEST_DEATH_NOTIFICATION, h, 0xd1);
    send_handle_cookie(BC_CLEAR_DEATH_NOTIFICATION, h, 0xd1);
    struct event cleared = expect(BR_CLEAR_DEATH_NOTIFICATION_DONE, "a death notification taken back");
    if (cleared.cookie != 0xd1) die("the cleared notification's cookie", (long)cleared.cookie, 0);
    // A descriptor to the caller's node, which takes none.
    struct binder_fd_object fdo = {.hdr.type = BINDER_TYPE_FD, .fd = ready[1]};
    transact(BC_TRANSACTION, h, 50, 0, &fdo, sizeof fdo, 1);
    expect(BR_FAILED_REPLY, "a descriptor to a node that takes none");
    struct binder_extended_error ee = {0};
    if (ioctl(fd, BINDER_GET_EXTENDED_ERROR, &ee) || ee.command != BR_FAILED_REPLY || ee.param != -EPERM) die("the extended error", ee.command, ee.param);
    // The reply: the handle, which is the caller's own node there.
    struct flat_binder_object give = {.hdr.type = BINDER_TYPE_HANDLE, .handle = h};
    reply_bytes(&e, &give, sizeof give, 1);

    // 2: let the references go, all of them.
    e = expect(BR_TRANSACTION, "the call to drop the node");
    if (e.t.code != 2) die("the drop call's code", e.t.code, 0);
    send_u32(BC_RELEASE, h);
    send_u32(BC_DECREFS, h);
    reply_bytes(&e, "ok", 3, 0);

    // 3: the node again. It has the same handle: the lowest free.
    e = expect(BR_TRANSACTION, "the call that gives the node again");
    memcpy(&got, (void *)(uintptr_t)e.t.data.ptr.buffer, sizeof got);
    if (e.t.code != 3 || got.hdr.type != BINDER_TYPE_HANDLE || got.handle != h) die("the node as it arrived again", got.hdr.type, got.handle);
    send_u32(BC_INCREFS, h);
    send_u32(BC_ACQUIRE, h);
    reply_bytes(&e, "ok", 3, 0);

    // 5: the first one-way call; with room for one more thread, the read
    // that takes it asks for a looper. The second is not readable until
    // the first's buffer is given back, and does not ask again.
    // (the last reply's completion first, which is waiting)
    looked = n_seen;
    read_once();
    took("the returns of a read after a reply", 2, BR_NOOP, BR_TRANSACTION_COMPLETE);
    uint32_t max = 1;
    if (ioctl(fd, BINDER_SET_MAX_THREADS, &max)) die("max threads", 0, 0);
    e = expect(BR_TRANSACTION, "the first one-way call");
    if (e.t.code != 31 || !(e.t.flags & TF_ONE_WAY)) die("the first one-way call's fields", e.t.code, e.t.flags);
    took("the returns of the read that took work with room for a thread", 2, BR_SPAWN_LOOPER, BR_TRANSACTION);
    // The call that waits comes next, ahead of the second one-way call,
    // which is held until the first's buffer is given back.
    struct event sync = expect(BR_TRANSACTION, "the call behind the one-way calls");
    if (sync.t.code != 6) die("the call that came before the second one-way call", sync.t.code, 0);
    took("the returns of the next read", 2, BR_NOOP, BR_TRANSACTION);
    reply_bytes(&sync, "ok", 3, 0);
    read_once();
    took("the returns of a read after a reply", 2, BR_NOOP, BR_TRANSACTION_COMPLETE);
    if (readable(fd, 50) != 0) die("the second one-way call readable before the first is done with", 0, 0);
    done_with(&e);
    if (readable(fd, 5000) != 1) die("the second one-way call once the first is done with", 0, 0);
    e = expect(BR_TRANSACTION, "the second one-way call");
    if (e.t.code != 32) die("the second one-way call's code", e.t.code, 0);
    took("the returns of the read that took it", 2, BR_NOOP, BR_TRANSACTION);
    done_with(&e);

    // 7: a call to the caller's node, which exits in it; its death was
    // asked for first.
    send_handle_cookie(BC_REQUEST_DEATH_NOTIFICATION, h, 0xd2);
    looked = n_seen;
    transact(BC_TRANSACTION, h, 99, 0, "die", 4, 0);
    expect(BR_DEAD_REPLY, "the reply of a call whose target exited");
    took("the returns of a call whose target exited", 3, BR_NOOP, BR_TRANSACTION_COMPLETE, BR_DEAD_REPLY);
    struct event dead = expect(BR_DEAD_BINDER, "the caller's death");
    if (dead.cookie != 0xd2) die("the death's cookie", (long)dead.cookie, 0);
    took("the returns of the read that told the death", 2, BR_NOOP, BR_DEAD_BINDER);
    send_ptr(BC_DEAD_BINDER_DONE, dead.cookie);

    int st;
    if (waitpid(child, &st, 0) != child || !WIFEXITED(st) || WEXITSTATUS(st)) die("the caller's exit", st, 0);
    printf("binderwork ok\n");
    return 0;
}
