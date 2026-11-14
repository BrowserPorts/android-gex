// The binder driver's protocol between two processes, by ioctl: one opens
// the device and becomes the context manager, the other calls it.
//
// - Both find protocol version 8; a second context manager is EBUSY.
// - A call to handle 0 arrives as BR_TRANSACTION with the caller's pid and
//   euid, its bytes in the manager's own mapping of the device, and its
//   reply comes back as BR_REPLY after BR_TRANSACTION_COMPLETE.
// - A binder object in a call arrives as a handle. The manager calls back
//   through it while the caller still waits for its reply: the call arrives
//   on the waiting thread, named by the pointer and cookie the caller gave.
// - A descriptor in a call arrives as a descriptor of the manager's, of the
//   same open file.
// - A one-way call completes for the caller at once and has no reply.
// - A call to a handle the caller has not got fails with BR_FAILED_REPLY.
// - The manager asks to hear of the caller's death, and does when it exits.
//
// Needs the device: /dev/binder, or binderfs mounted at /dev/binderfs.
// Without one the program says so and exits 77.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/android/binder.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAP_SIZE (128 * 1024)

static int fd;
static char *map;
static const char *who;

static pid_t other;

// Say what went wrong and end, and the other process with this one: it
// would wait for ever for a call or a reply that is not coming.
static void die(const char *what, long a, long b) {
    printf("binder: %s: %s (%ld, %ld; errno %d)\n", who, what, a, b, errno);
    fflush(stdout);
    if (other > 0) kill(other, SIGKILL);
    exit(1);
}

static void open_binder(void) {
    fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if (fd < 0) fd = open("/dev/binderfs/binder", O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        printf("binder: no device (/dev/binder, /dev/binderfs/binder): errno %d\n", errno);
        exit(77);
    }
    struct binder_version v = {0};
    if (ioctl(fd, BINDER_VERSION, &v) || v.protocol_version != BINDER_CURRENT_PROTOCOL_VERSION) die("version", v.protocol_version, 0);
    map = mmap(0, MAP_SIZE, PROT_READ, MAP_PRIVATE | MAP_NORESERVE, fd, 0);
    if (map == MAP_FAILED) die("mmap", 0, 0);
    uint32_t max = 0;
    if (ioctl(fd, BINDER_SET_MAX_THREADS, &max)) die("max threads", 0, 0);
}

// Write `n` bytes of commands, reading nothing.
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

static void send_ptr_cookie(uint32_t cmd, uint64_t ptr, uint64_t cookie) {
    struct {
        uint32_t cmd;
        struct binder_ptr_cookie pc;
    } __attribute__((packed)) b = {cmd, {ptr, cookie}};
    send(&b, sizeof b);
}

// A call (BC_TRANSACTION) or reply (BC_REPLY): `n` bytes at `data`, with
// the objects in it at `offsets`.
static void transact(uint32_t cmd, uint32_t handle, uint32_t code, uint32_t flags, const void *data, size_t n, const binder_size_t *offsets, size_t n_offsets) {
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
    b.t.offsets_size = n_offsets * sizeof *offsets;
    b.t.data.ptr.buffer = (uintptr_t)data;
    b.t.data.ptr.offsets = (uintptr_t)offsets;
    send(&b, sizeof b);
}

// What the driver returned and has not been looked at yet.
static char inbox[1024];
static size_t in_at, in_end;

struct event {
    uint32_t cmd;
    struct binder_transaction_data t;
    uint64_t cookie;
};

// The next return that is news: looper and reference bookkeeping is done
// on the way (a node's BR_INCREFS and BR_ACQUIRE are acknowledged).
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
        if (in_at + size > in_end) die("a return cut short", e.cmd, size);
        const char *arg = inbox + in_at;
        in_at += size;
        switch (e.cmd) {
        case BR_NOOP:
        case BR_SPAWN_LOOPER:
            continue;
        case BR_INCREFS:
        case BR_ACQUIRE: {
            struct binder_ptr_cookie pc;
            memcpy(&pc, arg, sizeof pc);
            send_ptr_cookie(e.cmd == BR_INCREFS ? BC_INCREFS_DONE : BC_ACQUIRE_DONE, pc.ptr, pc.cookie);
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
            memcpy(&e.cookie, arg, 8);
            return e;
        default:
            return e;
        }
    }
}

static struct event expect(uint32_t cmd, const char *what) {
    struct event e = next();
    if (e.cmd != cmd) die(what, e.cmd, cmd);
    return e;
}

// The bytes of a call or reply, which must lie in this process's mapping.
static const char *bytes_of(const struct event *e, size_t want, const char *what) {
    uintptr_t at = e->t.data.ptr.buffer;
    if (e->t.data_size != want) die(what, e->t.data_size, want);
    if (at < (uintptr_t)map || at + want > (uintptr_t)map + MAP_SIZE) die("bytes outside the mapping", (long)at, (long)(uintptr_t)map);
    return (const char *)at;
}

static void expect_bytes(const struct event *e, const char *want, const char *what) {
    if (memcmp(bytes_of(e, strlen(want) + 1, what), want, strlen(want) + 1)) die(what, 0, 0);
}

static void done_with(const struct event *e) { send_ptr(BC_FREE_BUFFER, e->t.data.ptr.buffer); }

static void reply(const struct event *to, const char *text) {
    done_with(to);
    transact(BC_REPLY, 0, 0, 0, text, strlen(text) + 1, 0, 0);
    expect(BR_TRANSACTION_COMPLETE, "a reply's completion");
}

// A call that waits for its reply, which must be `want`.
static void call(uint32_t handle, uint32_t code, const void *data, size_t n, const binder_size_t *offsets, size_t n_offsets, const char *want) {
    transact(BC_TRANSACTION, handle, code, TF_ACCEPT_FDS, data, n, offsets, n_offsets);
    expect(BR_TRANSACTION_COMPLETE, "a call's completion");
    struct event r = expect(BR_REPLY, "a reply");
    expect_bytes(&r, want, "a reply's bytes");
    done_with(&r);
}

static int client(int ready, pid_t manager) {
    who = "caller";
    other = manager;
    char c;
    if (read(ready, &c, 1) != 1) die("waiting for the manager", 0, 0);
    open_binder();
    // There is a context manager already.
    if (ioctl(fd, BINDER_SET_CONTEXT_MGR, 0) != -1 || errno != EBUSY) die("a second context manager", 0, 0);

    call(0, 1, "ping", 5, 0, 0, "pong");

    // A binder object of this process's: the manager calls back through
    // it before it replies.
    struct flat_binder_object obj = {.hdr.type = BINDER_TYPE_BINDER, .flags = 0x7f | FLAT_BINDER_FLAG_ACCEPTS_FDS, .binder = 0x1111, .cookie = 0x2222};
    binder_size_t at0 = 0;
    transact(BC_TRANSACTION, 0, 2, TF_ACCEPT_FDS, &obj, sizeof obj, &at0, 1);
    expect(BR_TRANSACTION_COMPLETE, "the object call's completion");
    struct event back = expect(BR_TRANSACTION, "the manager's call back");
    if (back.t.target.ptr != 0x1111 || back.t.cookie != 0x2222 || back.t.code != 20 || back.t.sender_pid != manager) die("the call back's target", (long)back.t.target.ptr, back.t.sender_pid);
    expect_bytes(&back, "call", "the call back's bytes");
    reply(&back, "back");
    struct event r = expect(BR_REPLY, "the object call's reply");
    expect_bytes(&r, "done", "the object call's reply bytes");
    done_with(&r);

    // A descriptor: the manager writes through its own copy.
    int p[2];
    if (pipe(p)) die("pipe", 0, 0);
    struct binder_fd_object fdo = {.hdr.type = BINDER_TYPE_FD, .fd = p[1]};
    call(0, 3, &fdo, sizeof fdo, &at0, 1, "ok");
    char got[4] = {0};
    if (read(p[0], got, 4) != 4 || memcmp(got, "fd!", 4)) die("the bytes written through the descriptor", 0, 0);

    // One way: complete at once, and no reply.
    transact(BC_TRANSACTION, 0, 4, TF_ONE_WAY, "one", 4, 0, 0);
    expect(BR_TRANSACTION_COMPLETE, "a one-way call's completion");

    // A handle this process has not got.
    transact(BC_TRANSACTION, 77, 9, 0, "none", 5, 0, 0);
    expect(BR_FAILED_REPLY, "a call to no handle");

    call(0, 5, "bye", 4, 0, 0, "bye");
    return 0;
}

int main(void) {
    // Is there a device at all? Found out before there are two processes.
    int probe = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if (probe < 0) probe = open("/dev/binderfs/binder", O_RDWR | O_CLOEXEC);
    if (probe < 0) {
        printf("binder: no device (/dev/binder, /dev/binderfs/binder): errno %d\n", errno);
        return 77;
    }
    close(probe);
    int ready[2];
    if (pipe(ready)) return 2;
    pid_t manager = getpid();
    pid_t child = fork();
    if (child == 0) {
        close(ready[1]);
        _exit(client(ready[0], manager));
    }

    who = "manager";
    other = child;
    open_binder();
    struct flat_binder_object mgr = {.flags = 0x7f | FLAT_BINDER_FLAG_ACCEPTS_FDS};
    if (ioctl(fd, BINDER_SET_CONTEXT_MGR_EXT, &mgr)) die("becoming the context manager", 0, 0);
    uint32_t enter = BC_ENTER_LOOPER;
    send(&enter, sizeof enter);
    if (write(ready[1], "r", 1) != 1) die("telling the caller", 0, 0);

    // 1: bytes, from the caller.
    struct event e = expect(BR_TRANSACTION, "the first call");
    if (e.t.code != 1 || e.t.target.ptr != 0 || e.t.sender_pid != child || e.t.sender_euid != geteuid() || e.t.offsets_size != 0)
        die("the first call's fields", e.t.code, e.t.sender_pid);
    expect_bytes(&e, "ping", "the first call's bytes");
    reply(&e, "pong");

    // 2: an object, which is a handle here.
    e = expect(BR_TRANSACTION, "the object call");
    if (e.t.code != 2 || e.t.offsets_size != sizeof(binder_size_t)) die("the object call's fields", e.t.code, e.t.offsets_size);
    struct flat_binder_object got;
    memcpy(&got, bytes_of(&e, sizeof got, "the object call's size"), sizeof got);
    if (got.hdr.type != BINDER_TYPE_HANDLE || got.handle == 0) die("the object as it arrived", got.hdr.type, got.handle);
    uint32_t h = got.handle;
    send_u32(BC_INCREFS, h);
    send_u32(BC_ACQUIRE, h);
    call(h, 20, "call", 5, 0, 0, "back");
    reply(&e, "done");

    // 3: a descriptor, which is one of this process's.
    e = expect(BR_TRANSACTION, "the descriptor call");
    struct binder_fd_object fdo;
    memcpy(&fdo, bytes_of(&e, sizeof fdo, "the descriptor call's size"), sizeof fdo);
    if (e.t.code != 3 || fdo.hdr.type != BINDER_TYPE_FD || (int)fdo.fd < 3) die("the descriptor as it arrived", fdo.hdr.type, fdo.fd);
    if (write(fdo.fd, "fd!", 4) != 4) die("writing through the descriptor", fdo.fd, 0);
    close(fdo.fd);
    reply(&e, "ok");

    // 4: one way. No sender to reply to.
    e = expect(BR_TRANSACTION, "the one-way call");
    if (e.t.code != 4 || !(e.t.flags & TF_ONE_WAY) || e.t.sender_pid != 0) die("the one-way call's fields", e.t.flags, e.t.sender_pid);
    expect_bytes(&e, "one", "the one-way call's bytes");
    done_with(&e);

    // 5: the last call; then the caller exits, and the handle's death is
    // told.
    struct {
        uint32_t cmd;
        struct binder_handle_cookie hc;
    } __attribute__((packed)) death = {BC_REQUEST_DEATH_NOTIFICATION, {h, 0xdead}};
    send(&death, sizeof death);
    e = expect(BR_TRANSACTION, "the last call");
    if (e.t.code != 5) die("the last call's code", e.t.code, 0);
    reply(&e, "bye");
    struct event dead = expect(BR_DEAD_BINDER, "the caller's death");
    if (dead.cookie != 0xdead) die("the death's cookie", (long)dead.cookie, 0);
    send_ptr(BC_DEAD_BINDER_DONE, dead.cookie);

    int st;
    if (waitpid(child, &st, 0) != child || !WIFEXITED(st) || WEXITSTATUS(st)) die("the caller's exit", st, 0);
    printf("binder ok\n");
    return 0;
}
