// The binder driver's scatter-gather calls (BC_TRANSACTION_SG), which
// hwbinder makes: buffers of the sender's that travel with a call, and
// arrays of descriptors in them.
//
// - A buffer object's bytes arrive in the target's mapping and its pointer
//   is the target's. One that names a parent buffer has the pointer to it
//   in the parent made the target's too.
// - A descriptor array's descriptors arrive as the target's, where they
//   lay in their parent buffer. They are closed when the target gives the
//   call's buffer back, and the read that follows returns at once.
// - Refused, with EINVAL in the extended error: a buffer longer than the
//   extra space the call asked for; a parent that is not an earlier
//   object; fix-ups in a parent out of order; extra space not a multiple
//   of eight; a parent that is the object at offset 0. A descriptor that
//   is not open is EBADF.
//
// Needs the device: /dev/binder, or binderfs mounted at /dev/binderfs.
// Without one the program says so and exits 77.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/android/binder.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

struct extended_error {
    uint32_t id, command;
    int32_t param;
};
#define GET_EXTENDED_ERROR _IOWR('b', 17, struct extended_error)

#define MAP_SIZE (64 * 1024)

static int fd;
static char *map;
static const char *who;
static pid_t other;

static void die(const char *what, long a, long b) {
    printf("bindersg: %s: %s (%ld, %ld; errno %d)\n", who, what, a, b, errno);
    fflush(stdout);
    if (other > 0) kill(other, SIGKILL);
    exit(1);
}

static int open_device(void) {
    int f = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if (f < 0) f = open("/dev/binderfs/binder", O_RDWR | O_CLOEXEC);
    if (f < 0) {
        printf("bindersg: no device (/dev/binder, /dev/binderfs/binder): errno %d\n", errno);
        exit(77);
    }
    return f;
}

static void open_binder(void) {
    fd = open_device();
    map = mmap(0, MAP_SIZE, PROT_READ, MAP_PRIVATE | MAP_NORESERVE, fd, 0);
    if (map == MAP_FAILED) die("mmap", 0, 0);
    uint32_t max = 0;
    if (ioctl(fd, BINDER_SET_MAX_THREADS, &max)) die("max threads", 0, 0);
}

struct result {
    uint32_t end;
    struct binder_transaction_data t;
    // What the read returned after the one that ended it.
    size_t rest;
};

// Write `cmds` and read returns until a call, a reply or an error.
static struct result exchange(const void *cmds, size_t n) {
    struct result res = {0};
    char inbox[512];
    struct binder_write_read bwr = {.write_size = n, .write_buffer = (uintptr_t)cmds};
    for (;;) {
        bwr.read_size = sizeof inbox;
        bwr.read_consumed = 0;
        bwr.read_buffer = (uintptr_t)inbox;
        if (ioctl(fd, BINDER_WRITE_READ, &bwr)) {
            // A signal ended the read; what was written stays written.
            if (errno != EINTR) die("write and read", bwr.write_consumed, n);
            if (bwr.write_consumed == bwr.write_size) bwr.write_size = bwr.write_consumed = 0;
            continue;
        }
        if (bwr.write_consumed != bwr.write_size) die("written", bwr.write_consumed, n);
        bwr.write_size = bwr.write_consumed = 0;
        for (size_t at = 0; at < bwr.read_consumed;) {
            uint32_t cmd;
            memcpy(&cmd, inbox + at, 4);
            at += 4;
            const char *arg = inbox + at;
            at += _IOC_SIZE(cmd);
            switch (cmd) {
            case BR_NOOP:
            case BR_TRANSACTION_COMPLETE:
                break;
            case BR_TRANSACTION:
            case BR_REPLY:
                memcpy(&res.t, arg, sizeof res.t);
                // fallthrough
            case BR_FAILED_REPLY:
            case BR_DEAD_REPLY:
                res.end = cmd;
                res.rest = bwr.read_consumed - at;
                return res;
            default:
                die("an unexpected return", cmd, 0);
            }
        }
    }
}

static void free_buffer(binder_uintptr_t buffer) {
    struct {
        uint32_t cmd;
        binder_uintptr_t buffer;
    } __attribute__((packed)) f = {BC_FREE_BUFFER, buffer};
    struct binder_write_read bwr = {.write_size = sizeof f, .write_buffer = (uintptr_t)&f};
    if (ioctl(fd, BINDER_WRITE_READ, &bwr)) die("free", 0, 0);
}

// What the parent buffer of the good call holds: text, and a pointer to
// the child buffer.
struct parent {
    char text[16];
    char *child;
};

static int in_map(uint64_t p, uint64_t n) {
    return p >= (uintptr_t)map && p + n <= (uintptr_t)map + MAP_SIZE;
}

// -- the manager -----------------------------------------------------------------

static int manager(int ready) {
    who = "manager";
    open_binder();
    struct flat_binder_object me = {.flags = 0x7f | FLAT_BINDER_FLAG_ACCEPTS_FDS};
    if (ioctl(fd, BINDER_SET_CONTEXT_MGR_EXT, &me)) die("context manager", 0, 0);
    uint32_t enter = BC_ENTER_LOOPER;
    struct binder_write_read bwr = {.write_size = sizeof enter, .write_buffer = (uintptr_t)&enter};
    if (ioctl(fd, BINDER_WRITE_READ, &bwr)) die("enter looper", 0, 0);
    if (write(ready, "s", 1) != 1) die("ready", 0, 0);

    for (;;) {
        struct result r = exchange("", 0);
        if (r.end != BR_TRANSACTION) die("not a call", r.end, 0);
        const char *data = (const char *)(uintptr_t)r.t.data.ptr.buffer;
        const binder_size_t *offsets = (const binder_size_t *)(uintptr_t)r.t.data.ptr.offsets;
        if (r.t.code == 9) return 0;
        if (r.t.code != 1) die("a call that should not have arrived", r.t.code, 0);
        if (r.t.data_size != 160 || r.t.offsets_size != 32) die("the call's sizes", r.t.data_size, r.t.offsets_size);
        struct binder_buffer_object a, b, c;
        struct binder_fd_array_object fda;
        memcpy(&a, data + offsets[0], sizeof a);
        memcpy(&b, data + offsets[1], sizeof b);
        memcpy(&c, data + offsets[2], sizeof c);
        memcpy(&fda, data + offsets[3], sizeof fda);
        if (a.hdr.type != BINDER_TYPE_PTR || b.hdr.type != BINDER_TYPE_PTR || c.hdr.type != BINDER_TYPE_PTR || fda.hdr.type != BINDER_TYPE_FDA) die("the objects' types", a.hdr.type, fda.hdr.type);
        // The buffers lie in this mapping, after the offsets, in order,
        // each on a multiple of eight.
        uint64_t extra = r.t.data.ptr.offsets + r.t.offsets_size;
        if (a.buffer != extra || b.buffer != extra + 24 || c.buffer != extra + 32) die("where the buffers are", a.buffer - extra, c.buffer - extra);
        if (!in_map(a.buffer, 24) || a.length != sizeof(struct parent) || b.length != 6 || c.length != 8) die("the buffers' lengths", a.length, b.length);
        const struct parent *p = (const struct parent *)(uintptr_t)a.buffer;
        if (strcmp(p->text, "parent buffer")) die("the parent's bytes", p->text[0], 0);
        if ((uintptr_t)p->child != b.buffer || strcmp(p->child, "child")) die("the pointer in the parent", (long)(uintptr_t)p->child, (long)b.buffer);
        if (fda.num_fds != 2 || fda.parent != 2 || fda.parent_offset != 0) die("the descriptor array", fda.num_fds, fda.parent);
        int fds[2];
        memcpy(fds, (const void *)(uintptr_t)c.buffer, sizeof fds);
        if (write(fds[0], "a", 1) != 1 || write(fds[1], "b", 1) != 1) die("the descriptors", fds[0], fds[1]);
        if (!(fcntl(fds[0], F_GETFD) & FD_CLOEXEC)) die("a descriptor that is not close-on-exec", fds[0], 0);

        // The buffer given back: the array's descriptors are closed, and
        // the read made with it returns with nothing to say.
        struct {
            uint32_t cmd;
            binder_uintptr_t buffer;
        } __attribute__((packed)) f = {BC_FREE_BUFFER, r.t.data.ptr.buffer};
        uint32_t back[8];
        struct binder_write_read gone = {.write_size = sizeof f, .write_buffer = (uintptr_t)&f, .read_size = sizeof back, .read_buffer = (uintptr_t)back};
        if (ioctl(fd, BINDER_WRITE_READ, &gone)) die("free", 0, 0);
        if (gone.read_consumed != 4 || back[0] != BR_NOOP) die("the read after the free", gone.read_consumed, back[0]);
        if (fcntl(fds[0], F_GETFD) != -1 || errno != EBADF || fcntl(fds[1], F_GETFD) != -1) die("the descriptors after the free", fds[0], fds[1]);

        struct {
            uint32_t cmd;
            struct binder_transaction_data t;
        } __attribute__((packed)) reply = {.cmd = BC_REPLY};
        struct binder_write_read sent = {.write_size = sizeof reply, .write_buffer = (uintptr_t)&reply};
        if (ioctl(fd, BINDER_WRITE_READ, &sent)) die("reply", 0, 0);
    }
}

// -- the client ------------------------------------------------------------------

struct sg_call {
    uint32_t cmd;
    struct binder_transaction_data_sg sg;
} __attribute__((packed));

static uint32_t call(uint32_t code, uint32_t flags, const void *data, size_t size, const binder_size_t *offsets, size_t n, size_t extra) {
    struct sg_call c;
    memset(&c, 0, sizeof c);
    c.cmd = BC_TRANSACTION_SG;
    c.sg.transaction_data.code = code;
    c.sg.transaction_data.flags = flags;
    c.sg.transaction_data.data_size = size;
    c.sg.transaction_data.offsets_size = n * sizeof *offsets;
    c.sg.transaction_data.data.ptr.buffer = (uintptr_t)data;
    c.sg.transaction_data.data.ptr.offsets = (uintptr_t)offsets;
    c.sg.buffers_size = extra;
    struct result r = exchange(&c, sizeof c);
    if (r.end == BR_REPLY) free_buffer(r.t.data.ptr.buffer);
    return r.end;
}

static void expect_refused(const char *what, uint32_t end, int err) {
    if (end != BR_FAILED_REPLY) die(what, end, 0);
    struct extended_error ee;
    if (ioctl(fd, GET_EXTENDED_ERROR, &ee)) die("extended error", 0, 0);
    if (ee.command != BR_FAILED_REPLY || ee.param != -err) die(what, ee.command, ee.param);
}

static struct binder_buffer_object ptr(const void *buffer, size_t length, int has_parent, size_t parent, size_t parent_offset) {
    struct binder_buffer_object o = {
        .hdr.type = BINDER_TYPE_PTR,
        .flags = has_parent ? BINDER_BUFFER_FLAG_HAS_PARENT : 0,
        .buffer = (uintptr_t)buffer,
        .length = length,
        .parent = parent,
        .parent_offset = parent_offset,
    };
    return o;
}

static int client(int ready) {
    who = "client";
    char c;
    if (read(ready, &c, 1) != 1) die("the manager did not start", 0, 0);
    open_binder();

    int one[2], two[2];
    if (pipe2(one, O_NONBLOCK) || pipe2(two, O_NONBLOCK)) die("pipe", 0, 0);
    static char child[6] = "child";
    static struct parent parent = {"parent buffer", child};
    static int fds[2];
    fds[0] = one[1];
    fds[1] = two[1];

    // A token, then: the parent buffer, its child, a buffer of two
    // descriptors, and the array that says they are descriptors.
    struct {
        uint64_t token;
        struct binder_buffer_object a, b, c;
        struct binder_fd_array_object fda;
    } __attribute__((packed)) data = {
        .token = 0x1122334455667788,
        .a = ptr(&parent, sizeof parent, 0, 0, 0),
        .b = ptr(child, sizeof child, 1, 0, offsetof(struct parent, child)),
        .c = ptr(fds, sizeof fds, 0, 0, 0),
        .fda = {.hdr.type = BINDER_TYPE_FDA, .num_fds = 2, .parent = 2, .parent_offset = 0},
    };
    binder_size_t offsets[4] = {offsetof(typeof(data), a), offsetof(typeof(data), b), offsetof(typeof(data), c), offsetof(typeof(data), fda)};
    size_t extra = 24 + 8 + 8;

    // Refused, each for its own reason; none reaches the manager.
    expect_refused("a buffer longer than the extra space", call(2, 0, &data, sizeof data, offsets, 4, extra - 8), EINVAL);
    expect_refused("extra space that is not a multiple of eight", call(2, 0, &data, sizeof data, offsets, 4, extra + 4), EINVAL);
    typeof(data) bad = data;
    bad.b.parent = 1;
    expect_refused("a parent that is not an earlier object", call(2, 0, &bad, sizeof bad, offsets, 4, extra), EINVAL);
    bad = data;
    bad.c = ptr(child, sizeof child, 1, 0, 0);
    bad.fda.num_fds = 0;
    expect_refused("fix-ups in a parent out of order", call(2, 0, &bad, sizeof bad, offsets, 4, extra), EINVAL);
    bad = data;
    static int closed[2] = {9999, 9998};
    bad.c.buffer = (uintptr_t)closed;
    expect_refused("a descriptor that is not open", call(2, 0, &bad, sizeof bad, offsets, 4, extra), EBADF);
    // With no token before it the parent is the object at offset 0, and
    // nothing may be fixed up in that one.
    binder_size_t at_zero[2] = {0, sizeof data.a};
    expect_refused("a parent at offset 0", call(2, 0, &data.a, sizeof data.a + sizeof data.b, at_zero, 2, 32), EINVAL);

    // The good one.
    uint32_t end = call(1, TF_ACCEPT_FDS, &data, sizeof data, offsets, 4, extra);
    if (end != BR_REPLY) die("the call", end, 0);
    if (read(one[0], &c, 1) != 1 || c != 'a') die("the first descriptor's pipe", c, 0);
    if (read(two[0], &c, 1) != 1 || c != 'b') die("the second descriptor's pipe", c, 0);
    // The manager's copies are closed: with ours closed too, the pipes
    // have no writer.
    close(one[1]);
    close(two[1]);
    if (read(one[0], &c, 1) != 0 || read(two[0], &c, 1) != 0) die("a pipe that still has a writer", errno, 0);

    // Tell the manager to go.
    struct sg_call bye;
    memset(&bye, 0, sizeof bye);
    bye.cmd = BC_TRANSACTION_SG;
    bye.sg.transaction_data.code = 9;
    bye.sg.transaction_data.flags = TF_ONE_WAY;
    struct binder_write_read bwr = {.write_size = sizeof bye, .write_buffer = (uintptr_t)&bye};
    if (ioctl(fd, BINDER_WRITE_READ, &bwr)) die("the last call", 0, 0);
    return 0;
}

static volatile sig_atomic_t client_done, client_status;

// The client is gone. If it failed, nothing more will come for the manager
// to read, so the test ends here and not in a read that never returns.
static void client_ended(int sig) {
    (void)sig;
    int status;
    if (waitpid(other, &status, WNOHANG) != other) return;
    client_status = !WIFEXITED(status) || WEXITSTATUS(status) ? (status ? status : 1) : 0;
    client_done = 1;
    if (client_status) {
        static const char said[] = "bindersg: the client failed\n";
        if (write(1, said, sizeof said - 1) < 0) _exit(1);
        _exit(1);
    }
}

int main(void) {
    close(open_device());
    int ready[2];
    if (pipe(ready)) return 2;
    // Blocked until `other` is known.
    sigset_t chld, was;
    sigemptyset(&chld);
    sigaddset(&chld, SIGCHLD);
    sigprocmask(SIG_BLOCK, &chld, &was);
    struct sigaction sa = {.sa_handler = client_ended, .sa_flags = SA_RESTART};
    sigaction(SIGCHLD, &sa, NULL);
    pid_t child = fork();
    if (child == 0) {
        signal(SIGCHLD, SIG_DFL);
        sigprocmask(SIG_SETMASK, &was, NULL);
        close(ready[1]);
        _exit(client(ready[0]));
    }
    close(ready[0]);
    other = child;
    sigprocmask(SIG_SETMASK, &was, NULL);
    manager(ready[1]);
    // The client's end: seen by the handler if it came first.
    sigprocmask(SIG_BLOCK, &chld, NULL);
    while (!client_done) sigsuspend(&was);
    if (client_status) {
        printf("bindersg: the client failed (status %#x)\n", client_status);
        return 1;
    }
    printf("bindersg ok\n");
    return 0;
}
