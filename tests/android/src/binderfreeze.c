// Freezing a process on the binder driver, as Android freezes a cached
// app: two processes, the context manager and a client that freezes it.
//
// - A frozen process takes no call that waits: its caller reads
//   BR_FROZEN_REPLY. A one-way call is kept for it, and its sender reads
//   BR_TRANSACTION_PENDING_FROZEN in place of the completion; of two that
//   say they update one another (TF_UPDATE_TXN), only the later is there
//   when it thaws.
// - BINDER_GET_FROZEN_INFO says what arrived while it was frozen, and
//   whether it has calls in hand.
// - A process with a call in hand is not frozen at once (EAGAIN). With a
//   time limit it is frozen when it replies within it, and not (EAGAIN,
//   after the limit) when it does not.
// - A pid with no open of the device: EINVAL.
// - A sender that fills the one-way space of its target is told so once
//   (BR_ONEWAY_SPAM_SUSPECT) if it asked to be, and then refused.
//
// Needs the device: /dev/binder, or binderfs mounted at /dev/binderfs.
// Without one the program says so and exits 77.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/android/binder.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

// As include/uapi/linux/android/binder.h has them; an NDK's copy may be
// older than some.
struct freeze_info {
    uint32_t pid, enable, timeout_ms;
};
struct frozen_status {
    uint32_t pid, sync_recv, async_recv;
};
struct extended_error {
    uint32_t id, command;
    int32_t param;
};
#define FREEZE _IOW('b', 14, struct freeze_info)
#define GET_FROZEN_INFO _IOWR('b', 15, struct frozen_status)
#define ENABLE_ONEWAY_SPAM_DETECTION _IOW('b', 16, uint32_t)
#define GET_EXTENDED_ERROR _IOWR('b', 17, struct extended_error)
#define FROZEN_REPLY _IO('r', 18)
#define ONEWAY_SPAM_SUSPECT _IO('r', 19)
#define TRANSACTION_PENDING_FROZEN _IO('r', 20)
#define UPDATE_TXN 0x40

#define MAP_SIZE (64 * 1024)

static int fd;
static const char *who;
static pid_t other;

static void die(const char *what, long a, long b) {
    printf("binderfreeze: %s: %s (%ld, %ld; errno %d)\n", who, what, a, b, errno);
    fflush(stdout);
    if (other > 0) kill(other, SIGKILL);
    exit(1);
}

static int open_device(void) {
    int f = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if (f < 0) f = open("/dev/binderfs/binder", O_RDWR | O_CLOEXEC);
    if (f < 0) {
        printf("binderfreeze: no device (/dev/binder, /dev/binderfs/binder): errno %d\n", errno);
        exit(77);
    }
    return f;
}

static void open_binder(void) {
    fd = open_device();
    if (mmap(0, MAP_SIZE, PROT_READ, MAP_PRIVATE | MAP_NORESERVE, fd, 0) == MAP_FAILED) die("mmap", 0, 0);
    uint32_t max = 0;
    if (ioctl(fd, BINDER_SET_MAX_THREADS, &max)) die("max threads", 0, 0);
}

static void put(int pipe_fd, const void *b, size_t n) {
    if (write(pipe_fd, b, n) != (ssize_t)n) die("pipe write", 0, 0);
}

static void get(int pipe_fd, void *b, size_t n) {
    for (size_t at = 0; at < n;) {
        ssize_t r = read(pipe_fd, (char *)b + at, n - at);
        if (r <= 0) die("pipe read", r, 0);
        at += r;
    }
}

struct result {
    // The return that ended it, and the first byte of a reply's data.
    uint32_t end;
    struct binder_transaction_data t;
};

// Write `cmds` and read returns until one ends the exchange: a call, a
// reply or an error; for a one-way call (`oneway`), its completion.
static struct result exchange(const void *cmds, size_t n, int oneway) {
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
                break;
            case BR_TRANSACTION_COMPLETE:
            case ONEWAY_SPAM_SUSPECT:
            case TRANSACTION_PENDING_FROZEN:
                if (!oneway) break;
                res.end = cmd;
                return res;
            case BR_TRANSACTION:
            case BR_REPLY:
                memcpy(&res.t, arg, sizeof res.t);
                // fallthrough
            case BR_FAILED_REPLY:
            case BR_DEAD_REPLY:
            case FROZEN_REPLY:
                res.end = cmd;
                return res;
            default:
                die("an unexpected return", cmd, 0);
            }
        }
    }
}

struct call {
    uint32_t cmd;
    struct binder_transaction_data t;
} __attribute__((packed));

static struct call a_call(uint32_t cmd, uint32_t code, uint32_t flags, const void *data, size_t n) {
    struct call c;
    memset(&c, 0, sizeof c);
    c.cmd = cmd;
    c.t.code = code;
    c.t.flags = flags;
    c.t.data_size = n;
    c.t.data.ptr.buffer = (uintptr_t)data;
    return c;
}

static void free_buffer(binder_uintptr_t buffer) {
    struct {
        uint32_t cmd;
        binder_uintptr_t buffer;
    } __attribute__((packed)) f = {BC_FREE_BUFFER, buffer};
    struct binder_write_read bwr = {.write_size = sizeof f, .write_buffer = (uintptr_t)&f};
    if (ioctl(fd, BINDER_WRITE_READ, &bwr)) die("free", 0, 0);
}

// A call to the manager, and the return that ends it.
static uint32_t call(uint32_t code, uint32_t flags, const void *data, size_t n) {
    struct call c = a_call(BC_TRANSACTION, code, flags, data, n);
    struct result r = exchange(&c, sizeof c, flags & TF_ONE_WAY);
    if (r.end == BR_REPLY) free_buffer(r.t.data.ptr.buffer);
    return r.end;
}

// -- the manager: does what the client asks of it down a pipe ---------------

static int manager(int from, int to) {
    who = "manager";
    open_binder();
    uint32_t zero = 0;
    if (ioctl(fd, BINDER_SET_CONTEXT_MGR, &zero)) die("context manager", 0, 0);
    uint32_t enter = BC_ENTER_LOOPER;
    struct binder_write_read bwr = {.write_size = sizeof enter, .write_buffer = (uintptr_t)&enter};
    if (ioctl(fd, BINDER_WRITE_READ, &bwr)) die("enter looper", 0, 0);
    put(to, "s", 1);
    int held = 0;
    for (;;) {
        char op;
        get(from, &op, 1);
        struct call reply = a_call(BC_REPLY, 0, 0, "", 0);
        switch (op) {
        case 'a': // read one call and answer it
        case 'r': { // read one call and keep it
            struct result r = exchange("", 0, 0);
            if (r.end != BR_TRANSACTION) die("not a call", r.end, 0);
            char ack[2] = {(char)r.t.code, r.t.data_size ? *(const char *)(uintptr_t)r.t.data.ptr.buffer : 0};
            int oneway = r.t.flags & TF_ONE_WAY;
            free_buffer(r.t.data.ptr.buffer);
            if (!oneway && op == 'a') {
                if (exchange(&reply, sizeof reply, 1).end != BR_TRANSACTION_COMPLETE) die("reply", 0, 0);
            } else if (!oneway) {
                held = 1;
            }
            put(to, ack, 2);
            break;
        }
        case 'd': // answer the kept call, after a while
            usleep(300 * 1000);
            // fallthrough
        case 'R': // answer the kept call
            if (!held) die("no call kept", 0, 0);
            held = 0;
            if (exchange(&reply, sizeof reply, 1).end != BR_TRANSACTION_COMPLETE) die("reply", 0, 0);
            put(to, "k", 1);
            break;
        case 'n': { // is there anything to read?
            struct pollfd p = {.fd = fd, .events = POLLIN};
            int n = poll(&p, 1, 0);
            if (n < 0) die("poll", 0, 0);
            put(to, n ? "1" : "0", 1);
            break;
        }
        case 'q':
            return 0;
        default:
            die("an unknown request", op, 0);
        }
    }
}

// -- the client ------------------------------------------------------------------

static int to_m, from_m;
static pid_t mgr;

static void ask(char op) {
    put(to_m, &op, 1);
}

static void expect_ack(int code, char first) {
    char ack[2];
    get(from_m, ack, 2);
    if (ack[0] != code || ack[1] != first) die("the manager read another call", ack[0], ack[1]);
}

static int freeze(pid_t pid, int enable, unsigned timeout_ms) {
    struct freeze_info info = {pid, enable, timeout_ms};
    return ioctl(fd, FREEZE, &info) ? -errno : 0;
}

static void expect_info(const char *when, unsigned sync, unsigned async) {
    struct frozen_status s = {.pid = mgr};
    if (ioctl(fd, GET_FROZEN_INFO, &s)) die(when, -1, -1);
    if (s.sync_recv != sync || s.async_recv != async) die(when, s.sync_recv, s.async_recv);
}

static long now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

// A second thread's call, which the manager keeps while the first freezes.
static void *calls(void *code) {
    uint32_t end = call((uint32_t)(uintptr_t)code, 0, "h", 1);
    return (void *)(uintptr_t)end;
}

static int client(int to, int from) {
    who = "client";
    to_m = to;
    from_m = from;
    char c;
    get(from_m, &c, 1);
    open_binder();

    // Not frozen: a call and its reply.
    ask('a');
    if (call(1, 0, "x", 1) != BR_REPLY) die("a call before any freeze", 0, 0);
    expect_ack(1, 'x');

    // Frozen.
    if (freeze(mgr, 1, 0)) die("freeze", 0, 0);
    expect_info("frozen, nothing sent", 0, 0);
    uint32_t end = call(9, 0, "x", 1);
    if (end != FROZEN_REPLY) die("a call to a frozen process", end, 0);
    struct extended_error ee;
    if (ioctl(fd, GET_EXTENDED_ERROR, &ee)) die("extended error", 0, 0);
    if (ee.command != FROZEN_REPLY || ee.param != 0) die("the frozen reply's extended error", ee.command, ee.param);
    end = call(2, TF_ONE_WAY, "p", 1);
    if (end != TRANSACTION_PENDING_FROZEN) die("a one-way call to a frozen process", end, 0);
    expect_info("frozen, both kinds sent", 3, 1);
    // Two that update one another, behind the first: the later replaces
    // the earlier.
    if (call(3, TF_ONE_WAY | UPDATE_TXN, "a", 1) != TRANSACTION_PENDING_FROZEN) die("the first update", 0, 0);
    if (call(3, TF_ONE_WAY | UPDATE_TXN, "b", 1) != TRANSACTION_PENDING_FROZEN) die("the second update", 0, 0);

    // Thawed: what was kept is read, in order.
    if (freeze(mgr, 0, 0)) die("thaw", 0, 0);
    expect_info("thawed, calls kept", 2, 0);
    ask('a');
    expect_ack(2, 'p');
    ask('a');
    expect_ack(3, 'b');
    ask('n');
    get(from_m, &c, 1);
    if (c != '0') die("more than the two kept calls", c, 0);
    expect_info("thawed, calls read", 0, 0);

    // A call in the manager's hands: not frozen at once.
    pthread_t t;
    void *ended;
    ask('r');
    if (pthread_create(&t, NULL, calls, (void *)(uintptr_t)4)) die("thread", 0, 0);
    expect_ack(4, 'h');
    int r = freeze(mgr, 1, 0);
    if (r != -EAGAIN) die("freeze with a call in hand", r, 0);
    // Frozen within a time limit, when the reply comes within it.
    ask('d');
    long t0 = now_ms();
    r = freeze(mgr, 1, 5000);
    long took = now_ms() - t0;
    if (r || took < 200 || took > 4000) die("freeze when the call is answered", r, took);
    pthread_join(t, &ended);
    if ((uintptr_t)ended != BR_REPLY) die("the answered call", (uintptr_t)ended, 0);
    get(from_m, &c, 1);
    if (call(9, 0, "x", 1) != FROZEN_REPLY) die("a call after the timed freeze", 0, 0);
    if (freeze(mgr, 0, 0)) die("thaw", 0, 0);

    // Not frozen when the limit passes first.
    ask('r');
    if (pthread_create(&t, NULL, calls, (void *)(uintptr_t)5)) die("thread", 0, 0);
    expect_ack(5, 'h');
    t0 = now_ms();
    r = freeze(mgr, 1, 150);
    took = now_ms() - t0;
    if (r != -EAGAIN || took < 140 || took > 3000) die("freeze when the call is not answered", r, took);
    ask('R');
    pthread_join(t, &ended);
    if ((uintptr_t)ended != BR_REPLY) die("the call answered late", (uintptr_t)ended, 0);
    get(from_m, &c, 1);
    ask('a');
    if (call(6, 0, "x", 1) != BR_REPLY) die("a call after the failed freeze", 0, 0);
    expect_ack(6, 'x');

    // Nobody has that pid.
    r = freeze(0x7ffffff0, 1, 0);
    if (r != -EINVAL) die("freeze of no process", r, 0);

    // One-way calls of a page each into a buffer of sixteen, half of it
    // theirs: the seventh leaves less than a tenth of the buffer for more
    // and its sender holds more than a quarter, the ninth does not fit.
    uint32_t on = 1;
    if (ioctl(fd, ENABLE_ONEWAY_SPAM_DETECTION, &on)) die("spam detection", 0, 0);
    static char page[4096];
    memset(page, 's', sizeof page);
    for (int i = 1; i <= 9; i++) {
        end = call(7, TF_ONE_WAY, page, sizeof page);
        uint32_t want = i == 7 ? ONEWAY_SPAM_SUSPECT : i == 9 ? BR_FAILED_REPLY : BR_TRANSACTION_COMPLETE;
        if (end != want) die("a one-way call of a page", i, end);
    }
    if (ioctl(fd, GET_EXTENDED_ERROR, &ee)) die("extended error", 0, 0);
    if (ee.command != BR_FAILED_REPLY || ee.param != -ENOSPC) die("the full buffer's extended error", ee.command, ee.param);
    for (int i = 1; i <= 8; i++) {
        ask('a');
        expect_ack(7, 's');
    }
    ask('n');
    get(from_m, &c, 1);
    if (c != '0') die("more than the eight calls that fitted", c, 0);

    ask('q');
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
        static const char said[] = "binderfreeze: the client failed\n";
        if (write(1, said, sizeof said - 1) < 0) _exit(1);
        _exit(1);
    }
}

int main(void) {
    close(open_device());
    int down[2], up[2];
    if (pipe(down) || pipe(up)) return 2;
    mgr = getpid();
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
        close(down[0]);
        close(up[1]);
        _exit(client(down[1], up[0]));
    }
    close(down[1]);
    close(up[0]);
    other = child;
    sigprocmask(SIG_SETMASK, &was, NULL);
    manager(down[0], up[1]);
    // The client's end: seen by the handler if it came first.
    sigprocmask(SIG_BLOCK, &chld, NULL);
    while (!client_done) sigsuspend(&was);
    if (client_status) {
        printf("binderfreeze: the client failed (status %#x)\n", client_status);
        return 1;
    }
    printf("binderfreeze ok\n");
    return 0;
}
