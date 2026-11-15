// A binder node that asks for its callers' security contexts
// (FLAT_BINDER_FLAG_TXN_SECURITY_CTX), as servicemanager's does.
//
// - Where the kernel's security module names the caller's credentials
//   (SELinux): a call to the node arrives as BR_TRANSACTION_SEC_CTX, with
//   the caller's context, a string, in the target's mapping after the
//   call's own bytes. It is what /proc/self/attr/current says of the
//   caller.
// - Where there is no module: the call fails, BR_FAILED_REPLY with
//   EOPNOTSUPP in the extended error, and never arrives. Under a module
//   that names processes but not their credentials (AppArmor) it fails
//   with that module's error, EINVAL.
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
#include <sys/prctl.h>
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

static void die(const char *what, long a, long b) {
    printf("binderctx: %s: %s (%ld, %ld; errno %d)\n", who, what, a, b, errno);
    fflush(stdout);
    exit(1);
}

static int open_device(void) {
    int f = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if (f < 0) f = open("/dev/binderfs/binder", O_RDWR | O_CLOEXEC);
    if (f < 0) {
        printf("binderctx: no device (/dev/binder, /dev/binderfs/binder): errno %d\n", errno);
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

struct call {
    uint32_t cmd;
    struct binder_transaction_data t;
} __attribute__((packed));

// The manager: one call, with its caller's context; the caller sent what
// it takes its own context to be.
static int manager(int ready) {
    who = "manager";
    prctl(PR_SET_PDEATHSIG, SIGKILL);
    open_binder();
    struct flat_binder_object me = {.flags = 0x7f | FLAT_BINDER_FLAG_ACCEPTS_FDS | FLAT_BINDER_FLAG_TXN_SECURITY_CTX};
    if (ioctl(fd, BINDER_SET_CONTEXT_MGR_EXT, &me)) die("context manager", 0, 0);
    uint32_t enter = BC_ENTER_LOOPER;
    struct binder_write_read bwr = {.write_size = sizeof enter, .write_buffer = (uintptr_t)&enter};
    if (ioctl(fd, BINDER_WRITE_READ, &bwr)) die("enter looper", 0, 0);
    if (write(ready, "s", 1) != 1) die("ready", 0, 0);

    struct {
        uint32_t noop, cmd;
        struct binder_transaction_data_secctx t;
    } __attribute__((packed)) in;
    struct binder_write_read rd = {.read_size = sizeof in, .read_buffer = (uintptr_t)&in};
    if (ioctl(fd, BINDER_WRITE_READ, &rd)) die("read", 0, 0);
    if (rd.read_consumed != sizeof in || in.noop != BR_NOOP || in.cmd != BR_TRANSACTION_SEC_CTX) die("not a call with a security context", rd.read_consumed, in.cmd);
    struct binder_transaction_data copy;
    memcpy(&copy, &in.t, sizeof copy);
    const struct binder_transaction_data *t = &copy;
    const char *sent = (const char *)(uintptr_t)t->data.ptr.buffer;
    const char *ctx = (const char *)(uintptr_t)in.t.secctx;
    // After the call's bytes and offsets, on a multiple of eight, inside
    // the mapping, and a string.
    uint64_t after = t->data.ptr.offsets + t->offsets_size;
    if (in.t.secctx < after || in.t.secctx % 8 || in.t.secctx < (uintptr_t)map || in.t.secctx + strlen(sent) + 1 > (uintptr_t)map + MAP_SIZE) die("where the context is", in.t.secctx - after, 0);
    if (strcmp(ctx, sent)) {
        printf("binderctx: manager: the context is '%s', the caller's is '%s'\n", ctx, sent);
        return 1;
    }
    struct {
        uint32_t free;
        binder_uintptr_t buffer;
        struct call reply;
    } __attribute__((packed)) out = {.free = BC_FREE_BUFFER, .buffer = t->data.ptr.buffer, .reply.cmd = BC_REPLY};
    struct binder_write_read wr = {.write_size = sizeof out, .write_buffer = (uintptr_t)&out};
    if (ioctl(fd, BINDER_WRITE_READ, &wr)) die("reply", 0, 0);
    pause();
    return 0;
}

int main(void) {
    close(open_device());
    int ready[2];
    if (pipe(ready)) return 2;
    pid_t mgr = fork();
    if (mgr == 0) {
        close(ready[0]);
        _exit(manager(ready[1]));
    }
    close(ready[1]);
    who = "client";
    char c;
    if (read(ready[0], &c, 1) != 1) die("the manager did not start", 0, 0);
    open_binder();

    // What the security module calls this process, if there is one.
    char mine[256] = "";
    int attr = open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC);
    ssize_t n = attr < 0 ? -1 : read(attr, mine, sizeof mine - 1);
    int named = n > 0;
    if (named) {
        mine[n] = 0;
        mine[strcspn(mine, "\n")] = 0;
    }

    struct call call;
    memset(&call, 0, sizeof call);
    call.cmd = BC_TRANSACTION;
    call.t.code = 1;
    call.t.data_size = strlen(mine) + 1;
    call.t.data.ptr.buffer = (uintptr_t)mine;
    uint32_t back[32];
    struct binder_write_read bwr = {.write_size = sizeof call, .write_buffer = (uintptr_t)&call, .read_size = sizeof back, .read_buffer = (uintptr_t)back};
    if (ioctl(fd, BINDER_WRITE_READ, &bwr)) die("call", 0, 0);
    if (back[0] != BR_NOOP) die("the call's returns", back[0], 0);
    if (back[1] == BR_TRANSACTION_COMPLETE) {
        // It arrived, and the manager found the context to be ours.
        if (back[2] != BR_REPLY || !named) die("a call that arrived", back[2], named);
        printf("binderctx: the call arrived with the caller's context, %s\n", mine);
    } else {
        if (back[1] != BR_FAILED_REPLY || bwr.read_consumed != 8) die("a call that did not arrive", back[1], bwr.read_consumed);
        struct extended_error ee;
        if (ioctl(fd, GET_EXTENDED_ERROR, &ee)) die("extended error", 0, 0);
        if (ee.command != BR_FAILED_REPLY || (ee.param != -EOPNOTSUPP && !(named && ee.param == -EINVAL))) die("the refusal's extended error", ee.command, ee.param);
        printf("binderctx: the call was refused, error %d: no module names the caller's credentials\n", -ee.param);
    }
    kill(mgr, SIGKILL);
    waitpid(mgr, NULL, 0);
    printf("binderctx ok\n");
    return 0;
}
