// A context manager for a program that needs one: binderhost <program>
// [arguments]. Android's tests of the binder driver are written to run on
// a device, where servicemanager is the context manager of /dev/binder and
// answers a ping. This is that much of it: it becomes the context manager,
// answers every call with an empty reply, runs the program, and exits as
// the program does.
//
// Needs the device: /dev/binder. Without one it says so and exits 77.
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

#define FAIL(...) (fprintf(stderr, "binderhost: " __VA_ARGS__), fprintf(stderr, "\n"), exit(1))

static int fd;

static void command(const void *cmds, size_t size) {
    struct binder_write_read bwr = {.write_size = size, .write_buffer = (uintptr_t)cmds};
    if (ioctl(fd, BINDER_WRITE_READ, &bwr) || bwr.write_consumed != size) FAIL("write: errno %d", errno);
}

// Serve until killed.
static void serve(int ready) {
    uint32_t enter = BC_ENTER_LOOPER;
    command(&enter, sizeof enter);
    if (write(ready, "r", 1) != 1) FAIL("ready: errno %d", errno);
    close(ready);
    for (;;) {
        uint32_t buf[256];
        struct binder_write_read bwr = {.read_size = sizeof buf, .read_buffer = (uintptr_t)buf};
        if (ioctl(fd, BINDER_WRITE_READ, &bwr)) {
            if (errno == EINTR) continue;
            FAIL("read: errno %d", errno);
        }
        const char *p = (const char *)buf, *end = p + bwr.read_consumed;
        while (p < end) {
            uint32_t cmd;
            memcpy(&cmd, p, sizeof cmd);
            p += sizeof cmd;
            switch (cmd) {
            case BR_NOOP:
            case BR_TRANSACTION_COMPLETE:
            case BR_SPAWN_LOOPER:
                break;
            case BR_INCREFS:
            case BR_ACQUIRE: {
                struct {
                    uint32_t cmd;
                    struct binder_ptr_cookie node;
                } __attribute__((packed)) done = {cmd == BR_INCREFS ? BC_INCREFS_DONE : BC_ACQUIRE_DONE};
                memcpy(&done.node, p, sizeof done.node);
                command(&done, sizeof done);
                p += sizeof done.node;
                break;
            }
            case BR_RELEASE:
            case BR_DECREFS:
                p += sizeof(struct binder_ptr_cookie);
                break;
            case BR_TRANSACTION: {
                struct binder_transaction_data tr;
                memcpy(&tr, p, sizeof tr);
                p += sizeof tr;
                struct {
                    uint32_t free;
                    binder_uintptr_t buffer;
                    uint32_t reply;
                    struct binder_transaction_data tr;
                } __attribute__((packed)) answer = {.free = BC_FREE_BUFFER, .buffer = tr.data.ptr.buffer, .reply = BC_REPLY};
                // A one-way call has no reply.
                command(&answer, tr.flags & TF_ONE_WAY ? sizeof answer.free + sizeof answer.buffer : sizeof answer);
                break;
            }
            default:
                FAIL("return %#x", cmd);
            }
        }
    }
}

int main(int argc, char **argv) {
    if (argc < 2) FAIL("usage: binderhost <program> [arguments]");
    fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        printf("binderhost: no device (/dev/binder): errno %d\n", errno);
        return 77;
    }
    close(fd);
    int ready[2];
    if (pipe(ready)) FAIL("pipe: errno %d", errno);
    pid_t manager = fork();
    if (manager < 0) FAIL("fork: errno %d", errno);
    if (manager == 0) {
        close(ready[0]);
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        // The device is a process's own: opened by the one that uses it.
        fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
        if (fd < 0) FAIL("open: errno %d", errno);
        if (mmap(NULL, 1 << 20, PROT_READ, MAP_PRIVATE | MAP_NORESERVE, fd, 0) == MAP_FAILED) FAIL("mmap: errno %d", errno);
        uint32_t none = 0;
        if (ioctl(fd, BINDER_SET_MAX_THREADS, &none)) FAIL("max threads: errno %d", errno);
        if (ioctl(fd, BINDER_SET_CONTEXT_MGR, &none)) FAIL("context manager: errno %d", errno);
        serve(ready[1]);
    }
    close(ready[1]);
    char c;
    if (read(ready[0], &c, 1) != 1) FAIL("the manager did not start");
    close(ready[0]);
    pid_t program = fork();
    if (program < 0) FAIL("fork: errno %d", errno);
    if (program == 0) {
        execv(argv[1], argv + 1);
        FAIL("exec %s: errno %d", argv[1], errno);
    }
    int status;
    if (waitpid(program, &status, 0) != program) FAIL("wait: errno %d", errno);
    kill(manager, SIGKILL);
    waitpid(manager, NULL, 0);
    if (WIFSIGNALED(status)) FAIL("%s: signal %d", argv[1], WTERMSIG(status));
    return WEXITSTATUS(status);
}
