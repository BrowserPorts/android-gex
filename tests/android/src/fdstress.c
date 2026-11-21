// Descriptors under the load system_server puts on them: threads that each
// keep an eventfd (a Looper's wake descriptor) and check it stays theirs,
// while they and others open, duplicate and close files (RandomAccessFile,
// dexopt's descriptors), and the main thread forks children that close
// every descriptor and exec, as Android's process spawning does. No thread's
// descriptor may change under it: system_server died of one that did
// ("Could not write wake signal to fd 94: Bad file descriptor").
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define THREADS 6
#define ROUNDS 400

static atomic_int bad;

static void fail(const char *what, int fd, long a) {
    printf("fdstress: %s (fd %d, %ld; errno %d)\n", what, fd, a, errno);
    atomic_store(&bad, 1);
}

// Each thread's own eventfd, identified by the inode it is (every eventfd
// is its own anonymous inode), checked after every step.
static void *worker(void *arg) {
    long id = (long)arg;
    int wake = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (wake < 0) {
        fail("eventfd", -1, id);
        return 0;
    }
    struct stat mine;
    fstat(wake, &mine);
    char path[64];
    snprintf(path, sizeof path, "/tmp/fdstress-%d-%ld", getpid(), id);
    for (int r = 0; r < ROUNDS && !atomic_load(&bad); r++) {
        // A wake: write and read back, as the Looper does.
        uint64_t one = 1, got;
        if (write(wake, &one, 8) != 8) fail("write to its eventfd", wake, r);
        if (read(wake, &got, 8) != 8 || got != 1) fail("read its eventfd", wake, r);
        // Files opened, duplicated and closed around it.
        int f = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        if (f < 0) {
            fail("open", -1, r);
            break;
        }
        int g = fcntl(f, F_DUPFD_CLOEXEC, 0);
        if (write(g, "x", 1) != 1) fail("write to a duplicate", g, r);
        close(f);
        close(g);
        struct stat now;
        if (fstat(wake, &now) || now.st_ino != mine.st_ino || now.st_dev != mine.st_dev) fail("its eventfd changed under it", wake, r);
    }
    unlink(path);
    close(wake);
    return 0;
}

int main(void) {
    pthread_t t[THREADS];
    for (long i = 0; i < THREADS; i++) pthread_create(&t[i], 0, worker, (void *)i);
    // Children forked from among the threads: each closes every descriptor
    // above 2, then execs (or exits, when there is nothing to exec).
    int spawned = 0;
    while (spawned < 60 && !atomic_load(&bad)) {
        pid_t p = fork();
        if (p == 0) {
            syscall(SYS_close_range, 3, ~0u, 0);
            execl("/system/bin/true", "true", (char *)0);
            execl("/bin/true", "true", (char *)0);
            _exit(0);
        }
        if (p < 0) {
            fail("fork", -1, spawned);
            break;
        }
        int status;
        waitpid(p, &status, 0);
        spawned++;
    }
    for (int i = 0; i < THREADS; i++) pthread_join(t[i], 0);
    if (atomic_load(&bad)) return 1;
    printf("fdstress ok\n");
    return 0;
}
