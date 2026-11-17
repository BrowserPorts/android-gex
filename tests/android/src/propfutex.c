// Android's property updates, as a pair of processes: init stores a new
// property's value in one shared file (the property's context area), then
// bumps a serial number in another (properties_serial) and wakes the
// waiters on it; a waiter, woken, reads the value from its own mapping of
// the first file. A wake on the second file's word must make the first
// file's stores visible too: a shared mapping is the same memory in every
// process. Prints what the reader read and checks it against Linux 7.0's.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static char area[64], serial[64];

static void *map(const char *path, int prot) {
    int fd = open(path, prot & PROT_WRITE ? O_RDWR : O_RDONLY);
    if (fd < 0)
        return NULL;
    void *p = mmap(NULL, 4096, prot, MAP_SHARED, fd, 0);
    close(fd);
    return p == MAP_FAILED ? NULL : p;
}

static long futex(volatile uint32_t *word, int op, uint32_t val, const struct timespec *limit) {
    return syscall(SYS_futex, word, op, val, limit, NULL, 0);
}

int main(void) {
    snprintf(area, sizeof area, "/tmp/gex-propfutex-area-%d", getpid());
    snprintf(serial, sizeof serial, "/tmp/gex-propfutex-serial-%d", getpid());
    for (const char *p = area; p; p = p == area ? serial : NULL) {
        int fd = open(p, O_RDWR | O_CREAT | O_TRUNC, 0600);
        if (fd < 0 || ftruncate(fd, 4096) != 0)
            return 2;
        close(fd);
    }
    int ready[2];
    if (pipe(ready) != 0)
        return 2;
    pid_t reader = fork();
    if (reader == 0) {
        // The reader: both files read-only, as a process maps the area.
        volatile uint32_t *value = map(area, PROT_READ), *s = map(serial, PROT_READ);
        if (!value || !s)
            _exit(3);
        char c = 1;
        write(ready[1], &c, 1);
        struct timespec limit = {5, 0};
        uint32_t seen = 0;
        // As __system_property_wait: wait on the serial while it is 0.
        while (*s == 0) {
            long r = futex(s, FUTEX_WAIT, 0, &limit);
            if (r != 0 && errno == ETIMEDOUT)
                break;
        }
        seen = *value;
        printf("serial %u, value %u\n", *s, seen);
        fflush(stdout);
        _exit(seen == 42 ? 0 : 1);
    }
    // The writer: both files read and write, as init maps them.
    volatile uint32_t *value = map(area, PROT_READ | PROT_WRITE), *s = map(serial, PROT_READ | PROT_WRITE);
    if (!value || !s)
        return 4;
    char c;
    read(ready[0], &c, 1);
    // Let the reader get to its wait.
    struct timespec pause = {0, 300 * 1000 * 1000};
    nanosleep(&pause, NULL);
    *value = 42;
    *s = 1;
    futex(s, FUTEX_WAKE, 1, NULL);
    // Then nothing more of this process's own until the reader is done
    // (the wait is the only call it makes).
    int status = 0;
    waitpid(reader, &status, 0);
    unlink(area);
    unlink(serial);
    int ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
    printf(ok ? "propfutex ok\n" : "propfutex: the reader did not see the value\n");
    return ok ? 0 : 1;
}
