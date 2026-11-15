// A futex in memory two processes share: a word in a file each maps
// MAP_SHARED, changed by one and waited on by the other. Android's
// properties are this: init writes a property's serial number in the
// property area and wakes its waiters, which are other processes that
// mapped the same file read-only.
//
// - A wait (without FUTEX_PRIVATE_FLAG) for the value the word has sleeps
//   until the other process changes the word and wakes it; the waiter then
//   sees the new value in its own mapping.
// - A wait for a value the word has not is EAGAIN; a wait nobody wakes
//   ends at its time limit, ETIMEDOUT.
// - A wake says how many it woke: none when nobody waits, both of two
//   waiters when asked for all.
// - The waiter maps the file by its name, for reading alone: it shares
//   nothing with the waker but the file.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
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

static char path[64];

static void die(const char *what, long a, long b) {
    printf("sharedfutex: %s (%ld, %ld; errno %d)\n", what, a, b, errno);
    unlink(path);
    exit(1);
}

static long futex(volatile uint32_t *word, int op, uint32_t val, const struct timespec *limit) {
    return syscall(SYS_futex, word, op, val, limit, NULL, 0);
}

// Wait, with a limit of five seconds on the whole, until the word is no
// longer `was`: what a property's reader does.
static uint32_t until_changed(volatile uint32_t *word, uint32_t was) {
    struct timespec limit = {5, 0};
    while (*word == was) {
        if (futex(word, FUTEX_WAIT, was, &limit) && errno == ETIMEDOUT) die("the word never changed", *word, was);
    }
    return *word;
}

// A waiter: maps the file by name, read-only, says it is ready, and
// answers each change of the word until the word is 3.
static void waiter(int ready, int answers) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) die("the waiter's open", 0, 0);
    volatile uint32_t *word = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0);
    if (word == MAP_FAILED) die("the waiter's mmap", 0, 0);
    close(fd);
    if (*word != 0) die("the word as the waiter first sees it", *word, 0);
    // A value it has not: no wait.
    if (futex(word, FUTEX_WAIT, 7, NULL) != -1 || errno != EAGAIN) die("a wait for another value", errno, EAGAIN);
    // Nobody wakes this one.
    struct timespec brief = {0, 50 * 1000 * 1000};
    if (futex(word, FUTEX_WAIT, 0, &brief) != -1 || errno != ETIMEDOUT) die("a wait nobody wakes", errno, ETIMEDOUT);
    char c = 'r';
    if (write(ready, &c, 1) != 1) die("ready", 0, 0);
    uint32_t seen = 0;
    while (seen != 3) {
        seen = until_changed(word, seen);
        c = '0' + seen;
        if (write(answers, &c, 1) != 1) die("an answer", 0, 0);
    }
    _exit(0);
}

static char get(int fd) {
    char c;
    if (read(fd, &c, 1) != 1) die("a waiter went", 0, 0);
    return c;
}

int main(void) {
    snprintf(path, sizeof path, "/tmp/gex-sharedfutex-%d", getpid());
    int fd = open(path, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0644);
    if (fd < 0 || ftruncate(fd, 4096)) die("the file", fd, 0);
    volatile uint32_t *word = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (word == MAP_FAILED) die("mmap", 0, 0);
    close(fd);
    // Nobody waits yet.
    if (futex(word, FUTEX_WAKE, INT_MAX, NULL) != 0) die("a wake of nobody", errno, 0);

    int ready[2], answers[2];
    if (pipe(ready) || pipe(answers)) die("pipe", 0, 0);
    pid_t pids[2];
    for (int i = 0; i < 2; i++) {
        pids[i] = fork();
        if (pids[i] < 0) die("fork", 0, 0);
        if (pids[i] == 0) waiter(ready[1], answers[1]);
    }
    get(ready[0]);
    get(ready[0]);

    // Each change, then the wake: both waiters see it, whether they were
    // asleep already or on their way.
    struct timespec pause = {0, 100 * 1000 * 1000};
    for (uint32_t v = 1; v <= 3; v++) {
        // Asleep by now, most likely: the wake then says so.
        nanosleep(&pause, NULL);
        *word = v;
        long woken = futex(word, FUTEX_WAKE, INT_MAX, NULL);
        if (woken < 0 || woken > 2) die("the wake's count", woken, errno);
        for (int i = 0; i < 2; i++) {
            char c = get(answers[0]);
            if (c != '0' + (char)v) die("what a waiter saw", c, v);
        }
    }
    for (int i = 0; i < 2; i++) {
        int st;
        if (waitpid(pids[i], &st, 0) != pids[i] || !WIFEXITED(st) || WEXITSTATUS(st)) die("a waiter's end", st, i);
    }
    munmap((void *)word, 4096);
    unlink(path);
    printf("sharedfutex ok\n");
    return 0;
}
