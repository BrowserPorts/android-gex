// A program a snapshot can be taken of and resumed from, one thread:
// what it prints, run whole, is what a run snapshotted partway prints
// followed by what the resumed run prints.
//
// It counts to N, a short sleep between steps, keeping its state where a
// snapshot must carry it: the count in a register and on the stack, a
// sum in the heap (brk), a buffer in an anonymous mapping, a signal
// disposition, a blocked signal, and a host file it reads line by line
// through one descriptor (its offset), from argv[1] (or /proc/self/cmdline
// when none). Each step prints the count and a check of all of it; the
// last prints "snapone ok".
#define _GNU_SOURCE
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#define N 40

static volatile sig_atomic_t got;
static void on_usr1(int s) { (void)s; got++; }

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    const char *path = argc > 1 ? argv[1] : "/proc/self/cmdline";
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        printf("open %s failed\n", path);
        return 1;
    }
    uint64_t *heap = sbrk(4096);
    unsigned char *anon = mmap(NULL, 1 << 16, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (heap == (void *)-1 || anon == MAP_FAILED) {
        printf("memory failed\n");
        return 1;
    }
    struct sigaction sa = {0};
    sa.sa_handler = on_usr1;
    sigaction(SIGUSR1, &sa, NULL);
    sigset_t block;
    sigemptyset(&block);
    sigaddset(&block, SIGUSR2);
    sigprocmask(SIG_BLOCK, &block, NULL);

    uint64_t sum = 0;
    long bytes = 0;
    for (int i = 1; i <= N; i++) {
        sum += (uint64_t)i * i;
        heap[i % 512] = sum;
        anon[(i * 997) % (1 << 16)] = (unsigned char)i;
        // A few bytes of the file each step, from where the last read left it.
        char buf[8];
        ssize_t n = read(fd, buf, sizeof buf);
        if (n > 0) bytes += n;
        struct timespec ts = {0, 50 * 1000 * 1000};
        nanosleep(&ts, NULL);
        // Everything it keeps, still as it left it.
        int ok = heap[i % 512] == sum && anon[(i * 997) % (1 << 16)] == (unsigned char)i;
        struct sigaction now;
        sigaction(SIGUSR1, NULL, &now);
        ok = ok && now.sa_handler == on_usr1;
        sigset_t cur;
        sigprocmask(SIG_BLOCK, NULL, &cur);
        ok = ok && sigismember(&cur, SIGUSR2);
        off_t at = lseek(fd, 0, SEEK_CUR);
        ok = ok && at == bytes;
        printf("step %d sum %llu read %ld %s\n", i, (unsigned long long)sum, bytes, ok ? "kept" : "LOST");
        if (!ok) return 1;
    }
    raise(SIGUSR1);
    printf("%s\n", got == 1 ? "snapone ok" : "snapone: the handler did not run");
    return 0;
}
