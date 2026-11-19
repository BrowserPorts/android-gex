// One file mapped shared at two addresses in one process is one memory: a
// write through one mapping is there to read through the other at once,
// with no system call between. ART's JIT keeps its cache so (a memfd mapped
// writable at one address, and read-only, longer, at another below 4 GiB),
// and the zygote checks what it wrote through one view by reading the
// other before it forks. Then: unmapping one leaves the other its bytes,
// memory mapped where one was is new and empty, and a child of a fork sees
// what the parent had.
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#define P 4096
static const char expected[] =
    "a write through the writable view, read through the other: 7\n"
    "a write at the far end, read through the other: 9\n"
    "the second writable view, read through the long one: 11\n"
    "a write through the long view, read through the first: 13\n"
    "every page of the writable view the same through the other: yes\n"
    "the long view after the first is unmapped: 7\n"
    "memory mapped where the first was: 0\n"
    "the long view after that: 7 13\n"
    "a child reads: 7 11\n";
static char out[1024];
static size_t used;
static void say(const char *s) {
    fputs(s, stdout);
    size_t n = strlen(s);
    if (used + n < sizeof out) {
        memcpy(out + used, s, n);
        used += n;
    }
}
int main(void) {
    char line[160];
    int fd = (int)syscall(SYS_memfd_create, "jit-cache", 0);
    const size_t data = 64 * P, code = 32 * P;
    if (fd < 0 || ftruncate(fd, data + code) != 0) {
        perror("memfd");
        return 1;
    }
    // As ART: the writable views first, then the long read-only one.
    volatile uint32_t *code_rw = mmap(0, code, PROT_READ | PROT_WRITE, MAP_SHARED, fd, data);
    volatile uint32_t *data_rw = mmap(0, data, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    // Below 4 GiB by a hint, as ART's own search asks.
    volatile uint32_t *all = mmap((void *)0x40000000, data + code, PROT_READ, MAP_SHARED, fd, 0);
    if (code_rw == MAP_FAILED || data_rw == MAP_FAILED || all == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    data_rw[5] = 7;
    snprintf(line, sizeof line, "a write through the writable view, read through the other: %u\n", all[5]);
    say(line);
    data_rw[data / 4 - 1] = 9;
    snprintf(line, sizeof line, "a write at the far end, read through the other: %u\n", all[data / 4 - 1]);
    say(line);
    code_rw[3] = 11;
    snprintf(line, sizeof line, "the second writable view, read through the long one: %u\n", all[data / 4 + 3]);
    say(line);
    // And the other way: a view mapped writable over the long one's range.
    volatile uint32_t *all_rw = mmap(0, data + code, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    all_rw[100] = 13;
    snprintf(line, sizeof line, "a write through the long view, read through the first: %u\n", data_rw[100]);
    say(line);
    munmap((void *)all_rw, data + code);
    int same = 1;
    for (size_t i = 0; i < data / 4; i += P / 4 + 1) {
        data_rw[i] ^= 0x5a5a;
        if (all[i] != data_rw[i])
            same = 0;
    }
    for (size_t i = 0; i < data / 4; i += P / 4 + 1)
        data_rw[i] ^= 0x5a5a;
    snprintf(line, sizeof line, "every page of the writable view the same through the other: %s\n", same ? "yes" : "no");
    say(line);
    void *was = (void *)data_rw;
    munmap(was, data);
    snprintf(line, sizeof line, "the long view after the first is unmapped: %u\n", all[5]);
    say(line);
    volatile uint32_t *anon = mmap(was, data, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    snprintf(line, sizeof line, "memory mapped where the first was: %u\n", anon[5]);
    say(line);
    anon[5] = 99;
    snprintf(line, sizeof line, "the long view after that: %u %u\n", all[5], all[100]);
    say(line);
    pid_t c = fork();
    if (c == 0) {
        snprintf(line, sizeof line, "a child reads: %u %u\n", all[5], all[data / 4 + 3]);
        fputs(line, stdout);
        fflush(stdout);
        _exit(strcmp(line, "a child reads: 7 11\n") == 0 ? 0 : 1);
    }
    int st = 0;
    waitpid(c, &st, 0);
    if (WIFEXITED(st) && WEXITSTATUS(st) == 0) {
        say("a child reads: 7 11\n");
    }
    if (strcmp(out, expected) != 0) {
        printf("dualview: not what Linux shows\n");
        return 1;
    }
    printf("dualview ok\n");
    return 0;
}
