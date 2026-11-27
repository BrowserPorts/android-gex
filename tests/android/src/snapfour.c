// snapone's test across two processes: a snapshot taken partway, resumed,
// must go on as the whole run does. The parent forks a child and talks to
// it over two pipes: each step it sends a number down one, the child adds
// it to a sum it keeps in its own memory and sends back the square, and
// the parent checks it. At the end the parent closes its end, the child
// sees end of file and exits with a check of its sum, and the parent
// waits for it. Both sleep a little each step, so a snapshot finds them
// in a read, a write or a sleep. Only the parent prints, so what it
// prints does not depend on timing.
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define N 30

static void nap(void) {
    struct timespec ts = {0, 40 * 1000 * 1000};
    nanosleep(&ts, NULL);
}

static int child(int in, int out) {
    uint64_t sum = 0, v;
    for (;;) {
        ssize_t n = read(in, &v, sizeof v);
        if (n == 0) break;
        if (n != sizeof v) return 2;
        sum += v;
        nap();
        uint64_t sq = v * v;
        if (write(out, &sq, sizeof sq) != sizeof sq) return 3;
    }
    // 1 + 2 + ... + N
    return sum == (uint64_t)N * (N + 1) / 2 ? 0 : 4;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    int down[2], up[2];
    if (pipe(down) || pipe(up)) {
        printf("pipe failed\n");
        return 1;
    }
    pid_t pid = fork();
    if (pid < 0) {
        printf("fork failed\n");
        return 1;
    }
    if (pid == 0) {
        close(down[1]);
        close(up[0]);
        _exit(child(down[0], up[1]));
    }
    close(down[0]);
    close(up[1]);
    int bad = 0;
    for (uint64_t i = 1; i <= N; i++) {
        if (write(down[1], &i, sizeof i) != sizeof i) {
            printf("step %d: write failed\n", (int)i);
            return 1;
        }
        uint64_t sq;
        if (read(up[0], &sq, sizeof sq) != sizeof sq) {
            printf("step %d: read failed\n", (int)i);
            return 1;
        }
        if (sq != i * i) bad = 1;
        nap();
        printf("step %d %s\n", (int)i, sq == i * i ? "ok" : "wrong");
    }
    close(down[1]);
    int st;
    if (waitpid(pid, &st, 0) != pid) {
        printf("waitpid failed\n");
        return 1;
    }
    int ok = !bad && WIFEXITED(st) && WEXITSTATUS(st) == 0;
    printf("%s\n", ok ? "snapfour ok" : "snapfour: the child lost its place");
    return 0;
}
