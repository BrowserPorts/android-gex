// snapfour's test with a child that runs another program: the parent
// forks, and the child execs the program named by argv[1] (another build
// of this one, at another path), which takes the child's part over the
// two pipes it is handed by number. A snapshot taken partway, resumed,
// must go on as the whole run does. Only the parent prints.
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
        uint64_t sq = v * v + 1;
        if (write(out, &sq, sizeof sq) != sizeof sq) return 3;
    }
    return sum == (uint64_t)N * (N + 1) / 2 ? 0 : 4;
}

int main(int argc, char **argv) {
    if (argc == 4 && strcmp(argv[1], "child") == 0) return child(atoi(argv[2]), atoi(argv[3]));
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 2) {
        printf("usage: snapfive PEER (another build of this program)\n");
        return 1;
    }
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
        char in[16], out[16];
        snprintf(in, sizeof in, "%d", down[0]);
        snprintf(out, sizeof out, "%d", up[1]);
        execl(argv[1], argv[1], "child", in, out, (char *)NULL);
        _exit(5);
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
        if (sq != i * i + 1) bad = 1;
        nap();
        printf("step %d %s\n", (int)i, sq == i * i + 1 ? "ok" : "wrong");
    }
    close(down[1]);
    int st;
    if (waitpid(pid, &st, 0) != pid) {
        printf("waitpid failed\n");
        return 1;
    }
    int ok = !bad && WIFEXITED(st) && WEXITSTATUS(st) == 0;
    printf("%s\n", ok ? "snapfive ok" : "snapfive: the child lost its place");
    return 0;
}
