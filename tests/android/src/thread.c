// The tagged address ABI is a thread's: a new thread and a forked child
// start with their creator's (Documentation/arch/arm64/tagged-address-abi.rst,
// "thread-scoped, inherited on clone() and fork()"), and each uses the
// heap's tagged pointers in its own system calls.
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PR_GET_TAGGED_ADDR_CTRL
#define PR_GET_TAGGED_ADDR_CTRL 56
#define PR_TAGGED_ADDR_ENABLE (1UL << 0)
#endif

static int fds[2];

// 0 when the calling thread has the ABI on and the kernel takes a heap
// pointer from it.
static int through_the_pipe(char c) {
    if (prctl(PR_GET_TAGGED_ADDR_CTRL, 0, 0, 0, 0) != (int)PR_TAGGED_ADDR_ENABLE) return 1;
    char *out = malloc(256), *in = malloc(256);
    if (!out || !in || (uintptr_t)out >> 56 != 0xb4) return 2;
    memset(out, c, 256);
    if (write(fds[1], out, 256) != 256) return 3;
    if (read(fds[0], in, 256) != 256) return 4;
    int bad = memcmp(in, out, 256) != 0;
    free(out);
    free(in);
    return bad ? 5 : 0;
}

static void *worker(void *arg) {
    (void)arg;
    return (void *)(intptr_t)through_the_pipe('t');
}

int main(void) {
    if (pipe(fds) != 0) return 1;
    int r = through_the_pipe('m');
    if (r) {
        printf("main %d\n", r);
        return 1;
    }
    pthread_t t;
    void *ret = (void *)-1;
    if (pthread_create(&t, NULL, worker, NULL) != 0 || pthread_join(t, &ret) != 0) {
        printf("pthread\n");
        return 1;
    }
    if (ret) {
        printf("thread %ld\n", (long)(intptr_t)ret);
        return 1;
    }
    pid_t pid = fork();
    if (pid < 0) {
        printf("fork\n");
        return 1;
    }
    if (pid == 0) _exit(through_the_pipe('c'));
    int status = 0;
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        printf("child %x\n", status);
        return 1;
    }
    printf("thread ok\n");
    return 0;
}
