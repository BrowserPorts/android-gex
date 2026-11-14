// PR_GET_AUXV: the auxiliary vector the program was started with, as the
// kernel saved it. Every pair up to AT_NULL is what getauxval answers, and
// what follows is zero. The call returns the size of all of it whatever
// length is asked for, and copies no more than that length. A forked child
// has its parent's, and a program it then runs has its own. /proc/self/auxv
// is the same vector, through its AT_NULL pair.
//
// The ids in it are the process's real and effective ones, and AT_SECURE is
// whether an effective one is not its real one. As root, a child makes all
// four differ and runs the program again to see them.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PR_GET_AUXV
#define PR_GET_AUXV 0x41555856
#endif

int main(int argc, char **argv) {
    int status = 0;
    unsigned long v[128];
    memset(v, 0xaa, sizeof v);
    long size = prctl(PR_GET_AUXV, v, sizeof v, 0, 0);
    if (size <= 0 || size % 16 || size > (long)sizeof v) {
        printf("auxv size %ld\n", size);
        return 1;
    }

    long words = size / 8, i = 0;
    int pairs = 0, seen = 0;
    for (; i + 1 < words && v[i] != AT_NULL; i += 2, pairs++) {
        if (getauxval(v[i]) != v[i + 1]) status |= 1;
        if (v[i] == AT_PAGESZ && v[i + 1] == 4096) seen |= 1;
        if (v[i] == AT_PHDR) seen |= 2;
        if (v[i] == AT_ENTRY) seen |= 4;
        if (v[i] == AT_RANDOM) seen |= 8;
    }
    if (pairs < 10 || seen != 15 || i + 1 >= words) status |= 2;
    for (; i < words; i++)
        if (v[i]) status |= 4;
    // Nothing past the size was written.
    if (v[words] != 0xaaaaaaaaaaaaaaaaUL) status |= 4;

    unsigned char part[40];
    memset(part, 0xaa, sizeof part);
    if (prctl(PR_GET_AUXV, part, 24, 0, 0) != size || memcmp(part, v, 24) || part[24] != 0xaa) status |= 8;
    if (prctl(PR_GET_AUXV, 0, 0, 0, 0) != size) status |= 8;

    errno = 0;
    if (prctl(PR_GET_AUXV, v, sizeof v, 1, 0) != -1 || errno != EINVAL) status |= 16;
    errno = 0;
    if (prctl(PR_GET_AUXV, v, sizeof v, 0, 1) != -1 || errno != EINVAL) status |= 16;

    // (Not as the program run with an effective id of its own: Linux gives
    // that one's /proc files to root, and it cannot open them.)
    if (argc < 2 || strcmp(argv[1], "ids")) {
        unsigned char file[1024];
        int fd = open("/proc/self/auxv", O_RDONLY);
        long got = read(fd, file, sizeof file);
        if (got != (pairs + 1) * 16 || memcmp(file, v, got)) status |= 64;
        close(fd);
    }

    int secure = getuid() != geteuid() || getgid() != getegid();
    if (getauxval(AT_UID) != getuid() || getauxval(AT_EUID) != geteuid()) status |= 128;
    if (getauxval(AT_GID) != getgid() || getauxval(AT_EGID) != getegid()) status |= 128;
    if (getauxval(AT_SECURE) != (unsigned long)secure) status |= 128;

    // Run again by a child below: the checks above were the new program's.
    if (argc > 1) {
        if (!strcmp(argv[1], "ids") && (getuid() != 2001 || geteuid() != 2002 || getgid() != 3003 || getegid() != 3004)) status |= 256;
        if (status) fprintf(stderr, "auxv %s %d\n", argv[1], status);
        return status ? 1 : 0;
    }

    if (geteuid() == 0) {
        pid_t ids = fork();
        if (ids == 0) {
            if (setresgid(3003, 3004, 3004) || setresuid(2001, 2002, 2002)) _exit(3);
            char *again[] = {argv[0], "ids", 0};
            execv(argv[0], again);
            _exit(2);
        }
        int st = -1;
        if (waitpid(ids, &st, 0) != ids || !WIFEXITED(st) || WEXITSTATUS(st)) status |= 256;
    }

    pid_t child = fork();
    if (child == 0) {
        unsigned long c[128];
        long n = prctl(PR_GET_AUXV, c, sizeof c, 0, 0);
        if (n != size || memcmp(c, v, size)) _exit(1);
        char *again[] = {argv[0], "again", 0};
        execv(argv[0], again);
        _exit(2);
    }
    int st = -1;
    if (waitpid(child, &st, 0) != child || !WIFEXITED(st) || WEXITSTATUS(st)) status |= 32;

    if (status) {
        printf("auxv %d\n", status);
        return 1;
    }
    printf("auxv ok\n");
    return 0;
}
