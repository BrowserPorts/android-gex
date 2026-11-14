// prctl: an option no kernel has is EINVAL, not success; what a thread or a
// process sets is read back, checked as the kernel checks it, and inherited
// as the kernel has it (a new thread's timer slack resets to its creator's;
// no-new-privileges crosses fork). Mappings take a name that
// /proc/self/maps shows, and under PR_SET_MDWE no mapping is writable and
// executable or gains execute.
//
// Only what Linux 6.8 and 6.18 answer alike, whoever runs it.
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define SET_VMA 0x53564d41
#define CAP_AMBIENT 47
#define SET_MDWE 65
#define GET_MDWE 66
// An address no process has: the kernel's half.
#define NOWHERE (-4096UL)

#define CHECK(c)                                          \
    do {                                                  \
        if (!(c)) {                                       \
            printf("%s:%d: %s\n", __FILE__, __LINE__, #c); \
            return 1;                                     \
        }                                                 \
    } while (0)

static long pr(long o, unsigned long a, unsigned long b, unsigned long c, unsigned long d) {
    errno = 0;
    return syscall(SYS_prctl, o, a, b, c, d);
}

// A call that must fail with `e`.
static int fails(int e, long o, unsigned long a, unsigned long b, unsigned long c, unsigned long d) {
    return pr(o, a, b, c, d) == -1 && errno == e;
}

static void *in_thread(void *out) {
    long *v = out;
    v[0] = pr(PR_GET_TIMERSLACK, 0, 0, 0, 0);
    v[1] = pr(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
    pr(PR_SET_TIMERSLACK, 99, 0, 0, 0);
    pr(PR_SET_TIMERSLACK, 0, 0, 0, 0);
    v[2] = pr(PR_GET_TIMERSLACK, 0, 0, 0, 0);
    return 0;
}

// Whether /proc/self/maps has a line for exactly [lo, hi) ending in `name`.
static int mapped_as(unsigned long lo, unsigned long hi, const char *name) {
    char want[64], line[512];
    snprintf(want, sizeof want, "%08lx-%08lx ", lo, hi);
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    int found = 0;
    while (fgets(line, sizeof line, f)) {
        size_t n = strlen(line), k = strlen(name);
        if (n && line[n - 1] == '\n') line[--n] = 0;
        if (!strncmp(line, want, strlen(want)) && n >= k && !strcmp(line + n - k, name)) found = 1;
    }
    fclose(f);
    return found;
}

static int mdwe(void) {
    const int rw = PROT_READ | PROT_WRITE, rx = PROT_READ | PROT_EXEC, anon = MAP_PRIVATE | MAP_ANONYMOUS;
    char *data = mmap(0, 8192, rw, anon, -1, 0);
    CHECK(data != MAP_FAILED);
    CHECK(pr(GET_MDWE, 0, 0, 0, 0) == 0);
    CHECK(fails(EINVAL, SET_MDWE, 2, 0, 0, 0));
    CHECK(fails(EINVAL, SET_MDWE, 4, 0, 0, 0));
    CHECK(fails(EINVAL, SET_MDWE, 1, 1, 0, 0));
    CHECK(pr(SET_MDWE, 1, 0, 0, 0) == 0);
    CHECK(pr(GET_MDWE, 0, 0, 0, 0) == 1);
    CHECK(fails(EPERM, SET_MDWE, 0, 0, 0, 0));
    CHECK(fails(EPERM, SET_MDWE, 3, 0, 0, 0));
    CHECK(pr(SET_MDWE, 1, 0, 0, 0) == 0);
    CHECK(mmap(0, 4096, rw | PROT_EXEC, anon, -1, 0) == MAP_FAILED && errno == EACCES);
    CHECK(mprotect(data, 4096, rx) == -1 && errno == EACCES);
    CHECK(mprotect(data, 4096, PROT_READ) == 0);
    // Mapped executable is allowed, and stays so.
    char *code = mmap(0, 4096, rx, anon, -1, 0);
    CHECK(code != MAP_FAILED);
    CHECK(mprotect(code, 4096, rx) == 0);
    CHECK(mprotect(code, 4096, rw | PROT_EXEC) == -1 && errno == EACCES);
    return 0;
}

int main(int argc, char **argv) {
    (void)argc;
    int word = -1;

    // No such option, and other architectures' options.
    CHECK(fails(EINVAL, 0, 0, 0, 0, 0));
    CHECK(fails(EINVAL, 48, 0, 0, 0, 0));
    CHECK(fails(EINVAL, 1000, 0, 0, 0, 0));
    CHECK(fails(EINVAL, PR_GET_FPEMU, (unsigned long)&word, 0, 0, 0));
    CHECK(fails(EINVAL, PR_GET_ENDIAN, (unsigned long)&word, 0, 0, 0));
    // Whether a read of the counter faults: an option arm64 has had since
    // Linux 6.12, and did not have before.
    if (pr(PR_GET_TSC, (unsigned long)&word, 0, 0, 0) == 0) {
        CHECK(word == PR_TSC_ENABLE);
        CHECK(pr(PR_SET_TSC, PR_TSC_ENABLE, 0, 0, 0) == 0);
        CHECK(fails(EINVAL, PR_SET_TSC, 3, 0, 0, 0));
    } else {
        CHECK(errno == EINVAL);
    }
    CHECK(fails(EINVAL, PR_GET_UNALIGN, (unsigned long)&word, 0, 0, 0));

    CHECK(pr(PR_GET_PDEATHSIG, (unsigned long)&word, 0, 0, 0) == 0 && word == 0);
    CHECK(fails(EFAULT, PR_GET_PDEATHSIG, NOWHERE, 0, 0, 0));
    CHECK(fails(EINVAL, PR_SET_PDEATHSIG, 65, 0, 0, 0));
    CHECK(pr(PR_SET_PDEATHSIG, 0, 0, 0, 0) == 0);
    word = -1;
    CHECK(pr(PR_GET_CHILD_SUBREAPER, (unsigned long)&word, 0, 0, 0) == 0 && word == 0);

    CHECK(pr(PR_GET_DUMPABLE, 0, 0, 0, 0) == 1);
    CHECK(fails(EINVAL, PR_SET_DUMPABLE, 2, 0, 0, 0));
    CHECK(pr(PR_SET_DUMPABLE, 0, 0, 0, 0) == 0 && pr(PR_GET_DUMPABLE, 0, 0, 0, 0) == 0);
    CHECK(pr(PR_SET_DUMPABLE, 1, 0, 0, 0) == 0 && pr(PR_GET_DUMPABLE, 0, 0, 0, 0) == 1);

    CHECK(pr(PR_GET_TIMING, 0, 0, 0, 0) == 0);
    CHECK(fails(EINVAL, PR_SET_TIMING, 1, 0, 0, 0));
    CHECK(pr(PR_GET_SECCOMP, 0, 0, 0, 0) == 0);

    CHECK(pr(PR_GET_KEEPCAPS, 0, 0, 0, 0) == 0);
    CHECK(fails(EINVAL, PR_SET_KEEPCAPS, 2, 0, 0, 0));
    CHECK(pr(PR_SET_KEEPCAPS, 1, 0, 0, 0) == 0 && pr(PR_GET_KEEPCAPS, 0, 0, 0, 0) == 1);
    CHECK(pr(PR_GET_SECUREBITS, 0, 0, 0, 0) == 1 << 4);
    CHECK(pr(PR_SET_KEEPCAPS, 0, 0, 0, 0) == 0 && pr(PR_GET_SECUREBITS, 0, 0, 0, 0) == 0);
    CHECK(pr(PR_CAPBSET_READ, 0, 0, 0, 0) == 1);
    CHECK(fails(EINVAL, PR_CAPBSET_READ, 64, 0, 0, 0));
    CHECK(pr(CAP_AMBIENT, 1 /* IS_SET */, 0, 0, 0) == 0);
    CHECK(fails(EINVAL, CAP_AMBIENT, 1, 64, 0, 0));
    CHECK(fails(EINVAL, CAP_AMBIENT, 4 /* CLEAR_ALL */, 1, 0, 0));
    CHECK(pr(CAP_AMBIENT, 4, 0, 0, 0) == 0);
    // Nothing is inheritable, so nothing can be made ambient.
    CHECK(fails(EPERM, CAP_AMBIENT, 2 /* RAISE */, 0, 0, 0));
    CHECK(pr(CAP_AMBIENT, 3 /* LOWER */, 0, 0, 0) == 0);
    CHECK(fails(EINVAL, CAP_AMBIENT, 5, 0, 0, 0));

    CHECK(pr(PR_MCE_KILL_GET, 0, 0, 0, 0) == PR_MCE_KILL_DEFAULT);
    CHECK(fails(EINVAL, PR_MCE_KILL_GET, 1, 0, 0, 0));
    CHECK(pr(PR_MCE_KILL, PR_MCE_KILL_SET, PR_MCE_KILL_EARLY, 0, 0) == 0);
    CHECK(pr(PR_MCE_KILL_GET, 0, 0, 0, 0) == PR_MCE_KILL_EARLY);
    CHECK(pr(PR_MCE_KILL, PR_MCE_KILL_SET, PR_MCE_KILL_LATE, 0, 0) == 0);
    CHECK(pr(PR_MCE_KILL_GET, 0, 0, 0, 0) == PR_MCE_KILL_LATE);
    CHECK(fails(EINVAL, PR_MCE_KILL, PR_MCE_KILL_CLEAR, 1, 0, 0));
    CHECK(fails(EINVAL, PR_MCE_KILL, PR_MCE_KILL_SET, 3, 0, 0));
    CHECK(pr(PR_MCE_KILL, PR_MCE_KILL_CLEAR, 0, 0, 0) == 0);
    CHECK(pr(PR_MCE_KILL_GET, 0, 0, 0, 0) == PR_MCE_KILL_DEFAULT);

    CHECK(pr(PR_GET_THP_DISABLE, 0, 0, 0, 0) == 0);
    CHECK(fails(EINVAL, PR_SET_THP_DISABLE, 1, 0, 1, 0));
    CHECK(pr(PR_SET_THP_DISABLE, 1, 0, 0, 0) == 0 && pr(PR_GET_THP_DISABLE, 0, 0, 0, 0) == 1);
    CHECK(pr(PR_SET_THP_DISABLE, 0, 0, 0, 0) == 0 && pr(PR_GET_THP_DISABLE, 0, 0, 0, 0) == 0);

    // The slack a zero resets to is the creator's when the thread was made.
    CHECK(pr(PR_GET_TIMERSLACK, 0, 0, 0, 0) == 50000);
    CHECK(pr(PR_SET_TIMERSLACK, 1234, 0, 0, 0) == 0 && pr(PR_GET_TIMERSLACK, 0, 0, 0, 0) == 1234);
    CHECK(pr(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 0);
    CHECK(fails(EINVAL, PR_SET_NO_NEW_PRIVS, 0, 0, 0, 0));
    CHECK(fails(EINVAL, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 1));
    CHECK(fails(EINVAL, PR_GET_NO_NEW_PRIVS, 1, 0, 0, 0));
    CHECK(pr(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0 && pr(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1);
    pthread_t t;
    long seen[3] = {0, 0, 0};
    CHECK(pthread_create(&t, 0, in_thread, seen) == 0 && pthread_join(t, 0) == 0);
    CHECK(seen[0] == 1234 && seen[1] == 1 && seen[2] == 1234);
    CHECK(pr(PR_GET_TIMERSLACK, 0, 0, 0, 0) == 1234);
    CHECK(pr(PR_SET_TIMERSLACK, 0, 0, 0, 0) == 0 && pr(PR_GET_TIMERSLACK, 0, 0, 0, 0) == 50000);

    // Names for anonymous mappings.
    const int rw = PROT_READ | PROT_WRITE, anon = MAP_PRIVATE | MAP_ANONYMOUS;
    char *m = mmap(0, 5 * 4096, rw, anon, -1, 0);
    CHECK(m != MAP_FAILED);
    unsigned long at = (unsigned long)m;
    CHECK(munmap(m + 4 * 4096, 4096) == 0);
    CHECK(pr(SET_VMA, 0, at + 4096, 4097, (unsigned long)"gex test") == 0);
    CHECK(mapped_as(at + 4096, at + 3 * 4096, "[anon:gex test]"));
    CHECK(fails(EINVAL, SET_VMA, 1, at, 4096, (unsigned long)"x"));
    CHECK(fails(EINVAL, SET_VMA, 0, at + 1, 4096, (unsigned long)"x"));
    CHECK(fails(EINVAL, SET_VMA, 0, at, 4096, (unsigned long)"a[b]"));
    CHECK(fails(EINVAL, SET_VMA, 0, at, 4096, (unsigned long)"tab\there"));
    char name[81];
    memset(name, 'n', 80);
    name[80] = 0;
    CHECK(fails(EINVAL, SET_VMA, 0, at, 4096, (unsigned long)name));
    name[79] = 0;
    CHECK(pr(SET_VMA, 0, at, 4096, (unsigned long)name) == 0);
    CHECK(fails(EFAULT, SET_VMA, 0, at, 4096, NOWHERE));
    // A gap: what is mapped is named all the same.
    CHECK(fails(ENOMEM, SET_VMA, 0, at + 3 * 4096, 2 * 4096, (unsigned long)"tail"));
    CHECK(mapped_as(at + 3 * 4096, at + 4 * 4096, "[anon:tail]"));
    // No name takes it away, and the pieces are one mapping again.
    CHECK(pr(SET_VMA, 0, at, 4 * 4096, 0) == 0);
    CHECK(!mapped_as(at + 4096, at + 3 * 4096, "[anon:gex test]"));
    int fd = open(argv[0], O_RDONLY);
    CHECK(fd >= 0);
    char *file = mmap(0, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
    CHECK(file != MAP_FAILED);
    CHECK(fails(EBADF, SET_VMA, 0, (unsigned long)file, 4096, (unsigned long)"file"));

    // In a child: the denial cannot be taken back. It has no-new-privileges
    // from its parent.
    fflush(stdout);
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        if (pr(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1 || pr(PR_GET_TIMERSLACK, 0, 0, 0, 0) != 50000) _exit(2);
        int r = mdwe();
        fflush(stdout);
        _exit(r);
    }
    int status = 0;
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(pr(GET_MDWE, 0, 0, 0, 0) == 0);

    printf("prctl ok\n");
    return 0;
}
