// The main thread's stack, as bionic finds it: /proc/self/stat's
// startstack looked up in /proc/self/maps, with the stack limit for its
// size. pthread_getattr_np on the main thread aborts the program when the
// address is in no mapping.
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>

int main(void) {
    int status = 0, local = 0;

    // startstack: the 28th field, counted from after the name.
    static char line[4096];
    unsigned long start = 0;
    FILE *f = fopen("/proc/self/stat", "re");
    if (!f || !fgets(line, sizeof line, f)) status |= 1;
    if (f) fclose(f);
    char *p = strrchr(line, ')');
    for (int field = 2; p && field < 28; field++) p = strchr(p + 1, ' ');
    if (!p || sscanf(p, " %lu", &start) != 1 || start == 0) status |= 2;

    // It is in a mapping, the one this function's frame is in.
    int found = 0;
    f = fopen("/proc/self/maps", "re");
    while (f && fgets(line, sizeof line, f)) {
        unsigned long lo, hi;
        if (sscanf(line, "%lx-%lx", &lo, &hi) == 2 && lo <= start && start <= hi) {
            found = lo <= (uintptr_t)&local && (uintptr_t)&local < hi;
        }
    }
    if (f) fclose(f);
    if (!found) status |= 4;

    pthread_attr_t attr;
    void *base = 0;
    size_t size = 0;
    struct rlimit lim;
    if (pthread_getattr_np(pthread_self(), &attr) || pthread_attr_getstack(&attr, &base, &size)) status |= 8;
    if (getrlimit(RLIMIT_STACK, &lim) || (lim.rlim_cur != RLIM_INFINITY && size != lim.rlim_cur)) status |= 16;
    uintptr_t here = (uintptr_t)&local;
    if (here < (uintptr_t)base || here >= (uintptr_t)base + size) status |= 32;

    if (status) {
        printf("mainstack %d\n", status);
        return 1;
    }
    printf("mainstack ok\n");
    return 0;
}
