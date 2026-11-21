// /sys/devices/system/cpu/cpufreq as Linux's cpufreq core lays it out, and
// as Android's CpuMonitorService reads it (CpuInfoReader): a policyN
// directory a frequency domain, whose related_cpus and affected_cpus name
// its processors, whose current frequency lies between its minimum and
// maximum; and each cpuN/cpufreq a link to the policy of processor N.
// Without cpufreq (a kernel built without it, or without a driver) the
// program says so and exits 77.
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CPU "/sys/devices/system/cpu"

static void die(const char *what, const char *path) {
    printf("cpufreq: %s (%s; errno %d)\n", what, path, errno);
    exit(1);
}

static long number(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) die("cannot read", path);
    long v;
    if (fscanf(f, "%ld", &v) != 1) die("not a number", path);
    fclose(f);
    return v;
}

// Whether the list file at `path` ("0", "0-3", "0 1 2") names processor `n`.
static int names(const char *path, long n) {
    FILE *f = fopen(path, "r");
    if (!f) die("cannot read", path);
    char buf[256];
    if (!fgets(buf, sizeof buf, f)) die("empty", path);
    fclose(f);
    for (char *p = buf; *p;) {
        char *end;
        long a = strtol(p, &end, 10);
        if (end == p) break;
        long b = a;
        if (*end == '-') b = strtol(end + 1, &end, 10);
        if (n >= a && n <= b) return 1;
        p = end;
        while (*p == ' ' || *p == ',') p++;
    }
    return 0;
}

int main(void) {
    DIR *d = opendir(CPU "/cpufreq");
    if (!d) {
        printf("cpufreq: this kernel has no cpufreq\n");
        return 77;
    }
    int policies = 0;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (strncmp(e->d_name, "policy", 6)) continue;
        long id = atol(e->d_name + 6);
        char path[PATH_MAX];
        snprintf(path, sizeof path, CPU "/cpufreq/%s/related_cpus", e->d_name);
        if (!names(path, id)) die("a policy's related_cpus does not name its first processor", path);
        snprintf(path, sizeof path, CPU "/cpufreq/%s/affected_cpus", e->d_name);
        if (access(path, R_OK)) die("no affected_cpus", path);
        char a[PATH_MAX], b[PATH_MAX], c[PATH_MAX];
        snprintf(a, sizeof a, CPU "/cpufreq/%s/scaling_cur_freq", e->d_name);
        snprintf(b, sizeof b, CPU "/cpufreq/%s/scaling_min_freq", e->d_name);
        snprintf(c, sizeof c, CPU "/cpufreq/%s/scaling_max_freq", e->d_name);
        long cur = number(a), min = number(b), max = number(c);
        if (cur < min || cur > max || min <= 0) die("the current frequency outside its bounds", a);
        policies++;
    }
    closedir(d);
    if (policies == 0) {
        // The core without a driver: a VM whose hypervisor offers none
        // (Linux 7.0 on Apple's virtualization has the directory empty).
        printf("cpufreq: this kernel has no cpufreq driver\n");
        return 77;
    }
    // Each processor's link, to the policy that names it.
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    for (long i = 0; i < n; i++) {
        char link[PATH_MAX], real[PATH_MAX], related[PATH_MAX];
        snprintf(link, sizeof link, CPU "/cpu%ld/cpufreq", i);
        struct stat st;
        if (lstat(link, &st) || !S_ISLNK(st.st_mode)) die("cpuN/cpufreq is not a link", link);
        if (!realpath(link, real) || strncmp(real, CPU "/cpufreq/policy", strlen(CPU "/cpufreq/policy"))) die("cpuN/cpufreq does not lead to a policy", link);
        snprintf(related, sizeof related, "%s/related_cpus", link);
        if (!names(related, i)) die("the policy a processor's link leads to does not name it", related);
    }
    printf("cpufreq ok\n");
    return 0;
}
