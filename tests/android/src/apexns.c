// Android's init and its two mount namespaces, as mount_namespace.cpp sets
// them up when APEXes cannot all be mounted before /data:
//
//   / shared (recursively), /apex a private tmpfs, /bootstrap-apex a tmpfs
//   (shared, under /); the namespace init is in is the bootstrap one; a
//   copy of it (unshare) is the default one; back in the bootstrap one,
//   /bootstrap-apex is bound onto /apex (MS_BIND | MS_REC).
//
// apexd-bootstrap then mounts the bootstrap APEXes under /apex in the
// bootstrap namespace: each one's payload at /apex/<name>@<version>, bound
// again at /apex/<name>, and writes /apex/apex-info-list.xml. Since /apex
// there is a bind of /bootstrap-apex, those mounts are under a shared mount
// whose peers are /bootstrap-apex in both namespaces: servicemanager (in
// the bootstrap namespace) and init (in the default one, where it skips
// what /bootstrap-apex holds when it reads the APEXes' .rc files) see them
// at /bootstrap-apex/<name>. In the default namespace /apex is a tmpfs of
// its own, and what apexd mounts there later is seen nowhere else.
//
// The same here under a tmpfs of the test's own, in a namespace of its
// own. Prints what each namespace sees, and checks it against what Linux
// 7.0 showed.
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

static char base[64];

// What Linux 7.0 printed.
static const char expected[] =
    "bootstrap apex: apex-info-list.xml runtime runtime@1\n"
    "bootstrap bootstrap-apex: apex-info-list.xml runtime runtime@1\n"
    "bootstrap bootstrap-apex/runtime/etc/runtime.rc: there\n"
    "bootstrap bootstrap-apex/runtime@1/etc/runtime.rc: there\n"
    "default apex:\n"
    "default bootstrap-apex: apex-info-list.xml runtime runtime@1\n"
    "default bootstrap-apex/runtime/etc/runtime.rc: there\n"
    "default bootstrap-apex/runtime@1/etc/runtime.rc: there\n"
    "default apex: sdkext sdkext@1\n"
    "default bootstrap-apex: apex-info-list.xml runtime runtime@1\n"
    "default apex/sdkext/etc/sdkext.rc: there\n"
    "bootstrap apex: apex-info-list.xml runtime runtime@1\n"
    "bootstrap bootstrap-apex: apex-info-list.xml runtime runtime@1\n";

static char out[4096];
static size_t used;

// Print, and keep what was printed.
static void say(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    char line[512];
    int n = vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    fputs(line, stdout);
    if (n > 0 && used + (size_t)n < sizeof out) {
        memcpy(out + used, line, (size_t)n);
        used += (size_t)n;
    }
}

static void die(const char *what) {
    printf("apexns: %s: errno %d\n", what, errno);
    exit(1);
}

static const char *at(const char *rel) {
    static char p[4][256];
    static int n;
    char *s = p[n++ % 4];
    snprintf(s, 256, "%s/%s", base, rel);
    return s;
}

static int cmp(const void *a, const void *b) {
    return strcmp(*(char *const *)a, *(char *const *)b);
}

// The names in a directory, sorted, on one line.
static void list(const char *ns, const char *rel) {
    char *names[64];
    int n = 0;
    DIR *d = opendir(at(rel));
    say("%s %s:", ns, rel);
    if (!d) {
        say(" (errno %d)\n", errno);
        return;
    }
    struct dirent *e;
    while ((e = readdir(d)) && n < 64) {
        if (e->d_name[0] != '.') names[n++] = strdup(e->d_name);
    }
    closedir(d);
    qsort(names, n, sizeof *names, cmp);
    for (int i = 0; i < n; i++) {
        say(" %s", names[i]);
        free(names[i]);
    }
    say("\n");
}

static void has(const char *ns, const char *rel) {
    say("%s %s: %s\n", ns, rel, access(at(rel), F_OK) == 0 ? "there" : "not there");
}

static void mount_apex(const char *name) {
    char payload[64], file[96];
    snprintf(payload, sizeof payload, "apex/%s@1", name);
    if (mkdir(at(payload), 0755)) die("mkdir payload");
    if (mount("tmpfs", at(payload), "tmpfs", 0, "mode=0755")) die("mount payload");
    snprintf(file, sizeof file, "%s/etc", payload);
    if (mkdir(at(file), 0755)) die("mkdir etc");
    snprintf(file, sizeof file, "%s/etc/%s.rc", payload, name);
    int fd = open(at(file), O_WRONLY | O_CREAT, 0644);
    if (fd < 0) die("an .rc file");
    close(fd);
    char bound[64];
    snprintf(bound, sizeof bound, "apex/%s", name);
    if (mkdir(at(bound), 0755)) die("mkdir bound");
    if (mount(at(payload), at(bound), NULL, MS_BIND, NULL)) die("bind the payload");
}

static void setns_to(int fd) {
    if (setns(fd, CLONE_NEWNS)) die("setns");
}

int main(void) {
    // A namespace of the test's own, nothing in it spreading to the host's.
    if (unshare(CLONE_NEWNS)) die("unshare");
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL)) die("make / private");
    snprintf(base, sizeof base, "/tmp/apexns.XXXXXX");
    if (!mkdtemp(base)) die("mkdtemp");
    if (mount("tmpfs", base, "tmpfs", 0, "mode=0755")) die("mount base");
    // What init does to / it does here to the base.
    if (mount(NULL, base, NULL, MS_REC | MS_SHARED, NULL)) die("make base shared");
    if (mkdir(at("apex"), 0755) || mkdir(at("bootstrap-apex"), 0755)) die("mkdir");
    if (mount("tmpfs", at("apex"), "tmpfs", 0, "mode=0755")) die("mount apex");
    if (mount("tmpfs", at("bootstrap-apex"), "tmpfs", 0, "mode=0755")) die("mount bootstrap-apex");
    if (mount(NULL, at("apex"), NULL, MS_PRIVATE, NULL)) die("make apex private");

    int bootstrap = open("/proc/self/ns/mnt", O_RDONLY | O_CLOEXEC);
    if (bootstrap < 0) die("open the bootstrap namespace");
    if (unshare(CLONE_NEWNS)) die("unshare the default namespace");
    int deflt = open("/proc/self/ns/mnt", O_RDONLY | O_CLOEXEC);
    if (deflt < 0) die("open the default namespace");
    setns_to(bootstrap);
    if (mount(at("bootstrap-apex"), at("apex"), NULL, MS_BIND | MS_REC, NULL)) die("bind bootstrap-apex on apex");

    // apexd-bootstrap.
    mount_apex("runtime");
    int fd = open(at("apex/apex-info-list.xml"), O_WRONLY | O_CREAT, 0644);
    if (fd < 0) die("apex-info-list.xml");
    close(fd);

    list("bootstrap", "apex");
    list("bootstrap", "bootstrap-apex");
    has("bootstrap", "bootstrap-apex/runtime/etc/runtime.rc");
    has("bootstrap", "bootstrap-apex/runtime@1/etc/runtime.rc");

    setns_to(deflt);
    list("default", "apex");
    list("default", "bootstrap-apex");
    has("default", "bootstrap-apex/runtime/etc/runtime.rc");
    has("default", "bootstrap-apex/runtime@1/etc/runtime.rc");

    // apexd, later, in the default namespace.
    mount_apex("sdkext");
    list("default", "apex");
    list("default", "bootstrap-apex");
    has("default", "apex/sdkext/etc/sdkext.rc");

    setns_to(bootstrap);
    list("bootstrap", "apex");
    list("bootstrap", "bootstrap-apex");
    // Leave nothing behind: the mounts go with the namespaces, the
    // directory with this.
    if (umount2(base, MNT_DETACH) || rmdir(base)) die("remove base");
    if (strcmp(out, expected) != 0) {
        printf("apexns: not what Linux shows\n");
        return 1;
    }
    printf("apexns ok\n");
    return 0;
}
