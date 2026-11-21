// selinuxfs, the filesystem a program talks to SELinux through: mounted,
// looked at, given a policy and asked.
//
// - A mount is of type SELINUX_MAGIC. Its root has the kernel's files, each
//   with its mode and inode number, a null device and six directories.
// - Before a policy (when the kernel has loaded none yet): nothing is
//   enforced, class and booleans are empty, a kernel SID reads its name,
//   and the question files answer that everything is allowed.
// - A policy is loaded by one write to load, from the file's start. The
//   directories it fills are then there, and the files read what it says.
// - context, access, create, member and relabel take a question and are
//   then read for its answer: once an open file, and a refused question
//   leaves nothing to read. validatetrans answers by the write.
// - A boolean's file takes the value it will have; commit_pending_bools
//   gives it.
// - status is twenty bytes to read and one read-only page to map, which
//   says when a policy was loaded or the booleans committed.
// - A write does not move a file's position, a write that is not from the
//   start is EINVAL, and nothing can be made or removed here.
//
// The policy is the kernel crate's test policy, built in. It is loaded
// into the kernel the program runs on, so on Linux this wants a machine
// kept for it: one booted with SELinux on and not enforcing. enforce is
// never set here.
//
// Needs the right to mount (root) and the filesystem; without them the
// program says so and exits 77.
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/vfs.h>
#include <unistd.h>

#define SELINUX_MAGIC 0xf97cff8c

// The policy: crates/gex-kernel/src/selinux/testdata/test.conf, as
// tests/fixtures.sh compiles it (test.33).
#ifndef TEST_POLICY
#error "build with -DTEST_POLICY=\"<path to test.33>\""
#endif
__asm__(".section .rodata\n"
        ".global test_policy\n"
        "test_policy:\n"
        ".incbin \"" TEST_POLICY "\"\n"
        ".global test_policy_end\n"
        "test_policy_end:\n"
        ".previous\n");
extern const char test_policy[], test_policy_end[];

static char dir[64];

static void die(const char *what, long a, long b) {
    printf("selinuxfs: %s (%ld, %ld; errno %d)\n", what, a, b, errno);
    umount2(dir, MNT_DETACH);
    rmdir(dir);
    exit(1);
}

static const char *in(const char *name) {
    static char path[4][160];
    static int at;
    char *p = path[at++ & 3];
    snprintf(p, 160, "%s/%s", dir, name);
    return p;
}

static int open_in(const char *name, int flags) {
    int fd = open(in(name), flags | O_CLOEXEC);
    if (fd < 0) die(name, flags, 0);
    return fd;
}

// What a file reads, whole, into buf: its length.
static long slurp(const char *name, char *buf, size_t size) {
    int fd = open_in(name, O_RDONLY);
    long n = read(fd, buf, size - 1);
    if (n < 0) die(name, n, 0);
    buf[n] = 0;
    close(fd);
    return n;
}

// A file reads exactly this text, with nothing after it.
static void reads(const char *name, const char *want) {
    char buf[256];
    long n = slurp(name, buf, sizeof buf);
    if (n != (long)strlen(want) || memcmp(buf, want, n)) {
        printf("selinuxfs: %s reads '%s', not '%s'\n", name, buf, want);
        die(name, n, strlen(want));
    }
}

// A context's file: the context and the NUL that ends it.
static void reads_context(const char *name, const char *want) {
    char buf[256];
    long n = slurp(name, buf, sizeof buf);
    if (n != (long)strlen(want) + 1 || memcmp(buf, want, n)) {
        printf("selinuxfs: %s reads '%s' in %ld bytes, not '%s' and its NUL\n", name, buf, n, want);
        die(name, n, strlen(want) + 1);
    }
}

static void mode_is(const char *name, mode_t type, mode_t mode, unsigned long ino) {
    struct stat st;
    if (stat(in(name), &st)) die(name, 0, 0);
    if ((st.st_mode & S_IFMT) != type || (st.st_mode & 07777) != mode) die(name, st.st_mode, mode);
    if (ino && st.st_ino != ino) die(name, st.st_ino, ino);
    if (type == S_IFREG && st.st_size != 0) die("a file's size", st.st_size, 0);
}

// The names in a directory, sorted and joined by spaces.
static const char *names(const char *name) {
    static char out[2048];
    char *list[128];
    int n = 0;
    DIR *d = opendir(in(name));
    if (!d) die(name, 0, 0);
    for (struct dirent *e; (e = readdir(d));) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        if (n == 128) die("a directory's size", n, 0);
        list[n++] = strdup(e->d_name);
    }
    closedir(d);
    for (int i = 0; i < n; i++)
        for (int j = i + 1; j < n; j++)
            if (strcmp(list[i], list[j]) > 0) {
                char *t = list[i];
                list[i] = list[j];
                list[j] = t;
            }
    out[0] = 0;
    for (int i = 0; i < n; i++) {
        if (i) strcat(out, " ");
        strcat(out, list[i]);
        free(list[i]);
    }
    return out;
}

static void names_are(const char *name, const char *want) {
    const char *got = names(name);
    if (strcmp(got, want)) {
        printf("selinuxfs: %s holds '%s', not '%s'\n", *name ? name : "the root", got, want);
        die("a directory's names", 0, 0);
    }
}

// The status file's five words.
static void status(uint32_t w[5]) {
    int fd = open_in("status", O_RDONLY);
    char more[64];
    long n = read(fd, more, sizeof more);
    if (n != 20) die("status's length", n, 20);
    memcpy(w, more, 20);
    if (read(fd, more, sizeof more) != 0) die("status read past its end", 0, 0);
    close(fd);
}

// Ask a question file: the answer's length, or -errno of the write. The
// answer is a string in buf either way (a context's NUL is counted).
static long ask(const char *file, const char *question, char *buf, size_t size) {
    int fd = open_in(file, O_RDWR);
    long w = write(fd, question, strlen(question));
    if (w < 0) {
        int e = errno;
        // A refused question leaves nothing to read and cannot be put
        // again; one too long to be taken was never put.
        if (read(fd, buf, size) != 0) die("an answer to a refused question", 0, 0);
        int again = e == EFBIG ? EFBIG : EBUSY;
        if (write(fd, question, strlen(question)) != -1 || errno != again) die("a second question after a refused one", errno, again);
        close(fd);
        return -e;
    }
    if (w != (long)strlen(question)) die("a question's write", w, strlen(question));
    long n = read(fd, buf, size - 1);
    if (n < 0) die("an answer", n, 0);
    buf[n] = 0;
    // Read to its end; and an open file is asked once.
    char more[8];
    if (read(fd, more, sizeof more) != 0) die("an answer read twice", 0, 0);
    if (write(fd, question, strlen(question)) != -1 || errno != EBUSY) die("a second question", errno, EBUSY);
    // The write did not move the position, the read did: from the start
    // the answer is there again.
    if (pread(fd, more, 1, 0) != 1 || more[0] != buf[0]) die("an answer read again from the start", more[0], buf[0]);
    close(fd);
    return n;
}

static void answers_context(const char *file, const char *question, const char *want) {
    char buf[512];
    long n = ask(file, question, buf, sizeof buf);
    if (n != (long)strlen(want) + 1 || strcmp(buf, want)) {
        printf("selinuxfs: %s '%s' answers '%s' (%ld), not '%s'\n", file, question, buf, n, want);
        die("an answer", n, strlen(want) + 1);
    }
}

// Write text to a file that takes a number: 0, or the errno.
static int put(int fd, const char *text) {
    long n = write(fd, text, strlen(text));
    if (n < 0) return errno;
    if (n != (long)strlen(text)) die("a short write", n, strlen(text));
    return 0;
}

#define FILE_T "system_u:object_r:file_t:s0"
#define EXEC_T "system_u:object_r:exec_t:s0"
#define KERNEL_T "system_u:system_r:kernel_t:s0"
#define INIT_T "system_u:system_r:init_t:s0"

int main(void) {
    if (geteuid() != 0) {
        printf("selinuxfs: not root, cannot mount\n");
        return 77;
    }
    snprintf(dir, sizeof dir, "/tmp/selinuxfs-test-%d", getpid());
    if (mkdir(dir, 0755)) {
        printf("selinuxfs: mkdir %s: errno %d\n", dir, errno);
        return 1;
    }
    if (mount("selinuxfs", dir, "selinuxfs", 0, NULL)) {
        printf("selinuxfs: cannot mount one: errno %d\n", errno);
        rmdir(dir);
        return errno == EPERM || errno == ENODEV || errno == EACCES ? 77 : 1;
    }
    struct statfs fs;
    if (statfs(dir, &fs) || (uint32_t)fs.f_type != SELINUX_MAGIC) die("the mount's type", fs.f_type, 0);

    // The tree.
    names_are("", "access avc booleans checkreqprot class commit_pending_bools context create deny_unknown disable enforce initial_contexts load member mls null policy "
                  "policy_capabilities policyvers reject_unknown relabel ss status user validatetrans");
    names_are("initial_contexts", "any_socket devnull file init kernel netif netmsg node port security unlabeled");
    names_are("avc", "cache_stats cache_threshold hash_stats");
    names_are("ss", "sidtab_hash_stats");
    mode_is("", S_IFDIR, 0755, 1);
    mode_is("load", S_IFREG, 0600, 3);
    mode_is("enforce", S_IFREG, 0644, 4);
    mode_is("context", S_IFREG, 0666, 5);
    mode_is("access", S_IFREG, 0666, 6);
    mode_is("policyvers", S_IFREG, 0444, 10);
    mode_is("commit_pending_bools", S_IFREG, 0200, 11);
    mode_is("checkreqprot", S_IFREG, 0644, 15);
    mode_is("status", S_IFREG, 0444, 19);
    mode_is("validatetrans", S_IFREG, 0222, 21);
    mode_is("booleans", S_IFDIR, 0555, 22);
    mode_is("null", S_IFCHR, 0666, 23);
    mode_is("avc", S_IFDIR, 0555, 24);
    mode_is("avc/cache_threshold", S_IFREG, 0644, 25);
    mode_is("ss", S_IFDIR, 0555, 28);
    mode_is("ss/sidtab_hash_stats", S_IFREG, 0444, 29);
    mode_is("initial_contexts", S_IFDIR, 0555, 30);
    mode_is("initial_contexts/kernel", S_IFREG, 0444, 0x01000001);
    mode_is("initial_contexts/devnull", S_IFREG, 0444, 0x0100001b);
    mode_is("class", S_IFDIR, 0555, 31);
    mode_is("policy_capabilities", S_IFDIR, 0555, 32);
    mode_is("policy_capabilities/open_perms", S_IFREG, 0444, 0x08000001);
    struct stat st;
    if (stat(dir, &st) || st.st_nlink != 8) die("the root's links", st.st_nlink, 8);
    if (stat(in("null"), &st) || major(st.st_rdev) != 1 || minor(st.st_rdev) != 3) die("null's numbers", major(st.st_rdev), minor(st.st_rdev));
    char buf[512];
    long n = slurp("policyvers", buf, sizeof buf);
    if (n < 2 || atoi(buf) < 33) die("policyvers", n, atoi(buf));
    reads("checkreqprot", "0");

    // Before a policy, where this kernel has loaded none.
    uint32_t w0[5];
    status(w0);
    if (names("class")[0]) {
        printf("selinuxfs: this kernel has a policy already; what it is like before one is not looked at\n");
    } else {
        if (w0[0] != 1 || w0[1] != 0 || w0[2] != 0 || w0[3] != 0 || w0[4] != 1) die("status before a policy", w0[1], w0[3]);
        names_are("booleans", "");
        reads("enforce", "0");
        reads("mls", "0");
        reads("deny_unknown", "1");
        reads("reject_unknown", "0");
        reads_context("initial_contexts/kernel", "kernel");
        reads_context("initial_contexts/file", "file");
        reads_context("initial_contexts/devnull", "devnull");
        // init is "kernel" until a policy: what is not is taken to mean
        // one is loaded.
        reads_context("initial_contexts/init", "kernel");
        reads("policy_capabilities/open_perms", "0");
        n = ask("access", "kernel file 6", buf, sizeof buf);
        if (n < 0 || strcmp(buf, "ffffffff ffffffff 0 ffffffff 0 0")) {
            printf("selinuxfs: access before a policy answers '%s'\n", buf);
            die("access before a policy", n, 0);
        }
        answers_context("context", "file", "file");
        answers_context("context", "anything-at-all", "kernel");
        // Something new is its maker's if it is a process (class 2), and
        // what it is made in's if not.
        answers_context("create", "kernel file 2", "kernel");
        answers_context("create", "kernel file 6 name", "file");
        int v = open_in("validatetrans", O_WRONLY);
        if (put(v, "file devnull 6 kernel")) die("validatetrans before a policy", errno, 0);
        close(v);
    }

    // The policy: whole, in one write, from the start.
    long size = test_policy_end - test_policy;
    int load = open_in("load", O_RDWR);
    if (pwrite(load, test_policy, size, 1) != -1 || errno != EINVAL) die("a policy written past the start", errno, EINVAL);
    if (write(load, test_policy, size / 2) != -1 || errno != EINVAL) die("half a policy", errno, EINVAL);
    uint32_t w[5];
    status(w);
    if (memcmp(w, w0, sizeof w)) die("status after policies that did not load", w[1], w[3]);
    if (write(load, test_policy, size) != size) die("load", size, 0);
    if (read(load, buf, sizeof buf) != -1 || errno != EINVAL) die("load read", errno, EINVAL);
    close(load);
    status(w);
    if (w[0] != 1 || w[1] != w0[1] + 2 || w[2] != 0 || w[3] != w0[3] + 1 || w[4] != 1) die("status after a load", w[1], w[3]);

    // What it filled.
    reads("mls", "1");
    reads("deny_unknown", "1");
    reads("reject_unknown", "0");
    reads("enforce", "0");
    names_are("booleans", "allow_stuff other_thing");
    names_are("class/file", "index perms");
    reads("class/file/index", "2");
    reads("class/file/perms/read", "1");
    reads("class/file/perms/open", "7");
    reads("class/binder/perms/transfer", "2");
    mode_is("class/file", S_IFDIR, 0555, 0);
    mode_is("class/file/index", S_IFREG, 0444, 0x04000000 | 2 * 33);
    mode_is("class/file/perms", S_IFDIR, 0555, 0);
    mode_is("class/file/perms/open", S_IFREG, 0444, 0x04000000 | (2 * 33 + 7));
    mode_is("booleans", S_IFDIR, 0555, 22);
    mode_is("class", S_IFDIR, 0555, 31);
    mode_is("booleans/allow_stuff", S_IFREG, 0644, 0);
    if (stat(in("booleans/allow_stuff"), &st) || (st.st_ino & ~0xfffffful) != 0x02000000) die("a boolean's inode", st.st_ino, 0);
    if (stat(in("class/file"), &st) || st.st_nlink != 3) die("a class's links", st.st_nlink, 3);
    reads_context("initial_contexts/kernel", KERNEL_T);
    reads_context("initial_contexts/file", "system_u:object_r:file_t:s0-s1:c0.c2");
    // The policy names init_t for init and has not the capability that
    // makes that count: init is the kernel's.
    reads_context("initial_contexts/init", KERNEL_T);
    reads("policy_capabilities/network_peer_controls", "1");
    reads("policy_capabilities/open_perms", "1");

    // Questions.
    answers_context("context", "system_u:object_r:old_file_t:s0", FILE_T);
    answers_context("context", "system_u:system_r:init_t:s0:c0.c1", "system_u:system_r:init_t:s0:c0,c1");
    if (ask("context", "nobody:system_r:init_t:s0", buf, sizeof buf) != -EINVAL) die("a context of no user", 0, 0);
    char want[128];
    snprintf(want, sizeof want, "5 ffffffff 0 ffffffff %u 0", w[3]);
    n = ask("access", KERNEL_T " " FILE_T " 2", buf, sizeof buf);
    if (n != (long)strlen(want) || strcmp(buf, want)) {
        printf("selinuxfs: access answers '%s', not '%s'\n", buf, want);
        die("access", n, 0);
    }
    // What follows the class is not read.
    n = ask("access", KERNEL_T " " FILE_T " 2 ffffffff and more", buf, sizeof buf);
    if (n < 0 || strcmp(buf, want)) die("access with more after the class", n, 0);
    answers_context("create", INIT_T " " EXEC_T " 1", "system_u:app_r:app_t:s1:c0,c1");
    answers_context("create", KERNEL_T " " FILE_T " 2 special", FILE_T);
    answers_context("member", KERNEL_T " " EXEC_T " 3", EXEC_T);
    answers_context("relabel", KERNEL_T " " EXEC_T " 2", EXEC_T);
    if (ask("access", KERNEL_T, buf, sizeof buf) != -EINVAL) die("half a question", 0, 0);
    char *big = malloc(8192);
    memset(big, 'a', 8192);
    big[4088] = 0;
    if (ask("access", big, buf, sizeof buf) != -EFBIG) die("a question of 4088 bytes", errno, EFBIG);
    big[4087] = 0;
    if (ask("access", big, buf, sizeof buf) != -EINVAL) die("a question of 4087 bytes", errno, EINVAL);
    free(big);

    // validatetrans: the write says.
    int v = open_in("validatetrans", O_RDWR);
    if (put(v, FILE_T " " FILE_T " 2 " KERNEL_T)) die("a relabel the rules let be made", errno, 0);
    if (put(v, FILE_T " " FILE_T " 2 " KERNEL_T)) die("and asked again in the same open file", errno, 0);
    if (put(v, FILE_T " system_u:object_r:tmp_t:s1:c0 2 " KERNEL_T) != EPERM) die("a relabel the rules refuse", errno, EPERM);
    if (put(v, FILE_T " " FILE_T " 2") != EINVAL) die("a relabel by no task", errno, EINVAL);
    if (pwrite(v, FILE_T, strlen(FILE_T), 3) != -1 || errno != EINVAL) die("validatetrans written past the start", errno, EINVAL);
    if (read(v, buf, sizeof buf) != -1 || errno != EINVAL) die("validatetrans read", errno, EINVAL);
    close(v);

    // The status page, mapped.
    int sfd = open_in("status", O_RDONLY);
    if (mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE, sfd, 0) != MAP_FAILED || errno != EPERM) die("status mapped for writing", errno, EPERM);
    if (mmap(NULL, 4096, PROT_READ, MAP_SHARED, sfd, 4096) != MAP_FAILED || errno != EIO) die("status mapped past its page", errno, EIO);
    if (mmap(NULL, 8192, PROT_READ, MAP_SHARED, sfd, 0) != MAP_FAILED || errno != EIO) die("two pages of status mapped", errno, EIO);
    volatile uint32_t *page = mmap(NULL, 4096, PROT_READ, MAP_SHARED, sfd, 0);
    if (page == MAP_FAILED) die("status mapped", 0, 0);
    close(sfd);
    for (int i = 0; i < 5; i++)
        if (page[i] != w[i]) die("the mapped status page", i, page[i]);
    for (int i = 5; i < 1024; i++)
        if (page[i]) die("the rest of the status page", i, page[i]);
    int efd = open_in("enforce", O_RDWR);
    if (mmap(NULL, 4096, PROT_READ, MAP_SHARED, efd, 0) != MAP_FAILED || errno != ENODEV) die("enforce mapped", errno, ENODEV);

    // A boolean: its file takes the value it will have, the commit gives
    // it, and the status page says there was one.
    int b = open_in("booleans/other_thing", O_RDWR);
    char was[8], will[8];
    if (read(b, was, 4) != 3 || (memcmp(was, "0 0", 3) && memcmp(was, "1 1", 3))) die("a boolean", was[0], was[2]);
    int now = was[0] == '1';
    snprintf(will, sizeof will, "%d", !now);
    if (pwrite(b, will, 1, 0) != 1) die("a boolean written", errno, 0);
    snprintf(want, sizeof want, "%d %d", now, !now);
    reads("booleans/other_thing", want);
    int c = open_in("commit_pending_bools", O_WRONLY);
    if (put(c, "0")) die("commit 0", errno, 0);
    reads("booleans/other_thing", want);
    uint32_t w2[5];
    status(w2);
    if (memcmp(w2, w, sizeof w)) die("status after a commit of nothing", w2[1], w2[3]);
    // Written again from the start: a write does not move the position.
    if (put(c, " 1\n")) die("commit 1", errno, 0);
    snprintf(want, sizeof want, "%d %d", !now, !now);
    reads("booleans/other_thing", want);
    status(w2);
    if (w2[1] != w[1] + 2 || w2[3] != w[3] + 1 || w2[2] != 0 || w2[4] != 1) die("status after a commit", w2[1], w2[3]);
    for (int i = 0; i < 5; i++)
        if (page[i] != w2[i]) die("the mapped status page after a commit", i, page[i]);
    // Back as it was, for whoever runs next.
    snprintf(will, sizeof will, "%d", now);
    if (pwrite(b, will, 1, 0) != 1 || put(c, "1") || put(c, "1")) die("a boolean put back", errno, 0);
    snprintf(want, sizeof want, "%d %d", now, now);
    reads("booleans/other_thing", want);
    status(w);
    if (w[1] != w2[1] + 4 || w[3] != w2[3] + 2) die("status after two more commits", w[1], w[3]);
    if (pwrite(b, "x", 1, 0) != -1 || errno != EINVAL) die("a boolean given no number", errno, EINVAL);
    if (pwrite(b, "1", 1, 1) != -1 || errno != EINVAL) die("a boolean written past the start", errno, EINVAL);
    close(b);
    close(c);

    // enforce: left as it is (0), which may be written as often as wanted.
    if (put(efd, "0") || put(efd, "0\n") || put(efd, " 0 and the rest")) die("enforce written 0", errno, 0);
    if (put(efd, "off") != EINVAL) die("enforce given no number", errno, EINVAL);
    if (pwrite(efd, "0", 1, 1) != -1 || errno != EINVAL) die("enforce written past the start", errno, EINVAL);
    if (read(efd, buf, 8) != 1 || buf[0] != '0') die("enforce read", buf[0], 0);
    // The read moved the position, and a write is from the start.
    if (write(efd, "0", 1) != -1 || errno != EINVAL) die("enforce written after a read", errno, EINVAL);
    close(efd);
    status(w2);
    if (memcmp(w2, w, sizeof w)) die("status after enforce written as it was", w2[1], w2[3]);

    // Files with no write, and writes nothing comes of.
    int m = open_in("mls", O_WRONLY);
    if (put(m, "1") != EINVAL) die("mls written", errno, EINVAL);
    close(m);
    int q = open_in("checkreqprot", O_WRONLY);
    if (put(q, "0")) die("checkreqprot written", errno, 0);
    close(q);
    reads("checkreqprot", "0");

    // null is the null device.
    int nul = open_in("null", O_RDWR);
    if (write(nul, "gone", 4) != 4 || read(nul, buf, 8) != 0) die("null", errno, 0);
    close(nul);

    // Nothing is made, removed or moved here.
    if (open(in("new"), O_CREAT | O_WRONLY, 0644) != -1 || errno != EACCES) die("a file made in the root", errno, EACCES);
    if (open(in("class/new"), O_CREAT | O_WRONLY, 0644) != -1 || errno != EACCES) die("a file made in class", errno, EACCES);
    if (mkdir(in("new"), 0755) != -1 || errno != EPERM) die("a directory made", errno, EPERM);
    if (mkdir(in("class"), 0755) != -1 || errno != EEXIST) die("a directory made over one", errno, EEXIST);
    if (unlink(in("enforce")) != -1 || errno != EPERM) die("enforce removed", errno, EPERM);
    if (rmdir(in("booleans")) != -1 || errno != EPERM) die("booleans removed", errno, EPERM);
    if (rename(in("enforce"), in("other")) != -1 || errno != EPERM) die("enforce renamed", errno, EPERM);
    if (open(in("enforce/x"), O_RDONLY) != -1 || errno != ENOTDIR) die("a name under a file", errno, ENOTDIR);
    if (open(in("nothing"), O_RDONLY) != -1 || errno != ENOENT) die("a name that is not there", errno, ENOENT);

    munmap((void *)page, 4096);
    if (umount(dir)) die("umount", 0, 0);
    rmdir(dir);
    printf("selinuxfs ok\n");
    return 0;
}
