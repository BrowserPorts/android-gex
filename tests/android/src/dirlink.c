// Symbolic links to directories in a mounted tmpfs, as Android's /dev has
// them (init.rc: `symlink /proc/self/fd /dev/fd`): a path goes through
// one to wherever it leads.
//
// - A link to a directory beside it, by a relative and by an absolute
//   name, and a link to such a link: a file under the directory is found
//   through each, for open, stat, access, a directory listing, and
//   making, renaming and removing things.
// - A link out of the mount, into another mount (/proc/self): the files
//   there.
// - The last name's link is the caller's: lstat and readlink see it,
//   O_NOFOLLOW refuses it.
// - Links that lead to each other are ELOOP.
//
// Not checked, because gex has it wrong: `..` after a link is the parent
// of where the link leads (`down/../inside` with down -> real/sub is
// real/inside), and gex takes a path's `..` before it follows any link.
//
// Mounts a tmpfs of its own (root); without that right the program says
// so and exits 77.
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

static char top[64];

static void die(const char *what, long a, long b) {
    printf("dirlink: %s (%ld, %ld; errno %d)\n", what, a, b, errno);
    exit(1);
}

static const char *at(const char *path) {
    static char full[4][256];
    static int turn;
    char *out = full[turn++ % 4];
    snprintf(out, 256, "%s/%s", top, path);
    return out;
}

static void put(const char *path, const char *text) {
    int fd = open(at(path), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0 || write(fd, text, strlen(text)) != (ssize_t)strlen(text)) die(path, fd, 0);
    close(fd);
}

static void reads(const char *path, const char *want) {
    char text[64] = {0};
    int fd = open(at(path), O_RDONLY);
    if (fd < 0) die(path, fd, 0);
    if (read(fd, text, sizeof text - 1) < 0 || strcmp(text, want)) {
        printf("dirlink: %s reads '%s'\n", path, text);
        exit(1);
    }
    close(fd);
}

static int has(const char *dir, const char *name) {
    DIR *d = opendir(at(dir));
    if (!d) die(dir, 0, 0);
    int found = 0;
    for (struct dirent *e; (e = readdir(d));) found += !strcmp(e->d_name, name);
    closedir(d);
    return found;
}

int main(void) {
    if (geteuid() != 0) {
        printf("dirlink: needs root\n");
        return 77;
    }
    strcpy(top, "/tmp/dirlink-XXXXXX");
    if (!mkdtemp(top) || mount("tmpfs", top, "tmpfs", 0, NULL)) die("a tmpfs", errno, 0);
    if (mkdir(at("real"), 0755) || mkdir(at("real/sub"), 0755)) die("mkdir", errno, 0);
    put("real/inside", "in");
    put("real/sub/deep", "deep");
    char target[128];
    snprintf(target, sizeof target, "%s/real", top);
    if (symlink("real", at("rel")) || symlink(target, at("abs")) || symlink("rel", at("twice")) || symlink("real/sub", at("down")) || symlink("/proc/self", at("proc"))) die("symlink", errno, 0);

    // Through each.
    reads("rel/inside", "in");
    reads("abs/inside", "in");
    reads("twice/inside", "in");
    reads("twice/sub/deep", "deep");
    reads("down/deep", "deep");
    struct stat a, b;
    if (stat(at("rel/inside"), &a) || stat(at("real/inside"), &b) || a.st_ino != b.st_ino) die("stat through a link", a.st_ino, b.st_ino);
    if (access(at("abs/sub/deep"), R_OK)) die("access through a link", errno, 0);
    if (!has("rel", "inside") || !has("twice/sub", "deep")) die("a listing through a link", 0, 0);
    // Made, renamed and removed through one.
    put("rel/made", "new");
    reads("real/made", "new");
    if (mkdir(at("twice/dir"), 0755) || stat(at("real/dir"), &a) || !S_ISDIR(a.st_mode)) die("mkdir through a link", errno, 0);
    if (rename(at("abs/made"), at("rel/dir/moved"))) die("rename through links", errno, 0);
    reads("real/dir/moved", "new");
    if (unlink(at("twice/dir/moved")) || rmdir(at("abs/dir")) || has("real", "dir")) die("removing through links", errno, 0);
    if (chdir(at("twice/sub"))) die("chdir through a link", errno, 0);
    int fd = open("deep", O_RDONLY);
    if (fd < 0) die("a name in a directory reached through a link", errno, 0);
    close(fd);
    if (chdir("/")) die("chdir", errno, 0);

    // Out of the mount, into another.
    if (stat(at("proc/status"), &a) || !S_ISREG(a.st_mode)) die("a link into /proc", errno, 0);
    // Two directories in: a descriptor's link there, which leads back to
    // the file in the tmpfs.
    int held = open(at("real/inside"), O_RDONLY);
    char through[64];
    snprintf(through, sizeof through, "proc/fd/%d", held);
    if (held < 0 || stat(at(through), &a) || stat(at("real/inside"), &b) || a.st_ino != b.st_ino) die("a descriptor's link through a link into /proc", errno, held);
    reads(through, "in");
    close(held);

    // The last name is the caller's.
    if (lstat(at("rel"), &a) || !S_ISLNK(a.st_mode) || a.st_size != 4) die("lstat of a link", a.st_mode, a.st_size);
    char got[128] = {0};
    if (readlink(at("twice"), got, sizeof got - 1) != 3 || strcmp(got, "rel")) die("readlink", errno, 0);
    if (open(at("rel"), O_RDONLY | O_NOFOLLOW) >= 0 || errno != ELOOP) die("O_NOFOLLOW of a link", errno, 0);
    if (stat(at("rel"), &a) || !S_ISDIR(a.st_mode)) die("stat of a link to a directory", errno, 0);
    if (stat(at("rel/nothing"), &a) == 0 || errno != ENOENT) die("a name that is not there, through a link", errno, 0);
    if (stat(at("real/inside/x"), &a) == 0 || errno != ENOTDIR) die("a name under a file", errno, 0);

    // Links without end.
    if (symlink("b", at("a")) || symlink("a", at("b"))) die("symlink", errno, 1);
    if (stat(at("a/x"), &a) == 0 || errno != ELOOP) die("links that lead to each other", errno, 0);
    if (stat(at("a"), &a) == 0 || errno != ELOOP) die("a link that leads to itself in the end", errno, 0);

    if (umount(top) || rmdir(top)) die("umount", errno, 0);
    printf("dirlink ok\n");
    return 0;
}
