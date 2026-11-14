// A descriptor's name in /proc/self/fd is where the open ended, not what
// was asked for: /proc/self/exe opened is the program's file. bionic's
// loader finds the program's real path this way, and its linker
// configuration by that path.
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int name_of(int fd, char *out) {
    char link[64];
    snprintf(link, sizeof link, "/proc/self/fd/%d", fd);
    ssize_t n = readlink(link, out, PATH_MAX - 1);
    if (n < 0) return -1;
    out[n] = 0;
    return 0;
}

int main(void) {
    static char exe[PATH_MAX], by_fd[PATH_MAX];
    int status = 0;
    ssize_t n = readlink("/proc/self/exe", exe, sizeof exe - 1);
    if (n <= 0 || exe[0] != '/') status |= 1;
    exe[n > 0 ? n : 0] = 0;

    int fd = open("/proc/self/exe", O_PATH | O_CLOEXEC);
    if (fd < 0 || name_of(fd, by_fd) || strcmp(by_fd, exe)) status |= 2;
    struct stat a, b;
    if (fstat(fd, &a) || stat(exe, &b) || a.st_ino != b.st_ino || a.st_size != b.st_size) status |= 4;
    close(fd);

    // Read as an ordinary file too.
    fd = open("/proc/self/exe", O_RDONLY);
    char magic[4] = {0};
    if (fd < 0 || read(fd, magic, 4) != 4 || memcmp(magic, "\177ELF", 4) || name_of(fd, by_fd) || strcmp(by_fd, exe)) status |= 8;
    close(fd);

    // A plain path names itself.
    fd = open("/proc/self", O_PATH | O_DIRECTORY);
    if (fd < 0 || name_of(fd, by_fd) || strncmp(by_fd, "/proc/", 6) || !strcmp(by_fd, "/proc/self")) status |= 16;
    close(fd);

    if (status) {
        printf("procfd %d (%s, %s)\n", status, exe, by_fd);
        return 1;
    }
    printf("procfd ok\n");
    return 0;
}
