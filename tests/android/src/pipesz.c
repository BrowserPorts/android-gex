// F_GETPIPE_SZ and F_SETPIPE_SZ: a pipe starts at 64 KiB; a new size is
// rounded up to a power of two of pages and returned, and is what the pipe
// then holds; a size below what is buffered is EBUSY; one over 2 GiB is
// EINVAL; one over /proc/sys/fs/pipe-max-size's default megabyte is EPERM
// without CAP_SYS_RESOURCE; a descriptor that is no pipe is EBADF.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static char block[70000];

static int fails(int fd, int cmd, long arg, int with) {
    errno = 0;
    return fcntl(fd, cmd, arg) == -1 && errno == with;
}

int main(void) {
    int status = 0;
    int p[2];
    if (pipe2(p, O_NONBLOCK)) return 2;

    if (fcntl(p[0], F_GETPIPE_SZ) != 65536 || fcntl(p[1], F_GETPIPE_SZ) != 65536) status |= 1;
    if (fcntl(p[1], F_SETPIPE_SZ, 1) != 4096 || fcntl(p[0], F_GETPIPE_SZ) != 4096) status |= 2;
    if (fcntl(p[0], F_SETPIPE_SZ, 0) != 4096) status |= 2;
    if (fcntl(p[1], F_SETPIPE_SZ, 5000) != 8192 || fcntl(p[1], F_GETPIPE_SZ) != 8192) status |= 2;

    // Two pages, and no more.
    memset(block, 'a', sizeof block);
    if (write(p[1], block, sizeof block) != 8192) status |= 4;
    errno = 0;
    if (write(p[1], block, 1) != -1 || errno != EAGAIN) status |= 4;

    if (!fails(p[1], F_SETPIPE_SZ, 4096, EBUSY) || fcntl(p[1], F_GETPIPE_SZ) != 8192) status |= 8;
    // Room again once it is larger.
    if (fcntl(p[1], F_SETPIPE_SZ, 16384) != 16384 || write(p[1], block, sizeof block) != 8192) status |= 8;
    if (read(p[0], block, sizeof block) != 16384) status |= 8;
    if (fcntl(p[1], F_SETPIPE_SZ, 4096) != 4096) status |= 8;

    if (!fails(p[1], F_SETPIPE_SZ, 0x80000001L, EINVAL) || !fails(p[1], F_SETPIPE_SZ, -1, EINVAL)) status |= 16;

    if (fcntl(p[1], F_SETPIPE_SZ, 1 << 20) != 1 << 20) status |= 32;
    if (geteuid() == 0) {
        if (fcntl(p[1], F_SETPIPE_SZ, (1 << 20) + 1) != 2 << 20) status |= 32;
    } else {
        if (!fails(p[1], F_SETPIPE_SZ, (1 << 20) + 1, EPERM) || fcntl(p[1], F_GETPIPE_SZ) != 1 << 20) status |= 32;
    }

    int null = open("/dev/null", O_RDWR);
    if (!fails(null, F_GETPIPE_SZ, 0, EBADF) || !fails(null, F_SETPIPE_SZ, 4096, EBADF)) status |= 64;
    if (!fails(99, F_GETPIPE_SZ, 0, EBADF)) status |= 64;

    if (status) {
        printf("pipesz %d\n", status);
        return 1;
    }
    printf("pipesz ok\n");
    return 0;
}
