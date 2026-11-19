/* write(2) with a count far past its small buffer, and writes far past a
 * file's end: each gives a count or an error, never kills the kernel. The
 * kernel is wasm32, so a guest's length or offset is wider than its
 * `usize`: a write of 1286 bytes far past a file's end grew the file's block
 * list past what a Vec can hold (a "capacity overflow" panic in the global
 * kernel, which took every process with it), and a write past 4 GiB of an
 * in-memory file wrapped to its start. core/big-write runs this as each
 * ABI's program (x86-64 and aarch64, static) and as wasm32 (rt-bigwrite).
 *
 *   big-write DIR   prints one line a case and "big-write ok" */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

static int bad;

static void counted(const char *what, int fd, size_t count) {
    static char small[16] = "0123456789abcdef";
    errno = 0;
    ssize_t n = write(fd, small, count);
    /* EFAULT (or, as Linux does, the bytes written before the fault) */
    int ok = n < 0 ? errno == EFAULT : (size_t)n <= count;
    printf("%s: %s\n", what, n < 0 ? strerror(errno) : ok ? "a count" : "too many");
    bad |= !ok;
}

static void far(const char *dir, const char *what, int64_t off) {
    char p[256], buf[1286], got[1286] = {0}, head[5] = {0};
    snprintf(p, sizeof p, "%s/big-write.tmp", dir);
    int f = open(p, O_RDWR | O_CREAT | O_TRUNC, 0644);
    write(f, "head", 4);
    memset(buf, 'x', sizeof buf);
    errno = 0;
    ssize_t n = pwrite(f, buf, sizeof buf, off);
    const char *r;
    if (n < 0) {
        /* too big for this file system, or no room for it */
        r = errno == EFBIG || errno == ENOSPC || errno == EINVAL ? "refused" : "wrong error";
        bad |= *r == 'w';
    } else {
        struct stat st;
        pread(f, got, sizeof got, off);
        pread(f, head, 4, 0);
        fstat(f, &st);
        /* the length too: a write wrapped to 32 bits reads back from where
         * it landed, but leaves the file short */
        r = n == (ssize_t)sizeof buf && !memcmp(got, buf, sizeof buf) && !strcmp(head, "head") && st.st_size == off + (off_t)sizeof buf ? "there" : "elsewhere";
        bad |= *r == 'e';
    }
    printf("%s past the end: %s\n", what, r);
    close(f);
    unlink(p);
}

int main(int argc, char **argv) {
    const char *dir = argc > 1 ? argv[1] : "/tmp";
    int pf[2], nul = open("/dev/null", O_WRONLY);
    char p[256];
    snprintf(p, sizeof p, "%s/big-write.cnt", dir);
    int f = open(p, O_RDWR | O_CREAT | O_TRUNC, 0644);
    pipe(pf);
    fcntl(pf[1], F_SETFL, O_NONBLOCK);
    const size_t counts[] = {SIZE_MAX, SIZE_MAX / 2, (size_t)1 << 31, (size_t)UINT32_MAX};
    for (int i = 0; i < 4; i++) {
        char w[64];
        snprintf(w, sizeof w, "count %d to a file", i);
        counted(w, f, counts[i]);
        snprintf(w, sizeof w, "count %d to a pipe", i);
        counted(w, pf[1], counts[i]);
        snprintf(w, sizeof w, "count %d to /dev/null", i);
        counted(w, nul, counts[i]);
    }
    close(f);
    unlink(p);
    far(dir, "2 GiB", (int64_t)1 << 31);
    far(dir, "4 GiB", ((int64_t)1 << 32) + 100);
    far(dir, "5 GiB", ((int64_t)5 << 30) + 100);
    far(dir, "2 TiB", (int64_t)1 << 41);
    /* with 64 KiB blocks (an OPFSFilesystem's), block 2^30 and block
     * 2^32 + 2^29: a block list of 4 GiB, or one whose number wraps to 32
     * bits onto 2 GiB of list */
    far(dir, "64 TiB", (int64_t)1 << 46);
    far(dir, "2^48 + 2^45", ((int64_t)1 << 48) + ((int64_t)1 << 45));
    far(dir, "2^62", (int64_t)1 << 62);
    puts(bad ? "big-write FAILED" : "big-write ok");
    return bad;
}
