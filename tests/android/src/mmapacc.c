// What a file's access mode allows a mapping of it (mm/mmap.c's
// do_mmap): a shared mapping that may be written needs the file open for
// writing (EACCES), any mapping needs it open for reading (EACCES), and a
// private one may be written whatever the file allows, being a copy. A
// shared mapping of a file not open for writing never becomes writable
// (mprotect is EACCES).
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static int failed;

static void want(const char *what, void *p, int err) {
    int got = p == MAP_FAILED ? errno : 0;
    if (got != err) {
        printf("mmapacc: %s: want %d, got %d\n", what, err, got);
        failed = 1;
    }
    if (p != MAP_FAILED) munmap(p, 4096);
}

int main(void) {
    char path[] = "/tmp/mmapacc-XXXXXX";
    int w = mkstemp(path);
    if (w < 0 || ftruncate(w, 4096)) {
        printf("mmapacc: setup (errno %d)\n", errno);
        return 1;
    }
    int ro = open(path, O_RDONLY), wo = open(path, O_WRONLY), rw = open(path, O_RDWR);
    if (ro < 0 || wo < 0 || rw < 0) {
        printf("mmapacc: open (errno %d)\n", errno);
        return 1;
    }
    want("read-only, shared, written", mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, ro, 0), EACCES);
    want("read-only, shared, read", mmap(NULL, 4096, PROT_READ, MAP_SHARED, ro, 0), 0);
    want("read-only, private, written", mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE, ro, 0), 0);
    want("write-only, shared", mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, wo, 0), EACCES);
    want("write-only, private", mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, wo, 0), EACCES);
    want("read-write, shared, written", mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, rw, 0), 0);
    // Never writable, shared and not open for writing.
    void *p = mmap(NULL, 4096, PROT_READ, MAP_SHARED, ro, 0);
    if (p == MAP_FAILED || mprotect(p, 4096, PROT_READ | PROT_WRITE) != -1 || errno != EACCES) {
        printf("mmapacc: mprotect of a read-only shared mapping (errno %d)\n", errno);
        failed = 1;
    }
    if (p != MAP_FAILED) munmap(p, 4096);
    unlink(path);
    if (failed) return 1;
    printf("mmapacc ok\n");
    return 0;
}
