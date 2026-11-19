// A file mapping is whole pages: the bytes of its last page past the
// length asked for are the file's, and zero only past the file's end. A
// mapping read only to its length left the rest of the page zero, and a
// read of the file at those offsets, which takes in what the process's
// shared mappings of it hold, returned the zeros: libziparchive mapped a
// 40-byte zip entry, found no local header just after it, and Android's
// package manager could not parse an APEX.
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#define P 4096
static const char expected[] =
    "private, 40 bytes: byte 100 is the file's: yes, byte 4095: yes\n"
    "shared, 40 bytes: byte 100 is the file's: yes, byte 4095: yes\n"
    "read of the next 30 bytes with the shared mapping there: the file's\n"
    "last page, 40 bytes of a file ending 300 into it: byte 299 the file's: yes, byte 300 zero: yes\n";
static char out[1024];
static size_t used;
static void say(const char *s) {
    fputs(s, stdout);
    size_t n = strlen(s);
    if (used + n < sizeof out) {
        memcpy(out + used, s, n);
        used += n;
    }
}
static unsigned char at(long i) { return (unsigned char)(i * 7 + 3); }
int main(void) {
    char path[] = "/data/local/tmp/mapfill.XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) {
        snprintf(path, sizeof path, "/tmp/mapfill.XXXXXX");
        fd = mkstemp(path);
    }
    if (fd < 0) {
        perror("mkstemp");
        return 1;
    }
    unlink(path);
    const long size = 2 * P + 300;
    unsigned char *file = malloc(size);
    for (long i = 0; i < size; i++) file[i] = at(i);
    if (write(fd, file, size) != size) {
        perror("write");
        return 1;
    }
    char line[200];
    for (int shared = 0; shared < 2; shared++) {
        unsigned char *p = mmap(0, 40, PROT_READ, shared ? MAP_SHARED : MAP_PRIVATE, fd, 0);
        snprintf(line, sizeof line, "%s, 40 bytes: byte 100 is the file's: %s, byte 4095: %s\n", shared ? "shared" : "private",
                 p[100] == at(100) ? "yes" : "no", p[4095] == at(4095) ? "yes" : "no");
        say(line);
        if (shared) {
            unsigned char buf[30];
            ssize_t n = pread(fd, buf, sizeof buf, 40);
            say(n == 30 && memcmp(buf, file + 40, 30) == 0 ? "read of the next 30 bytes with the shared mapping there: the file's\n"
                                                           : "read of the next 30 bytes with the shared mapping there: not the file's\n");
        }
        munmap(p, 40);
    }
    unsigned char *q = mmap(0, 40, PROT_READ, MAP_SHARED, fd, 2 * P);
    snprintf(line, sizeof line, "last page, 40 bytes of a file ending 300 into it: byte 299 the file's: %s, byte 300 zero: %s\n",
             q[299] == at(2 * P + 299) ? "yes" : "no", q[300] == 0 ? "yes" : "no");
    say(line);
    if (strcmp(out, expected) != 0) {
        printf("mapfill: not what Linux shows\n");
        return 1;
    }
    printf("mapfill ok\n");
    return 0;
}
