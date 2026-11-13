// bionic starts, its allocator and stdio work, and the program's arguments
// and exit status are its own.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    (void)argv;
    if (argc != 1) {
        printf("argc %d\n", argc);
        return 1;
    }
    size_t n = 1 << 20;
    unsigned char *p = malloc(n);
    if (!p) {
        perror("malloc");
        return 1;
    }
    memset(p, 7, n);
    unsigned sum = 0;
    for (size_t i = 0; i < n; i += 4096) sum += p[i];
    free(p);
    if (sum != 7 * (n / 4096)) {
        printf("sum %u\n", sum);
        return 1;
    }
    printf("hello ok\n");
    return 0;
}
