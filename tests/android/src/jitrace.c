// Code run while another thread writes the page it is on again, as a JIT
// writes its code cache (ART's puts new methods beside ones that run): one
// thread calls small functions at many places in one executable page, each
// called for the first time after the page was last flushed, while another
// writes them again (the same instructions) and flushes the instruction
// cache over them. Every call must return what its function returns; the
// writer's flush must never make a call fault.
#define _GNU_SOURCE
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define FUNCS 256
#define STRIDE 16
#define CALLS 400000

static uint32_t *page;
static atomic_int done;

// `mov w0, #k; ret` at function k.
static void write_func(int k) {
    uint32_t *f = page + k * STRIDE / 4;
    f[0] = 0x52800000u | ((uint32_t)k << 5);
    f[1] = 0xd65f03c0u;
}

static void *writer(void *arg) {
    (void)arg;
    unsigned k = 0;
    while (!atomic_load(&done)) {
        write_func(k % FUNCS);
        __builtin___clear_cache((char *)(page + (k % FUNCS) * STRIDE / 4), (char *)(page + (k % FUNCS) * STRIDE / 4 + 2));
        k += 37;
    }
    return NULL;
}

int main(void) {
    page = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        printf("jitrace: mmap failed\n");
        return 1;
    }
    for (int k = 0; k < FUNCS; k++) write_func(k);
    __builtin___clear_cache((char *)page, (char *)page + 4096);
    pthread_t t;
    if (pthread_create(&t, NULL, writer, NULL)) {
        printf("jitrace: pthread_create failed\n");
        return 1;
    }
    unsigned k = 0;
    for (int i = 0; i < CALLS; i++) {
        k = (k + 101) % FUNCS;
        int (*f)(void) = (int (*)(void))(page + k * STRIDE / 4);
        int r = f();
        if (r != (int)k) {
            printf("jitrace: function %u returned %d\n", k, r);
            return 1;
        }
    }
    atomic_store(&done, 1);
    pthread_join(t, NULL);
    printf("jitrace ok\n");
    return 0;
}
