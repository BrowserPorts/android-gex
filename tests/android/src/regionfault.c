// A loop whose head sets a register its inner loop uses, where the inner
// loop faults and a handler lets the access through and returns: the
// shape of ART's ClassLinker::FindClass, whose class-table probe reads
// objects ART's collector faults in. The register must be what the head
// set when the faulting access runs again. Translated as one region, the
// fault path once wrote back only what the emitter had seen written so
// far, and the head is emitted after the probe: the register came back
// as it was before the loop, the probe's bound with it, and it never
// ended. Each round protects the table's page again, so every round
// faults once inside the probe.
#define _GNU_SOURCE
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define ROUNDS 50
#define TABLES 32
#define SLOTS 64

static uint32_t *tables[TABLES];
static uint64_t bounds[TABLES];
static volatile long faults;

static void on_segv(int sig, siginfo_t *si, void *uc) {
    (void)sig;
    (void)uc;
    uintptr_t page = (uintptr_t)si->si_addr & ~(uintptr_t)4095;
    for (int k = 0; k < TABLES; k++) {
        if (page == (uintptr_t)tables[k]) {
            faults++;
            mprotect(tables[k], 4096, PROT_READ | PROT_WRITE);
            return;
        }
    }
    _exit(3);
}

// One pass over the tables, as FindClass's walk over its class sets: the
// loop's head takes the table and its bound (x19), and the probe looks
// from slot 0 for an empty slot, wrapping at the bound, giving up after
// `limit` steps. The first read of each table faults (its page is
// protected), inside the probe, after the head has set x19. Tables found.
static long pass(long limit) {
    uint64_t found;
    __asm__ volatile(
        "mov x19, #0\n"
        "mov x26, #0\n"
        "mov %[found], #0\n"
        "0:\n"
        "ldr x19, [%[bounds], x26, lsl #3]\n"
        // As FindClass's: an empty set is skipped, which ends the head's
        // block, so the probe's first read is in a later one.
        "cbz x19, 3f\n"
        "ldr x8, [%[tables], x26, lsl #3]\n"
        "mov x24, #0\n"
        "mov x25, #0\n"
        "1:\n"
        "ldr w10, [x8, x24, lsl #2]\n"
        "cbz w10, 2f\n"
        // More blocks in the probe, as FindClass's has (a hash check and a
        // descriptor compare): the region grown from the outer head stops
        // at its block limit before it meets the probe's own back edge, and
        // so takes the probe's head in as a member.
        "tbnz w10, #31, 4f\n"
        "tbnz w10, #30, 4f\n"
        "tbnz w10, #29, 4f\n"
        "tbnz w10, #28, 4f\n"
        "tbnz w10, #27, 4f\n"
        "tbnz w10, #26, 4f\n"
        "tbnz w10, #25, 4f\n"
        "tbnz w10, #24, 4f\n"
        "4:\n"
        "add x25, x25, #1\n"
        "cmp x25, %[limit]\n"
        "b.hs 3f\n"
        "add x9, x24, #1\n"
        "cmp x9, x19\n"
        "csinc x24, xzr, x24, hs\n"
        "b 1b\n"
        "2:\n"
        "add %[found], %[found], #1\n"
        "3:\n"
        "add x26, x26, #1\n"
        "cmp x26, %[n]\n"
        "b.lo 0b\n"
        : [found] "=&r"(found)
        : [tables] "r"(tables), [bounds] "r"(bounds), [limit] "r"(limit), [n] "r"((uint64_t)TABLES)
        : "x8", "x9", "x10", "x19", "x24", "x25", "x26", "cc", "memory");
    return (long)found;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    for (int k = 0; k < TABLES; k++) {
        tables[k] = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (tables[k] == MAP_FAILED) {
            printf("mmap failed\n");
            return 1;
        }
        // Full but for the last slot of its bound, as a probe that starts
        // at 0 must walk to it.
        bounds[k] = 8 + k;
        for (uint64_t i = 0; i < SLOTS; i++) tables[k][i] = i == bounds[k] - 1 ? 0 : 0x100 + i;
    }
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_segv;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);
    long found = 0;
    for (int r = 0; r < ROUNDS; r++) {
        for (int k = 0; k < TABLES; k++) mprotect(tables[k], 4096, PROT_NONE);
        found += pass(4 * SLOTS);
    }
    printf("passes %d, tables found %ld of %d, faults %s\n", ROUNDS, found, ROUNDS * TABLES, faults == ROUNDS * TABLES ? "one a table" : "not one a table");
    printf("%s\n", found == ROUNDS * TABLES ? "regionfault ok" : "regionfault: a probe lost its bound");
    return 0;
}
