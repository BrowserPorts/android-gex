/* The stack protector's guard and failure (-fstack-protector), as MinGW's
 * libssp provides them (gexcc-win): the guard from rand_s at startup. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

uintptr_t __stack_chk_guard = (uintptr_t)0x2f8a6c1d5e3b9047ull;

errno_t __cdecl rand_s(unsigned int *);

__attribute__((constructor)) static void gexcc_win_ssp_init(void)
{
    unsigned int a, b;
    if (!rand_s(&a) && !rand_s(&b))
        __stack_chk_guard = ((uintptr_t)a << 32 | b) & ~(uintptr_t)0xff;
}

void __stack_chk_fail(void)
{
    fputs("*** stack smashing detected ***: terminated\n", stderr);
    abort();
}
