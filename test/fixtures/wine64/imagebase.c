/* `&__ImageBase`, the image's own base as MSVC's and MinGW's linkers define
 * it, is the program's module handle; so is it through an offset into the
 * headers (a constant expression) and when chosen in a branch (a phi). */
#include <windows.h>
#include <stdio.h>

extern IMAGE_DOS_HEADER __ImageBase;

static __attribute__((noinline)) const void *pick(int k)
{
    return k ? (const void *)&__ImageBase : (const void *)GetModuleHandleW(NULL);
}

int main(int argc, char **argv)
{
    HMODULE self = GetModuleHandleW(NULL);
    int base = (HMODULE)&__ImageBase == self;
    int lfanew = (const char *)&__ImageBase.e_lfanew - (const char *)self == 0x3c;
    int phi = pick(argc > 0) == (const void *)self;
    int mz = __ImageBase.e_magic == IMAGE_DOS_SIGNATURE;
    printf("imagebase: base %d lfanew %d phi %d mz %d\n", base, lfanew, phi, mz);
    if (base && lfanew && phi && mz) printf("imagebase ok\n");
    return 0;
}
