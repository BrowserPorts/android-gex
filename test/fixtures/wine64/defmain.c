/* defdll.dll's exports: a call, and its data written and read on both sides */
#include <stdio.h>
__declspec(dllimport) int defdll_get(void);
__declspec(dllimport) extern int defdll_val, defdll_val2;
int main(void)
{
    int a = defdll_get();
    defdll_val = 43;
    int b = defdll_get();
    printf(a == 42 && b == 43 && defdll_val2 == 7 ? "defdll: ok\n" : "defdll: failed %d %d %d\n", a, b, defdll_val2);
    return !(a == 42 && b == 43 && defdll_val2 == 7);
}
