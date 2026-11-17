/* Weak undefined data, tested by its address: it links, even without
 * GEXCC_WIN_UNDEFINED=stub, and its address is null. */
#include <stdio.h>
extern int wkdata_maybe __attribute__((weak));
int main(void) { printf("wkdata: %s\n", &wkdata_maybe ? "defined" : "null"); return 0; }
