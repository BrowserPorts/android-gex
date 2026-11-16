#include "owndll.h"

OWN_API int own_count = 41;
OWN_API struct own_pt own_pt = {5, 7};

OWN_API int own_add(int a, int b) { return a + b + own_count; }
OWN_API int own_pt_sum(struct own_pt p) { return p.x * 10 + p.y; }
OWN_API int *own_count_addr(void) { return &own_count; }
OWN_API struct own_pt *own_pt_addr(void) { return &own_pt; }
OWN_API void own_bump(void) { own_count += 100; own_pt.y += 1; }
