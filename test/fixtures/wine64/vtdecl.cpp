// vtdecl: this object emits VtBase's vtable (its key function, ~VtBase, is
// defined here) while VtEvent is incomplete, so clang declares VtBase::make,
// which the vtable takes the address of, with a placeholder `void ()` type.
// No entry thunk may be made from that declaration: it would call make
// through the wrong type. The address comes from vtdecl2.cpp's definition.
#include <stdio.h>
#include "vtdecl.h"
VtBase::~VtBase() {}
int main() {
  VtBase b;
  int r = vt_use(&b, 5);
  printf("vtdecl: %s %d\n", r == 5 + 6 + 7 + 3 * 7 ? "ok" : "FAIL", r);
  return r == 5 + 6 + 7 + 3 * 7 ? 0 : 1;
}
