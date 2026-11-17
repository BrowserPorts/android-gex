// vtdecl: a class whose vtable is emitted where a virtual's return type is
// incomplete (vtdecl.cpp), its definition in another object (vtdecl2.cpp).
struct VtEvent;
struct VtBase {
  virtual ~VtBase();
  virtual VtEvent make(int v);
  int seed = 7;
};
int vt_use(VtBase *b, int v);
