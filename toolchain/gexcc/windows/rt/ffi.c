/* gexcc-win's libffi: libffi 3's ffi_prep_cif and ffi_call for native
 * wasm64 modules under gex (include-rt/ffi.h says what reaches what).
 *
 * A native callee's wasm type follows clang's WebAssembly C ABI as gexcc-win
 * builds (LLP64 lowered: long is i32, pointers i64): integers of 32 bits
 * or fewer are i32, 64-bit ones and pointers i64, float f32, double and long
 * double f64. A struct whose one element (recursively) is a scalar of the
 * struct's size goes as that scalar; any other struct by value goes as a
 * pointer to a copy, and one returned goes through a pointer the caller
 * passes first (the function then returns nothing). A variadic call's
 * variable arguments go in a buffer (each at its alignment, at least 4,
 * every one taking a multiple of 4 bytes) whose pointer follows the fixed
 * ones.
 *
 * A guest callee is called as Win64 calls: one 8-byte slot per argument, a
 * struct of 1, 2, 4 or 8 bytes in its slot and any other as a pointer to a
 * copy, a returned struct of another size through a pointer in the first
 * slot. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ffi.h>

__attribute__((import_module("gex"), import_name("ffi_thunk")))
unsigned long long __gexw_ffi_thunk(const char *sig, unsigned int len);
unsigned long long __gexw_ffi_icall_limit(void);
uint64_t __gexw_guest_call64(uint64_t target, const uint64_t *slots, uint32_t n, uint32_t fp);

#define SCALAR(name, sz, t) ffi_type ffi_type_##name = { sz, sz, t, NULL };
SCALAR(void, 1, FFI_TYPE_VOID)
SCALAR(uint8, 1, FFI_TYPE_UINT8)
SCALAR(sint8, 1, FFI_TYPE_SINT8)
SCALAR(uint16, 2, FFI_TYPE_UINT16)
SCALAR(sint16, 2, FFI_TYPE_SINT16)
SCALAR(uint32, 4, FFI_TYPE_UINT32)
SCALAR(sint32, 4, FFI_TYPE_SINT32)
SCALAR(uint64, 8, FFI_TYPE_UINT64)
SCALAR(sint64, 8, FFI_TYPE_SINT64)
SCALAR(float, 4, FFI_TYPE_FLOAT)
SCALAR(double, 8, FFI_TYPE_DOUBLE)
SCALAR(longdouble, 8, FFI_TYPE_DOUBLE)
SCALAR(pointer, 8, FFI_TYPE_POINTER)

/* a struct's size and alignment, from its elements, when it has none yet */
static ffi_status init_type(ffi_type *t)
{
    size_t size = 0;
    unsigned short align = 1;
    ffi_type **e;

    switch (t->type)
    {
    case FFI_TYPE_VOID: case FFI_TYPE_INT: case FFI_TYPE_FLOAT: case FFI_TYPE_DOUBLE:
    case FFI_TYPE_UINT8: case FFI_TYPE_SINT8: case FFI_TYPE_UINT16: case FFI_TYPE_SINT16:
    case FFI_TYPE_UINT32: case FFI_TYPE_SINT32: case FFI_TYPE_UINT64: case FFI_TYPE_SINT64:
    case FFI_TYPE_POINTER:
        return t->size ? FFI_OK : FFI_BAD_TYPEDEF;
    case FFI_TYPE_STRUCT:
        break;
    default:
        return FFI_BAD_TYPEDEF;
    }
    if (!t->elements || !t->elements[0]) return FFI_BAD_TYPEDEF;
    if (t->size && t->alignment) return FFI_OK;
    for (e = t->elements; *e; e++)
    {
        if ((*e)->type == FFI_TYPE_VOID || init_type(*e) != FFI_OK) return FFI_BAD_TYPEDEF;
        size = (size + (*e)->alignment - 1) & ~((size_t)(*e)->alignment - 1);
        size += (*e)->size;
        if ((*e)->alignment > align) align = (*e)->alignment;
    }
    t->size = (size + align - 1) & ~((size_t)align - 1);
    t->alignment = align;
    return FFI_OK;
}

ffi_status ffi_get_struct_offsets(ffi_abi abi, ffi_type *t, size_t *offsets)
{
    size_t off = 0;
    ffi_type **e;
    if (abi <= FFI_FIRST_ABI || abi >= FFI_LAST_ABI) return FFI_BAD_ABI;
    if (t->type != FFI_TYPE_STRUCT || init_type(t) != FFI_OK) return FFI_BAD_TYPEDEF;
    for (e = t->elements; *e; e++)
    {
        off = (off + (*e)->alignment - 1) & ~((size_t)(*e)->alignment - 1);
        if (offsets) *offsets++ = off;
        off += (*e)->size;
    }
    return FFI_OK;
}

/* the scalar a struct goes as (its one element's, recursively, when that is
 * the struct's size), the type itself for a scalar, or NULL */
static ffi_type *as_scalar(ffi_type *t)
{
    while (t->type == FFI_TYPE_STRUCT)
    {
        if (!t->elements[0] || t->elements[1] || t->elements[0]->size != t->size) return NULL;
        t = t->elements[0];
    }
    return t;
}

static char wasm_letter(const ffi_type *t)
{
    switch (t->type)
    {
    case FFI_TYPE_VOID: return 'v';
    case FFI_TYPE_FLOAT: return 'f';
    case FFI_TYPE_DOUBLE: return 'd';
    case FFI_TYPE_UINT64: case FFI_TYPE_SINT64: case FFI_TYPE_POINTER: return 'I';
    default: return 'i';
    }
}

/* the integer at `p` of type `t`, extended to 64 bits as its signedness says */
static uint64_t load_int(const ffi_type *t, const void *p)
{
    switch (t->type)
    {
    case FFI_TYPE_UINT8: return *(const uint8_t *)p;
    case FFI_TYPE_SINT8: return (uint64_t)(int64_t)*(const int8_t *)p;
    case FFI_TYPE_UINT16: return *(const uint16_t *)p;
    case FFI_TYPE_SINT16: return (uint64_t)(int64_t)*(const int16_t *)p;
    case FFI_TYPE_UINT32: return *(const uint32_t *)p;
    case FFI_TYPE_INT: case FFI_TYPE_SINT32: return (uint64_t)(int64_t)*(const int32_t *)p;
    default: { uint64_t v; memcpy(&v, p, 8); return v; }
    }
}

static int is_integer(const ffi_type *t)
{
    return t->type != FFI_TYPE_VOID && t->type != FFI_TYPE_FLOAT && t->type != FFI_TYPE_DOUBLE && t->type != FFI_TYPE_STRUCT;
}

static ffi_status prep(ffi_cif *cif, ffi_abi abi, unsigned nfixed, unsigned nargs, ffi_type *rtype, ffi_type **atypes)
{
    unsigned i;
    if (abi <= FFI_FIRST_ABI || abi >= FFI_LAST_ABI) return FFI_BAD_ABI;
    if (nfixed > nargs || init_type(rtype) != FFI_OK) return FFI_BAD_TYPEDEF;
    for (i = 0; i < nargs; i++)
        if (!atypes[i] || atypes[i]->type == FFI_TYPE_VOID || init_type(atypes[i]) != FFI_OK) return FFI_BAD_TYPEDEF;
    /* (a variable argument as C promotes it: no float, no integer narrower than int) */
    for (i = nfixed; i < nargs; i++)
    {
        ffi_type *t = atypes[i];
        if (t->type == FFI_TYPE_FLOAT || ((t->type == FFI_TYPE_UINT8 || t->type == FFI_TYPE_SINT8 || t->type == FFI_TYPE_UINT16 || t->type == FFI_TYPE_SINT16)))
            return FFI_BAD_ARGTYPE;
    }
    cif->abi = abi;
    cif->nargs = nargs;
    cif->nfixed = nfixed;
    cif->arg_types = atypes;
    cif->rtype = rtype;
    cif->bytes = 8 * nargs;
    cif->flags = 0;
    cif->thunk = 0;
    return FFI_OK;
}

ffi_status ffi_prep_cif(ffi_cif *cif, ffi_abi abi, unsigned int nargs, ffi_type *rtype, ffi_type **atypes)
{
    return prep(cif, abi, nargs, nargs, rtype, atypes);
}

ffi_status ffi_prep_cif_var(ffi_cif *cif, ffi_abi abi, unsigned int nfixedargs, unsigned int ntotalargs,
                            ffi_type *rtype, ffi_type **atypes)
{
    ffi_status s = prep(cif, abi, nfixedargs, ntotalargs, rtype, atypes);
    if (s == FFI_OK) cif->flags = 1;
    return s;
}

/* the value at `r` (`t`'s, as the callee left it in its own width) into
 * libffi's rvalue: an integer narrower than ffi_arg widened to it */
static void store_result(const ffi_type *rt, const ffi_type *s, void *rvalue, const void *r)
{
    if (rt->type == FFI_TYPE_VOID) return;
    if (rt->type == FFI_TYPE_STRUCT) { memcpy(rvalue, r, rt->size); return; }
    if (s->type == FFI_TYPE_FLOAT) { memcpy(rvalue, r, 4); return; }
    if (s->type == FFI_TYPE_DOUBLE) { memcpy(rvalue, r, 8); return; }
    *(ffi_arg *)rvalue = load_int(s, r);
}

static void call_guest(ffi_cif *cif, uint64_t fn, void *rvalue, void **avalue)
{
    ffi_type *rt = cif->rtype;
    size_t rs = rt->size;
    int sret = rt->type == FFI_TYPE_STRUCT && rs != 1 && rs != 2 && rs != 4 && rs != 8;
    unsigned n = cif->nargs + sret, k = 0, i;
    uint64_t *slots = __builtin_alloca(8 * (n ? n : 1)), r;
    int fp = rt->type == FFI_TYPE_FLOAT || rt->type == FFI_TYPE_DOUBLE;

    if (sret) slots[k++] = (uint64_t)(uintptr_t)rvalue;
    for (i = 0; i < cif->nargs; i++, k++)
    {
        ffi_type *t = cif->arg_types[i];
        size_t ts = t->size;
        slots[k] = 0;
        if (t->type == FFI_TYPE_STRUCT)
        {
            if (ts == 1 || ts == 2 || ts == 4 || ts == 8) memcpy(&slots[k], avalue[i], ts);
            else
            {
                void *copy = __builtin_alloca_with_align(ts, 128);
                memcpy(copy, avalue[i], ts);
                slots[k] = (uint64_t)(uintptr_t)copy;
            }
        }
        else if (t->type == FFI_TYPE_FLOAT) memcpy(&slots[k], avalue[i], 4);
        else if (t->type == FFI_TYPE_DOUBLE) memcpy(&slots[k], avalue[i], 8);
        else slots[k] = load_int(t, avalue[i]);
    }
    r = __gexw_guest_call64(fn, slots, n, fp);
    if (sret) return;
    if (rt->type == FFI_TYPE_STRUCT) { memcpy(rvalue, &r, rs); return; }
    store_result(rt, rt, rvalue, &r);
}

static void call_native(ffi_cif *cif, uint64_t fn, void *rvalue, void **avalue)
{
    ffi_type *rt = cif->rtype, *rs = as_scalar(rt);
    int sret = !rs, var = cif->flags & 1;
    unsigned np = sret + cif->nfixed + var, k = 0, i;
    uint64_t *tmp = __builtin_alloca(8 * (np ? np : 1));
    void **av = __builtin_alloca(sizeof(void *) * (np ? np : 1));
    uint64_t rbuf[2] = { 0, 0 };
    void (*thunk)(uint64_t, void **, void *);

    if (!cif->thunk)
    {
        char *sig = __builtin_alloca(np + 3);
        unsigned m = 0;
        if (sret) sig[m++] = 'I';
        for (i = 0; i < cif->nfixed; i++)
        {
            ffi_type *s = as_scalar(cif->arg_types[i]);
            sig[m++] = s ? wasm_letter(s) : 'I';
        }
        if (var) sig[m++] = 'I';
        sig[m++] = ':';
        sig[m++] = sret ? 'v' : wasm_letter(rs);
        cif->thunk = __gexw_ffi_thunk(sig, m);
    }
    if (sret) { tmp[k] = (uint64_t)(uintptr_t)rvalue; av[k] = &tmp[k]; k++; }
    for (i = 0; i < cif->nfixed; i++, k++)
    {
        ffi_type *t = cif->arg_types[i], *s = as_scalar(t);
        if (!s)
        {
            void *copy = __builtin_alloca_with_align(t->size, 128);
            memcpy(copy, avalue[i], t->size);
            tmp[k] = (uint64_t)(uintptr_t)copy;
            av[k] = &tmp[k];
        }
        else if (wasm_letter(s) == 'i')
        {
            tmp[k] = load_int(s, avalue[i]);
            av[k] = &tmp[k];
        }
        else av[k] = avalue[i];
    }
    if (var)
    {
        /* clang's WebAssembly va_list: each at its alignment (at least 4),
         * each taking a multiple of 4 bytes; a struct that is not a scalar
         * as a pointer to a copy */
        size_t size = 0, off = 0;
        unsigned char *buf;
        for (i = cif->nfixed; i < cif->nargs; i++)
        {
            ffi_type *t = cif->arg_types[i];
            size_t ts = as_scalar(t) ? t->size : 8, ta = as_scalar(t) ? t->alignment : 8;
            if (ta < 4) ta = 4;
            size = (size + ta - 1) & ~(ta - 1);
            size += (ts + 3) & ~(size_t)3;
        }
        buf = __builtin_alloca_with_align(size ? size : 8, 128);
        for (i = cif->nfixed; i < cif->nargs; i++)
        {
            ffi_type *t = cif->arg_types[i];
            size_t ts = as_scalar(t) ? t->size : 8, ta = as_scalar(t) ? t->alignment : 8;
            if (ta < 4) ta = 4;
            off = (off + ta - 1) & ~(ta - 1);
            if (as_scalar(t)) memcpy(buf + off, avalue[i], ts);
            else
            {
                void *copy = __builtin_alloca_with_align(t->size, 128);
                uint64_t p = (uint64_t)(uintptr_t)copy;
                memcpy(copy, avalue[i], t->size);
                memcpy(buf + off, &p, 8);
            }
            off += (ts + 3) & ~(size_t)3;
        }
        tmp[k] = (uint64_t)(uintptr_t)buf;
        av[k] = &tmp[k];
        k++;
    }
    thunk = (void (*)(uint64_t, void **, void *))(uintptr_t)cif->thunk;
    thunk(fn, av, rbuf);
    if (!sret) store_result(rt, rs, rvalue, rbuf);
}

void ffi_call(ffi_cif *cif, void (*fn)(void), void *rvalue, void **avalue)
{
    uint64_t f = (uint64_t)(uintptr_t)fn;
    uint64_t rdummy[4];
    /* (libffi allows a null rvalue for a result the caller ignores) */
    if (!rvalue && cif->rtype->type != FFI_TYPE_VOID)
        rvalue = cif->rtype->size <= sizeof(rdummy) ? (void *)rdummy : __builtin_alloca_with_align(cif->rtype->size, 128);
    if (f < __gexw_ffi_icall_limit()) call_native(cif, f, rvalue, avalue);
    else call_guest(cif, f, rvalue, avalue);
}

/* Closures. A closure's function value is a guest address: the closure
 * itself, where ffi_prep_closure_loc writes a skeleton stub (ud2; ud2) and
 * gex binds the address (gex.ffi_closure) to this module's one closure
 * entry, as it binds an export's skeleton to its adapter. A call reaches it
 * as any guest function: guest code calls it, native code through the ICALL
 * exit stub (the value is above gex.icall_limit64) and __gexw_guest_call64.
 * The entry finds the closure by the address the call went to
 * (ctx::LAST_TARGET), reads the arguments as Win64 passed them (call_guest's
 * layout, the other way), and calls the closure's function. No code is made
 * per closure, so it is the same with and without gex's JIT. */
__attribute__((import_module("gex"), import_name("ffi_closure")))
int __gexw_ffi_closure_bind(unsigned long long addr, unsigned long long entry);
__attribute__((import_module("gex"), import_name("ffi_closure_free")))
void __gexw_ffi_closure_unbind(unsigned long long addr);

uint64_t __gexw_arg(int ctx, uint32_t k);
double __gexw_argf64(int ctx, uint32_t k);
float __gexw_argf32(int ctx, uint32_t k);
uint64_t __gexw_argptr(int ctx, uint32_t k);
int __gexw_ret(int ctx, uint64_t ret, uint64_t rax);
int __gexw_ret_void(int ctx, uint64_t ret);
int __gexw_ret_f64(int ctx, uint64_t ret, double v);
int __gexw_ret_f32(int ctx, uint64_t ret, float v);
int __gexw_entry(int ctx, int depth, unsigned int need, unsigned long long ret,
                 int (*body)(int, int, unsigned int, unsigned long long));

/* gex_abi::ctx::LAST_TARGET: the address the guest's call went to */
#define GEXW_CTX_LAST_TARGET 352u

static int win64_small(size_t size)
{
    return size == 1 || size == 2 || size == 4 || size == 8;
}

static int __gexw_ffi_closure_body(int ctx, int depth, unsigned int need, unsigned long long ret)
{
    ffi_closure *c = (ffi_closure *)(uintptr_t)*(uint64_t *)(uintptr_t)(uint32_t)(ctx + GEXW_CTX_LAST_TARGET);
    ffi_cif *cif = c->cif;
    ffi_type *rt = cif->rtype;
    int sret = rt->type == FFI_TYPE_STRUCT && !win64_small(rt->size);
    unsigned n = cif->nargs, k = sret, i;
    void **av = __builtin_alloca(sizeof(void *) * (n ? n : 1));
    uint64_t *vals = __builtin_alloca(8 * (n ? n : 1));
    uint64_t rbuf[4] = { 0, 0, 0, 0 };
    void *rv = sret ? (void *)(uintptr_t)__gexw_arg(ctx, 0) : (void *)rbuf;
    uint64_t r = 0;
    (void)depth; (void)need;

    for (i = 0; i < n; i++, k++)
    {
        ffi_type *t = cif->arg_types[i];
        if (t->type == FFI_TYPE_STRUCT)
            av[i] = (void *)(uintptr_t)(win64_small(t->size) ? __gexw_argptr(ctx, k) : __gexw_arg(ctx, k));
        else if (t->type == FFI_TYPE_FLOAT) { float f = __gexw_argf32(ctx, k); vals[i] = 0; memcpy(&vals[i], &f, 4); av[i] = &vals[i]; }
        else if (t->type == FFI_TYPE_DOUBLE) { double d = __gexw_argf64(ctx, k); memcpy(&vals[i], &d, 8); av[i] = &vals[i]; }
        else { vals[i] = __gexw_arg(ctx, k); av[i] = &vals[i]; }
    }
    c->fun(cif, rv, av, c->user_data);
    if (sret) return __gexw_ret(ctx, ret, (uint64_t)(uintptr_t)rv);
    switch (rt->type)
    {
    case FFI_TYPE_VOID: return __gexw_ret_void(ctx, ret);
    case FFI_TYPE_FLOAT: { float f; memcpy(&f, rbuf, 4); return __gexw_ret_f32(ctx, ret, f); }
    case FFI_TYPE_DOUBLE: { double d; memcpy(&d, rbuf, 8); return __gexw_ret_f64(ctx, ret, d); }
    case FFI_TYPE_STRUCT: memcpy(&r, rbuf, rt->size); return __gexw_ret(ctx, ret, r);
    default: return __gexw_ret(ctx, ret, rbuf[0]);  /* (libffi widens it to ffi_arg) */
    }
}

/* the entry gex binds each closure's address to (an adapter's type) */
static int __gexw_ffi_closure_entry(int ctx, int depth, unsigned int need, unsigned long long ret)
{
    return __gexw_entry(ctx, depth, need, ret, __gexw_ffi_closure_body);
}

void *ffi_closure_alloc(size_t size, void **code)
{
    /* (16-aligned, as Win64's heap gives every block) */
    void *c = calloc(1, size < sizeof(ffi_closure) ? sizeof(ffi_closure) : size);
    if (code) *code = c;
    return c;
}

void ffi_closure_free(void *closure)
{
    ffi_closure *c = closure;
    if (!c) return;
    if (c->tramp[0] == 0x0f) __gexw_ffi_closure_unbind((uint64_t)(uintptr_t)c);
    free(c);
}

ffi_status ffi_prep_closure_loc(ffi_closure *closure, ffi_cif *cif,
                                void (*fun)(ffi_cif *, void *, void **, void *), void *user_data, void *codeloc)
{
    static const unsigned char stub[4] = { 0x0f, 0x0b, 0x0f, 0x0b };
    /* (the entry finds the closure at the address called: the code is the
     * closure, as ffi_closure_alloc gives it) */
    if (!closure || codeloc != (void *)closure || ((uintptr_t)closure & 15)) return FFI_BAD_ABI;
    if (cif->abi <= FFI_FIRST_ABI || cif->abi >= FFI_LAST_ABI) return FFI_BAD_ABI;
    closure->cif = cif;
    closure->fun = fun;
    closure->user_data = user_data;
    if (closure->tramp[0] == 0x0f) return FFI_OK;  /* bound already: a new cif, function or data */
    memcpy(closure->tramp, stub, sizeof(stub));
    if (__gexw_ffi_closure_bind((uint64_t)(uintptr_t)closure, (uint64_t)(uintptr_t)&__gexw_ffi_closure_entry))
    {
        memset(closure->tramp, 0, sizeof(stub));
        return FFI_BAD_ABI;
    }
    return FFI_OK;
}

ffi_status ffi_prep_closure(ffi_closure *closure, ffi_cif *cif,
                            void (*fun)(ffi_cif *, void *, void **, void *), void *user_data)
{
    return ffi_prep_closure_loc(closure, cif, fun, user_data, closure);
}
