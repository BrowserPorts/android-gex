/* psdk_inc/intrin-impl.h for gexcc-win: the intrinsics mingw-w64's headers
 * name for Windows x64, in portable C (mingw-w64's own are x86 inline asm).
 * The headers include it several times, each time for one group; this one
 * defines everything the first time. Port I/O, control and model-specific
 * registers are left out: a program that uses them fails to compile.
 * __readgs* and __writegs* read the TEB, which the x64 GS segment holds. */
#ifndef GEXW_INTRIN_IMPL_H
#define GEXW_INTRIN_IMPL_H

#include <_mingw.h>

#ifdef __cplusplus
extern "C" {
#endif

/* (as mingw-w64 has them: extern inline, as the C runtime declares some) */
#define __GEXW_INTRIN __MINGW_INTRIN_INLINE

#ifndef _ReadWriteBarrier
#define _ReadWriteBarrier() __atomic_signal_fence(__ATOMIC_SEQ_CST)
#define _ReadBarrier _ReadWriteBarrier
#define _WriteBarrier _ReadWriteBarrier
#endif

/* bit scans and tests */
__GEXW_INTRIN unsigned char _BitScanForward(unsigned __LONG32 *i, unsigned __LONG32 m)
{ if (!m) return 0; *i = __builtin_ctz(m); return 1; }
__GEXW_INTRIN unsigned char _BitScanReverse(unsigned __LONG32 *i, unsigned __LONG32 m)
{ if (!m) return 0; *i = 31 - __builtin_clz(m); return 1; }
__GEXW_INTRIN unsigned char _BitScanForward64(unsigned __LONG32 *i, unsigned __int64 m)
{ if (!m) return 0; *i = __builtin_ctzll(m); return 1; }
__GEXW_INTRIN unsigned char _BitScanReverse64(unsigned __LONG32 *i, unsigned __int64 m)
{ if (!m) return 0; *i = 63 - __builtin_clzll(m); return 1; }

#define __GEXW_BITTEST(name, T, op) \
  __GEXW_INTRIN unsigned char name(T *b, T o) { unsigned char r = (*b >> o) & 1; op; return r; }
__GEXW_BITTEST(_bittest, const __LONG32, (void)0)
__GEXW_BITTEST(_bittestandset, __LONG32, *b |= (__LONG32)1 << o)
__GEXW_BITTEST(_bittestandreset, __LONG32, *b &= ~((__LONG32)1 << o))
__GEXW_BITTEST(_bittestandcomplement, __LONG32, *b ^= (__LONG32)1 << o)
__GEXW_BITTEST(_bittest64, const __int64, (void)0)
__GEXW_BITTEST(_bittestandset64, __int64, *b |= (__int64)1 << o)
__GEXW_BITTEST(_bittestandreset64, __int64, *b &= ~((__int64)1 << o))
__GEXW_BITTEST(_bittestandcomplement64, __int64, *b ^= (__int64)1 << o)

#define __GEXW_ABITTEST(name, T, f, m) \
  __GEXW_INTRIN unsigned char name(T volatile *b, T o) \
  { return (f(b, m, __ATOMIC_SEQ_CST) >> o) & 1; }
__GEXW_ABITTEST(_interlockedbittestandset, __LONG32, __atomic_fetch_or, (__LONG32)1 << o)
__GEXW_ABITTEST(_interlockedbittestandreset, __LONG32, __atomic_fetch_and, ~((__LONG32)1 << o))
__GEXW_ABITTEST(_interlockedbittestandcomplement, __LONG32, __atomic_fetch_xor, (__LONG32)1 << o)
__GEXW_ABITTEST(_interlockedbittestandset64, __int64, __atomic_fetch_or, (__int64)1 << o)
__GEXW_ABITTEST(_interlockedbittestandreset64, __int64, __atomic_fetch_and, ~((__int64)1 << o))
__GEXW_ABITTEST(_interlockedbittestandcomplement64, __int64, __atomic_fetch_xor, (__int64)1 << o)
#define InterlockedBitTestAndSet _interlockedbittestandset
#define InterlockedBitTestAndReset _interlockedbittestandreset
#define InterlockedBitTestAndComplement _interlockedbittestandcomplement
#define InterlockedBitTestAndSet64 _interlockedbittestandset64
#define InterlockedBitTestAndReset64 _interlockedbittestandreset64
#define InterlockedBitTestAndComplement64 _interlockedbittestandcomplement64

/* interlocked operations, all sequentially consistent as on x64 */
#define __GEXW_FETCH(name, T, f) \
  __GEXW_INTRIN T name(T volatile *d, T v) { return f(d, v, __ATOMIC_SEQ_CST); }
#define __GEXW_OPFETCH(name, T, f) \
  __GEXW_INTRIN T name(T volatile *d, T v) { return f(d, v, __ATOMIC_SEQ_CST); }
__GEXW_FETCH(_InterlockedAnd8, char, __atomic_fetch_and)
__GEXW_FETCH(_InterlockedOr8, char, __atomic_fetch_or)
__GEXW_FETCH(_InterlockedXor8, char, __atomic_fetch_xor)
__GEXW_FETCH(_InterlockedAnd16, short, __atomic_fetch_and)
__GEXW_FETCH(_InterlockedOr16, short, __atomic_fetch_or)
__GEXW_FETCH(_InterlockedXor16, short, __atomic_fetch_xor)
__GEXW_FETCH(_InterlockedAnd, __LONG32, __atomic_fetch_and)
__GEXW_FETCH(_InterlockedOr, __LONG32, __atomic_fetch_or)
__GEXW_FETCH(_InterlockedXor, __LONG32, __atomic_fetch_xor)
__GEXW_FETCH(_InterlockedExchangeAdd8, char, __atomic_fetch_add)
__GEXW_FETCH(_InterlockedExchangeAdd16, short, __atomic_fetch_add)
__GEXW_FETCH(_InterlockedExchangeAdd, __LONG32, __atomic_fetch_add)
__GEXW_FETCH(_InterlockedExchange8, char, __atomic_exchange_n)
__GEXW_FETCH(_InterlockedExchange16, short, __atomic_exchange_n)
__GEXW_FETCH(_InterlockedExchange, __LONG32, __atomic_exchange_n)
__GEXW_OPFETCH(_InterlockedAdd, __LONG32, __atomic_add_fetch)
__GEXW_FETCH(_InterlockedAnd64, __int64, __atomic_fetch_and)
__GEXW_FETCH(_InterlockedOr64, __int64, __atomic_fetch_or)
__GEXW_FETCH(_InterlockedXor64, __int64, __atomic_fetch_xor)
__GEXW_FETCH(_InterlockedExchangeAdd64, __int64, __atomic_fetch_add)
__GEXW_FETCH(_InterlockedExchange64, __int64, __atomic_exchange_n)
__GEXW_OPFETCH(_InterlockedAdd64, __int64, __atomic_add_fetch)

__GEXW_INTRIN short _InterlockedIncrement16(short volatile *a) { return __atomic_add_fetch(a, 1, __ATOMIC_SEQ_CST); }
__GEXW_INTRIN short _InterlockedDecrement16(short volatile *a) { return __atomic_sub_fetch(a, 1, __ATOMIC_SEQ_CST); }
__GEXW_INTRIN __LONG32 _InterlockedIncrement(__LONG32 volatile *a) { return __atomic_add_fetch(a, 1, __ATOMIC_SEQ_CST); }
__GEXW_INTRIN __LONG32 _InterlockedDecrement(__LONG32 volatile *a) { return __atomic_sub_fetch(a, 1, __ATOMIC_SEQ_CST); }
__GEXW_INTRIN __int64 _InterlockedIncrement64(__int64 volatile *a) { return __atomic_add_fetch(a, 1, __ATOMIC_SEQ_CST); }
__GEXW_INTRIN __int64 _InterlockedDecrement64(__int64 volatile *a) { return __atomic_sub_fetch(a, 1, __ATOMIC_SEQ_CST); }

#define __GEXW_CAS(name, T) \
  __GEXW_INTRIN T name(T volatile *d, T x, T c) \
  { __atomic_compare_exchange_n(d, &c, x, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST); return c; }
__GEXW_CAS(_InterlockedCompareExchange8, char)
__GEXW_CAS(_InterlockedCompareExchange16, short)
__GEXW_CAS(_InterlockedCompareExchange, __LONG32)
__GEXW_CAS(_InterlockedCompareExchange64, __int64)
__GEXW_INTRIN void *_InterlockedCompareExchangePointer(void *volatile *d, void *x, void *c)
{ __atomic_compare_exchange_n(d, &c, x, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST); return c; }
__GEXW_INTRIN void *_InterlockedExchangePointer(void *volatile *d, void *v)
{ return __atomic_exchange_n(d, v, __ATOMIC_SEQ_CST); }
__GEXW_INTRIN unsigned char _InterlockedCompareExchange128(__int64 volatile *d, __int64 hi, __int64 lo, __int64 *c)
{
  __int128 e = ((__int128)c[1] << 64) | (unsigned __int64)c[0];
  __int128 x = ((__int128)hi << 64) | (unsigned __int64)lo;
  unsigned char r = __atomic_compare_exchange_n((__int128 volatile *)d, &e, x, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
  c[0] = (__int64)e; c[1] = (__int64)(e >> 64);
  return r;
}

/* fences, and the SSE ones winnt.h's macros name */
__GEXW_INTRIN void __faststorefence(void) { __atomic_thread_fence(__ATOMIC_SEQ_CST); }
__GEXW_INTRIN void _mm_mfence(void) { __atomic_thread_fence(__ATOMIC_SEQ_CST); }
__GEXW_INTRIN void _mm_lfence(void) { __atomic_thread_fence(__ATOMIC_SEQ_CST); }
__GEXW_INTRIN void _mm_sfence(void) { __atomic_thread_fence(__ATOMIC_SEQ_CST); }
__GEXW_INTRIN void _mm_pause(void) { }
__GEXW_INTRIN void _mm_clflush(void const *p) { (void)p; }
#define _mm_prefetch(p, h) ((void)(p), (void)(h))
__GEXW_INTRIN unsigned int _mm_getcsr(void) { return 0x1f80; }
__GEXW_INTRIN void _mm_setcsr(unsigned int c) { (void)c; }

/* string moves and stores */
#define __GEXW_STOS(name, T) \
  __GEXW_INTRIN void name(T *d, T v, size_t n) { while (n--) *d++ = v; }
#define __GEXW_MOVS(name, T) \
  __GEXW_INTRIN void name(T *d, T const *s, size_t n) { while (n--) *d++ = *s++; }
__GEXW_STOS(__stosb, unsigned char)
__GEXW_STOS(__stosw, unsigned short)
__GEXW_STOS(__stosd, unsigned __LONG32)
__GEXW_STOS(__stosq, unsigned __int64)
__GEXW_MOVS(__movsb, unsigned char)
__GEXW_MOVS(__movsw, unsigned short)
__GEXW_MOVS(__movsd, unsigned __LONG32)
__GEXW_MOVS(__movsq, unsigned __int64)

/* bit counts, rotates, 128-bit arithmetic */
__GEXW_INTRIN unsigned short __popcnt16(unsigned short v) { return __builtin_popcount(v); }
__GEXW_INTRIN unsigned int __popcnt(unsigned int v) { return __builtin_popcount(v); }
__GEXW_INTRIN unsigned __int64 __popcnt64(unsigned __int64 v) { return __builtin_popcountll(v); }
__GEXW_INTRIN unsigned short __lzcnt16(unsigned short v) { return v ? __builtin_clz(v) - 16 : 16; }
__GEXW_INTRIN unsigned int __lzcnt(unsigned int v) { return v ? __builtin_clz(v) : 32; }
__GEXW_INTRIN unsigned __int64 __lzcnt64(unsigned __int64 v) { return v ? __builtin_clzll(v) : 64; }
__GEXW_INTRIN unsigned char _rotl8(unsigned char v, unsigned char s) { s &= 7; return s ? (v << s) | (v >> (8 - s)) : v; }
__GEXW_INTRIN unsigned char _rotr8(unsigned char v, unsigned char s) { s &= 7; return s ? (v >> s) | (v << (8 - s)) : v; }
__GEXW_INTRIN unsigned short _rotl16(unsigned short v, unsigned char s) { s &= 15; return s ? (v << s) | (v >> (16 - s)) : v; }
__GEXW_INTRIN unsigned short _rotr16(unsigned short v, unsigned char s) { s &= 15; return s ? (v >> s) | (v << (16 - s)) : v; }
__GEXW_INTRIN unsigned __LONG32 _lrotl(unsigned __LONG32 v, int s) { s &= 31; return s ? (v << s) | (v >> (32 - s)) : v; }
__GEXW_INTRIN unsigned __LONG32 _lrotr(unsigned __LONG32 v, int s) { s &= 31; return s ? (v >> s) | (v << (32 - s)) : v; }
__GEXW_INTRIN unsigned __int64 __shiftleft128(unsigned __int64 lo, unsigned __int64 hi, unsigned char n)
{ n &= 63; return n ? (hi << n) | (lo >> (64 - n)) : hi; }
__GEXW_INTRIN unsigned __int64 __shiftright128(unsigned __int64 lo, unsigned __int64 hi, unsigned char n)
{ n &= 63; return n ? (lo >> n) | (hi << (64 - n)) : lo; }
__GEXW_INTRIN unsigned __int64 __umulh(unsigned __int64 a, unsigned __int64 b)
{ return (unsigned __int64)(((unsigned __int128)a * b) >> 64); }
__GEXW_INTRIN __int64 __mulh(__int64 a, __int64 b) { return (__int64)(((__int128)a * b) >> 64); }
__GEXW_INTRIN unsigned __int64 _umul128(unsigned __int64 a, unsigned __int64 b, unsigned __int64 *hi)
{ unsigned __int128 r = (unsigned __int128)a * b; *hi = (unsigned __int64)(r >> 64); return (unsigned __int64)r; }
__GEXW_INTRIN __int64 _mul128(__int64 a, __int64 b, __int64 *hi)
{ __int128 r = (__int128)a * b; *hi = (__int64)(r >> 64); return (__int64)r; }

/* the CPU: an x64 baseline with nothing optional (cpuid leaf 0 reports no
 * further leaves) */
__GEXW_INTRIN void __cpuid(int r[4], int leaf) { (void)leaf; r[0] = r[1] = r[2] = r[3] = 0; }
__GEXW_INTRIN void __cpuidex(int r[4], int leaf, int sub) { (void)leaf; (void)sub; r[0] = r[1] = r[2] = r[3] = 0; }
__GEXW_INTRIN unsigned __int64 _xgetbv(unsigned int x) { (void)x; return 0; }
__GEXW_INTRIN void __int2c(void) { __builtin_trap(); }

/* the GS segment: the TEB */
struct _TEB *__stdcall __wine_wasm_current_teb(void);
#define __GEXW_GS(T, sfx) \
  __GEXW_INTRIN T __readgs##sfx(unsigned __LONG32 o) { return *(T *)((char *)__wine_wasm_current_teb() + o); } \
  __GEXW_INTRIN void __writegs##sfx(unsigned __LONG32 o, T v) { *(T *)((char *)__wine_wasm_current_teb() + o) = v; }
__GEXW_GS(unsigned char, byte)
__GEXW_GS(unsigned short, word)
__GEXW_GS(unsigned __LONG32, dword)
__GEXW_GS(unsigned __int64, qword)

#ifdef __cplusplus
}
#endif

#endif /* GEXW_INTRIN_IMPL_H */
