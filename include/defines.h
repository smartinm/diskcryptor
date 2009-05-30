#ifndef _DEFINES_H_
#define _DEFINES_H_

#ifdef IS_DRIVER
 #include <ntifs.h>
#endif

#if !defined(IS_DRIVER) && !defined(BOOT_LDR)
 #include <windows.h>
 #include <stdio.h>
#endif

#ifndef _WCHAR_T_DEFINED 
 typedef short wchar_t;
#endif

typedef unsigned __int64 u64;
typedef unsigned long    u32;
typedef unsigned short   u16;
typedef unsigned char    u8;

typedef __int64 s64;
typedef long    s32;
typedef short   s16;
typedef char    s8;

#define d8(x)  ((u8)(x))
#define d16(x) ((u16)(x))
#define d32(x) ((u32)(x))
#define d64(x) ((u64)(x))

typedef void (*callback)(void*);
typedef void (*callback_ex)(void*,void*);

#pragma pack (push, 1)

 typedef struct {
	 u64 a, b;
 } be128;

 #pragma pack (pop)

#define MAX_PATH 260
#define BE16(x) _byteswap_ushort(x)
#define BE32(x) _byteswap_ulong(x)
#define BE64(x) _byteswap_uint64(x)

#define le32_to_cpu(x) (x)
#define cpu_to_le32(x) (x)

#if _MSC_VER >= 1400
 #define GETU32(pt)     (_byteswap_ulong(*(u32*)(pt)))
 #define PUTU32(ct, st) (*(u32*)(ct) = _byteswap_ulong(st))
 #define GETU64(pt)     (_byteswap_uint64(*(u64*)(pt)))
 #define PUTU64(ct, st) (*(u64*)(ct) = _byteswap_uint64(st))
 #define ROR64(x,y)     (_rotr64((x),(y)))
 #define ROL64(x,y)     (_rotl64((x),(y)))
 #define ROL32(x,y)     (_rotl((x), (y)))
 #define ROR32(x,y)     (_rotr((x), (y)))
 #define bsf(x,y)       (_BitScanForward((x),(y)))
 #define bsr(x,y)       (_BitScanReverse((x),(y)))
#else 
 #define GETU32(pt) (((u32)(pt)[0] << 24) ^ ((u32)(pt)[1] << 16) ^ ((u32)(pt)[2] <<  8) ^ ((u32)(pt)[3]))
 #define PUTU32(ct, st) { (ct)[0] = (u8)((st) >> 24); (ct)[1] = (u8)((st) >> 16); (ct)[2] = (u8)((st) >>  8); (ct)[3] = (u8)(st); }
#endif

#define stdcall  __stdcall
#define fastcall __fastcall
#define aligned  __declspec(align(32))

#define p8(x)  ((u8*)(x))
#define p16(x) ((u16*)(x))
#define p32(x) ((u32*)(x))
#define p64(x) ((u64*)(x))
#define pv(x)  ((void*)(x))
#define ppv(x) ((void**)(x)) 

#define in_reg(a,base,size)     ( (a >= base) && (a < base+size)  )
#define is_intersect(start1, size1, start2, size2) ( max(start1, start2) < min(start1 + size1, start2 + size2) )
#define addof(a,o)              ( pv(p8(a)+o) )

#define put_b(p,d) { p8(p)[0]  = (u8)(d);  p = pv((p8(p) + 1));  }
#define put_w(p,d) { p16(p)[0] = (u16)(d); p = pv((p16(p) + 1)); }
#define put_d(p,d) { p32(p)[0] = (u32)(d); p = pv((p32(p) + 1)); }

#ifdef BOOT_LDR
 #pragma warning(disable:4142)
 typedef unsigned long size_t;
 #pragma warning(default:4142)
#endif


#ifdef _M_X64

#define xor128(d,x,y) { \
	p64(d)[0] = p64(x)[0] ^ p64(y)[0], \
	p64(d)[1] = p64(x)[1] ^ p64(y)[1]; \
   } 

#else

#define xor128(d,x,y) { \
	p32(d)[0] = p32(x)[0] ^ p32(y)[0], \
	p32(d)[1] = p32(x)[1] ^ p32(y)[1], \
	p32(d)[2] = p32(x)[2] ^ p32(y)[2], \
	p32(d)[3] = p32(x)[3] ^ p32(y)[3]; \
   } 

#endif

#ifndef max
 #define max(a,b) (((a) > (b)) ? (a) : (b))
#endif

#ifndef min
 #define min(a,b) (((a) < (b)) ? (a) : (b))
#endif

#ifndef _align
 #define _align(size, align) (((size) + ((align) - 1)) & ~((align) - 1))
#endif

#ifndef PAGE_SIZE
 #define PAGE_SIZE 0x1000
#endif

#ifndef bittest
#ifdef _M_IX86 
 #define bittest(a,b) ( _bittest(p32(&a),b) )
#else
 #define bittest(a,b) ( sizeof(a) == sizeof(u32) ? _bittest(p32(&a),b):_bittest64(p64(&a),b) )   
#endif /* _M_IX86 */
#endif /* bittest */

#ifndef NULL
 #define NULL pv(0)
#endif

#ifndef MAX_PATH
 #define MAX_PATH 260
#endif

#define sizeof_w(x)  ( sizeof(x) / sizeof(wchar_t) ) /* return number of wide characters in array */
#define array_num(x) ( sizeof(x) / sizeof((x)[0]) )  /* return number of elements in array */

#define zeromem(m,s) memset(m, 0, s)

#ifdef IS_DRIVER
 #define mem_alloc(x) ExAllocatePoolWithTag(NonPagedPoolCacheAligned, (x), '1_cd')
 #define mem_free(x)  ExFreePool(x)
#else 
 #define mem_alloc(x) malloc(x)
 #define mem_free(x)  free(x)
#endif

/* size optimized intrinsics */
#define mincpy(a,b,c) __movsb(pv(a), pv(b), (size_t)(c))
#define memset(a,b,c) __stosb(pv(a), (char)(b), (size_t)(c))

/* zeromem for 4byte aligned blocks */
#define zerofast(m,s) __stosd(pv(m),0,(size_t)(s) / 4)

/* fast intrinsics for memory copying and zeroing */
#ifdef _M_IX86 
 #define fastcpy(a,b,c) __movsd(pv(a), pv(b), (size_t)(c) / 4)

 #define autocpy(a,b,c) { \
    if (!((c) % 4)) { __movsd(pv(a), pv(b), (size_t)(c) / 4); } else \
    if (!((c) % 2)) { __movsw(pv(a), pv(b), (size_t)(c) / 2); } else \
    { __movsb(pv(a), pv(b), (size_t)(c)); } }
  
 #define zeroauto(m,s) { \
    if (!((s) % 4)) { __stosd(pv(m), 0, (size_t)(s) / 4); } else \
    if (!((s) % 2)) { __stosw(pv(m), 0, (size_t)(s) / 2); } else \
	{ __stosb(pv(m), 0, (size_t)(s)); } }

 #define _disable() { __asm { cli }; }
 #define _enable()  { __asm { sti }; }
#else
 #define fastcpy(a,b,c) __movsq(pv(a), pv(b), (size_t)(c) / 8)
 
 #define autocpy(a,b,c) { \
    if (!((c) % 8)) { __movsq(pv(a), pv(b), (size_t)(c) / 8); } else \
    if (!((c) % 4)) { __movsd(pv(a), pv(b), (size_t)(c) / 4); } else \
    if (!((c) % 2)) { __movsw(pv(a), pv(b), (size_t)(c) / 2); } else \
    { __movsb(pv(a), pv(b), (size_t)(c)); } }

 #define zeroauto(m,s) { \
    if (!((s) % 8)) { __stosq(pv(m), 0, (size_t)(s) / 8); } else \
    if (!((s) % 4)) { __stosd(pv(m), 0, (size_t)(s) / 4); } else \
    if (!((s) % 2)) { __stosw(pv(m), 0, (size_t)(s) / 2); } else \
	{ __stosb(pv(m), 0, (size_t)(s)); } }
#endif

#define lock_inc(x)    ( _InterlockedIncrement(x) )
#define lock_dec(x)    ( _InterlockedDecrement(x) )
#define lock_xchg(p,v) ( _InterlockedExchange((p),(v)) )

#pragma warning(disable:4995)
#pragma intrinsic(memcpy,memset,memcmp)
#pragma intrinsic(strcpy,strcmp,strlen)
#pragma intrinsic(strcat)
#pragma warning(default:4995)


#endif
