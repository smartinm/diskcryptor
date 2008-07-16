#ifndef _DEFINES_
#define _DEFINES_

#ifdef KMDF_MAJOR_VERSION
 #include <ntifs.h>
#endif

typedef unsigned __int64 u64;
typedef unsigned long    u32;
typedef unsigned short   u16;
typedef unsigned char    u8;

typedef __int64 s64;
typedef long    s32;
typedef short   s16;
typedef char    s8;

typedef void (*callback)(void*);

#pragma pack (push, 1)

 typedef struct {
	 u64 a, b;
 } be128;

 #pragma pack (pop)

#define MAX_PATH 260
#define BE16(x) _byteswap_ushort(x)
#define BE32(x) _byteswap_ulong(x)
#define BE64(x) _byteswap_uint64(x)

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

#ifdef _M_IX86 
 #define ASM_CRYPTO
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

#define in_reg(a,base,size) ( (a >= base) && (a < base+size)  )
#define addof(a,o)          pv(p8(a)+o)

#define put_b(p,d) { p8(p)[0]  = (u8)(d);  p = pv((p8(p) + 1));  }
#define put_w(p,d) { p16(p)[0] = (u16)(d); p = pv((p16(p) + 1)); }
#define put_d(p,d) { p32(p)[0] = (u32)(d); p = pv((p32(p) + 1)); }

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


#ifndef NULL
 #define NULL pv(0)
#endif

#ifndef MAX_PATH
 #define MAX_PATH 260
#endif

#define sizeof_w(x)  ( sizeof(x) / sizeof(wchar_t) ) /* return number of wide characters in array */
#define array_num(x) ( sizeof(x) / sizeof((x)[0]) )  /* return number of elements in array */

#define zeromem(m,s) memset(m, 0, s)
#define BYTE_ORDER LITTLE_ENDIAN

//#define DBG_MSG
//#define DBG_COM

#ifdef DBG_MSG
 #ifdef DBG_COM 
  void com_print(char *format, ...);
  #define DbgMsg com_print
 #else
  #define DbgMsg DbgPrint
 #endif
#else
 #define DbgMsg
#endif

#ifdef NTDDI_VERSION
 #define mem_alloc(x) ExAllocatePool(NonPagedPool, x)
 #define mem_free(x)  ExFreePool(x)
#else 
 #define mem_alloc(x) malloc(x)
 #define mem_free(x)  free(x)
#endif

#ifdef DBG_FILE
void debug_out(char *format, ...);
#endif

/* define memcpy for 64 bit aligned blocks */
#ifdef _M_IX86 
 #define fastcpy(a,b,c) __movsd(pv(a), pv(b), (size_t)(c) / 4)
#else
 #define fastcpy(a,b,c) __movsq(pv(a), pv(b), (size_t)(c) / 8)
#endif  

#define memcpy(a,b,c) __movsb((char*)(a), (char*)(b), (size_t)(c))
#define memset(a,b,c) __stosb((char*)(a),(char)(b),(size_t)(c))

#define lock_inc(x)    ( _InterlockedIncrement(x) )
#define lock_dec(x)    ( _InterlockedDecrement(x) )
#define lock_xchg(p,v) ( _InterlockedExchange((p),(v)) )

#pragma warning(disable:4995)
#pragma intrinsic(memcpy,memset,memcmp)
#pragma intrinsic(strcpy,strcmp,strlen)
#pragma intrinsic(strcat)
#pragma warning(default:4995)

#endif
