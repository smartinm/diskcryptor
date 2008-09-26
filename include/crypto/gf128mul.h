#ifndef _GF128MUL_
#define _GF128MUL_

#include "defines.h"
#include "cryptodef.h"

#ifdef SMALL_CODE
 void stdcall gf128_mul64(u8 *gf_a, u8 *gf_b, u8 *gf_p);
#else

#ifdef GFMUL_ASM
 #pragma pack (push, 1)
#endif

typedef struct _gf128mul_32k {
	be128 t[8][256];

} gf128mul_32k;

#ifdef GFMUL_ASM
 #pragma pack (pop)
#endif

void gf128mul_init_32k(gf128mul_32k *ctx, const be128 *g);
void gf128mul_x_ble(be128 *r, const be128 *x);
void pcall gf128mul64_table(be128 *p, u8 *a, gf128mul_32k *ctx); 

#endif

#endif