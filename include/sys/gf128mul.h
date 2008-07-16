#ifndef _GF128MUL_
#define _GF128MUL_

#pragma pack (push, 1)

 
typedef struct _gf128mul_32k {
	be128 t[8][256];

} gf128mul_32k;

#pragma pack (pop)


void gf128mul_init_32k(gf128mul_32k *ctx, const be128 *g);
void stdcall gf128mul64_table(be128 *p, u8 *a, gf128mul_32k *ctx);

#endif