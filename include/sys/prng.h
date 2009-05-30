#ifndef _PRNG_
#define _PRNG_

#include "defines.h"
#include "aes.h"

typedef calign struct _rnd_ctx {
	aes256_key key;
	be128      index;

} rnd_ctx;

void rnd_add_buff(void *data, int size);
void rnd_reseed_now();
int  rnd_get_bytes(u8 *buf, int len);
int  rnd_init_prng();

rnd_ctx *rnd_fast_init();
void     rnd_fast_free(rnd_ctx *ctx);
void     rnd_fast_rand(rnd_ctx *ctx, u8 *buf, int len);

#endif