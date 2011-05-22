#ifndef _SHA512_H_
#define _SHA512_H_

#include "defines.h"

typedef struct _sha512_ctx {
    u64    hash[8];
	u64    length;
	size_t curlen;
    u8     buf[128];

} sha512_ctx;

#define SHA512_DIGEST_SIZE 64
#define SHA512_BLOCK_SIZE  128

void _stdcall sha512_init(sha512_ctx *ctx);
void _stdcall sha512_hash(sha512_ctx *ctx, const unsigned char *in, size_t inlen);
void _stdcall sha512_done(sha512_ctx *ctx, unsigned char *out);

#endif