#ifndef _SHA512_
#define _SHA512_

#include "defines.h"
#include "cryptodef.h"

typedef struct {
    u64    length;
	size_t curlen;
	u64    hash[8];
    u8     buf[128];

} sha512_ctx;

#define SHA512_DIGEST_SIZE 64
#define SHA512_BLOCK_SIZE  128

void sha512_init(sha512_ctx *ctx);
void sha512_hash(sha512_ctx *ctx, unsigned char *in, size_t inlen);
void sha512_done(sha512_ctx *ctx, unsigned char *out);

#endif