#ifndef _SHA1_
#define _SHA1_

#include "defines.h"

#define SHA1_DIGESTSIZE  20
#define SHA1_BLOCKSIZE   64

typedef struct
{   u32 count[2];
    u32 hash[5];
 	u8  buff[128];
	int idx;

} sha1_ctx;


void sha1_init(sha1_ctx *ctx);
void sha1_hash(sha1_ctx *ctx, void *data, size_t len);
void sha1_done(sha1_ctx *ctx, u8 *hval);

#endif
