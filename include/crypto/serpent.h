#ifndef _SERPENT_
#define _SERPENT_

#include "cryptodef.h"

#define SERPENT_MIN_KEY_SIZE		  0
#define SERPENT_MAX_KEY_SIZE		 32
#define SERPENT_EXPKEY_WORDS		132
#define SERPENT_BLOCK_SIZE		 16

typedef struct _serpent_ctx {
	u32 expkey[SERPENT_EXPKEY_WORDS + 8];
} serpent_ctx;

void serpent_setkey(const u8 *key, serpent_ctx *ctx);

void pcall serpent_encrypt(const u8 *src, u8 *dst, serpent_ctx *ctx);
void pcall serpent_decrypt(const u8 *src, u8 *dst, serpent_ctx *ctx);

#define serpent_encrypt_ptr(key) ( serpent_encrypt )
#define serpent_decrypt_ptr(key) ( serpent_decrypt )

#endif