#ifndef _CRYPTO_TWOFISH_H
#define _CRYPTO_TWOFISH_H

#include "defines.h"
#include "cryptodef.h"

#define TF_MIN_KEY_SIZE 16
#define TF_MAX_KEY_SIZE 32
#define TF_BLOCK_SIZE 16

/* Structure for an expanded Twofish key.  s contains the key-dependent
 * S-boxes composed with the MDS matrix; w contains the eight "whitening"
 * subkeys, K[0] through K[7].	k holds the remaining, "round" subkeys.  Note
 * that k[i] corresponds to what the Twofish paper calls K[i+8]. */
#ifdef TWOFISH_ASM
 #pragma pack (push,1)
#endif

typedef struct _twofish_ctx {
#ifdef SMALL_CODE
	u32 l_key[40];
	u32 mk_tab[4 * 256];
#else
	u32 s[4][256], w[8], k[32];
#endif
} twofish_ctx;

#ifdef TWOFISH_ASM
 #pragma pack (pop)
#endif

void pcall twofish_encrypt(const u8 *in, u8 *out, twofish_ctx *ctx);
void pcall twofish_decrypt(const u8 *in, u8 *out, twofish_ctx *ctx);
void twofish_setkey(const u8 *key, twofish_ctx *ctx);

#define twofish_encrypt_ptr(key) ( twofish_encrypt )
#define twofish_decrypt_ptr(key) ( twofish_decrypt )

#endif
