#ifndef _CRYPTO_
#define _CRYPTO_

#include "defines.h"
#include "..\sys\driver.h"
#include "gf128mul.h"
#include "aes.h"
#include "twofish.h"
#include "serpent.h"

#define CF_AES                 0
#define CF_TWOFISH             1
#define CF_SERPENT             2
#define CF_AES_TWOFISH         3
#define CF_TWOFISH_SERPENT     4
#define CF_SERPENT_AES         5
#define CF_AES_TWOFISH_SERPENT 6
#define CF_CIPHERS_NUM         7

#define EM_XTS 0
#define EM_LRW 1
#define EM_NUM 2

typedef void (*c_setkey_proc)(u8 *data, void *key);

typedef void (pcall *c_crypt_proc)(u8 *in, u8 *out, void *key);

typedef void (*e_mode_proc)(
		u8 *in, u8 *out, size_t len, u64 offset, struct _dc_key *key
		);

typedef struct _dc_cipher {
	int           key_len;
	c_setkey_proc set_key; /* set key function */
	c_crypt_proc  encrypt; /* encrypt function */
	c_crypt_proc  decrypt; /* decrypt function */

} dc_cipher;

typedef aligned struct _chain_ctx {
	aes256_key  aes_key;
	twofish_ctx twofish_key;
	serpent_ctx serpent_key;

} chain_ctx;

typedef aligned union _cipher_key {
	aes256_key  aes_key;
	twofish_ctx twofish_key;
	serpent_ctx serpent_key;
	chain_ctx   chain_key;

} cipher_key;

typedef aligned struct _dc_key
{
	union 
	{
		struct {
#ifndef SMALL_CODE
			gf128mul_32k gf_ctx;
			be128        inctab[64];
#else
			u8           gf_key[16];
#endif
		} lrw;
		struct {
			cipher_key   tweak_k;
			c_crypt_proc encrypt;			
		} xts;
	} mode_k;
	
	c_crypt_proc encrypt;
	c_crypt_proc decrypt;
	cipher_key   cipher_k;
	e_mode_proc  mode_encrypt;
	e_mode_proc  mode_decrypt;
#ifndef SMALL_CODE
	int          cipher;
	int          mode;
#endif
} dc_key;

void dc_cipher_init(
	   dc_key *key, int cipher, int mode, char *d_key
	   );

#ifndef SMALL_CODE
 void dc_cipher_reinit(dc_key *key);
#endif

#define dc_cipher_encrypt(in, out, len, offset, key) { \
	(key)->mode_encrypt(in, out, len, offset, key); \
}

#define dc_cipher_decrypt(in, out, len, offset, key) { \
	(key)->mode_decrypt(in, out, len, offset, key); \
}

int dc_decrypt_header(
	  dc_key    *hdr_key,
	  dc_header *header, crypt_info *crypt, char *password
	  );

#define dc_init_crypto() { \
	aes256_gentab(); \
}


#endif