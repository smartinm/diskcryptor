#ifndef _CRYPTO_
#define _CRYPTO_

#include "boot.h"
#include "gf128mul.h"
#include "mini_aes.h"

typedef struct _aes_key
{
	u8         gf_key[16];
	aes256_key aes_key;
		
} aes_key;

void aes_lrw_init_key(aes_key *key, char *cipher_k, char *tweak_k);

#define aes_lrw_encrypt(in, out, len, start, key) { \
	aes_lrw_process(in, out, len, start, key, \
	   aes_encrypt); \
   }

#define aes_lrw_decrypt(in, out, len, start, key) { \
	aes_lrw_process(in, out, len, start, key, \
	   aes_decrypt); \
   }

typedef void (*aescode)(u8 *in, u8 *out, aes256_key *key);

void aes_lrw_process(
		u8 *in, u8 *out, 
		int  len, u64 start, 
		aes_key *key, 
		aescode cryptprc 
		);

#endif