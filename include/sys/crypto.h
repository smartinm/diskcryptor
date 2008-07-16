#ifndef _CRYPTO_
#define _CRYPTO_

#include "defines.h"
#include "gf128mul.h"
#include "aes.h"

typedef aligned struct _aes_key
{
	gf128mul_32k gf_ctx;
	be128        inctab[64];
	aes256_key   aes_key;
		
} aes_key;

void aes_lrw_init_key(aes_key *key, char *cipher_k, char *tweak_k);

#define lrw_index(off) (((u64)(off) >> 4) | 1)

#ifdef ASM_CRYPTO

#define aes_lrw_encrypt(in, out, len, idx, key) { \
	aes_lrw_process(in, out, len, idx, key, \
       pv((key)->aes_key.ek_code)); \
   }

#define aes_lrw_decrypt(in, out, len, idx, key) { \
	aes_lrw_process(in, out, len, idx, key, \
       pv((key)->aes_key.dk_code)); \
   }

#else

#define aes_lrw_encrypt(in, out, len, index, key) { \
	aes_lrw_process(in, out, len, index, key, \
	   aes256_encrypt); \
   }

#define aes_lrw_decrypt(in, out, len, index, key) { \
	aes_lrw_process(in, out, len, index, key, \
	   aes256_decrypt); \
   }

#endif


void stdcall aes_lrw_process(
				char *in, char *out, 
				size_t len, u64 idx, 
				aes_key *key, 
				aescode cryptprc);

#endif