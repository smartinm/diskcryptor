#ifndef _AES256_
#define _AES256_

#include "defines.h"

typedef unsigned long  u32;
typedef unsigned short u16;
typedef unsigned char  u8;

#define ROUNDS 14

typedef aligned struct _aes256_key
{
#ifdef ASM_CRYPTO
	u8 dk_code[4096];
	u8 ek_code[4096];
#endif
	u32 enc_key[4 *(ROUNDS + 1)];
	u32 dec_key[4 *(ROUNDS + 1)];

} aes256_key;

#ifdef ASM_CRYPTO 
 typedef void (fastcall *aescode)(unsigned char *in, unsigned char *out);

 #define aes256_decrypt(in, out, key) ((aescode)(key)->dk_code)(in, out)
 #define aes256_encrypt(in, out, key) ((aescode)(key)->ek_code)(in, out)
#else
 typedef void (*aescode)(unsigned char *in, unsigned char *out, aes256_key *key);

 void aes256_decrypt(unsigned char *in, unsigned char *out, aes256_key *key);
 void aes256_encrypt(unsigned char *in, unsigned char *out, aes256_key *key);
#endif

void aes256_set_key(unsigned char *data, aes256_key *key);

#define AES_KEY_SIZE   32
#define AES_BLOCK_SIZE 16

#endif