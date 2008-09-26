#ifndef _AES256_
#define _AES256_

#include "defines.h"
#include "cryptodef.h"

#define ROUNDS 14

typedef aligned struct _aes256_key
{
#ifdef AES_ASM
	u8 dk_code[4096];
	u8 ek_code[4096];
#endif
	u32 enc_key[4 *(ROUNDS + 1)];
	u32 dec_key[4 *(ROUNDS + 1)];

} aes256_key;

typedef void (pcall *aescode)(unsigned char *in, unsigned char *out, aes256_key *key);

#ifdef AES_ASM 
 #define aes256_decrypt(in, out, key) ((aescode)(key)->dk_code)(in, out, key)
 #define aes256_encrypt(in, out, key) ((aescode)(key)->ek_code)(in, out, key)

 #define aes256_decrypt_ptr(key) ((aescode)((aes256_key*)(key))->dk_code)
 #define aes256_encrypt_ptr(key) ((aescode)((aes256_key*)(key))->ek_code)
#else
 void pcall aes256_decrypt(unsigned char *in, unsigned char *out, aes256_key *key);
 void pcall aes256_encrypt(unsigned char *in, unsigned char *out, aes256_key *key);

 #define aes256_decrypt_ptr(key) ( aes256_decrypt )
 #define aes256_encrypt_ptr(key) ( aes256_encrypt )
#endif

void aes256_set_key(unsigned char *data, aes256_key *key);

#ifdef SMALL_CODE
 void aes256_gentab();
#else
 #define aes256_gentab()
#endif

#define AES_KEY_SIZE   32
#define AES_BLOCK_SIZE 16

#endif