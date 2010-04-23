#ifndef _AES_SMALL_H_
#define _AES_SMALL_H_

#include "defines.h"

#define ROUNDS 14

typedef align16 struct _aes256_key {
	align16 u32 enc_key[4 *(ROUNDS + 1)];
	align16 u32 dec_key[4 *(ROUNDS + 1)];
} aes256_key;

#define AES_KEY_SIZE   32
#define AES_BLOCK_SIZE 16

void aes256_set_key(const unsigned char *key, aes256_key *skey);
void aes256_encrypt(const unsigned char *in, unsigned char *out, aes256_key *key);
void aes256_decrypt(const unsigned char *in, unsigned char *out, aes256_key *key);
void aes256_gentab();

#endif