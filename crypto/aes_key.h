#ifndef _AES_KEY_H_
#define _AES_KEY_H_

#include "defines.h"

#define ROUNDS 14

typedef align16 struct _aes256_key {
	align16 u32 enc_key[4 *(ROUNDS + 1)];
	align16 u32 dec_key[4 *(ROUNDS + 1)];
#ifdef _M_IX86
	align16 u8  ek_code[3072];
	align16 u8  dk_code[3072];
#endif
} aes256_key;

#define AES_KEY_SIZE   32
#define AES_BLOCK_SIZE 16

void _stdcall aes256_set_key(const unsigned char *key, aes256_key *skey);

#endif