#ifndef _MINI_AES_
#define _MINI_AES_

#define ROUNDS 14

typedef struct _aes256_key
{
	u32 enc_key[4 *(ROUNDS + 1)];
	u32 dec_key[4 *(ROUNDS + 1)];

} aes256_key;

void aes256_set_key(u8 *data, aes256_key *key);
void aes_encrypt(u8 *in, u8 *out, aes256_key *key);
void aes_decrypt(u8 *in, u8 *out, aes256_key *key);

#endif