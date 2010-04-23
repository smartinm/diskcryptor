#ifndef _FAST_CRYPT_
#define _FAST_CRYPT_

int  dc_init_fast_crypt();
void dc_free_fast_crypt();

#define F_MIN_REQ      2048 /* minimum block size for one request */
#define F_OP_THRESOLD  4096 /* parallelized crypt thresold */

int dc_parallelized_crypt(
	   int   is_encrypt, xts_key *key, callback_ex on_complete, void *param1, void *param2,
	   const unsigned char *in, unsigned char *out, u32 len, u64 offset);

void dc_fast_crypt_op(
		int   is_encrypt, xts_key *key,
		const unsigned char *in, unsigned char *out, u32 len, u64 offset);

#define dc_fast_encrypt(in, out, len, offset, key) dc_fast_crypt_op(1, key, in, out, len, offset)
#define dc_fast_decrypt(in, out, len, offset, key) dc_fast_crypt_op(0, key, in, out, len, offset)

#endif