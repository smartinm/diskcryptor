#ifndef _FAST_CRYPT_
#define _FAST_CRYPT_

int  dc_init_fast_crypt();
void dc_free_fast_crypt();

#define F_OP_ENCRYPT    0
#define F_OP_DECRYPT    1

#define F_MIN_REQ      2048 /* minimum block size for one request */
#define F_OP_THRESOLD  8192 /* parallelized crypt thresold */

int dc_parallelized_crypt(
	  int  op_type, dc_key *key,
	  u8  *io_src, u8 *io_dst, size_t io_size, u64 io_offs,
	  callback_ex on_complete, void *param1, void *param2
	  );

void dc_fast_crypt_op(
	   int op, u8 *in, u8 *out, size_t len, u64 offset, dc_key *key
	   );

#define dc_fast_encrypt(in, out, len, offset, key) { \
	dc_fast_crypt_op(F_OP_ENCRYPT, in, out, len, offset, key); \
}

#define dc_fast_decrypt(in, out, len, offset, key) { \
	dc_fast_crypt_op(F_OP_DECRYPT, in, out, len, offset, key); \
}

void dc_crypt_bench();

#endif