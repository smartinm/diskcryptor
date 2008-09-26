/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2007 
    * ntldr <ntldr@freed0m.org> PGP key ID - 0xC48251EB4F8E4E6E
    *

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "defines.h" 
#include "cryptodef.h"
#include "crypto.h"
#include "aes.h"
#include "twofish.h"
#include "serpent.h"
#include "..\sys\driver.h"
#include "pkcs5.h"
#include "crc32.h"
#include "gf128mul.h"
#include "aes.h"

#define XTS_TWEAK_UNIT_SIZE SECTOR_SIZE
#define XTS_BLOCK_SIZE      16

#ifndef SMALL_CODE

static int iv_to_index(u32 *p)
{
	u32 bps;
	
	if (bsf(&bps, ~p[0]) == 0) {
		if (bsf(&bps, ~p[1]) == 0) {
			bps = 64;
		} else bps += 32;
	}

	return bps;
}

void lrw_mode_process(
		u8 *in, u8 *out, size_t len, u64 offset, struct _dc_key *key, c_crypt_proc cryptprc
		)
{
	u8  t[16];
	u64 idx = (offset >> 4) | 1;
	int i;

	gf128mul64_table(pv(t), pv(&idx), &key->mode_k.lrw.gf_ctx);

	do
	{
		xor128(out, in, t);
		cryptprc(out, out, &key->cipher_k);
		xor128(out, out, t);

		if ( (len -= 16) == 0 ) {
			break;
		}

		i = iv_to_index(pv(&idx));
		xor128(t, t, &key->mode_k.lrw.inctab[i]); 
		in += 16; out += 16; idx++;
	} while (1); 	
}

#else /* SMALL_CODE */

void lrw_mode_process(
		u8 *in, u8 *out, size_t len, u64 offset, struct _dc_key *key, c_crypt_proc cryptprc
		)
{
	u8  t[16];
	u64 x, idx;

	idx = (offset >> 4) | 1;
	
	while (len != 0)
	{
		x = BE64(idx);
		gf128_mul64(key->mode_k.lrw.gf_key, pv(&x), t);

		xor128(out, in, t);
		cryptprc(out, out, &key->cipher_k);
		xor128(out, out, t);

		idx++; len -= 16;
		in += 16; out += 16; 
	}

	/* prevent leaks */
	zeroauto(t, sizeof(t));
}

#endif /* SMALL_CODE */

void xts_mode_process(
		u8 *in, u8 *out, size_t len, u64 offset,
	    c_crypt_proc tweak_enc, c_crypt_proc cryptprc,
		void *cipher_k, void *tweak_k
		)
{
	be128 t, idx;
	u32   b_max, b_num;
	u32   b_base;
#ifdef SMALL_CODE
	u32   cfg;
#endif

	b_max = (u32)(len / XTS_BLOCK_SIZE);
	idx.b = 0;

	if (len < XTS_TWEAK_UNIT_SIZE) {
		b_base = b_max; idx.a = 0;
	} else {
		idx.a  = (offset / XTS_TWEAK_UNIT_SIZE) + 1;
		b_base = (XTS_TWEAK_UNIT_SIZE / XTS_BLOCK_SIZE);
	}

	do
	{
		b_num = b_base, b_max -= b_base;

		/* derive first tweak value */
		tweak_enc(pv(&idx), pv(&t), tweak_k);
		
		do
		{
			/* encrypt block */
			xor128(out, in, &t);			
			cryptprc(out, out, cipher_k);						
			xor128(out, out, &t);

			/* update pointers */
			in += 16; out += 16;

			if (--b_num == 0) {
				break;
			}
		
			/* derive next tweak value */
#ifndef SMALL_CODE
			gf128mul_x_ble(&t, &t);
#else
			cfg = (t.b & 0x8000000000000000) ? 135 : 0;			
			t.b = (t.b << 1) | (t.a >> 63);
			t.a = (t.a << 1) ^ cfg;		
#endif			
		} while (1);
		/* update tweak unit index */
		idx.a++;
	} while (b_max != 0);
}

static void lrw_mode_encrypt(u8 *in, u8 *out, size_t len, u64 offset, dc_key *key)
{
	lrw_mode_process(in, out, len, offset, key, key->encrypt);
}

static void lrw_mode_decrypt(u8 *in, u8 *out, size_t len, u64 offset, dc_key *key)
{
	lrw_mode_process(in, out, len, offset, key, key->decrypt);
}

static void aes_twofish_setkey(u8 *key, chain_ctx *ctx)
{
	twofish_setkey(key, &ctx->twofish_key);
	aes256_set_key(key + TF_MAX_KEY_SIZE, &ctx->aes_key);
}

static void pcall aes_twofish_encrypt(u8 *in, u8 *out, chain_ctx *ctx) 
{
	twofish_encrypt(in, out, &ctx->twofish_key);
	aes256_encrypt(out, out, &ctx->aes_key);
}

static void pcall aes_twofish_decrypt(u8 *in, u8 *out, chain_ctx *ctx) 
{
	aes256_decrypt(in, out, &ctx->aes_key);
	twofish_decrypt(out, out, &ctx->twofish_key);
}

static void twofish_serpent_setkey(u8 *key, chain_ctx *ctx)
{
	serpent_setkey(key, &ctx->serpent_key);
	twofish_setkey(key + SERPENT_MAX_KEY_SIZE, &ctx->twofish_key);
}

static void pcall twofish_serpent_encrypt(u8 *in, u8 *out, chain_ctx *ctx) 
{
	serpent_encrypt(in, out, &ctx->serpent_key);
	twofish_encrypt(out, out, &ctx->twofish_key);
}

static void pcall twofish_serpent_decrypt(u8 *in, u8 *out, chain_ctx *ctx) 
{
	twofish_decrypt(in, out, &ctx->twofish_key);
	serpent_decrypt(out, out, &ctx->serpent_key);
}

static void serpent_aes_setkey(u8 *key, chain_ctx *ctx)
{
	aes256_set_key(key, &ctx->aes_key);
	serpent_setkey(key + AES_KEY_SIZE, &ctx->serpent_key);
}

static void pcall serpent_aes_encrypt(u8 *in, u8 *out, chain_ctx *ctx) 
{
	aes256_encrypt(in, out, &ctx->aes_key);
	serpent_encrypt(out, out, &ctx->serpent_key);
}

static void pcall serpent_aes_decrypt(u8 *in, u8 *out, chain_ctx *ctx) 
{
	serpent_decrypt(in, out, &ctx->serpent_key);
	aes256_decrypt(out, out, &ctx->aes_key);
}

static void aes_twofish_serpent_setkey(u8 *key, chain_ctx *ctx)
{
	serpent_setkey(key, &ctx->serpent_key);
	twofish_setkey(key + SERPENT_MAX_KEY_SIZE, &ctx->twofish_key);
	aes256_set_key(key + SERPENT_MAX_KEY_SIZE + TF_MAX_KEY_SIZE, &ctx->aes_key);
}

static void pcall aes_twofish_serpent_encrypt(u8 *in, u8 *out, chain_ctx *ctx) 
{
	serpent_encrypt(in, out, &ctx->serpent_key);
	twofish_encrypt(out, out, &ctx->twofish_key);
	aes256_encrypt(out, out, &ctx->aes_key);
}

static void pcall aes_twofish_serpent_decrypt(u8 *in, u8 *out, chain_ctx *ctx) 
{
	aes256_decrypt(in, out, &ctx->aes_key);
	twofish_decrypt(out, out, &ctx->twofish_key);
	serpent_decrypt(out, out, &ctx->serpent_key);	
}

static void xts_single_encrypt(u8 *in, u8 *out, size_t len, u64 offset, dc_key *key)
{
	xts_mode_process(
		in, out, len, offset, key->mode_k.xts.encrypt, 
		key->encrypt, &key->cipher_k, &key->mode_k.xts.tweak_k
		);
}

static void xts_single_decrypt(u8 *in, u8 *out, size_t len, u64 offset, dc_key *key)
{
	xts_mode_process(
		in, out, len, offset, key->mode_k.xts.encrypt, 
		key->decrypt, &key->cipher_k, &key->mode_k.xts.tweak_k
		);
}

static void xts_aes_twofish_encrypt(u8 *in, u8 *out, size_t len, u64 offset, dc_key *key)
{
	aes256_key  *ae_key = &key->cipher_k.chain_key.aes_key;
	twofish_ctx *tf_key = &key->cipher_k.chain_key.twofish_key;
	chain_ctx   *tw_key = &key->mode_k.xts.tweak_k.chain_key;

	xts_mode_process(
		in, out, len, offset, twofish_encrypt_ptr(&tw_key->twofish_key),
		twofish_encrypt_ptr(tf_key), tf_key, &tw_key->twofish_key
		);
	
	xts_mode_process(
		out, out, len, offset, aes256_encrypt_ptr(&tw_key->aes_key), 
		aes256_encrypt_ptr(ae_key), ae_key, &tw_key->aes_key
		);
}

static void xts_aes_twofish_decrypt(u8 *in, u8 *out, size_t len, u64 offset, dc_key *key)
{
	aes256_key  *ae_key = &key->cipher_k.chain_key.aes_key;
	twofish_ctx *tf_key = &key->cipher_k.chain_key.twofish_key;
	chain_ctx   *tw_key = &key->mode_k.xts.tweak_k.chain_key;

	xts_mode_process(
		in, out, len, offset, aes256_encrypt_ptr(&tw_key->aes_key), 
		aes256_decrypt_ptr(ae_key), ae_key, &tw_key->aes_key
		);

	xts_mode_process(
		out, out, len, offset, twofish_encrypt_ptr(&tw_key->twofish_key), 
		twofish_decrypt_ptr(tf_key), tf_key, &tw_key->twofish_key
		);	
}

static void xts_twofish_serpent_encrypt(u8 *in, u8 *out, size_t len, u64 offset, dc_key *key)
{
	serpent_ctx *sp_key = &key->cipher_k.chain_key.serpent_key;
	twofish_ctx *tf_key = &key->cipher_k.chain_key.twofish_key;
	chain_ctx   *tw_key = &key->mode_k.xts.tweak_k.chain_key;

	xts_mode_process(
		in, out, len, offset, serpent_encrypt_ptr(&tw_key->serpent_key), 
		serpent_encrypt_ptr(sp_key), sp_key, &tw_key->serpent_key
		);

	xts_mode_process(
		out, out, len, offset, twofish_encrypt_ptr(&tw_key->twofish_key), 
		twofish_encrypt_ptr(tf_key), tf_key, &tw_key->twofish_key
		);	
}

static void xts_twofish_serpent_decrypt(u8 *in, u8 *out, size_t len, u64 offset, dc_key *key)
{
	serpent_ctx *sp_key = &key->cipher_k.chain_key.serpent_key;
	twofish_ctx *tf_key = &key->cipher_k.chain_key.twofish_key;
	chain_ctx   *tw_key = &key->mode_k.xts.tweak_k.chain_key;

	xts_mode_process(
		in, out, len, offset, twofish_encrypt_ptr(&tw_key->twofish_key), 
		twofish_decrypt_ptr(tf_key), tf_key, &tw_key->twofish_key
		);	

	xts_mode_process(
		out, out, len, offset, serpent_encrypt_ptr(&tw_key->serpent_key), 
		serpent_decrypt_ptr(sp_key), sp_key, &tw_key->serpent_key
		);	
}

static void xts_serpent_aes_encrypt(u8 *in, u8 *out, size_t len, u64 offset, dc_key *key)
{
	serpent_ctx *sp_key = &key->cipher_k.chain_key.serpent_key;
	aes256_key  *ae_key = &key->cipher_k.chain_key.aes_key;
	chain_ctx   *tw_key = &key->mode_k.xts.tweak_k.chain_key;

	xts_mode_process(
		in, out, len, offset, aes256_encrypt_ptr(&tw_key->aes_key), 
		aes256_encrypt_ptr(ae_key), ae_key, &tw_key->aes_key
		);

	xts_mode_process(
		out, out, len, offset, serpent_encrypt_ptr(&tw_key->serpent_key), 
		serpent_encrypt_ptr(sp_key), sp_key, &tw_key->serpent_key
		);		
}

static void xts_serpent_aes_decrypt(u8 *in, u8 *out, size_t len, u64 offset, dc_key *key)
{
	serpent_ctx *sp_key = &key->cipher_k.chain_key.serpent_key;
	aes256_key  *ae_key = &key->cipher_k.chain_key.aes_key;
	chain_ctx   *tw_key = &key->mode_k.xts.tweak_k.chain_key;

	xts_mode_process(
		in, out, len, offset, serpent_encrypt_ptr(&tw_key->serpent_key), 
		serpent_decrypt_ptr(sp_key), sp_key, &tw_key->serpent_key
		);	

	xts_mode_process(
		out, out, len, offset, aes256_encrypt_ptr(&tw_key->aes_key), 
		aes256_decrypt_ptr(ae_key), ae_key, &tw_key->aes_key
		);		
}

static void xts_aes_twofish_serpent_encrypt(u8 *in, u8 *out, size_t len, u64 offset, dc_key *key)
{
	aes256_key  *ae_key = &key->cipher_k.chain_key.aes_key;
	twofish_ctx *tf_key = &key->cipher_k.chain_key.twofish_key;
	serpent_ctx *sp_key = &key->cipher_k.chain_key.serpent_key;
	chain_ctx   *tw_key = &key->mode_k.xts.tweak_k.chain_key;

	xts_mode_process(
		in, out, len, offset, serpent_encrypt_ptr(&tw_key->serpent_key), 
		serpent_encrypt_ptr(sp_key),  sp_key, &tw_key->serpent_key
		);

	xts_mode_process(
		out, out, len, offset, twofish_encrypt_ptr(&tw_key->twofish_key), 
		twofish_encrypt_ptr(tf_key), tf_key, &tw_key->twofish_key
		);	

	xts_mode_process(
		out, out, len, offset, aes256_encrypt_ptr(&tw_key->aes_key), 
		aes256_encrypt_ptr(ae_key), ae_key, &tw_key->aes_key
		);			
}

static void xts_aes_twofish_serpent_decrypt(u8 *in, u8 *out, size_t len, u64 offset, dc_key *key)
{
	aes256_key  *ae_key = &key->cipher_k.chain_key.aes_key;
	twofish_ctx *tf_key = &key->cipher_k.chain_key.twofish_key;
	serpent_ctx *sp_key = &key->cipher_k.chain_key.serpent_key;
	chain_ctx   *tw_key = &key->mode_k.xts.tweak_k.chain_key;

	xts_mode_process(
		in, out, len, offset, aes256_encrypt_ptr(&tw_key->aes_key), 
		aes256_decrypt_ptr(ae_key), ae_key, &tw_key->aes_key
		);	

	xts_mode_process(
		out, out, len, offset, twofish_encrypt_ptr(&tw_key->twofish_key), 
		twofish_decrypt_ptr(tf_key), tf_key, &tw_key->twofish_key
		);

	xts_mode_process(
		out, out, len, offset, serpent_encrypt_ptr(&tw_key->serpent_key), 
		serpent_decrypt_ptr(sp_key), sp_key, &tw_key->serpent_key
		);
}

static dc_cipher dc_ciphers[] = {
#ifdef AES_ASM
	{ 32, aes256_set_key, NULL,  NULL  },                                                         /* AES */
#else
	{ 32, aes256_set_key, aes256_encrypt,  aes256_decrypt  },                                     /* AES */
#endif
	{ 32, twofish_setkey, twofish_encrypt, twofish_decrypt },                                     /* Twofish */
	{ 32, serpent_setkey, serpent_encrypt, serpent_decrypt },                                     /* Serpent */
	{ 64, aes_twofish_setkey, aes_twofish_encrypt, aes_twofish_decrypt },                         /* AES-Twofish */
	{ 64, twofish_serpent_setkey, twofish_serpent_encrypt, twofish_serpent_decrypt },             /* Twofish-Serpent */
	{ 64, serpent_aes_setkey, serpent_aes_encrypt, serpent_aes_decrypt },                         /* Serpent-AES */
	{ 96, aes_twofish_serpent_setkey, aes_twofish_serpent_encrypt, aes_twofish_serpent_decrypt }  /* AES-Twofish-Serpent */
};

static struct {
	e_mode_proc encrypt;
	e_mode_proc decrypt;
} xts_procs[] = {
	{ xts_single_encrypt, xts_single_decrypt },                          /* AES */
	{ xts_single_encrypt, xts_single_decrypt },                          /* Twofish */
	{ xts_single_encrypt, xts_single_decrypt },                          /* Serpent */
	{ xts_aes_twofish_encrypt, xts_aes_twofish_decrypt },                /* AES-Twofish */
	{ xts_twofish_serpent_encrypt, xts_twofish_serpent_decrypt },        /* Twofish-Serpent */
	{ xts_serpent_aes_encrypt, xts_serpent_aes_decrypt },                /* Serpent-AES */
	{ xts_aes_twofish_serpent_encrypt, xts_aes_twofish_serpent_decrypt } /* AES-Twofish-Serpent */
};


void dc_cipher_init(
	   dc_key *key, int cipher, int mode, char *d_key
	   )
{
	char *c_k;
#ifndef SMALL_CODE
	u32 t[2];
	int i;
#endif

	if (mode == EM_LRW)
	{
#ifndef SMALL_CODE
		/* initialize GF(2^128) multiplication table */
		gf128mul_init_32k(
			&key->mode_k.lrw.gf_ctx, pv(d_key)
			);

		/* initialize increment table */
		t[0] = t[1] = 0;
		for (i = 0; i < 64; i++) 
		{
			t[i / 32] |= 1 << (i % 32);
			
			gf128mul64_table(
				&key->mode_k.lrw.inctab[i], pv(t), &key->mode_k.lrw.gf_ctx
				);
		}
#else
		/* copy tweak key */
		autocpy(key->mode_k.lrw.gf_key, d_key, 16); 
#endif
		key->mode_encrypt = lrw_mode_encrypt; 
		key->mode_decrypt = lrw_mode_decrypt; 
		c_k = d_key + LRW_TWEAK_SIZE;
	} else 
	{
		/* init XTS tweak key */
		dc_ciphers[cipher].set_key(
			d_key + dc_ciphers[cipher].key_len, &key->mode_k.xts.tweak_k
			);
		key->mode_k.xts.encrypt = dc_ciphers[cipher].encrypt;
#ifdef AES_ASM
		if (cipher == CF_AES) {
			key->mode_k.xts.encrypt = aes256_encrypt_ptr(&key->mode_k.xts.tweak_k);
		}
#endif 
		key->mode_encrypt = xts_procs[cipher].encrypt;
		key->mode_decrypt = xts_procs[cipher].decrypt;
		c_k = d_key;
	}

	dc_ciphers[cipher].set_key(c_k, &key->cipher_k);
	key->encrypt = dc_ciphers[cipher].encrypt;
	key->decrypt = dc_ciphers[cipher].decrypt;
#ifdef AES_ASM
	if (cipher == CF_AES) {
		key->encrypt = aes256_encrypt_ptr(&key->cipher_k);
		key->decrypt = aes256_decrypt_ptr(&key->cipher_k);
	}
#endif
#ifndef SMALL_CODE
	key->cipher = cipher;
	key->mode   = mode;
#endif
}

#ifndef SMALL_CODE
void dc_cipher_reinit(dc_key *key)
{
#ifdef AES_ASM
	if (key->cipher == CF_AES) 
	{
		key->encrypt = aes256_encrypt_ptr(&key->cipher_k);
		key->decrypt = aes256_decrypt_ptr(&key->cipher_k);

		if (key->mode == EM_XTS) {
			key->mode_k.xts.encrypt = aes256_encrypt_ptr(&key->mode_k.xts.tweak_k);
		}
	}
#endif
}
#endif
int dc_decrypt_header(
	  dc_key    *hdr_key,
	  dc_header *header, crypt_info *crypt, char *password
	  )
{
	u8        dk[DISKKEY_SIZE];
	int       i, j, k, succs;
	dc_header hcopy;
	size_t    pss_len;	

	pss_len = strlen(password);
	succs   = 0;

	for (i = 0; i < PRF_NUM; i++)
	{
		pkcs5_2_prf(
			i, -1, password, pss_len, header->salt, PKCS5_SALT_SIZE, 
			dk, PKCS_DERIVE_MAX
			);

		for (j = 0; j < CF_CIPHERS_NUM; j++)
		{
			for (k = 0; k < EM_NUM; k++)
			{
				dc_cipher_init(hdr_key, j, k, dk);

				dc_cipher_decrypt(
					pv(&header->sign), pv(&hcopy.sign), 
					HEADER_ENCRYPTEDDATASIZE, 0, hdr_key 
					);

				/* Magic 'TRUE' or 'DTMP' */
				if (IS_DC_SIGN(hcopy.sign) == 0) {
					continue;
				}
#ifndef NO_CRC32
				/* Check CRC of the key set */
				if (BE32(hcopy.key_crc) != crc32(hcopy.key_data, DISKKEY_SIZE)) {
					continue;
				}			
#endif
				autocpy(&header->sign, &hcopy.sign, HEADER_ENCRYPTEDDATASIZE);

				crypt->prf_id    = i;
				crypt->cipher_id = j;
				crypt->mode_id   = k;
				succs = 1; goto brute_done;
			}
		}
	}
brute_done:;

	/* prevent leaks */
	zeroauto(dk, sizeof(dk));
	zeroauto(&hcopy, sizeof(hcopy));

	return succs;
}

