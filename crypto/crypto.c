/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2007 
    * ntldr <ntldr@diskcryptor.net> PGP key ID - 0xC48251EB4F8E4E6E
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
#include "pkcs5.h"
#include "crc32.h"
#include "gf128mul.h"
#include "aes.h"

#define XTS_TWEAK_UNIT_SIZE SECTOR_SIZE
#define XTS_BLOCK_SIZE      16

void xts_mode_process(
		u8 *in, u8 *out, size_t len, u64 offset,
	    c_crypt_proc tweak_enc, c_crypt_proc cryptprc,
		void *cipher_k, void *tweak_k
		)
{
#ifdef AES_ASM_VIA
	u8    calign tmp[XTS_BLOCK_SIZE];
#endif
	be128 calign t, idx;
	u32   b_max, b_num;
	u32   b_base;
#ifdef SMALL_CODE
	u32   cfg;
#endif

	b_max  = (u32)(len / XTS_BLOCK_SIZE);
	b_base = (XTS_TWEAK_UNIT_SIZE / XTS_BLOCK_SIZE);
	idx.a  = (offset / XTS_TWEAK_UNIT_SIZE) + 1;
	idx.b  = 0;	

	do
	{
		b_num = b_base, b_max -= b_base;

#ifdef AES_ASM_VIA
		if (tweak_enc == aes256_encrypt_ace) {
			aes256_ace_rekey();
		}
#endif

		/* derive first tweak value */
		tweak_enc(pv(&idx), pv(&t), tweak_k);

#ifdef AES_ASM_VIA
		if (tweak_enc == aes256_encrypt_ace) {
			aes256_ace_rekey();
		}
#endif
		
		do
		{
#ifdef AES_ASM_VIA
			/* encrypt block */
			xor128(tmp, in, &t);		
			cryptprc(tmp, tmp, cipher_k);					
			xor128(out, tmp, &t);
#else
			xor128(out, in, &t);
			cryptprc(out, out, cipher_k);
			xor128(out, out, &t);
#endif

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


static void aes_twofish_setkey(u8 *key, chain_ctx *ctx)
{
	twofish_setkey(key, &ctx->twofish_key);
	aes256_set_key(key + TF_MAX_KEY_SIZE, &ctx->aes_key);
}

static void twofish_serpent_setkey(u8 *key, chain_ctx *ctx)
{
	serpent_setkey(key, &ctx->serpent_key);
	twofish_setkey(key + SERPENT_MAX_KEY_SIZE, &ctx->twofish_key);
}

static void serpent_aes_setkey(u8 *key, chain_ctx *ctx)
{
	aes256_set_key(key, &ctx->aes_key);
	serpent_setkey(key + AES_KEY_SIZE, &ctx->serpent_key);
}


static void aes_twofish_serpent_setkey(u8 *key, chain_ctx *ctx)
{
	serpent_setkey(key, &ctx->serpent_key);
	twofish_setkey(key + SERPENT_MAX_KEY_SIZE, &ctx->twofish_key);
	aes256_set_key(key + SERPENT_MAX_KEY_SIZE + TF_MAX_KEY_SIZE, &ctx->aes_key);
}

static void xts_single_encrypt(u8 *in, u8 *out, size_t len, u64 offset, dc_key *key)
{
	xts_mode_process(
		in, out, len, offset, key->xts.encrypt, 
		key->encrypt, &key->cipher_k, &key->xts.tweak_k);
}

static void xts_single_decrypt(u8 *in, u8 *out, size_t len, u64 offset, dc_key *key)
{
	xts_mode_process(
		in, out, len, offset, key->xts.encrypt, 
		key->decrypt, &key->cipher_k, &key->xts.tweak_k);
}

static void xts_aes_twofish_encrypt(u8 *in, u8 *out, size_t len, u64 offset, dc_key *key)
{
	aes256_key  *ae_key = &key->cipher_k.chain_key.aes_key;
	twofish_ctx *tf_key = &key->cipher_k.chain_key.twofish_key;
	chain_ctx   *tw_key = &key->xts.tweak_k.chain_key;

	xts_mode_process(
		in, out, len, offset, twofish_encrypt_ptr(&tw_key->twofish_key),
		twofish_encrypt_ptr(tf_key), tf_key, &tw_key->twofish_key);
	
	xts_mode_process(
		out, out, len, offset, aes256_encrypt_ptr(&tw_key->aes_key), 
		aes256_encrypt_ptr(ae_key), ae_key, &tw_key->aes_key);
}

static void xts_aes_twofish_decrypt(u8 *in, u8 *out, size_t len, u64 offset, dc_key *key)
{
	aes256_key  *ae_key = &key->cipher_k.chain_key.aes_key;
	twofish_ctx *tf_key = &key->cipher_k.chain_key.twofish_key;
	chain_ctx   *tw_key = &key->xts.tweak_k.chain_key;

	xts_mode_process(
		in, out, len, offset, aes256_encrypt_ptr(&tw_key->aes_key), 
		aes256_decrypt_ptr(ae_key), ae_key, &tw_key->aes_key);

	xts_mode_process(
		out, out, len, offset, twofish_encrypt_ptr(&tw_key->twofish_key), 
		twofish_decrypt_ptr(tf_key), tf_key, &tw_key->twofish_key);	
}

static void xts_twofish_serpent_encrypt(u8 *in, u8 *out, size_t len, u64 offset, dc_key *key)
{
	serpent_ctx *sp_key = &key->cipher_k.chain_key.serpent_key;
	twofish_ctx *tf_key = &key->cipher_k.chain_key.twofish_key;
	chain_ctx   *tw_key = &key->xts.tweak_k.chain_key;

	xts_mode_process(
		in, out, len, offset, serpent_encrypt_ptr(&tw_key->serpent_key), 
		serpent_encrypt_ptr(sp_key), sp_key, &tw_key->serpent_key);

	xts_mode_process(
		out, out, len, offset, twofish_encrypt_ptr(&tw_key->twofish_key), 
		twofish_encrypt_ptr(tf_key), tf_key, &tw_key->twofish_key);	
}

static void xts_twofish_serpent_decrypt(u8 *in, u8 *out, size_t len, u64 offset, dc_key *key)
{
	serpent_ctx *sp_key = &key->cipher_k.chain_key.serpent_key;
	twofish_ctx *tf_key = &key->cipher_k.chain_key.twofish_key;
	chain_ctx   *tw_key = &key->xts.tweak_k.chain_key;

	xts_mode_process(
		in, out, len, offset, twofish_encrypt_ptr(&tw_key->twofish_key), 
		twofish_decrypt_ptr(tf_key), tf_key, &tw_key->twofish_key);	

	xts_mode_process(
		out, out, len, offset, serpent_encrypt_ptr(&tw_key->serpent_key), 
		serpent_decrypt_ptr(sp_key), sp_key, &tw_key->serpent_key);	
}

static void xts_serpent_aes_encrypt(u8 *in, u8 *out, size_t len, u64 offset, dc_key *key)
{
	serpent_ctx *sp_key = &key->cipher_k.chain_key.serpent_key;
	aes256_key  *ae_key = &key->cipher_k.chain_key.aes_key;
	chain_ctx   *tw_key = &key->xts.tweak_k.chain_key;

	xts_mode_process(
		in, out, len, offset, aes256_encrypt_ptr(&tw_key->aes_key), 
		aes256_encrypt_ptr(ae_key), ae_key, &tw_key->aes_key);

	xts_mode_process(
		out, out, len, offset, serpent_encrypt_ptr(&tw_key->serpent_key), 
		serpent_encrypt_ptr(sp_key), sp_key, &tw_key->serpent_key);		
}

static void xts_serpent_aes_decrypt(u8 *in, u8 *out, size_t len, u64 offset, dc_key *key)
{
	serpent_ctx *sp_key = &key->cipher_k.chain_key.serpent_key;
	aes256_key  *ae_key = &key->cipher_k.chain_key.aes_key;
	chain_ctx   *tw_key = &key->xts.tweak_k.chain_key;

	xts_mode_process(
		in, out, len, offset, serpent_encrypt_ptr(&tw_key->serpent_key), 
		serpent_decrypt_ptr(sp_key), sp_key, &tw_key->serpent_key);	

	xts_mode_process(
		out, out, len, offset, aes256_encrypt_ptr(&tw_key->aes_key), 
		aes256_decrypt_ptr(ae_key), ae_key, &tw_key->aes_key);		
}

static void xts_aes_twofish_serpent_encrypt(u8 *in, u8 *out, size_t len, u64 offset, dc_key *key)
{
	aes256_key  *ae_key = &key->cipher_k.chain_key.aes_key;
	twofish_ctx *tf_key = &key->cipher_k.chain_key.twofish_key;
	serpent_ctx *sp_key = &key->cipher_k.chain_key.serpent_key;
	chain_ctx   *tw_key = &key->xts.tweak_k.chain_key;

	xts_mode_process(
		in, out, len, offset, serpent_encrypt_ptr(&tw_key->serpent_key), 
		serpent_encrypt_ptr(sp_key),  sp_key, &tw_key->serpent_key);

	xts_mode_process(
		out, out, len, offset, twofish_encrypt_ptr(&tw_key->twofish_key), 
		twofish_encrypt_ptr(tf_key), tf_key, &tw_key->twofish_key);	

	xts_mode_process(
		out, out, len, offset, aes256_encrypt_ptr(&tw_key->aes_key), 
		aes256_encrypt_ptr(ae_key), ae_key, &tw_key->aes_key);			
}

static void xts_aes_twofish_serpent_decrypt(u8 *in, u8 *out, size_t len, u64 offset, dc_key *key)
{
	aes256_key  *ae_key = &key->cipher_k.chain_key.aes_key;
	twofish_ctx *tf_key = &key->cipher_k.chain_key.twofish_key;
	serpent_ctx *sp_key = &key->cipher_k.chain_key.serpent_key;
	chain_ctx   *tw_key = &key->xts.tweak_k.chain_key;

	xts_mode_process(
		in, out, len, offset, aes256_encrypt_ptr(&tw_key->aes_key), 
		aes256_decrypt_ptr(ae_key), ae_key, &tw_key->aes_key);	

	xts_mode_process(
		out, out, len, offset, twofish_encrypt_ptr(&tw_key->twofish_key), 
		twofish_decrypt_ptr(tf_key), tf_key, &tw_key->twofish_key);

	xts_mode_process(
		out, out, len, offset, serpent_encrypt_ptr(&tw_key->serpent_key), 
		serpent_decrypt_ptr(sp_key), sp_key, &tw_key->serpent_key);
}

static dc_cipher dc_ciphers[] = {
#ifndef AES_STATIC
	{ 32, aes256_set_key, NULL,  NULL  },                      /* AES */
#else
	{ 32, aes256_set_key, aes256_encrypt,  aes256_decrypt  },  /* AES */
#endif
	{ 32, twofish_setkey, twofish_encrypt, twofish_decrypt },  /* Twofish */
	{ 32, serpent_setkey, serpent_encrypt, serpent_decrypt },  /* Serpent */
	{ 64, aes_twofish_setkey, NULL, NULL },                    /* AES-Twofish */
	{ 64, twofish_serpent_setkey, NULL, NULL },                /* Twofish-Serpent */
	{ 64, serpent_aes_setkey, NULL, NULL },                    /* Serpent-AES */
	{ 96, aes_twofish_serpent_setkey, NULL, NULL }             /* AES-Twofish-Serpent */
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
	   dc_key *key, int cipher, char *d_key
	   )
{
	/* init XTS tweak key */
	dc_ciphers[cipher].set_key(
		d_key + dc_ciphers[cipher].key_len, &key->xts.tweak_k);

	key->xts.encrypt = dc_ciphers[cipher].encrypt;
#ifndef AES_STATIC
	if (cipher == CF_AES) {
		key->xts.encrypt = aes256_encrypt_ptr(&key->xts.tweak_k);
	}
#endif 
	key->mode_encrypt = xts_procs[cipher].encrypt;
	key->mode_decrypt = xts_procs[cipher].decrypt;
	
	/* init cipher key */
	dc_ciphers[cipher].set_key(d_key, &key->cipher_k);
	key->encrypt = dc_ciphers[cipher].encrypt;
	key->decrypt = dc_ciphers[cipher].decrypt;
#ifndef AES_STATIC
	if (cipher == CF_AES) {
		key->encrypt = aes256_encrypt_ptr(&key->cipher_k);
		key->decrypt = aes256_decrypt_ptr(&key->cipher_k);
	}
#endif
#ifndef SMALL_CODE
	key->cipher = cipher;
#endif
}

#ifndef SMALL_CODE
void dc_cipher_reinit(dc_key *key)
{
#ifndef AES_STATIC
	if (key->cipher == CF_AES) {
		key->encrypt = aes256_encrypt_ptr(&key->cipher_k);
		key->decrypt = aes256_decrypt_ptr(&key->cipher_k);
		key->xts.encrypt = aes256_encrypt_ptr(&key->xts.tweak_k);
	}
#endif
}
#endif

#ifndef NO_PKCS5

int dc_decrypt_header(
	  dc_key *hdr_key, dc_header *header, dc_pass *password
	  )
{
	u8        dk[DISKKEY_SIZE];
	int       i, succs;
	dc_header *hcopy;

#ifdef BOOT_LDR
	hcopy = pv(0x9000);
#else
	if ( (hcopy = mem_alloc(sizeof(dc_header))) == NULL ) {
		return 0;
	}
#endif
	succs = 0;

	sha512_pkcs5_2(
		1000, password->pass, password->size, 
		header->salt, PKCS5_SALT_SIZE, dk, PKCS_DERIVE_MAX);

	for (i = 0; i < CF_CIPHERS_NUM; i++)
	{
		dc_cipher_init(hdr_key, i, dk);

		dc_cipher_decrypt(
			pv(header), pv(hcopy), sizeof(dc_header), 0, hdr_key);

		/* Magic 'DCRP' */
		if (hcopy->sign != DC_VOLM_SIGN) {
			continue;
		}
#ifndef NO_CRC32
		/* Check CRC of header */
		if (hcopy->hdr_crc != crc32(pv(&hcopy->version), DC_CRC_AREA_SIZE)) {
			continue;
		}			
#endif
		/* copy decrypted part to output */
		autocpy(&header->sign, &hcopy->sign, DC_ENCRYPTEDDATASIZE);
		succs = 1; break;
	}
	/* prevent leaks */
	zeroauto(dk,    sizeof(dk));
	zeroauto(hcopy, sizeof(dc_header));

#ifndef BOOT_LDR
	mem_free(hcopy);
#endif

	return succs;
}

#endif /* NO_PKCS5 */
