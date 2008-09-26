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
#include "sha1.h"
#include "sha512.h"
#include "pkcs5.h"

typedef union _hash_ctx {
	sha512_ctx sha512;
	sha1_ctx   sha1;

} hash_ctx;

typedef void (*hash_init)(void *ctx);
typedef void (*hash_hash)(void *ctx, unsigned char *in, size_t inlen);
typedef void (*hash_done)(void *ctx, unsigned char *out);

typedef struct _prf_ctx{
	size_t    block_s;
	size_t    digest_s;
	int       int_count;
	hash_init init;
	hash_hash hash;
	hash_done done;
	
} prf_ctx;


static prf_ctx prfs[] = {
	{ SHA512_BLOCK_SIZE, SHA512_DIGEST_SIZE, 1000, sha512_init, sha512_hash, sha512_done },  /* HMAC-SHA-512 */
	{ SHA1_BLOCK_SIZE, SHA1_DIGEST_SIZE, 2000, sha1_init, sha1_hash, sha1_done }             /* HMAC-SHA-1   */
};

#define HASH_MAX_BLOCK_SIZE  (max(SHA1_BLOCK_SIZE, SHA512_BLOCK_SIZE))
#define HASH_MAX_DIGEST_SIZE (max(SHA1_DIGEST_SIZE, SHA512_DIGEST_SIZE))

void prf_hmac(prf_ctx *prf, char *k, size_t k_len, char *d, size_t d_len, char *out)
{
	hash_ctx ctx;
	u8       buf[HASH_MAX_BLOCK_SIZE];
	u8       hval[HASH_MAX_DIGEST_SIZE];
	size_t   i;

	/* zero key buffer */
#ifndef SMALL_CODE
	zerofast(buf, prf->block_s);
#else
	zeroauto(buf, HASH_MAX_BLOCK_SIZE);
#endif

	/* compress hmac key */
	if (k_len > prf->block_s) {
		prf->init(&ctx);
		prf->hash(&ctx, k, k_len);
		prf->done(&ctx, buf);
	} else {
		memcpy(buf, k, k_len);
	}

	/* create the hash initial vector */ 
#ifndef SMALL_CODE
	for (i = 0; i < (prf->block_s / 4); i++) {
		p32(buf)[i] ^= 0x36363636;
	}
#else
	for (i = 0; i < HASH_MAX_BLOCK_SIZE; i++) {
		buf[i] ^= 0x36;
	}
#endif	

	/* hash key and data */
	prf->init(&ctx);
	prf->hash(&ctx, buf, prf->block_s);
	prf->hash(&ctx, d, d_len);
	prf->done(&ctx, hval);

	/* create the second HMAC vector */
#ifndef SMALL_CODE
	for (i = 0; i < (prf->block_s / 4); i++) {
        p32(buf)[i] ^= 0x6A6A6A6A;
    }
#else
	for (i = 0; i < HASH_MAX_BLOCK_SIZE; i++) {
        buf[i] ^= 0x6A;
    } 
#endif

	/* calculate "outer" hash */
	prf->init(&ctx);
	prf->hash(&ctx, buf, prf->block_s);
	prf->hash(&ctx, hval, prf->digest_s);
	prf->done(&ctx, out);	

	/* prevent leaks */
#ifndef SMALL_CODE
	zerofast(buf, prf->block_s);
	zerofast(hval, prf->digest_s);
	zeroauto(&ctx, sizeof(ctx));
#else
	zeroauto(buf,  HASH_MAX_BLOCK_SIZE);
	zeroauto(hval, HASH_MAX_DIGEST_SIZE);
	zeroauto(&ctx, sizeof(ctx));
#endif
}

#ifdef CRYPT_TESTS

void make_hmac(int prf_id, char *k, size_t k_len, char *d, size_t d_len, char *out)
{
	prf_hmac(&prfs[prf_id], k, k_len, d, d_len, out);
}

#endif /* CRYPT_TESTS */

void pkcs5_2_prf(
		  int   prf_id, int i_count,
		  char *pwd,  size_t pwd_len, 
		  char *salt, size_t salt_len, 		  
		  char *dk, size_t dklen
		  )
{
	prf_ctx *prf = &prfs[prf_id];
	u8       buff[128];
	u8       blk[HASH_MAX_DIGEST_SIZE];
	u8       hmac[HASH_MAX_DIGEST_SIZE];
	u32      block = 1;
	size_t   c_len, j;
	int      i;
	
	if (i_count == -1) {
		i_count = prf->int_count;
	}

	while (dklen != 0)
	{
		/* first interation */
		memcpy(buff, salt, salt_len);
		PUTU32(buff + salt_len, block);
		prf_hmac(prf, pwd, pwd_len, buff, salt_len + 4, hmac);
		memcpy(blk, hmac, prf->digest_s);

		/* next interations */
		for (i = 1; i < i_count; i++) 
		{
			prf_hmac(prf, pwd, pwd_len, hmac, prf->digest_s, hmac);

#ifndef SMALL_CODE
			for (j = 0; j < (prf->digest_s / 4); j++) {
				p32(blk)[j] ^= p32(hmac)[j];
			}
#else
			for (j = 0; j < HASH_MAX_DIGEST_SIZE; j++) {
				blk[j] ^= hmac[j];
			}
#endif
		}

		c_len = min(dklen, prf->digest_s);
		memcpy(dk, blk, c_len);
		dk += c_len; dklen -= c_len; block++;
	}

	/* prevent leaks */
	zeroauto(buff, sizeof(buff));
	zeroauto(blk,  sizeof(blk));
	zeroauto(hmac, sizeof(hmac));
}
