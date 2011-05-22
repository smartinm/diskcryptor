/*
    *
    * Copyright (c) 2007-2010
    * ntldr <ntldr@diskcryptor.net> PGP key ID - 0xC48251EB4F8E4E6E
    *

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 3 as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#include "defines.h"
#include "sha512.h"
#include "pkcs5.h"

void _stdcall sha512_hmac(const char *k, size_t k_len, const char *d, size_t d_len, char *out)
{
	sha512_ctx ctx;
	u8         buf[SHA512_BLOCK_SIZE];
	u8         hval[SHA512_DIGEST_SIZE];
	size_t     i;

	/* zero key buffer */
	memset(buf, 0, sizeof(buf));

	/* compress hmac key */
	if (k_len > SHA512_BLOCK_SIZE) {
		sha512_init(&ctx);
		sha512_hash(&ctx, k, k_len);
		sha512_done(&ctx, buf);
	} else {
		memcpy(buf, k, k_len);
	}

	/* create the hash initial vector */ 
	for (i = 0; i < (SHA512_BLOCK_SIZE / 4); i++) {
		p32(buf)[i] ^= 0x36363636;
	}

	/* hash key and data */
	sha512_init(&ctx);
	sha512_hash(&ctx, buf, SHA512_BLOCK_SIZE);
	sha512_hash(&ctx, d, d_len);
	sha512_done(&ctx, hval);

	/* create the second HMAC vector */
	for (i = 0; i < (SHA512_BLOCK_SIZE / 4); i++) {
        p32(buf)[i] ^= 0x6A6A6A6A;
    }

	/* calculate "outer" hash */
	sha512_init(&ctx);
	sha512_hash(&ctx, buf, SHA512_BLOCK_SIZE);
	sha512_hash(&ctx, hval, SHA512_DIGEST_SIZE);
	sha512_done(&ctx, out);	

	/* prevent leaks */
	burn(buf,  sizeof(buf));
	burn(hval, sizeof(hval));
	burn(&ctx, sizeof(ctx));
}


void _stdcall sha512_pkcs5_2(
	   int i_count,
	   const void *pwd,  size_t pwd_len, 
	   const char *salt, size_t salt_len, 		  
	   char       *dk,   size_t dklen
	   )
{
	u8       buff[128];
	u8       blk[SHA512_DIGEST_SIZE];
	u8       hmac[SHA512_DIGEST_SIZE];
	u32      block = 1;
	size_t   c_len, j;
	int      i;

	while (dklen != 0)
	{
		/* first interation */
		memcpy(buff, salt, salt_len);
		p32(buff + salt_len)[0] = BE32(block);
		sha512_hmac(pwd, pwd_len, buff, salt_len + 4, hmac);
		memcpy(blk, hmac, SHA512_DIGEST_SIZE);

		/* next interations */
		for (i = 1; i < i_count; i++) 
		{
			sha512_hmac(pwd, pwd_len, hmac, SHA512_DIGEST_SIZE, hmac);

			for (j = 0; j < (SHA512_DIGEST_SIZE / 4); j++) {
				p32(blk)[j] ^= p32(hmac)[j];
			}
		}

		c_len = min(dklen, SHA512_DIGEST_SIZE);
		memcpy(dk, blk, c_len);
		dk += c_len; dklen -= c_len; block++;
	}

	/* prevent leaks */
	burn(buff, sizeof(buff));
	burn(blk,  sizeof(blk));
	burn(hmac, sizeof(hmac));
}