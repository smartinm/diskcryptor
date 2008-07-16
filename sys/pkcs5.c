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

#include "sha1.h"
#include "pkcs5.h"
#include "defines.h"

void sha1_hmac(char *k, size_t k_len, char *d, size_t d_len, char *out)
{
	sha1_ctx ctx;
	u8       buf[SHA1_BLOCKSIZE];
	u8       hval[SHA1_DIGESTSIZE];
	int      i;

	/* zero key buffer */
	zeromem(buf, sizeof(buf));

	/* compress hmac key */
	if (k_len > SHA1_BLOCKSIZE) {
		sha1_init(&ctx);
		sha1_hash(&ctx, k, k_len);
		sha1_done(&ctx, buf);
	} else {
		memcpy(buf, k, k_len);
	}

	/* create the hash initial vector */ 
	for (i = 0; i < SHA1_BLOCKSIZE; i++) {
		buf[i] ^= 0x36;
	}

	/* hash key and data */
	sha1_init(&ctx);
	sha1_hash(&ctx, buf, sizeof(buf));
	sha1_hash(&ctx, d, d_len);
	sha1_done(&ctx, hval);

	 /* create the second HMAC vector */
	for (i = 0; i < SHA1_BLOCKSIZE; i++) {
        buf[i] ^= (0x5C ^ 0x36);
    } 

	/* calculate "outer" hash */
	sha1_init(&ctx);
	sha1_hash(&ctx, buf, sizeof(buf));
	sha1_hash(&ctx, hval, sizeof(hval));
	sha1_done(&ctx, out);

	/* prevent leaks */
	zeromem(buf, sizeof(buf));
	zeromem(hval, sizeof(hval));
	zeromem(&ctx, sizeof(ctx));
}



void sha1_pkcs5_2(
		  char *pwd,  size_t pwd_len, 
		  char *salt, size_t salt_len, 
		  int iterations, 
		  char *dk, size_t dklen
		  )
{
	u8     buff[128];
	u8     blk[SHA1_DIGESTSIZE];
	u8     hmac[SHA1_DIGESTSIZE];
	u32    block = 1;
	int    i, j;
	size_t c_len;

	while (dklen != 0)
	{
		/* first interation */
		memcpy(buff, salt, salt_len);
		PUTU32(buff + salt_len, block);
		sha1_hmac(pwd, pwd_len, buff, salt_len + 4, hmac);
		memcpy(blk, hmac, SHA1_DIGESTSIZE);

		/* next interations */
		for (i = 1; i < iterations; i++) {
			sha1_hmac(pwd, pwd_len, hmac, SHA1_DIGESTSIZE, hmac);

			for (j = 0; j < SHA1_DIGESTSIZE; j++) {
				blk[j] ^= hmac[j];
			}
		}

		c_len = min(dklen, SHA1_DIGESTSIZE);
		memcpy(dk, blk, c_len);
		dk += c_len; dklen -= c_len; block++;
	}

	/* prevent leaks */
	zeromem(buff, sizeof(buff));
	zeromem(blk,  sizeof(blk));
	zeromem(hmac, sizeof(hmac));
}
