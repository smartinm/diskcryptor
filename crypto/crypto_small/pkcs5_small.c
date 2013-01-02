/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2010
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
#include <intrin.h>
#include "sha512_small.h"
#include "pkcs5_small.h"

void sha512_hmac(const void *k, size_t k_len, const void *d, size_t d_len, char *out)
{
	sha512_ctx    ctx;
	unsigned char buf[SHA512_BLOCK_SIZE];
	unsigned char hval[SHA512_DIGEST_SIZE];
	unsigned long i;

	// zero key buffer
	__stosb(buf, 0, sizeof(buf));

	// compress hmac key
	if (k_len > SHA512_BLOCK_SIZE) {
		sha512_init(&ctx);
		sha512_hash(&ctx, (const unsigned char*)k, k_len);
		sha512_done(&ctx, buf);
	} else {
		__movsb(buf, (const unsigned char*)k, k_len);
	}

	// create the hash initial vector
	for (i = 0; i < SHA512_BLOCK_SIZE; i++) {
		buf[i] ^= 0x36;
	}

	// hash key and data
	sha512_init(&ctx);
	sha512_hash(&ctx, buf, SHA512_BLOCK_SIZE);
	sha512_hash(&ctx, (const unsigned char*)d, d_len);
	sha512_done(&ctx, hval);

	// create the second HMAC vector
	for (i = 0; i < SHA512_BLOCK_SIZE; i++) {
		buf[i] ^= 0x6A;
	} 

	// calculate "outer" hash
	sha512_init(&ctx);
	sha512_hash(&ctx, buf, SHA512_BLOCK_SIZE);
	sha512_hash(&ctx, hval, SHA512_DIGEST_SIZE);
	sha512_done(&ctx, (unsigned char*)out);

	// prevent leaks
	__stosb(buf, 0, sizeof(buf));
	__stosb(hval, 0, sizeof(hval));
	__stosb((unsigned char*)&ctx, 0, sizeof(ctx));
}

void sha512_pkcs5_2(int i_count, const void *pwd, size_t pwd_len, const char *salt, size_t salt_len, char *dk, size_t dklen)
{
	unsigned char buff[128];
	unsigned char blk[SHA512_DIGEST_SIZE];
	unsigned char hmac[SHA512_DIGEST_SIZE];
	unsigned long block = 1;
	size_t c_len;
	int    j, i;

	while (dklen != 0)
	{
		// first interation
		__movsb(buff, (const unsigned char*)salt, salt_len);
		((unsigned long*)(buff + salt_len))[0] = _byteswap_ulong(block);
		sha512_hmac(pwd, pwd_len, buff, salt_len + 4, (char*)hmac);
		__movsb(blk, hmac, SHA512_DIGEST_SIZE);

		// next interations
		for (i = 1; i < i_count; i++) 
		{
			sha512_hmac(pwd, pwd_len, hmac, SHA512_DIGEST_SIZE, (char*)hmac);

			for (j = 0; j < SHA512_DIGEST_SIZE; j++) {
				blk[j] ^= hmac[j];
			}
		}
		__movsb((unsigned char*)dk, blk, (c_len = dklen < SHA512_DIGEST_SIZE ? dklen : SHA512_DIGEST_SIZE));
		dk += c_len; dklen -= c_len; block++;
	}
	
	// prevent leaks
	__stosb(buff, 0, sizeof(buff));
	__stosb(blk, 0, sizeof(blk));
	__stosb(hmac, 0, sizeof(hmac));
}
