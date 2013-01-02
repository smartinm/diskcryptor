/*
    *
    * Copyright (c) 2007-2012
    * ntldr <ntldr@diskcryptor.net> PGP key ID - 0x1B6A24550F33E44A
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
#include <memory.h>
#include <intrin.h>
#include "sha512.h"
#include "pkcs5.h"

void _stdcall sha512_hmac(const void *k, size_t k_len, const void *d, size_t d_len, char *out)
{
	sha512_ctx    ctx;
	unsigned char buf[SHA512_BLOCK_SIZE];
	unsigned char hval[SHA512_DIGEST_SIZE];
	unsigned long i;

	// zero key buffer
	memset(buf, 0, sizeof(buf));

	// compress hmac key
	if (k_len > SHA512_BLOCK_SIZE) {
		sha512_init(&ctx);
		sha512_hash(&ctx, (const unsigned char*)k, k_len);
		sha512_done(&ctx, buf);
	} else {
		memcpy(buf, k, k_len);
	}

	// create the hash initial vector
	for (i = 0; i < (SHA512_BLOCK_SIZE / 4); i++) {
		((unsigned long*)buf)[i] ^= 0x36363636;
	}

	// hash key and data
	sha512_init(&ctx);
	sha512_hash(&ctx, buf, SHA512_BLOCK_SIZE);
	sha512_hash(&ctx, (const unsigned char*)d, d_len);
	sha512_done(&ctx, hval);

	// create the second HMAC vector
	for (i = 0; i < (SHA512_BLOCK_SIZE / 4); i++) {
		((unsigned long*)buf)[i] ^= 0x6A6A6A6A;
	}

	// calculate "outer" hash
	sha512_init(&ctx);
	sha512_hash(&ctx, buf, SHA512_BLOCK_SIZE);
	sha512_hash(&ctx, hval, SHA512_DIGEST_SIZE);
	sha512_done(&ctx, (unsigned char*)out);

	// test buffers size alignment at compile-time
	static_assert( !(sizeof(buf) % sizeof(unsigned long)), "sizeof must be 4 byte aligned");
	static_assert( !(sizeof(hval) % sizeof(unsigned long)), "sizeof must be 4 byte aligned");
	static_assert( !(sizeof(ctx) % sizeof(unsigned long)), "sizeof must be 4 byte aligned");

	// prevent leaks
	__stosd((unsigned long*)&buf, 0, (sizeof(buf) / sizeof(unsigned long)));
	__stosd((unsigned long*)&hval, 0, (sizeof(hval) / sizeof(unsigned long)));
	__stosd((unsigned long*)&ctx, 0, (sizeof(ctx) / sizeof(unsigned long)));
}


void _stdcall sha512_pkcs5_2(int i_count, const void *pwd, size_t pwd_len, const char *salt, size_t salt_len, char *dk, size_t dklen)
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
		memcpy(buff, salt, salt_len);
		((unsigned long*)(buff + salt_len))[0] = _byteswap_ulong(block);
		sha512_hmac(pwd, pwd_len, buff, salt_len + 4, (char*)hmac);
		memcpy(blk, hmac, SHA512_DIGEST_SIZE);

		// next interations
		for (i = 1; i < i_count; i++) 
		{
			sha512_hmac(pwd, pwd_len, hmac, SHA512_DIGEST_SIZE, (char*)hmac);

			for (j = 0; j < (SHA512_DIGEST_SIZE / 4); j++) {
				((unsigned long*)blk)[j] ^= ((unsigned long*)hmac)[j];
			}
		}

		memcpy(dk, blk, (c_len = dklen < SHA512_DIGEST_SIZE ? dklen : SHA512_DIGEST_SIZE));
		dk += c_len; dklen -= c_len; block++;
	}

	// test buffers size alignment at compile-time
	static_assert( !(sizeof(buff) % sizeof(unsigned long)), "sizeof must be 4 byte aligned");
	static_assert( !(sizeof(blk) % sizeof(unsigned long)), "sizeof must be 4 byte aligned");
	static_assert( !(sizeof(hmac) % sizeof(unsigned long)), "sizeof must be 4 byte aligned");

	// prevent leaks
	__stosd((unsigned long*)&buff, 0, (sizeof(buff) / sizeof(unsigned long)));
	__stosd((unsigned long*)&blk, 0, (sizeof(blk) / sizeof(unsigned long)));
	__stosd((unsigned long*)&hmac, 0, (sizeof(hmac) / sizeof(unsigned long)));
}