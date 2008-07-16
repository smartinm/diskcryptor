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

#include "boot.h"
#include "sha1.h"


#define K1 0x5A827999
#define K2 0x6ED9EBA1
#define K3 0x8F1BBCDC
#define K4 0xCA62C1D6

static
void sha1_compress(sha1_ctx ctx[1])
{
	u32 W[80];
	u32 a, b, c, d, e;
	u32 i, t;
       
	/* Part 1: Transfer buffer with little -> big endian conversion */
	for (i = 0; i <= 15; i++) {
		W[i] = BE32(p32(ctx->buff)[i]);
	}

	/* Part 2: Calculate remaining "expanded message blocks" */
	for (i = 16; i <= 79; i++) {
		t = W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16];
		W[i] = ROL32(t, 1);
	}

	a = ctx->hash[0]; b = ctx->hash[1];
    c = ctx->hash[2]; d = ctx->hash[3];
    e = ctx->hash[4];
	i = 0;
	
	do
	{
		e += ROL32(a, 5) + (d ^ (b & (c ^ d))) + W[i++] + K1; b = ROR32(b, 2);
		t = e; e = d; d = c; c = b; b = a; a = t;
	} while (i != 20);

	do
	{
		e += ROL32(a, 5) + (d ^ b ^ c) + W[i++] + K2; b = ROR32(b, 2);
		t = e; e = d; d = c; c = b; b = a; a = t;
	} while (i != 40);

	do
	{
		e += ROL32(a, 5) + ((b & c) | (d & (b | c))) + W[i++] + K3; b = ROR32(b, 2);
		t = e; e = d; d = c; c = b; b = a; a = t;
	} while (i != 60);

	do
	{
		e += ROL32(a, 5) + (d ^ b ^ c) + W[i++] + K4; b = ROR32(b, 2);
		t = e; e = d; d = c; c = b; b = a; a = t;
	} while (i != 80);

    ctx->hash[0] += a; ctx->hash[1] += b;
    ctx->hash[2] += c; ctx->hash[3] += d;
    ctx->hash[4] += e;

	zeromem(W, sizeof(W));
}

void sha1_init(sha1_ctx *ctx)
{
    zeromem(ctx, sizeof(sha1_ctx));

    ctx->hash[0] = 0x67452301;
    ctx->hash[1] = 0xefcdab89;
    ctx->hash[2] = 0x98badcfe;
    ctx->hash[3] = 0x10325476;
    ctx->hash[4] = 0xc3d2e1f0;
}


void sha1_hash(sha1_ctx *ctx, void *data, int len)
{
	u8 *msg = data;
	u32 cnt = ctx->count[0];

	if( (ctx->count[0] += (u32)(len << 3)) < cnt) {
		ctx->count[1]++;
	}

	while (len--) {
		/* fill block with msg data */
		ctx->buff[ctx->idx++] = *msg++;

		if (ctx->idx == SHA1_BLOCKSIZE) {
			ctx->idx = 0;
			sha1_compress(ctx);
		}
	}
}


void sha1_done(sha1_ctx *ctx, u8 *hval)
{
	int i;
	
	/* Message padding */
	/* 1. append bit '1' after msg */
	ctx->buff[ctx->idx] = 0x80;	
	
	i = ctx->idx+1;
	memset(ctx->buff + i, 0, 64 - i);
		
	/* 2. Compress if more than 448 bits, (no room for 64 bit length) */
    if (ctx->idx >= 56) {
		sha1_compress(ctx);
		memset(ctx->buff, 0, 56);
	}
	/* Write 64 bit msg length into the last bits of the last block */
	/* (in big endian format) and do a final compress */
	p32(ctx->buff)[14] = BE32(ctx->count[1]);
	p32(ctx->buff)[15] = BE32(ctx->count[0]);
	sha1_compress(ctx);
	/* Hash->Digest to little endian format */
	for (i = 0; i <= 4; i++) {
		p32(hval)[i] = BE32(ctx->hash[i]);	
	}
}
