/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2002, Dr Brian Gladman, Worcester, UK. All rights reserve
    * Copyright (c) 2007 ntldr <ntldr@freed0m.org> PGP key ID - 0xC48251EB4F8E4E6E
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

#include <string.h>   
#include <stdlib.h> 
#include "sha1.h"
#include "defines.h"


#define K1 0x5A827999
#define K2 0x6ED9EBA1
#define K3 0x8F1BBCDC
#define K4 0xCA62C1D6

#ifdef SMALL_CODE

static void sha1_compress(sha1_ctx ctx[1])
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

	/* prevent leaks */
	zeroauto(W, sizeof(W));
}


void sha1_init(sha1_ctx *ctx)
{
    zeroauto(ctx, sizeof(sha1_ctx));
    ctx->hash[0] = 0x67452301;
    ctx->hash[1] = 0xefcdab89;
    ctx->hash[2] = 0x98badcfe;
    ctx->hash[3] = 0x10325476;
    ctx->hash[4] = 0xc3d2e1f0;
}


void sha1_hash(sha1_ctx *ctx, void *data, size_t len)
{
	u8 *msg = data;
	u32 cnt = ctx->count[0];

	if( (ctx->count[0] += (u32)(len << 3)) < cnt) {
		ctx->count[1]++;
	}

	while (len--) 
	{
		/* fill block with msg data */
		ctx->buff[ctx->idx++] = *msg++;

		if (ctx->idx == SHA1_BLOCK_SIZE) {
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
		zeroauto(ctx->buff, 56);
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

#else /* SMALL_CODE */

/* Discovered by Rich Schroeppel and Colin Plumb   */
#define ch(x,y,z)       ((z) ^ ((x) & ((y) ^ (z))))
#define parity(x,y,z)   ((x) ^ (y) ^ (z))
#define maj(x,y,z)      (((x) & (y)) | ((z) & ((x) ^ (y))))
#define q(v,n)  v##n

#define one_cycle(v,a,b,c,d,e,f,k,h)            \
    q(v,e) += ROR32(q(v,a),27) +               \
              f(q(v,b),q(v,c),q(v,d)) + k + h;  \
    q(v,b)  = ROR32(q(v,b), 2)

#define five_cycle(v,f,k,i)                 \
    one_cycle(v, 0,1,2,3,4, f,k,hf(i  ));   \
    one_cycle(v, 4,0,1,2,3, f,k,hf(i+1));   \
    one_cycle(v, 3,4,0,1,2, f,k,hf(i+2));   \
    one_cycle(v, 2,3,4,0,1, f,k,hf(i+3));   \
    one_cycle(v, 1,2,3,4,0, f,k,hf(i+4))

static void sha1_compress(sha1_ctx ctx[1])
{
	u32 *w = p32(ctx->buff);
    u32  v0, v1, v2, v3, v4;
    v0 = ctx->hash[0]; v1 = ctx->hash[1];
    v2 = ctx->hash[2]; v3 = ctx->hash[3];
    v4 = ctx->hash[4];

#define hf(i)   w[i]
    five_cycle(v, ch, K1,  0);
    five_cycle(v, ch, K1,  5);
    five_cycle(v, ch, K1, 10);
    one_cycle(v,0,1,2,3,4, ch, K1, hf(15)); \

#undef  hf
#define hf(i) (w[(i) & 15] = ROL32(                    \
                 w[((i) + 13) & 15] ^ w[((i) + 8) & 15] \
               ^ w[((i) +  2) & 15] ^ w[(i) & 15], 1))

    one_cycle(v,4,0,1,2,3, ch, K1, hf(16));
    one_cycle(v,3,4,0,1,2, ch, K1, hf(17));
    one_cycle(v,2,3,4,0,1, ch, K1, hf(18));
    one_cycle(v,1,2,3,4,0, ch, K1, hf(19));

    five_cycle(v, parity, K2,  20);
    five_cycle(v, parity, K2,  25);
    five_cycle(v, parity, K2,  30);
    five_cycle(v, parity, K2,  35);

    five_cycle(v, maj, K3,  40);
    five_cycle(v, maj, K3,  45);
    five_cycle(v, maj, K3,  50);
    five_cycle(v, maj, K3,  55);

    five_cycle(v, parity, K4,  60);
    five_cycle(v, parity, K4,  65);
    five_cycle(v, parity, K4,  70);
    five_cycle(v, parity, K4,  75);

    ctx->hash[0] += v0; ctx->hash[1] += v1;
    ctx->hash[2] += v2; ctx->hash[3] += v3;
    ctx->hash[4] += v4;
}

void sha1_init(sha1_ctx ctx[1])
{
    ctx->count[0] = ctx->count[1] = 0;
    ctx->hash[0] = 0x67452301;
    ctx->hash[1] = 0xefcdab89;
    ctx->hash[2] = 0x98badcfe;
    ctx->hash[3] = 0x10325476;
    ctx->hash[4] = 0xc3d2e1f0;
}

/* SHA1 hash data in an array of bytes into hash buffer and */
/* call the hash_compile function as required.              */

#define SHA1_MASK   (SHA1_BLOCK_SIZE - 1)

#define bsw_32(p,n) \
    { u32 _i; for (_i = 0; _i < (n); _i++) p32(p)[_i] = BE32(p32(p)[_i]); }

void sha1_hash(sha1_ctx *ctx, void *data, size_t len)
{
	u32 pos = (u32)(ctx->count[0] & SHA1_MASK), 
		space = SHA1_BLOCK_SIZE - pos;
    u8 *sp = data;

	if((ctx->count[0] += (u32)len) < (u32)len) {
		++(ctx->count[1]);
	}

    while (len >= space)     /* tranfer whole blocks if possible  */
    {
        memcpy(((unsigned char*)ctx->buff) + pos, sp, space);
        sp += space; len -= space; space = SHA1_BLOCK_SIZE; pos = 0;
        bsw_32(ctx->buff, SHA1_BLOCK_SIZE >> 2);
        sha1_compress(ctx);
    }

    memcpy(((unsigned char*)ctx->buff) + pos, sp, len);
}

/* SHA1 final padding and digest calculation  */

void sha1_done(sha1_ctx *ctx, u8 *hval)
{   u32    i = (u32)(ctx->count[0] & SHA1_MASK);

    /* put bytes in the buffer in an order in which references to   */
    /* 32-bit words will put bytes with lower addresses into the    */
    /* top of 32 bit words on BOTH big and little endian machines   */
    bsw_32(ctx->buff, (i + 3) >> 2);

    /* we now need to mask valid bytes and add the padding which is */
    /* a single 1 bit and as many zero bits as necessary. Note that */
    /* we can always add the first padding byte here because the    */
    /* buffer always has at least one empty slot                    */
    p32(ctx->buff)[i >> 2] &= 0xffffff80 << 8 * (~i & 3);
    p32(ctx->buff)[i >> 2] |= 0x00000080 << 8 * (~i & 3);

    /* we need 9 or more empty positions, one for the padding byte  */
    /* (above) and eight for the length count. If there is not      */
    /* enough space, pad and empty the buffer                       */
    if(i > SHA1_BLOCK_SIZE - 9)
    {
        if(i < 60) p32(ctx->buff)[15] = 0;
        sha1_compress(ctx);
        i = 0;
    }
    else    /* compute a word index for the empty buffer positions  */
        i = (i >> 2) + 1;

	while(i < 14) /* and zero pad all but last two positions        */
        p32(ctx->buff)[i++] = 0;

    /* the following 32-bit length fields are assembled in the      */
    /* wrong byte order on little endian machines but this is       */
    /* corrected later since they are only ever used as 32-bit      */
    /* word values.                                                 */
    p32(ctx->buff)[14] = (ctx->count[1] << 3) | (ctx->count[0] >> 29);
    p32(ctx->buff)[15] = ctx->count[0] << 3;
	sha1_compress(ctx);

    /* extract the hash value as bytes in case the hash buffer is   */
    /* misaligned for 32-bit words                                  */
   /* for(i = 0; i < SHA1_DIGEST_SIZE; ++i)
        hval[i] = (unsigned char)(ctx->hash[i >> 2] >> (8 * (~i & 3)));*/
	p32(hval)[0] = BE32(ctx->hash[0]); p32(hval)[1] = BE32(ctx->hash[1]);
	p32(hval)[2] = BE32(ctx->hash[2]); p32(hval)[3] = BE32(ctx->hash[3]);
	p32(hval)[4] = BE32(ctx->hash[4]);	
}

#endif /* SMALL_CODE */