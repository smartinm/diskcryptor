/*
    *
    * Copyright (c) 2007-2010 
    * ntldr <ntldr@diskcryptor.net> PGP key ID - 0xC48251EB4F8E4E6E
    * based on rijndael-alg-fst.c
    *  @author Vincent Rijmen <vincent.rijmen@esat.kuleuven.ac.be>
    *  @author Antoon Bosselaers <antoon.bosselaers@esat.kuleuven.ac.be>
    *  @author Paulo Barreto <paulo.barreto@terra.com.br>
	*  @author Serge Trusov <serge.trusov@gmail.com>
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
#include "aes_small.h"

static u32 Te0[256];
static u32 Td0[256];
static u8  Te4[256];
static u8  Td4[256];

#define Td0(x) (Td0[x])
#define Td1(x) ROR32(Td0(x), 24)
#define Td2(x) ROR32(Td0(x), 16)
#define Td3(x) ROR32(Td0(x), 8) 
#define Td4(x) Td4[x]

#define Te0(x) (Te0[x])
#define Te1(x) ROR32(Te0(x), 24)
#define Te2(x) ROR32(Te0(x), 16)
#define Te3(x) ROR32(Te0(x), 8) 
#define Te4(x) Te4[x]
#define WPOLY  0x11b

#define lfsr2(x) ((x & 0x80) ? x<<1 ^ WPOLY: x<<1)
 
static u32 key_mix(u32 temp)
{
	return (Te4[d8(temp >> 8 )]) << 0  ^ (Te4[d8(temp >> 16)]) << 8  ^
		   (Te4[d8(temp >> 24)]) << 16 ^ (Te4[d8(temp >> 0 )]) << 24;
}

void aes256_set_key(const unsigned char *key, aes256_key *skey)
{
	u32 *ek, *dk;
   	int  j, i, k;
	u32  t, rcon, d;

	ek = skey->enc_key;
	
	memcpy(ek, key, AES_KEY_SIZE);
	
	i = 7; rcon = 1;
	do 
	{
		for (t = key_mix(ek[7]) ^ rcon, j = 0; j < 4; j++) {
			t ^= ek[j]; ek[8 + j] = t;
		}        
		if (--i == 0) break;		
		
		for (t = key_mix(ROR32(ek[11], 24)), j = 4; j < 8; j++) {
			t ^= ek[j]; ek[8 + j] = t;
		}
        ek += 8; rcon <<= 1;
	} while (1);

	ek = skey->enc_key;
	dk = skey->dec_key;

	for (i = 0, j = 4*ROUNDS; i <= j; i += 4, j -= 4) 
	{
		for (k = 0; k < 4; k++) {
			dk[i + k] = ek[j + k]; dk[j + k] = ek[i + k];
		}
	}
	for (i = 0; i < (ROUNDS-1) * 4; i++) 
	{
		t = dk[i + 4], d = 0;

		for (j = 32; j; j -= 8) {
			d ^= ROR32(Td0(Te4[d8(t)]), j); t >>= 8;
		}
		dk[i + 4] = d;
	}
}

void aes256_encrypt(const unsigned char *in, unsigned char *out, aes256_key *key)
{
	u32  s[4];
	u32  t[4];
	u32 *rk, x;
	u32  r, n;

	rk   = key->enc_key;
	s[0] = p32(in)[0] ^ *rk++; s[1] = p32(in)[1] ^ *rk++;
    s[2] = p32(in)[2] ^ *rk++; s[3] = p32(in)[3] ^ *rk++;
	r    = ROUNDS-1;

	do
	{
		for (n = 0; n < 4; n++)
		{
			t[n] = (Te0(d8(s[0] >> 0 ))) ^ (Te1(d8(s[1] >> 8 ))) ^
				   (Te2(d8(s[2] >> 16))) ^ (Te3(d8(s[3] >> 24))) ^ *rk++;

			x = s[0]; s[0] = s[1]; s[1] = s[2]; s[2] = s[3]; s[3] = x;
		}
		s[0] = t[0]; s[1] = t[1]; s[2] = t[2]; s[3] = t[3];
	} while (--r);
  
	for (n = 0; n < 4; n++)
	{
		s[n] = (Te4(d8(t[0] >> 0 )) << 0 ) ^ (Te4(d8(t[1] >> 8 )) << 8 ) ^
			   (Te4(d8(t[2] >> 16)) << 16) ^ (Te4(d8(t[3] >> 24)) << 24) ^ *rk++;
		
		x = t[0]; t[0] = t[1]; t[1] = t[2]; t[2] = t[3]; t[3] = x;
	}	
	memcpy(out, s, AES_BLOCK_SIZE);
}

void aes256_decrypt(const unsigned char *in, unsigned char *out, aes256_key *key)
{
	u32  s[4];
	u32  t[4];
	u32 *rk, x;
	u32  r, n;
	
	rk   = key->dec_key;
    s[0] = p32(in)[0] ^ *rk++; s[1] = p32(in)[1] ^ *rk++;
    s[2] = p32(in)[2] ^ *rk++; s[3] = p32(in)[3] ^ *rk++;
	r    = ROUNDS-1;

	do
	{
		for (n = 0; n < 4; n++)
		{
			t[n] = (Td0(d8(s[0] >> 0 ))) ^ (Td1(d8(s[3] >> 8 ))) ^
				   (Td2(d8(s[2] >> 16))) ^ (Td3(d8(s[1] >> 24))) ^ *rk++;

			x = s[0]; s[0] = s[1]; s[1] = s[2]; s[2] = s[3]; s[3] = x;
		}		
		s[0] = t[0]; s[1] = t[1]; s[2] = t[2]; s[3] = t[3];
	} while (--r);

	for (n = 0; n < 4; n++)
	{
		s[n] = (Td4(d8(t[0] >> 0 )) << 0 ) ^ (Td4(d8(t[3] >> 8 )) << 8 ) ^
			   (Td4(d8(t[2] >> 16)) << 16) ^ (Td4(d8(t[1] >> 24)) << 24) ^ *rk++;
		
		x = t[0]; t[0] = t[1]; t[1] = t[2]; t[2] = t[3]; t[3] = x;
	}
	memcpy(out, s, AES_BLOCK_SIZE);
}

void aes256_gentab()
{
	u8 pow[256], log[256];
	u8 i, w;
		
	i = 0; w = 1; 
	do
    {
        pow[i] = w;
		log[w] = i;          
		w ^= lfsr2(w);
    } while(++i);

	log[0] = 0; pow[255] = 0; i = 0;
    do
    {
        w = pow[255 - log[i]];		
		w ^= w << 1 ^ w << 2 ^ w << 3 ^ w << 4 ^
			 w >> 4 ^ w >> 5 ^ w >> 6 ^ w >> 7 ^ (1<<6 ^ 1<<5 ^ 1<<1 ^ 1<<0);        
        Te4[i] = w;
        Td4[w] = i;
    } while(++i);

	i = 0;
    do
    {
		u8 f = Te4[i]; 
		u8 r = Td4[i];
		u8 x = lfsr2(f);		

        Te0[i] = (f ^ x) << 24 | f << 16 | f << 8 | x;
		Td0[i] = ! r ? r :
                 pow[(0x68 + log[r]) % 255] << 24 ^
                 pow[(0xEE + log[r]) % 255] << 16 ^
                 pow[(0xC7 + log[r]) % 255] <<  8 ^
                 pow[(0xDF + log[r]) % 255] <<  0;     
    } while (++i);
}