/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2008 
    * ntldr <ntldr@freed0m.org> PGP key ID - 0xC48251EB4F8E4E6E
    * based on rijndael-alg-fst.c
    *  @author Vincent Rijmen <vincent.rijmen@esat.kuleuven.ac.be>
    *  @author Antoon Bosselaers <antoon.bosselaers@esat.kuleuven.ac.be>
    *  @author Paulo Barreto <paulo.barreto@terra.com.br>
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
#include "mini_aes.h"
#include "mini_aes_tab.h"


static u32 key_mix(u32 temp)
{
   return (Te4[(temp >> 8 ) & 0xFF]) << 0  ^ 
          (Te4[(temp >> 16) & 0xFF]) << 8  ^
          (Te4[(temp >> 24) & 0xFF]) << 16 ^
          (Te4[(temp >> 0 ) & 0xFF]) << 24;
}

static u32 key_mix2(u32 temp)
{
   return Td0(Te4[(temp >> 0 ) & 0xFF]) ^
          Td1(Te4[(temp >> 8 ) & 0xFF]) ^
          Td2(Te4[(temp >> 16) & 0xFF]) ^
          Td3(Te4[(temp >> 24) & 0xFF]);
} 

void aes256_set_key(u8 *data, aes256_key *key)
{
	u32 *ek, *dk;
   	int  j, i;
	u32  t, rcon;

	ek = key->enc_key;
	i  = 0;

	ek[0] = p32(data)[0]; ek[1] = p32(data)[1];
	ek[2] = p32(data)[2]; ek[3] = p32(data)[3];
	ek[4] = p32(data)[4]; ek[5] = p32(data)[5];
	ek[6] = p32(data)[6]; ek[7] = p32(data)[7];
	
	i = 7; rcon = 1;
	do 
	{
		ek[ 8] = ek[0] ^ key_mix(ek[7]) ^ rcon;
        ek[ 9] = ek[1] ^ ek[ 8];
        ek[10] = ek[2] ^ ek[ 9];
        ek[11] = ek[3] ^ ek[10];
        
		if (--i == 0) {
			break;
		};

        ek[12] = ek[4] ^ key_mix(ROR32(ek[11], 24));
        ek[13] = ek[5] ^ ek[12];
        ek[14] = ek[6] ^ ek[13];
        ek[15] = ek[7] ^ ek[14];
        ek += 8; rcon <<= 1;
	} while (1);

	ek = key->enc_key;
	dk = key->dec_key;
	
	for (i = 0, j = 4*ROUNDS; i <= j; i += 4, j -= 4) {
		t = ek[i    ]; dk[i    ] = ek[j    ]; dk[j    ] = t;
		t = ek[i + 1]; dk[i + 1] = ek[j + 1]; dk[j + 1] = t;
		t = ek[i + 2]; dk[i + 2] = ek[j + 2]; dk[j + 2] = t;
		t = ek[i + 3]; dk[i + 3] = ek[j + 3]; dk[j + 3] = t;
	}

	i = (ROUNDS-1) * 4;

	do {
		dk[4] = key_mix2(dk[4]); dk++;
	} while (--i);
}

void aes_decrypt(u8 *in, u8 *out, aes256_key *key)
{
	u32  s[4];
	u32  t[4];
	u32 *rk, x;
	int  r, n;
	
	rk   = key->dec_key;
    s[0] = p32(in)[0] ^ *rk++; s[1] = p32(in)[1] ^ *rk++;
    s[2] = p32(in)[2] ^ *rk++; s[3] = p32(in)[3] ^ *rk++;
	r    = ROUNDS-1;

	do
	{
		for (n = 0; n < 4; n++)
		{
			t[n] =
				(Td0((s[0] >> 0 ) & 0xff)) ^
				(Td1((s[3] >> 8 ) & 0xff)) ^
				(Td2((s[2] >> 16) & 0xff)) ^
				(Td3((s[1] >> 24) & 0xff)) ^
				(*rk++);

			x = s[0]; s[0] = s[1]; s[1] = s[2]; s[2] = s[3]; s[3] = x;
		}

		s[0] = t[0]; s[1] = t[1]; s[2] = t[2]; s[3] = t[3];
	} while (--r);

	for (n = 0; n < 4; n++)
	{
		s[n] = 
			(Td4((t[0] >> 0 ) & 0xff) << 0 ) ^
			(Td4((t[3] >> 8 ) & 0xff) << 8 ) ^
			(Td4((t[2] >> 16) & 0xff) << 16) ^
			(Td4((t[1] >> 24) & 0xff) << 24) ^
			(*rk++);
		
		x = t[0]; t[0] = t[1]; t[1] = t[2]; t[2] = t[3]; t[3] = x;
	}
	
	p32(out)[0] = s[0]; p32(out)[1] = s[1];
	p32(out)[2] = s[2]; p32(out)[3] = s[3];	
}

void aes_encrypt(unsigned char *in, unsigned char *out, aes256_key *key)
{
	u32  s[4];
	u32  t[4];
	u32 *rk, x;
	int  r, n;

	rk   = key->enc_key;
	s[0] = p32(in)[0] ^ *rk++; s[1] = p32(in)[1] ^ *rk++;
    s[2] = p32(in)[2] ^ *rk++; s[3] = p32(in)[3] ^ *rk++;
	r    = ROUNDS-1;

	do
	{
		for (n = 0; n < 4; n++)
		{
			t[n] =
				(Te0((s[0] >> 0 ) & 0xff)) ^
				(Te1((s[1] >> 8 ) & 0xff)) ^
				(Te2((s[2] >> 16) & 0xff)) ^
				(Te3((s[3] >> 24) & 0xff)) ^
				(*rk++);

			x = s[0]; s[0] = s[1]; s[1] = s[2]; s[2] = s[3]; s[3] = x;
		}

		s[0] = t[0]; s[1] = t[1]; s[2] = t[2]; s[3] = t[3];
	} while (--r);
  
	for (n = 0; n < 4; n++)
	{
		s[n] = 
			(Te4((t[0] >> 0 ) & 0xff) << 0 ) ^
			(Te4((t[1] >> 8 ) & 0xff) << 8 ) ^
			(Te4((t[2] >> 16) & 0xff) << 16) ^
			(Te4((t[3] >> 24) & 0xff) << 24) ^
			(*rk++);
		
		x = t[0]; t[0] = t[1]; t[1] = t[2]; t[2] = t[3]; t[3] = x;
	}
	
	p32(out)[0] = s[0]; p32(out)[1] = s[1];
	p32(out)[2] = s[2]; p32(out)[3] = s[3];	
}
