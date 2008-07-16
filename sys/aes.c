/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2007-2008 
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

#include "defines.h"
#include "aes.h"
#include "aes_tab.h"


static u32 key_mix(u32 t)
{
   return Te4_1[(t >>  8) & 0xFF] ^ Te4_2[(t >> 16) & 0xFF] ^ 
	      Te4_3[t >> 24] ^ Te4_4[t & 0xFF];
}

static u32 key_mix2(u32 t)
{
   return Td0[Te4_1[t & 0xFF]] ^ Td1[Te4_1[(t >> 8) & 0xFF]] ^
          Td2[Te4_1[(t >> 16) & 0xFF]] ^ Td3[Te4_1[t >> 24]];
} 

#ifdef ASM_CRYPTO
 void gen_cipher_code(u8 *dst, void *src, int srclen, u32 *rk);
#endif

void aes256_set_key(unsigned char *data, aes256_key *key)
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

#ifdef ASM_CRYPTO
	gen_cipher_code(key->dk_code, decryptor, sizeof(decryptor), key->dec_key);
	gen_cipher_code(key->ek_code, encryptor, sizeof(encryptor), key->enc_key);
#endif
}

#ifdef ASM_CRYPTO

static void gen_cipher_code(u8 *dst, void *src, int srclen, u32 *rk)
{
	u32 a, b;
	u32 off;

	/* copy AES code to code buffer */
	memcpy(dst, src, srclen);

	/* patch round keys and all AES tables references in code */
	for (off = 0; off <= srclen - sizeof(void*);) 
	{
		/* get patch signature and parameter */
		a = p32(dst + off)[0]; b = (a & 0xff);

		switch (a >> 16)
		{
			case 0x4567: /* patch AES table reference */
			  ppv(dst + off)[0] = rel_tab[b]; 
			  off += sizeof(void*);
			break;
			case 0x1234: /* patch round key */
			  p32(dst + off)[0] = rk[b];  
			  off += sizeof(void*);
			break;
			default: off++;
		}
	}
}

#else
 
void aes256_encrypt(unsigned char *in, unsigned char *out, aes256_key *key)
{
	u32 *rk;
	u32  s0, s1, s2, s3, t0, t1, t2, t3;
	int  r;

	rk = key->enc_key;
	s0 = p32(in)[0] ^ rk[0]; s1 = p32(in)[1] ^ rk[1];
	s2 = p32(in)[2] ^ rk[2]; s3 = p32(in)[3] ^ rk[3];
	r  = ROUNDS >> 1;	
    
    do
	{
		t0 = Te0[s0 & 0xff] ^ Te1[(s1 >> 8) & 0xff] ^ Te2[(s2 >> 16) & 0xff] ^ Te3[s3 >> 24] ^ rk[4];
        t1 = Te0[s1 & 0xff] ^ Te1[(s2 >> 8) & 0xff] ^ Te2[(s3 >> 16) & 0xff] ^ Te3[s0 >> 24] ^ rk[5];
        t2 = Te0[s2 & 0xff] ^ Te1[(s3 >> 8) & 0xff] ^ Te2[(s0 >> 16) & 0xff] ^ Te3[s1 >> 24] ^ rk[6];
        t3 = Te0[s3 & 0xff] ^ Te1[(s0 >> 8) & 0xff] ^ Te2[(s1 >> 16) & 0xff] ^ Te3[s2 >> 24] ^ rk[7];

        rk += 8;

		if (--r == 0) {
            break;
        }

        s0 = Te0[t0 & 0xff] ^ Te1[(t1 >> 8) & 0xff] ^ Te2[(t2 >> 16) & 0xff] ^ Te3[t3 >> 24] ^ rk[0];
        s1 = Te0[t1 & 0xff] ^ Te1[(t2 >> 8) & 0xff] ^ Te2[(t3 >> 16) & 0xff] ^ Te3[t0 >> 24] ^ rk[1];
        s2 = Te0[t2 & 0xff] ^ Te1[(t3 >> 8) & 0xff] ^ Te2[(t0 >> 16) & 0xff] ^ Te3[t1 >> 24] ^ rk[2];
        s3 = Te0[t3 & 0xff] ^ Te1[(t0 >> 8) & 0xff] ^ Te2[(t1 >> 16) & 0xff] ^ Te3[t2 >> 24] ^ rk[3];
	} while (1);

	s0 = Te4_1[t0 & 0xff] ^ Te4_2[(t1 >> 8) & 0xff] ^ Te4_3[(t2 >> 16) & 0xff] ^ Te4_4[t3 >> 24] ^ rk[0];
	p32(out)[0] = s0;
	s1 = Te4_1[t1 & 0xff] ^ Te4_2[(t2 >> 8) & 0xff] ^ Te4_3[(t3 >> 16) & 0xff] ^ Te4_4[t0 >> 24] ^ rk[1];
	p32(out)[1] = s1;
	s2 = Te4_1[t2 & 0xff] ^ Te4_2[(t3 >> 8) & 0xff] ^ Te4_3[(t0 >> 16) & 0xff] ^ Te4_4[t1 >> 24] ^ rk[2];
	p32(out)[2] = s2;
	s3 = Te4_1[t3 & 0xff] ^ Te4_2[(t0 >> 8) & 0xff] ^ Te4_3[(t1 >> 16) & 0xff] ^ Te4_4[t2 >> 24] ^ rk[3];	
	p32(out)[3] = s3;
}


void aes256_decrypt(unsigned char *in, unsigned char *out, aes256_key *key)
{
	u32 *rk;
	u32  s0, s1, s2, s3, t0, t1, t2, t3;
	int  r;

	rk = key->dec_key;
    s0 = p32(in)[0] ^ rk[0]; s1 = p32(in)[1] ^ rk[1];
    s2 = p32(in)[2] ^ rk[2]; s3 = p32(in)[3] ^ rk[3];
    r  = ROUNDS >> 1;
    do
	{
		t0 = Td0[s0 & 0xff] ^ Td1[(s3 >> 8) & 0xff] ^ Td2[(s2 >> 16) & 0xff] ^ Td3[s1 >> 24] ^ rk[4];
        t1 = Td0[s1 & 0xff] ^ Td1[(s0 >> 8) & 0xff] ^ Td2[(s3 >> 16) & 0xff] ^ Td3[s2 >> 24] ^ rk[5];
        t2 = Td0[s2 & 0xff] ^ Td1[(s1 >> 8) & 0xff] ^ Td2[(s0 >> 16) & 0xff] ^ Td3[s3 >> 24] ^ rk[6];
        t3 = Td0[s3 & 0xff] ^ Td1[(s2 >> 8) & 0xff] ^ Td2[(s1 >> 16) & 0xff] ^ Td3[s0 >> 24] ^ rk[7];

        rk += 8;
        if (--r == 0) {
            break;
        }

        s0 = Td0[t0 & 0xff] ^ Td1[(t3 >> 8) & 0xff] ^ Td2[(t2 >> 16) & 0xff] ^ Td3[t1 >> 24] ^ rk[0];
        s1 = Td0[t1 & 0xff] ^ Td1[(t0 >> 8) & 0xff] ^ Td2[(t3 >> 16) & 0xff] ^ Td3[t2 >> 24] ^ rk[1];
        s2 = Td0[t2 & 0xff] ^ Td1[(t1 >> 8) & 0xff] ^ Td2[(t0 >> 16) & 0xff] ^ Td3[t3 >> 24] ^ rk[2];
        s3 = Td0[t3 & 0xff] ^ Td1[(t2 >> 8) & 0xff] ^ Td2[(t1 >> 16) & 0xff] ^ Td3[t0 >> 24] ^ rk[3];
    } while (1);
    
   	s0 = Td4_1[t0 & 0xff] ^ Td4_2[(t3 >> 8) & 0xff] ^ Td4_3[(t2 >> 16) & 0xff] ^ Td4_4[t1 >> 24] ^ rk[0];
	p32(out)[0] = s0;
   	s1 = Td4_1[t1 & 0xff] ^ Td4_2[(t0 >> 8) & 0xff] ^ Td4_3[(t3 >> 16) & 0xff] ^ Td4_4[t2 >> 24] ^ rk[1];
	p32(out)[1] = s1;
   	s2 = Td4_1[t2 & 0xff] ^ Td4_2[(t1 >> 8) & 0xff] ^ Td4_3[(t0 >> 16) & 0xff] ^ Td4_4[t3 >> 24] ^ rk[2];
	p32(out)[2] = s2;
   	s3 = Td4_1[t3 & 0xff] ^ Td4_2[(t2 >> 8) & 0xff] ^ Td4_3[(t1 >> 16) & 0xff] ^ Td4_4[t0 >> 24] ^ rk[3];
	p32(out)[3] = s3;
}

#endif