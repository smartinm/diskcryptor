/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2007-2008 
    * ntldr <ntldr@freed0m.org> PGP key ID - 0xC48251EB4F8E4E6E
    * based on rijndael-alg-fst.c
    *  @author Vincent Rijmen <vincent.rijmen@esat.kuleuven.ac.be>
    *  @author Antoon Bosselaers <antoon.bosselaers@esat.kuleuven.ac.be>
    *  @author Paulo Barreto <paulo.barreto@terra.com.br>
	*  @author Serge Trusov <serge.trusov@gmail.com>
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

#ifdef AES_ASM
 void gen_cipher_code(u8 *dst, void *src, int srclen, u32 *rk);
#endif

#ifdef SMALL_CODE
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
#endif /* SMALL_CODE */

#ifdef SMALL_CODE
 
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

#else

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

#endif

#ifdef AES_ASM
 extern int aes_enc_begin;
 extern int aes_dec_begin;
 extern int aes_enc_size;
 extern int aes_dec_size;
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
#ifdef AES_ASM
	gen_cipher_code(key->dk_code, &aes_dec_begin, aes_dec_size, key->dec_key);
	gen_cipher_code(key->ek_code, &aes_enc_begin, aes_enc_size, key->enc_key);
#endif
}

#ifdef AES_ASM

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

#else /* AES_ASM */
 
#ifdef SMALL_CODE

void aes256_encrypt(unsigned char *in, unsigned char *out, aes256_key *key)
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

void aes256_decrypt(u8 *in, u8 *out, aes256_key *key)
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

static u8 lfsr2(u8 a)
{
    return (a & 0x80) ? a<<1 ^ WPOLY: a<<1;
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

	log[0] = 0; pow[255] = 0;
    i = 0;
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

#else /* SMALL_CODE */

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

#endif /* SMALL_CODE */
#endif /* AES_ASM */