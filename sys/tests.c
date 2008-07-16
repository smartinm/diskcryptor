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

#include <ntifs.h>
#include "defines.h"
#include "tests.h"
#include "sha1.h"
#include "pkcs5.h"
#include "gf128mul.h"
#include "crc32.h"
#include "crypto.h"
#include "sha512.h"
/*


#include "aes.h"

*/
static struct {
	u8 key[32];
	u8 plaintext[16];
	u8 ciphertext[16];
} aes256_vectors[] = {
	{
		{ 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
		  0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f },
		{ 0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff },
		{ 0x8e,0xa2,0xb7,0xca,0x51,0x67,0x45,0xbf,0xea,0xfc,0x49,0x90,0x4b,0x49,0x60,0x89 }
	},
	{
		{ 0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c,
		  0x76,0x2e,0x71,0x60,0xf3,0x8b,0x4d,0xa5,0x6a,0x78,0x4d,0x90,0x45,0x19,0x0c,0xfe },
		{ 0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34 },
		{ 0x1a,0x6e,0x6c,0x2c,0x66,0x2e,0x7d,0xa6,0x50,0x1f,0xfb,0x62,0xbc,0x9e,0x93,0xf3 }
	}
};

static struct {
	u8  cipher_k[32];
	u8  tweak_k[16];
	u8  index[8];
	u32 size;
	u8 *plaintext;
	u8 *ciphertext;	
} aes256_lrw_vectors[] = {
	{
		{ 0xf8, 0xd4, 0x76, 0xff, 0xd6, 0x46, 0xee, 0x6c, 0x23, 0x84, 0xcb, 
		  0x1c, 0x77, 0xd6, 0x19, 0x5d, 0xfe, 0xf1, 0xa9, 0xf3, 0x7b, 0xbc, 
		  0x8d, 0x21, 0xa7, 0x9c, 0x21, 0xf8, 0xcb, 0x90, 0x02, 0x89 },
		{ 0xa8, 0x45, 0x34, 0x8e, 0xc8, 0xc5, 0xb5, 0xf1, 0x26, 0xf5, 0x0e, 0x76, 0xfe, 0xfd, 0x1b, 0x1e },
		{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
		16,
		"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46",
		"\xbd\x06\xb8\xe1\xdb\x98\x89\x9e\xc4\x98\xe4\x91\xcf\x1c\x70\x2b"
	},
	{
		{ 0xfb, 0x76, 0x15, 0xb2, 0x3d, 0x80, 0x89, 0x1d, 0xd4, 0x70, 0x98, 
		  0x0b, 0xc7, 0x95, 0x84, 0xc8, 0xb2, 0xfb, 0x64, 0xce, 0x60, 0x97,
		  0x87, 0x8d, 0x17, 0xfc, 0xe4, 0x5a, 0x49, 0xe8, 0x30, 0xb7 },
		{ 0x6e, 0x78, 0x17, 0xe7, 0x2d, 0x5e, 0x12, 0xd4, 0x60, 0x64, 0x04, 0x7a, 0xf1, 0x2f, 0x9e, 0x0c },
		{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 },
		16,
		"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46",
		"\x5b\x90\x8e\xc1\xab\xdd\x67\x5f\x3d\x69\x8a\x95\x53\xc8\x9c\xe5"
	}, 
	{
		{ 0xf8, 0xd4, 0x76, 0xff, 0xd6, 0x46, 0xee, 0x6c, 0x23, 0x84, 0xcb, 0x1c, 0x77, 0xd6, 0x19, 0x5d,
		  0xfe, 0xf1, 0xa9, 0xf3, 0x7b, 0xbc, 0x8d, 0x21, 0xa7, 0x9c, 0x21, 0xf8, 0xcb, 0x90, 0x02, 0x89 },
		{ 0xa8, 0x45, 0x34, 0x8e, 0xc8, 0xc5, 0xb5, 0xf1, 0x26, 0xf5, 0x0e, 0x76, 0xfe, 0xfd, 0x1b, 0x1e },
		{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
		512,
		"\x05\x11\xb7\x18\xab\xc6\x2d\xac\x70\x5d\xf6\x22\x94\xcd\xe5\x6c"
		"\x17\x6b\xf6\x1c\xf0\xf3\x6e\xf8\x50\x38\x1f\x71\x49\xb6\x57\xd6"
		"\x8f\xcb\x8d\x6b\xe3\xa6\x29\x90\xfe\x2a\x62\x82\xae\x6d\x8b\xf6"
		"\xad\x1e\x9e\x20\x5f\x38\xbe\x04\xda\x10\x8e\xed\xa2\xa4\x87\xab"
		"\xda\x6b\xb4\x0c\x75\xba\xd3\x7c\xc9\xac\x42\x31\x95\x7c\xc9\x04"
		"\xeb\xd5\x6e\x32\x69\x8a\xdb\xa6\x15\xd7\x3f\x4f\x2f\x66\x69\x03"
		"\x9c\x1f\x54\x0f\xde\x1f\xf3\x65\x4c\x96\x12\xed\x7c\x92\x03\x01"
		"\x6f\xbc\x35\x93\xac\xf1\x27\xf1\xb4\x96\x82\x5a\x5f\xb0\xa0\x50"
		"\x89\xa4\x8e\x66\x44\x85\xcc\xfd\x33\x14\x70\xe3\x96\xb2\xc3\xd3"
		"\xbb\x54\x5a\x1a\xf9\x74\xa2\xc5\x2d\x64\x75\xdd\xb4\x54\xe6\x74"
		"\x8c\xd3\x9d\x9e\x86\xab\x51\x53\xb7\x93\x3e\x6f\xd0\x4e\x2c\x40"
		"\xf6\xa8\x2e\x3e\x9d\xf4\x66\xa5\x76\x12\x73\x44\x1a\x56\xd7\x72"
		"\x88\xcd\x21\x8c\x4c\x0f\xfe\xda\x95\xe0\x3a\xa6\xa5\x84\x46\xcd"
		"\xd5\x3e\x9d\x3a\xe2\x67\xe6\x60\x1a\xe2\x70\x85\x58\xc2\x1b\x09"
		"\xe1\xd7\x2c\xca\xad\xa8\x8f\xf9\xac\xb3\x0e\xdb\xca\x2e\xe2\xb8"
		"\x51\x71\xd9\x3c\x6c\xf1\x56\xf8\xea\x9c\xf1\xfb\x0c\xe6\xb7\x10"
		"\x1c\xf8\xa9\x7c\xe8\x53\x35\xc1\x90\x3e\x76\x4a\x74\xa4\x21\x2c"
		"\xf6\x2c\x4e\x0f\x94\x3a\x88\x2e\x41\x09\x6a\x33\x7d\xf6\xdd\x3f"
		"\x8d\x23\x31\x74\x84\xeb\x88\x6e\xcc\xb9\xbc\x22\x83\x19\x07\x22"
		"\xa5\x2d\xdf\xa5\xf3\x80\x85\x78\x84\x39\x6a\x6d\x6a\x99\x4f\xa5"
		"\x15\xfe\x46\xb0\xe4\x6c\xa5\x41\x3c\xce\x8f\x42\x60\x71\xa7\x75"
		"\x08\x40\x65\x8a\x82\xbf\xf5\x43\x71\x96\xa9\x4d\x44\x8a\x20\xbe"
		"\xfa\x4d\xbb\xc0\x7d\x31\x96\x65\xe7\x75\xe5\x3e\xfd\x92\x3b\xc9"
		"\x55\xbb\x16\x7e\xf7\xc2\x8c\xa4\x40\x1d\xe5\xef\x0e\xdf\xe4\x9a"
		"\x62\x73\x65\xfd\x46\x63\x25\x3d\x2b\xaf\xe5\x64\xfe\xa5\x5c\xcf"
		"\x24\xf3\xb4\xac\x64\xba\xdf\x4b\xc6\x96\x7d\x81\x2d\x8d\x97\xf7"
		"\xc5\x68\x77\x84\x32\x2b\xcc\x85\x74\x96\xf0\x12\x77\x61\xb9\xeb"
		"\x71\xaa\x82\xcb\x1c\xdb\x89\xc8\xc6\xb5\xe3\x5c\x7d\x39\x07\x24"
		"\xda\x39\x87\x45\xc0\x2b\xbb\x01\xac\xbc\x2a\x5c\x7f\xfc\xe8\xce"
		"\x6d\x9c\x6f\xed\xd3\xc1\xa1\xd6\xc5\x55\xa9\x66\x2f\xe1\xc8\x32"
		"\xa6\x5d\xa4\x3a\x98\x73\xe8\x45\xa4\xc7\xa8\xb4\xf6\x13\x03\xf6"
		"\xe9\x2e\xc4\x29\x0f\x84\xdb\xc4\x21\xc4\xc2\x75\x67\x89\x37\x0a",

		"\x1a\x1d\xa9\x30\xad\xf9\x2f\x9b\xb6\x1d\xae\xef\xf0\x2f\xf8\x5a"
		"\x39\x3c\xbf\x2a\xb2\x45\xb2\x23\x1b\x63\x3c\xcf\xaa\xbe\xcf\x4e"
		"\xfa\xe8\x29\xc2\x20\x68\x2b\x3c\x2e\x8b\xf7\x6e\x25\xbd\xe3\x3d"
		"\x66\x27\xd6\xaf\xd6\x64\x3e\xe3\xe8\x58\x46\x97\x39\x51\x07\xde"
		"\xcb\x37\xbc\xa9\xc0\x5f\x75\xc3\x0e\x84\x23\x1d\x16\xd4\x1c\x59"
		"\x9c\x1a\x02\x55\xab\x3a\x97\x1d\xdf\xdd\xc7\x06\x51\xd7\x70\xae"
		"\x23\xc6\x8c\xf5\x1e\xa0\xe5\x82\xb8\xb2\xbf\x04\xa0\x32\x8e\x68"
		"\xeb\xaf\x6e\x2d\x94\x22\x2f\xce\x4c\xb5\x59\xe2\xa2\x2f\xa0\x98"
		"\x1a\x97\xc6\xd4\xb5\x00\x59\xf2\x84\x14\x72\xb1\x9a\x6e\xa3\x7f"
		"\xea\x20\xe7\xcb\x65\x77\x3a\xdf\xc8\x97\x67\x15\xc2\x2a\x27\xcc"
		"\x18\x55\xa1\x24\x0b\x24\x24\xaf\x5b\xec\x68\xb8\xc8\xf5\xba\x63"
		"\xff\xed\x89\xce\xd5\x3d\x88\xf3\x25\xef\x05\x7c\x3a\xef\xeb\xd8"
		"\x7a\x32\x0d\xd1\x1e\x58\x59\x99\x90\x25\xb5\x26\xb0\xe3\x2b\x6c"
		"\x4c\xa9\x8b\x84\x4f\x5e\x01\x50\x41\x30\x58\xc5\x62\x74\x52\x1d"
		"\x45\x24\x6a\x42\x64\x4f\x97\x1c\xa8\x66\xb5\x6d\x79\xd4\x0d\x48"
		"\xc5\x5f\xf3\x90\x32\xdd\xdd\xe1\xe4\xa9\x9f\xfc\xc3\x52\x5a\x46"
		"\xe4\x81\x84\x95\x36\x59\x7a\x6b\xaa\xb3\x60\xad\xce\x9f\x9f\x28"
		"\xe0\x01\x75\x22\xc4\x4e\xa9\x62\x5c\x62\x0d\x00\xcb\x13\xe8\x43"
		"\x72\xd4\x2d\x53\x46\xb5\xd1\x16\x22\x18\xdf\x34\x33\xf5\xd6\x1c"
		"\xb8\x79\x78\x97\x94\xff\x72\x13\x4c\x27\xfc\xcb\xbf\x01\x53\xa6"
		"\xb4\x50\x6e\xde\xdf\xb5\x43\xa4\x59\xdf\x52\xf9\x7c\xe0\x11\x6f"
		"\x2d\x14\x8e\x24\x61\x2c\xe1\x17\xcc\xce\x51\x0c\x19\x8a\x82\x30"
		"\x94\xd5\x3d\x6a\x53\x06\x5e\xbd\xb7\xeb\xfa\xfd\x27\x51\xde\x85"
		"\x1e\x86\x53\x11\x53\x94\x00\xee\x2b\x8c\x08\x2a\xbf\xdd\xae\x11"
		"\xcb\x1e\xa2\x07\x9a\x80\xcf\x62\x9b\x09\xdc\x95\x3c\x96\x8e\xb1"
		"\x09\xbd\xe4\xeb\xdb\xca\x70\x7a\x9e\xfa\x31\x18\x45\x3c\x21\x33"
		"\xb0\xb3\x2b\xea\xf3\x71\x2d\xe1\x03\xad\x1b\x48\xd4\x67\x27\xf0"
		"\x62\xe4\x3d\xfb\x9b\x08\x76\xe7\xdd\x2b\x01\x39\x04\x5a\x58\x7a"
		"\xf7\x11\x90\xec\xbd\x51\x5c\x32\x6b\xd7\x35\x39\x02\x6b\xf2\xa6"
		"\xd0\x0d\x07\xe1\x06\xc4\x5b\x7d\xe4\x6a\xd7\xee\x15\x1f\x83\xb4"
		"\xa3\xa7\x5e\xc3\x90\xb7\xef\xd3\xb7\x4f\xf8\x92\x4c\xb7\x3c\x29"
		"\xcd\x7e\x2b\x5d\x43\xea\x42\xe7\x74\x3f\x7d\x58\x88\x75\xde\x3e"
	}
};

static struct {
	u8 *msg;
	u8  hash[20];
} sha1_vectors[] = {
	{
		"abc",
        { 0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 
	      0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d }
	},
    { 
		"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		{ 0x84, 0x98, 0x3E, 0x44, 0x1C, 0x3B, 0xD2, 0x6E, 0xBA, 0xAE, 
		  0x4A, 0xA1, 0xF9, 0x51, 0x29, 0xE5, 0xE5, 0x46, 0x70, 0xF1 }
	}
};

static struct {
	u8 *key;
	u8 *data;
	u8 *hmac;
} sha1_hmac_vectors[] = {
	{
		"\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68"
		"\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81"
		"\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a"
		"\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3",
		"Sample #3",
		"\xbc\xf4\x1e\xab\x8b\xb2\xd8\x02\xf3\xd0\x5c\xaf\x7c\xb0\x92\xec\xf8\xd1\xa3\xaa",
	}, 
	{
		"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
		"Hi There",
		"\xb6\x17\x31\x86\x55\x05\x72\x64\xe2\x8b\xc0\xb6\xfb\x37\x8c\x8e\xf1\x46\xbe\x00"
	},
	{
		"Jefe",
		"what do ya want for nothing?",
		"\xef\xfc\xdf\x6a\xe5\xeb\x2f\xa2\xd2\x74\x16\xd5\xf1\x84\xdf\x9c\x25\x9a\x7c\x79"
	},
	{
		"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA",
		"\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
		"\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
		"\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD",
		"\x12\x5d\x73\x42\xb9\xac\x11\xcd\x91\xa3\x9a\xf4\x8a\xa1\x7b\x4f\x63\xf1\x75\xd3"
	}
};

static struct {
      u8 *msg;
      u8  hash[64];
} sha512_vectors[] = {
	{ 
		"abc",
		{ 0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
		  0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
		  0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
		  0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e, 0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f }
    },
    { 
		"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
		{ 0x8e, 0x95, 0x9b, 0x75, 0xda, 0xe3, 0x13, 0xda, 0x8c, 0xf4, 0xf7, 0x28, 0x14, 0xfc, 0x14, 0x3f,
		  0x8f, 0x77, 0x79, 0xc6, 0xeb, 0x9f, 0x7f, 0xa1, 0x72, 0x99, 0xae, 0xad, 0xb6, 0x88, 0x90, 0x18,
		  0x50, 0x1d, 0x28, 0x9e, 0x49, 0x00, 0xf7, 0xe4, 0x33, 0x1b, 0x99, 0xde, 0xc4, 0xb5, 0x43, 0x3a,
		  0xc7, 0xd3, 0x29, 0xee, 0xb6, 0xdd, 0x26, 0x54, 0x5e, 0x96, 0xe5, 0x5b, 0x87, 0x4b, 0xe9, 0x09 }
    }
};

static struct 
{
  int iterations;
  u8  *password;
  u8  *salt;
  int  dklen;
  u8  *key;
} pkcs5_vectors[] = 
{
	{1, "password", "ATHENA.MIT.EDUraeburn", 16, "\xCD\xED\xB5\x28\x1B\xB2\xF8\x01\x56\x5A\x11\x22\xB2\x56\x35\x15"},
	{2, "password", "ATHENA.MIT.EDUraeburn", 16, "\x01\xdb\xee\x7f\x4a\x9e\x24\x3e\x98\x8b\x62\xc7\x3c\xda\x93\x5d"},
	{2, "password", "ATHENA.MIT.EDUraeburn", 32, "\x01\xdb\xee\x7f\x4a\x9e\x24\x3e\x98\x8b\x62\xc7\x3c\xda\x93\x5d"
	"\xa0\x53\x78\xb9\x32\x44\xec\x8f\x48\xa9\x9e\x61\xad\x79\x9d\x86"},
	{1200, "password", "ATHENA.MIT.EDUraeburn", 16, "\x5c\x08\xeb\x61\xfd\xf7\x1e\x4e\x4e\xc3\xcf\x6b\xa1\xf5\x51\x2b"},
	{1200, "password", "ATHENA.MIT.EDUraeburn", 32, "\x5c\x08\xeb\x61\xfd\xf7\x1e\x4e\x4e\xc3\xcf\x6b\xa1\xf5\x51\x2b"
	"\xa7\xe5\x2d\xdb\xc5\xe5\x14\x2f\x70\x8a\x31\xe2\xe6\x2b\x1e\x13"},
	{5, "password", "\x12\x34\x56\x78\x78\x56\x34\x12\x00", 16,
	"\xd1\xda\xa7\x86\x15\xf2\x87\xe6\xa1\xc8\xb1\x20\xd7\x06\x2a\x49"},
	{5, "password", "\x12\x34\x56\x78\x78\x56\x34\x12\x00", 32,
	"\xd1\xda\xa7\x86\x15\xf2\x87\xe6\xa1\xc8\xb1\x20\xd7\x06\x2a\x49"
	"\x3f\x98\xd2\x03\xe6\xbe\x49\xa6\xad\xf4\xfa\x57\x4b\x6e\x64\xee"},
	{1200, "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
	"pass phrase equals block size", 16,
	"\x13\x9c\x30\xc0\x96\x6b\xc3\x2b\xa5\x5f\xdb\xf2\x12\x53\x0a\xc9"},
	{1200, "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
	"pass phrase equals block size", 32, "\x13\x9c\x30\xc0\x96\x6b\xc3\x2b\xa5\x5f\xdb\xf2\x12\x53\x0a\xc9"
	"\xc5\xec\x59\xf1\xa4\x52\xf5\xcc\x9a\xd9\x40\xfe\xa0\x59\x8e\xd1"},
	{1200, "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
	"pass phrase exceeds block size", 16, "\x9c\xca\xd6\xd4\x68\x77\x0c\xd5\x1b\x10\xe6\xa6\x87\x21\xbe\x61"},
	{1200, "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", "pass phrase exceeds block size", 32,
	"\x9c\xca\xd6\xd4\x68\x77\x0c\xd5\x1b\x10\xe6\xa6\x87\x21\xbe\x61"
	"\x1a\x8b\x4d\x28\x26\x01\xdb\x3b\x36\xbe\x92\x46\x91\x5e\xc8\x2a"},
	{50, "\xF0\x9D\x84\x9E\x00", "EXAMPLE.COMpianist", 16, "\x6b\x9c\xf2\x6d\x45\x45\x5a\x43\xa5\xb8\xbb\x27\x6a\x40\x3b\x39"},
	{50, "\xF0\x9D\x84\x9E\x00", "EXAMPLE.COMpianist", 32, "\x6b\x9c\xf2\x6d\x45\x45\x5a\x43\xa5\xb8\xbb\x27\x6a\x40\x3b\x39"
	"\xe7\xfe\x37\xa0\xc4\x1e\x02\xc2\x81\xff\x30\x69\xe1\xe9\x4f\x52"},
	{500, "All n-entities must communicate with other n-entities via n-1 "
	"entiteeheehees", "\x12\x34\x56\x78\x78\x56\x34\x12\x00", 16, "\x6A\x89\x70\xBF\x68\xC9\x2C\xAE\xA8\x4A\x8D\xF2\x85\x10\x85\x86"}
};


static
int test_hmac_sha1()
{
	char *key, *dat;
	char  hmac[SHA1_DIGESTSIZE];
	int   i;

	for (i = 0; i < sizeof(sha1_hmac_vectors) /
		            sizeof(sha1_hmac_vectors[0]); i++)
	{
		key = sha1_hmac_vectors[i].key;
		dat = sha1_hmac_vectors[i].data;

		sha1_hmac(key, strlen(key), dat, 
			strlen(dat), hmac);

		if (memcmp(hmac, sha1_hmac_vectors[i].hmac, SHA1_DIGESTSIZE) != 0) {
			return 0;
		}
	}

	return 1;
}

static
int test_pkcs5()
{
	u8  dk[64];
	u8 *pass, *salt;
	int i, dklen;

	for (i = 0; i < sizeof(pkcs5_vectors) / 
		            sizeof(pkcs5_vectors[0]); i++)
	{
		pass  = pkcs5_vectors[i].password;
		salt  = pkcs5_vectors[i].salt;
		dklen = pkcs5_vectors[i].dklen;

		sha1_pkcs5_2(
			pass, strlen(pass), salt, strlen(salt), 
			pkcs5_vectors[i].iterations,
			dk, dklen);

		if (memcmp(dk, pkcs5_vectors[i].key, dklen) != 0) {
			return 0;
		}
	}

	return 1;
}

static
int test_aes_lrw()
{
	u8       tmp[512];
	aes_key *key  = NULL;
	int      resl = 0;
	u8      *ct, *pt;
	int      i, size;
	u64      index;

	do
	{
		if ( (key = mem_alloc(sizeof(aes_key))) == NULL ) {
			break;
		}

		for (i = 0; i < sizeof(aes256_lrw_vectors) /
			            sizeof(aes256_lrw_vectors[0]); i++)
		{
			ct    = aes256_lrw_vectors[i].ciphertext;
			pt    = aes256_lrw_vectors[i].plaintext;
			size  = aes256_lrw_vectors[i].size;
			index = BE64(p64(aes256_lrw_vectors[i].index)[0]);

			aes_lrw_init_key(
				key, aes256_lrw_vectors[i].cipher_k, 
				aes256_lrw_vectors[i].tweak_k
				);

			aes_lrw_encrypt(pt, tmp, size, index, key);

			if (memcmp(tmp, ct, size) != 0) {
				goto exit;
			}

			aes_lrw_decrypt(ct, tmp, size, index, key);

			if (memcmp(tmp, pt, size) != 0) {
				goto exit;
			}
		}
		resl = 1;
	} while (0);
exit:;
	if (key != NULL) {
		mem_free(key);
	}

	return resl;
}


static
int test_aes256()
{
	char        tmp[16];
	aes256_key *key  = NULL;
	int         resl = 0;
	int         i;	

	do
	{
		if ((key = mem_alloc(sizeof(aes256_key))) == NULL) {
			break;
		}

		for (i = 0; i < sizeof(aes256_vectors) / 
			            sizeof(aes256_vectors[0]); i++) 
		{
			aes256_set_key(aes256_vectors[i].key, key);

			aes256_encrypt(aes256_vectors[i].plaintext, tmp, key);

			if (memcmp(aes256_vectors[i].ciphertext, tmp, sizeof(tmp)) != 0) {
				goto exit;
			}

			aes256_decrypt(aes256_vectors[i].ciphertext, tmp, key);

			if (memcmp(aes256_vectors[i].plaintext, tmp, sizeof(tmp)) != 0) {
				goto exit;
			}
		}
		resl = 1;
	} while (0);
exit:;
	if (key != NULL) {
		mem_free(key);
	}

	return resl;
}

static
int test_sha1()
{
	sha1_ctx ctx;
	u8      *msg;
	u8       hash[20];
	int      i;

	for (i = 0; i < sizeof(sha1_vectors) /
		            sizeof(sha1_vectors[0]); i++)
	{
		msg = sha1_vectors[i].msg;

		sha1_init(&ctx);
		sha1_hash(&ctx, msg, strlen(msg));
		sha1_done(&ctx, hash);

		if (memcmp(hash, sha1_vectors[i].hash, 20) != 0) {
			return 0;
		}
	}

	return 1;
}

static
int test_sha512()
{
	sha512_ctx ctx;
	u8        *msg;
	u8         hash[64];	
	int        i;
	
	for (i = 0; i < sizeof(sha512_vectors) / 
	                sizeof(sha512_vectors[0]); i++) 
	{
		msg = sha512_vectors[i].msg;

		sha512_init(&ctx);
		sha512_hash(&ctx, msg, strlen(msg));
		sha512_done(&ctx, hash);

		if (memcmp(hash, sha512_vectors[i].hash, 64) != 0) {
			return 0;
		}
	}
	return 1;
}

int crypto_self_test()
{
	if (test_sha1() == 0) {
		DbgMsg("sha1 error");
		return 0;
	}

	if (test_sha512() == 0) {
		DbgMsg("SHA512 error");
		return 0;
	}

	if (test_hmac_sha1() == 0) {
		DbgMsg("sha1 hmac error");
		return 0;
	}

	if (test_pkcs5() == 0) {
		DbgMsg("pkcs5 error");
		return 0;
	}

	if (crc32_test() == 0) {
		DbgMsg("CRC32 error");
		return 0;
	}

	if (test_aes256() == 0) {
		DbgMsg("AES error");
		return 0;
	}

	if (test_aes_lrw() == 0) {
		DbgMsg("AES-LRW error");
		return 0;
	}	

	return 1;
}