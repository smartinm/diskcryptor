/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2008 
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
#include "crypto.h"
#include "mini_aes.h"
#include "gf128mul.h"


void aes_lrw_init_key(aes_key *key, char *cipher_k, char *tweak_k)
{
	/* initialize aes256 key */
	aes256_set_key(cipher_k, &key->aes_key);

	/* copy tweak key */
	memcpy(key->gf_key, tweak_k, sizeof(key->gf_key));
}

void aes_lrw_process(
		u8 *in, u8 *out, 
		int  len, u64 start, 
		aes_key *key, 
		aescode cryptprc 
		)
{
	u8  t[16];
	u64 x, idx;

	idx = (start << 5) | 1;
	
	while (len != 0)
	{
		x = BE64(idx);
		gf128_mul64(key->gf_key, pv(&x), t);

		xor128(out, in, t);
		cryptprc(out, out, &key->aes_key);
		xor128(out, out, t);

		idx++; len -= 16;
		in += 16; out += 16; 
	}

	/* prevent leaks */
	zeromem(t, sizeof(t));
}

