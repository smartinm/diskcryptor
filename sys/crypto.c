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

#include "defines.h" 
#include "crypto.h"
#include "aes.h"



void aes_lrw_init_key(aes_key *key, char *cipher_k, char *tweak_k)
{
	u32 t[2];
	int i;
	
	/* initialize aes256 key */
	aes256_set_key(cipher_k, &key->aes_key);

	/* initialize GF(2^128) multiplication table */
	gf128mul_init_32k(&key->gf_ctx, pv(tweak_k));

	/* initialize increment table */
	t[0] = t[1] = 0;
	for (i = 0; i < 64; i++) {
		t[i / 32] |= 1 << (i % 32);
		gf128mul64_table(&key->inctab[i], pv(t), &key->gf_ctx);
	}
}

#ifndef ASM_CRYPTO

static int iv_to_index(u32 *p)
{
	u32 bps;
	
	if (bsf(&bps, ~p[0]) == 0) {
		if (bsf(&bps, ~p[1]) == 0) {
			bps = 64;
		} else bps += 32;
	}

	return bps;
}

void stdcall aes_lrw_process(
				char  *in, char *out, 
				size_t len, u64 idx, 
				aes_key *key, 
				aescode cryptprc 
				)
{
	u8  t[16];
	int i;

	gf128mul64_table(pv(t), pv(&idx), &key->gf_ctx);

	do
	{
		xor128(out, in, t);
		cryptprc(out, out, &key->aes_key);
		xor128(out, out, t);

		if ( (len -= 16) == 0 ) {
			break;
		}

		i = iv_to_index(pv(&idx));
		xor128(t, t, &key->inctab[i]); 
		in += 16; out += 16; idx++;
	} while (1);  
	
}

#endif