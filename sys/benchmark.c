/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2007-2008 
    * ntldr <ntldr@diskcryptor.net> PGP key ID - 0xC48251EB4F8E4E6E
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
#include "driver.h"
#include "crypto.h"
#include "prng.h"
#include "fast_crypt.h"
#include "benchmark.h"

int dc_k_benchmark(crypt_info *crypt, dc_bench *info)
{
	u8      key[DISKKEY_SIZE];	
	u8     *buff = NULL;
	dc_key *dc_k = NULL;
	u64     freq, time;
	u64     offset;
	int     resl, i;

	do
	{
		if ( (buff  = mem_alloc(TEST_BLOCK_LEN)) == NULL ) {
			resl = ST_NOMEM; break;
		}

		if ( (dc_k = mem_alloc(sizeof(dc_key))) == NULL ) {
			resl = ST_NOMEM; break;
		}

		offset = 0;

		for (i = 0; i < TEST_BLOCK_LEN; i++) {
			buff[i] = (u8)i;
		}

		for (i = 0; i < DISKKEY_SIZE; i++) {
			key[i] = (u8)i;
		}
		
		dc_cipher_init(
			dc_k, crypt->cipher_id, key);

		time = KeQueryPerformanceCounter(pv(&freq)).QuadPart;

		for (i = 0; i < TEST_BLOCK_NUM; i++) 
		{
			dc_fast_encrypt(
				buff, buff, TEST_BLOCK_LEN, offset, dc_k);

			offset += TEST_BLOCK_LEN;
		}

		time = KeQueryPerformanceCounter(NULL).QuadPart - time;

		info->data_size = TEST_BLOCK_LEN * TEST_BLOCK_NUM;
		info->enc_time  = time;
		info->cpu_freq  = freq; resl = ST_OK;
	} while (0);

	if (buff != NULL) {
		mem_free(buff);
	}

	if (dc_k != NULL) {
		mem_free(dc_k);
	}

	return resl;
}