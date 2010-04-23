/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2007-2008 
    * ntldr <ntldr@diskcryptor.net> PGP key ID - 0xC48251EB4F8E4E6E
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

#include <ntifs.h>
#include "defines.h"
#include "driver.h"
#include "xts_fast.h"
#include "prng.h"
#include "fast_crypt.h"
#include "benchmark.h"
#include "misc_mem.h"

int dc_k_benchmark(crypt_info *crypt, dc_bench *info)
{
	u8       key[DISKKEY_SIZE];	
	u8      *buff = NULL;
	xts_key *dc_k = NULL;
	u64      freq, time;
	u64      offset;
	int      resl, i;

	do
	{
		if ( (buff = mm_alloc(TEST_BLOCK_LEN, 0)) == NULL ) {
			resl = ST_NOMEM; break;
		}
		if ( (dc_k = mm_alloc(sizeof(xts_key), 0)) == NULL ) {
			resl = ST_NOMEM; break;
		}
		offset = 0;

		for (i = 0; i < TEST_BLOCK_LEN; i++) {
			buff[i] = d8(i);
		}
		for (i = 0; i < DISKKEY_SIZE; i++) {
			key[i] = d8(i);
		}		
		xts_set_key(key, crypt->cipher_id, dc_k);

		time = KeQueryPerformanceCounter(pv(&freq)).QuadPart;

		for (i = 0; i < TEST_BLOCK_NUM; i++) {
			dc_fast_encrypt(buff, buff, TEST_BLOCK_LEN, offset, dc_k);
			offset += TEST_BLOCK_LEN;
		}
		time = KeQueryPerformanceCounter(NULL).QuadPart - time;

		info->data_size = TEST_BLOCK_LEN * TEST_BLOCK_NUM;
		info->enc_time  = time;
		info->cpu_freq  = freq; resl = ST_OK;
	} while (0);

	if (buff != NULL) { mm_free(buff); }
	if (dc_k != NULL) { mm_free(dc_k); }

	return resl;
}