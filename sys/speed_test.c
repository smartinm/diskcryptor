/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2007-2008 
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
#include "speed_test.h"
#include "driver.h"
#include "crypto.h"
#include "prng.h"

int dc_k_speed_test(speed_test *test)
{
	LARGE_INTEGER freq;
	ULONGLONG     start;
	ULONGLONG     enc_c;
	ULONGLONG     dec_c;
	u8            key[DISKKEY_SIZE];
	ULONGLONG     offset;	
	u8           *buff  = NULL;
	aes_key      *aes_k = NULL;
	int           resl;
	u32           i;

	do
	{
		if ( (buff  = mem_alloc(TEST_BLOCK_LEN)) == NULL ) {
			resl = ST_NOMEM; break;
		}

		if ( (aes_k = mem_alloc(sizeof(aes_key))) == NULL ) {
			resl = ST_NOMEM; break;
		}

		for (i = 0; i < TEST_BLOCK_LEN; i++) {
			buff[i] = (u8)i;
		}

		rnd_get_bytes(
			key, sizeof(key)
			);

		rnd_get_bytes(
			(void*)&offset, sizeof(offset)
			);

		aes_lrw_init_key(
			aes_k, key + DISK_IV_SIZE, key
			);

		start = KeQueryPerformanceCounter(&freq).QuadPart;

		for (i = 0; i < TEST_BLOCK_NUM; i++) 
		{
			aes_lrw_encrypt(
				buff, buff, TEST_BLOCK_LEN, offset, aes_k
				); 
		}

		enc_c = KeQueryPerformanceCounter(NULL).QuadPart;

		for (i = 0; i < TEST_BLOCK_NUM; i++) 
		{
			aes_lrw_decrypt(
				buff, buff, TEST_BLOCK_LEN, offset, aes_k
				); 
		}

		dec_c = KeQueryPerformanceCounter(NULL).QuadPart;

		if (dc_conf_flags & CONF_QUEUE_IO) {
			test->data_size = TEST_BLOCK_LEN * TEST_BLOCK_NUM * KeNumberProcessors;
		} else {
			test->data_size = TEST_BLOCK_LEN * TEST_BLOCK_NUM;
		}

		test->enc_time  = enc_c - start;
		test->dec_time  = dec_c - enc_c;
		test->cpu_freq  = freq.QuadPart; resl = ST_OK;
	} while (0);

	if (buff != NULL) {
		mem_free(buff);
	}

	if (aes_k != NULL) {
		mem_free(aes_k);
	}

	return resl;
}