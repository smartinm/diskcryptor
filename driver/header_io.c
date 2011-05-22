/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2010-2011
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

#include "defines.h"
#include "devhook.h"
#include "misc_mem.h"
#include "crypto_head.h"
#include "device_io.h"
#include "header_io.h"
#include "crc32.h"

int io_read_header(dev_hook *hook, dc_header **header, xts_key **out_key, dc_pass *password)
{
	xts_key *hdr_key = NULL;
	int      hdr_len = max(sizeof(dc_header), hook->bps);
	int      resl;

	/* allocate memory for header */
	if ( (*header = mm_alloc(hdr_len, MEM_SECURE | MEM_SUCCESS)) == NULL ) return ST_NOMEM;
	do
	{
		/* read volume header */
		if ( (resl = io_hook_rw(hook, *header, hdr_len, 0, 1)) != ST_OK ) break;
		/* decrypt volume header */
		if (password != NULL)
		{
			/* allocate memory for header key */
			if ( (hdr_key = mm_alloc(sizeof(xts_key), MEM_SECURE)) == NULL ) { resl = ST_NOMEM; break; }
			/* try to decrypt header */
			if (cp_decrypt_header(hdr_key, *header, password) == 0) { resl = ST_PASS_ERR; break; }
			/* save decrypted header and key */ 
			if (out_key != NULL) { *out_key = hdr_key; hdr_key = NULL; }
		}
	} while (0);

	if (resl != ST_OK) {
		mm_free(*header); *header = NULL;
	}
	if (hdr_key != NULL) mm_free(hdr_key);
	return resl;
}

int io_write_header(dev_hook *hook, dc_header *header, xts_key *hdr_key, dc_pass *password)
{
	u8         salt[PKCS5_SALT_SIZE];
	int        hdr_len = max(sizeof(dc_header), hook->bps);
	dc_header *hcopy = NULL;
	xts_key   *h_key = hdr_key;
	int        resl;

	do
	{
		if ( (hcopy = mm_alloc(hdr_len, MEM_SECURE | MEM_SUCCESS)) == NULL ) { resl = ST_NOMEM; break; }
		memcpy(hcopy, header, sizeof(dc_header));
		
		if (h_key == NULL) {
			if ( (h_key = mm_alloc(sizeof(xts_key), MEM_SECURE | MEM_SUCCESS)) == NULL ) { resl = ST_NOMEM; break; }
		}
		if (hdr_key == NULL)
		{
			/* add volume header to random pool because RNG not 
			   have sufficient entropy at boot time 
			*/
			cp_rand_add_seed(header, sizeof(dc_header));
			/* generate new salt */
			cp_rand_bytes(salt, PKCS5_SALT_SIZE);
			/* copy salt to header */
			memcpy(hcopy->salt, salt, PKCS5_SALT_SIZE);
			/* init new header key */
			cp_set_header_key(h_key, salt, header->alg_1, password);
		} else {
			/* save original salt */
			memcpy(salt, header->salt, PKCS5_SALT_SIZE);
		}
		/* calc header CRC */
		hcopy->hdr_crc = crc32(pv(&hcopy->version), DC_CRC_AREA_SIZE);
		/* encrypt header with new key */
		xts_encrypt(pv(hcopy), pv(hcopy), sizeof(dc_header), 0, h_key);
		/* restore original salt */
		memcpy(hcopy->salt, salt, PKCS5_SALT_SIZE);		
		
		/* fill the gap with random numbers */
		if (hdr_len > sizeof(dc_header)) {
			cp_rand_bytes(pv(hcopy + 1), hdr_len - sizeof(dc_header));
		}
		/* write new header */
		resl = io_hook_rw(hook, hcopy, hdr_len, 0, 0);
	} while (0);

	/* prevent leaks */
	burn(salt, sizeof(salt));
	/* free resources */
	if (h_key != NULL && h_key != hdr_key) mm_free(h_key);
	if (hcopy != NULL) mm_free(hcopy);	
	return resl;
}