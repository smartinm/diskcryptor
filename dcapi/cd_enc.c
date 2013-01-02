/*
    *
    * DiskCryptor - open source partition encryption tool
	* Copyright (c) 2009
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

#include <windows.h>
#include "defines.h"
#include "cd_enc.h"
#include "drv_ioctl.h"
#include "xts_fast.h"
#include "pkcs5.h"
#include "crc32.h"
#include "drvinst.h"

#define CD_BUFSZ (1024 * 1024)

static int alg_ok;

static 
int do_cd_encrypt(
	  HANDLE h_src, HANDLE h_dst, u64 iso_sz, xts_key *v_key, cd_callback callback, void *param
	  )
{
	void *buff;
	u32   bytes, block;
	u32   w_len;
	int   resl;
	u64   offset = 0;
	u64   remain = iso_sz;

	do
	{
		buff = VirtualAlloc(NULL, CD_BUFSZ, MEM_COMMIT+MEM_RESERVE, PAGE_READWRITE);

		if (buff == NULL) {
			resl = ST_NOMEM; break;
		}

		resl = ST_OK;
		do
		{
			block = d32(min(remain, CD_BUFSZ));
			w_len = _align(block, CD_SECTOR_SIZE);

			if (ReadFile(h_src, buff, block, &bytes, NULL) == 0) {
				resl = ST_IO_ERROR; break;
			}			
			xts_encrypt(buff, buff, w_len, offset, v_key);			

			if (WriteFile(h_dst, buff, w_len, &bytes, NULL) == 0) {
				resl = ST_IO_ERROR; break;
			}
			remain -= block, offset += w_len;

			if (callback != NULL) {
				resl = callback(iso_sz, offset, param);
			}
		} while ( (remain != 0) && (resl == ST_OK) );
	} while (0);

	if (buff != NULL) {
		VirtualFree(buff, 0, MEM_RELEASE);
	}

	return resl;
}


int dc_encrypt_cd(
	  wchar_t *src_path, wchar_t *dst_path, dc_pass *pass, 
	  int      cipher, cd_callback callback, void *param
	  )
{
	dc_conf_data conf;
	HANDLE       h_src = NULL;
	HANDLE       h_dst = NULL;
	xts_key     *v_key = NULL;
	xts_key     *h_key = NULL;
	dc_header    head;
	int          resl;
	u64          iso_sz;
	u32          bytes;
	u8           salt[PKCS5_SALT_SIZE];
	u8           dk[DISKKEY_SIZE];
	
	if (alg_ok == 0) 
	{
		if (dc_load_conf(&conf) == ST_OK) {
			xts_init(conf.conf_flags & CONF_HW_CRYPTO);
		} else {
			xts_init(0);
		}
		alg_ok = 1;
	}

	do
	{
		if ( (resl = dc_lock_memory(dk, sizeof(dk))) != ST_OK ) {
			break;
		}
		if ( (resl = dc_lock_memory(&head, sizeof(head))) != ST_OK ) {
			break;
		}

		h_src = CreateFile(
			src_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, 0);

		if (h_src == INVALID_HANDLE_VALUE) {
			h_src = NULL; resl = ST_NO_OPEN_FILE; break;
		}

		h_dst = CreateFile(
			dst_path, GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, 0);

		if (h_dst == INVALID_HANDLE_VALUE) {
			h_dst = NULL; resl = ST_NO_CREATE_FILE; break;
		}

		if (GetFileSizeEx(h_src, pv(&iso_sz)) == 0) {
			resl = ST_IO_ERROR; break;
		}

		v_key = VirtualAlloc(NULL, sizeof(xts_key), MEM_COMMIT+MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		h_key = VirtualAlloc(NULL, sizeof(xts_key), MEM_COMMIT+MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		
		if ( (v_key == NULL) || (h_key == NULL) ) {
			resl = ST_NOMEM; break;
		}

		/* lock keys in memory */
		if ( (resl = dc_lock_memory(v_key, sizeof(xts_key))) != ST_OK ) {
			break;
		}
		if ( (resl = dc_lock_memory(h_key, sizeof(xts_key))) != ST_OK ) {
			break;
		}

		/* create volume header */
		memset(&head, 0, sizeof(dc_header));

		dc_get_random(pv(salt),          PKCS5_SALT_SIZE);
		dc_get_random(pv(&head.disk_id), sizeof(u32));
		dc_get_random(pv(head.key_1),    DISKKEY_SIZE);

		head.sign     = DC_VOLUME_SIGN;
		head.version  = DC_HDR_VERSION;
		head.flags    = VF_NO_REDIR;
		head.alg_1    = cipher;
		head.data_off = sizeof(dc_header);
		head.hdr_crc  = crc32(pv(&head.version), DC_CRC_AREA_SIZE);

		/* initialize volume key */
		xts_set_key(head.key_1, cipher, v_key);

		/* initialize header key */
		sha512_pkcs5_2(
			1000, pass->pass, 
			pass->size, salt, PKCS5_SALT_SIZE, dk, PKCS_DERIVE_MAX);

		xts_set_key(dk, cipher, h_key);

		/* encrypt volume header */
		xts_encrypt(pv(&head), pv(&head), sizeof(dc_header), 0, h_key);

		/* save salt */
		memcpy(head.salt, salt, PKCS5_SALT_SIZE);

		/* write volume header to file */
		if (WriteFile(h_dst, &head, sizeof(head), &bytes, NULL) == 0) {
			resl = ST_IO_ERROR; break;
		}

		resl = do_cd_encrypt(h_src, h_dst, iso_sz, v_key, callback, param);
	} while (0);

	/* prevent leaks */
	burn(dk, sizeof(dk));
	burn(&head, sizeof(head));
	dc_unlock_memory(dk);
	dc_unlock_memory(&head);

	if (v_key != NULL) {
		burn(v_key, sizeof(xts_key));
		dc_unlock_memory(v_key);
		VirtualFree(v_key, 0, MEM_RELEASE);
	}

	if (h_key != NULL) {
		burn(h_key, sizeof(xts_key));
		dc_unlock_memory(h_key);
		VirtualFree(h_key, 0, MEM_RELEASE);
	}

	if (h_src != NULL) {
		CloseHandle(h_src);
	}

	if (h_dst != NULL) 
	{
		CloseHandle(h_dst);

		if (resl != ST_OK) {
			DeleteFile(dst_path);
		}	
	}

	return resl;
}

 