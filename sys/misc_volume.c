/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2008-2009
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
#include "devhook.h"
#include "misc_volume.h"
#include "crypto.h"
#include "pkcs5.h"
#include "misc.h"
#include "mount.h"
#include "crc32.h"
#include "prng.h"
#include "fast_crypt.h"
#include "debug.h"

static
int dc_write_header(
	  dev_hook *hook, dc_header *header, dc_pass *password
	  )
{
	u8         salt[PKCS5_SALT_SIZE];
	dc_header *t_header;
	dc_key    *hdr_key;
	int        resl;

	t_header = NULL; hdr_key = NULL;
	do
	{
		if ( (t_header = mem_alloc(sizeof(dc_header))) == NULL ) {
			resl = ST_NOMEM; break;
		}

		if ( (hdr_key = mem_alloc(sizeof(dc_key))) == NULL ) {
			resl = ST_NOMEM; break;
		}

		/* copy header to new buffer */
		autocpy(t_header, header, sizeof(dc_header));

		/* add volume header to random pool because RNG not 
		   have sufficient entropy at boot time 
		*/
		rnd_add_buff(header, sizeof(dc_header));
		/* generate new salt */
		rnd_get_bytes(t_header->salt, PKCS5_SALT_SIZE);
		/* save original salt */
		autocpy(salt, t_header->salt, PKCS5_SALT_SIZE);
		/* calc header CRC */
		t_header->hdr_crc = crc32(pv(&t_header->version), DC_CRC_AREA_SIZE);

		/* init new header key */
		dc_init_hdr_key(
			hdr_key, t_header, hook->crypt.cipher_id, password);
				
		/* encrypt header with new key */
		dc_cipher_encrypt(
			pv(t_header), pv(t_header), sizeof(dc_header), 0, hdr_key);

		/* restore original salt */
		autocpy(t_header->salt, salt, PKCS5_SALT_SIZE);

		/* write new header */
		resl = dc_device_rw(
			hook, IRP_MJ_WRITE, t_header, sizeof(dc_header), 0);
	} while (0);

	/* prevent leaks */
	if (hdr_key != NULL) {
		zeroauto(hdr_key, sizeof(dc_key));
		mem_free(hdr_key);
	}

	if (t_header != NULL) {
		zeroauto(t_header, sizeof(dc_header));
		mem_free(t_header);
	}

	zeroauto(salt, sizeof(salt));

	return resl;
}

int dc_backup_header(wchar_t *dev_name, dc_pass *password, void *out)
{
	dc_header *header = NULL;
	dc_key    *hdr_key = NULL;
	dev_hook  *hook    = NULL;
	int        resl;
	s8         salt[PKCS5_SALT_SIZE];

	do
	{
		if ( (hook = dc_find_hook(dev_name)) == NULL ) {
			resl = ST_NF_DEVICE; break;
		}

		wait_object_infinity(&hook->busy_lock);

		if (hook->flags & (F_SYNC | F_UNSUPRT | F_DISABLE | F_CDROM)) {
			resl = ST_ERROR; break;
		}

		/* get device params */
		if ( (hook->dsk_size == 0) && (dc_get_dev_params(hook) != ST_OK) ) {
			resl = ST_RW_ERR; break;
		}

		if ( (header = mem_alloc(sizeof(dc_header))) == NULL ) {
			resl = ST_NOMEM; break;
		}

		if ( (hdr_key = mem_alloc(sizeof(dc_key))) == NULL ) {
			resl = ST_NOMEM; break;
		}

		resl = dc_device_rw(
			hook, IRP_MJ_READ, header, sizeof(dc_header), 0);

		if (resl != ST_OK) {
			break;
		}

		if (dc_decrypt_header(hdr_key, header, password) == 0) {
			resl = ST_PASS_ERR; break;
		}

		/* generate new salt */
		rnd_get_bytes(header->salt, PKCS5_SALT_SIZE);
		/* save original salt */
		autocpy(salt, header->salt, PKCS5_SALT_SIZE);
		
		/* init new header key */
		dc_init_hdr_key(
			hdr_key, header, header->alg_1, password);
		
		/* encrypt header with new key */
		dc_cipher_encrypt(
			pv(header), pv(header), sizeof(dc_header), 0, hdr_key);

		/* restore original salt */
		autocpy(header->salt, salt, PKCS5_SALT_SIZE);

		/* copy header to output */
		autocpy(out, header, sizeof(dc_header));
		resl = ST_OK;
	} while (0);

	if (hook != NULL) {
		KeReleaseMutex(&hook->busy_lock, FALSE);
		dc_deref_hook(hook);
	}

	/* prevent leaks */
	if (hdr_key != NULL) {
		zeroauto(hdr_key, sizeof(dc_key));
		mem_free(hdr_key);
	}

	if (header != NULL) {
		zeroauto(header, sizeof(dc_header));
		mem_free(header);
	}

	zeroauto(salt, sizeof(salt));

	return resl;
}

int dc_restore_header(wchar_t *dev_name, dc_pass *password, void *in)
{
	dc_header *header = NULL;
	dc_key    *hdr_key = NULL;
	dev_hook  *hook = NULL;
	int        resl;

	do
	{
		if ( (hook = dc_find_hook(dev_name)) == NULL ) {
			resl = ST_NF_DEVICE; break;
		}

		wait_object_infinity(&hook->busy_lock);

		if (hook->flags & (F_ENABLED | F_CDROM)) {
			resl = ST_ERROR; break;
		}

		/* get device params */
		if ( (hook->dsk_size == 0) && (dc_get_dev_params(hook) == 0) ) {
			resl = ST_RW_ERR; break;
		}

		if ( (header = mem_alloc(sizeof(dc_header))) == NULL ) {
			resl = ST_NOMEM; break;
		}

		/* copy header from input */
		autocpy(header, in, sizeof(dc_header));

		if ( (hdr_key = mem_alloc(sizeof(dc_key))) == NULL ) {
			resl = ST_NOMEM; break;
		}

		/* decrypt header */
		if (dc_decrypt_header(hdr_key, header, password) == 0) {
			resl = ST_PASS_ERR; break;
		}

		/* write volume header */
		resl = dc_write_header(hook, header, password);
	} while (0);

	if (hook != NULL) {
		KeReleaseMutex(&hook->busy_lock, FALSE);
		dc_deref_hook(hook);
	}

	/* prevent leaks */
	if (hdr_key != NULL) {
		zeroauto(hdr_key, sizeof(dc_key));
		mem_free(hdr_key);
	}

	if (header != NULL) {
		zeroauto(header, sizeof(dc_header));
		mem_free(header);
	}

	return resl;
}

int dc_format_start(wchar_t *dev_name, dc_pass *password, crypt_info *crypt)
{
	IO_STATUS_BLOCK iosb;
	NTSTATUS        status;
	dc_header      *header = NULL;
	dev_hook       *hook   = NULL;
	HANDLE          h_dev  = NULL;
	u8             *buff   = NULL;
	rnd_ctx        *r_ctx  = NULL;	
	int             w_init = 0;
	int             resl;

	DbgMsg("dc_format_start\n");

	do
	{
		if ( (hook = dc_find_hook(dev_name)) == NULL ) {
			resl = ST_NF_DEVICE; break;
		}

		wait_object_infinity(&hook->busy_lock);

		if (hook->flags & (F_ENABLED | F_UNSUPRT | F_DISABLE | F_CDROM)) {
			resl = ST_ERROR; break;
		}

		/* verify encryption info */
		if ( (crypt->cipher_id >= CF_CIPHERS_NUM) || (crypt->wp_mode >= WP_NUM) ) {
			resl = ST_ERROR; break;
		}

		/* get device params */
		if (dc_get_dev_params(hook) != ST_OK) {
			resl = ST_RW_ERR; break;
		}

		if ( (header = mem_alloc(sizeof(dc_header))) == NULL ) {
			resl = ST_NOMEM; break;
		}

		if ( (buff = mem_alloc(ENC_BLOCK_SIZE)) == NULL ) {
			resl = ST_NOMEM; break;
		}

		/* temporary disable automounting */
		hook->flags |= F_NO_AUTO_MOUNT;

		/* open volume device */
		if ( (h_dev = io_open_device(hook->dev_name)) == NULL ) {
			resl = ST_LOCK_ERR; break; 
		}		
		/* lock volume */
		status = ZwFsControlFile(
					h_dev, NULL, NULL, NULL, &iosb, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0);

		if (NT_SUCCESS(status) == FALSE) {
			resl = ST_LOCK_ERR; break; 
		}

		/* enable automounting */
		hook->flags &= ~F_NO_AUTO_MOUNT;
		/* set encryption info */
		hook->crypt = *crypt;

		/* init data wiping */
		resl = dc_wipe_init(
			&hook->wp_ctx, hook, ENC_BLOCK_SIZE, crypt->wp_mode);

		if (resl == ST_OK) {
			w_init = 1;			
		} else break;

		/* init random context */
		if ( (r_ctx = rnd_fast_init()) == NULL ) {
			resl = ST_NOMEM; break;
		}

		/* wipe first sectors */
		dc_wipe_process(&hook->wp_ctx, 0, DC_AREA_SIZE);

		/* create volume header */
		zeroauto(header, sizeof(dc_header));

		rnd_get_bytes(pv(header->salt),     PKCS5_SALT_SIZE);
		rnd_get_bytes(pv(&header->disk_id), sizeof(u32));
		rnd_get_bytes(pv(header->key_1),    DISKKEY_SIZE);

		header->sign     = DC_VOLM_SIGN;
		header->version  = DC_HDR_VERSION;
		header->alg_1    = crypt->cipher_id;
		header->stor_off = hook->dsk_size - DC_AREA_SIZE;
		header->use_size = header->stor_off;

		/* write volume header */
		if ( (resl = dc_write_header(hook, header, password)) != ST_OK ) {
			break;
		}

		/* mount device */
		if ( (resl = dc_mount_device(dev_name, password, 0)) != ST_OK ) {
			break;
		}
		
		/* set hook fields */
		hook->flags    |= F_FORMATTING;
		hook->tmp_size  = DC_AREA_SIZE;
		hook->tmp_buff  = buff;
		hook->fmt_rnd   = r_ctx;
	} while (0);

	if ( (resl != ST_OK) )
	{
		if (r_ctx != NULL) {
			rnd_fast_free(r_ctx);
		}

		if (w_init != 0) {
			dc_wipe_free(&hook->wp_ctx);
		}

		if (buff != NULL) {
			mem_free(buff);
		}
	}

	/* prevent leaks */
	if (header != NULL) {
		zeroauto(header, sizeof(dc_header));
		mem_free(header);
	}

	if (hook != NULL) {
		KeReleaseMutex(&hook->busy_lock, FALSE);
		dc_deref_hook(hook);
	}

	if (h_dev != NULL)
	{
		if (resl != ST_LOCK_ERR)
		{
			/* dismount volume */
			ZwFsControlFile(
				h_dev, NULL, NULL, NULL, &iosb, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0);

			/* unlock volume */
			ZwFsControlFile(
				h_dev, NULL, NULL, NULL, &iosb, FSCTL_UNLOCK_VOLUME, NULL, 0, NULL, 0);
		}
		/* close device */
		ZwClose(h_dev);
	}		

	return resl;
}

int dc_format_step(wchar_t *dev_name, int wp_mode)
{
	dev_hook *hook = NULL;
	u8       *buff;
	int       resl;
	u64       offs;
	u32       size;

	do
	{
		if ( (hook = dc_find_hook(dev_name)) == NULL ) {
			resl = ST_NF_DEVICE; break;
		}

		wait_object_infinity(&hook->busy_lock);

		if ( !(hook->flags & F_FORMATTING) ) {
			resl = ST_ERROR; break;
		}

		offs = hook->tmp_size;
		buff = hook->tmp_buff;
		size = d32(min(hook->dsk_size - offs, ENC_BLOCK_SIZE));

		if (size == 0) {
			dc_format_done(dev_name);
			resl = ST_FINISHED; break;
		}

		if (hook->crypt.wp_mode != wp_mode)
		{
			dc_wipe_free(&hook->wp_ctx);

			resl = dc_wipe_init(
				&hook->wp_ctx, hook, ENC_BLOCK_SIZE, wp_mode);

			if (resl == ST_OK) {
				hook->crypt.wp_mode = d8(wp_mode);
			} else {
				dc_wipe_init(&hook->wp_ctx, hook, ENC_BLOCK_SIZE, WP_NONE);
				hook->crypt.wp_mode = WP_NONE;
			}
		}

		/* wipe sectors */
		dc_wipe_process(&hook->wp_ctx, offs, size);

		/* fill buffer from fast PRNG */
		rnd_fast_rand(hook->fmt_rnd, buff, size);

		/* encrypt buffer with volume key */
		dc_fast_encrypt(
			buff, buff, size, offs, &hook->dsk_key);

		resl = dc_device_rw(
			hook, IRP_MJ_WRITE, buff, size, offs);

		if ( (resl == ST_OK) || (resl == ST_RW_ERR) ) {
			hook->tmp_size += size;
		}

		if ( (resl == ST_MEDIA_CHANGED) || (resl == ST_NO_MEDIA) ) {			
			dc_process_unmount(hook, MF_NOFSCTL); resl = ST_FINISHED;
		}
	} while (0);

	if (hook != NULL) {
		KeReleaseMutex(&hook->busy_lock, FALSE);
		dc_deref_hook(hook);
	}

	return resl;
}

int dc_format_done(wchar_t *dev_name)
{
	dev_hook *hook = NULL;
	int       resl;

	DbgMsg("dc_format_done\n");

	do
	{
		if ( (hook = dc_find_hook(dev_name)) == NULL ) {
			resl = ST_NF_DEVICE; break;
		}

		wait_object_infinity(&hook->busy_lock);

		if ( !(hook->flags & F_FORMATTING) ) {
			resl = ST_ERROR; break;
		}

		/* set hook fields */
		hook->tmp_size = 0;
		hook->flags   &= ~F_FORMATTING;		
		/* free resources */
		rnd_fast_free(hook->fmt_rnd);
		dc_wipe_free(&hook->wp_ctx);
		mem_free(hook->tmp_buff);
		resl = ST_OK;
	} while (0);

	if (hook != NULL) {
		KeReleaseMutex(&hook->busy_lock, FALSE);
		dc_deref_hook(hook);
	}

	return resl;
}

int dc_change_pass(wchar_t *dev_name, dc_pass *old_pass, dc_pass *new_pass)
{
	dc_header *header;
	dev_hook  *hook    = NULL;
	dc_key    *hdr_key = NULL;
	int        wp_init = 0;
	int        resl;
	wipe_ctx   wipe;	
	
	header = NULL;
	do
	{
		if ( (hook = dc_find_hook(dev_name)) == NULL ) {
			resl = ST_NF_DEVICE; break;
		}

		wait_object_infinity(&hook->busy_lock);

		if ( !(hook->flags & F_ENABLED) ) {
			resl = ST_NO_MOUNT; break;
		}

		if (hook->flags & (F_SYNC | F_FORMATTING | F_CDROM)) {
			resl = ST_ERROR; break;
		}

		if ( (header = mem_alloc(sizeof(dc_header))) == NULL ) {
			resl = ST_NOMEM; break;
		}

		if ( (hdr_key = mem_alloc(sizeof(dc_key))) == NULL ) {
			resl = ST_NOMEM; break;
		}

		/* read old volume header */
		resl = dc_device_rw(
			hook, IRP_MJ_READ, header, sizeof(dc_header), 0);	
		
		if (resl != ST_OK) {			
			break;
		}

		/* decrypt volume header */
		if (dc_decrypt_header(hdr_key, header, old_pass) == 0) {
			resl = ST_PASS_ERR; break;
		}

		/* init data wipe */
		resl = dc_wipe_init(&wipe, hook, DC_AREA_SIZE, WP_GUTMANN);

		if (resl == ST_OK) {
			wp_init = 1;
		} else break;

		/* wipe volume header */
		dc_wipe_process(&wipe, 0, DC_AREA_SIZE);		
		/* write new volume header */
		resl = dc_write_header(hook, header, new_pass);
	} while (0);

	if (wp_init != 0) {
		dc_wipe_free(&wipe);
	}

	if (hook != NULL) {
		KeReleaseMutex(&hook->busy_lock, FALSE);
		dc_deref_hook(hook);
	}

	/* prevent leaks */
	if (hdr_key != NULL) {
		zeroauto(hdr_key, sizeof(dc_key));
		mem_free(hdr_key);
	}

	if (header != NULL) {
		zeroauto(header, sizeof(dc_header));
		mem_free(header);
	}
	
	return resl;
}
