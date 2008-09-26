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

void dc_random_sectors(dev_hook *hook, u64 offset, u32 length)
{
	rnd_ctx *rnd  = rnd_fast_init();
	u8      *data = mem_alloc(length);

	if ( (rnd != NULL) && (data != NULL) )
	{
		rnd_fast_rand(rnd, data, length);
		dc_device_rw(hook, IRP_MJ_WRITE, data, length, offset);
	}

	if (data != NULL) {
		mem_free(data);
	}

	if (rnd != NULL) {
		rnd_fast_free(rnd);
	}
}

int dc_backup_header(wchar_t *dev_name, char *password, void *out)
{
	dc_header  header;
	dc_key    *hdr_key = NULL;
	dc_key    *new_key = NULL;
	dev_hook  *hook    = NULL;
	crypt_info crypt;
	int        resl;

	lock_inc(&dc_data_lock);

	do
	{
		if ( (hook = dc_find_hook(dev_name)) == NULL ) {
			resl = ST_NF_DEVICE; break;
		}

		wait_object_infinity(&hook->busy_lock);

		if (hook->flags & (F_SYNC | F_UNSUPRT | F_DISABLE)) {
			resl = ST_ERROR; break;
		}

		resl = dc_device_rw(
			hook, IRP_MJ_READ, &header, sizeof(dc_header), 0
			);

		if (resl != ST_OK) {
			break;
		}

		hdr_key = dc_fast_dec_header(&header, &crypt, password);

		if (hdr_key == NULL) {
			resl = ST_PASS_ERR; break;
		}

		/* generate new salt */
		rnd_get_bytes(header.salt, PKCS5_SALT_SIZE);

		/* init new header key */
		if ( (new_key = dc_init_hdr_key(&crypt, &header, password)) == NULL ) {
			resl = ST_NOMEM; break;
		}

		/* encrypt header with new key */
		dc_cipher_encrypt(
			pv(&header.sign), pv(&header.sign), HEADER_ENCRYPTEDDATASIZE, 1, new_key
			);

		/* copy header to output */
		autocpy(out, &header, sizeof(dc_header));
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

	if (new_key != NULL) {
		zeroauto(new_key, sizeof(dc_key));
		mem_free(new_key);
	}

	zeroauto(&header, sizeof(dc_header));

	lock_dec(&dc_data_lock);

	return resl;
}

int dc_restore_header(wchar_t *dev_name, char *password, void *in)
{
	dc_header header;
	dc_key   *hdr_key = NULL;
	dev_hook *hook = NULL;
	int       resl;

	lock_inc(&dc_data_lock);

	do
	{
		if ( (hook = dc_find_hook(dev_name)) == NULL ) {
			resl = ST_NF_DEVICE; break;
		}

		wait_object_infinity(&hook->busy_lock);

		if (hook->flags & F_ENABLED) {
			resl = ST_ERROR; break;
		}

		/* copy header from input */
		autocpy(&header, in, sizeof(dc_header));

		/* decrypt header */
		hdr_key = dc_fast_dec_header(&header, &hook->crypt, password);

		if (hdr_key == NULL) {
			resl = ST_PASS_ERR; break;
		}

		/* write volume header */
		if ( (resl = dc_write_header(hook, &header, 0, password)) != ST_OK ) {
			break;
		}		
		/* write backup header */
		resl = dc_write_header(hook, &header, DC_BACKUP_OFFSET(hook), password);
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

	zeroauto(&header, sizeof(dc_header));

	lock_dec(&dc_data_lock);

	return resl;
}

int dc_format_start(wchar_t *dev_name, char *password, crypt_info *crypt)
{
	dc_header header;
	dev_hook *hook  = NULL;
	HANDLE    h_dev = NULL;
	u8       *buff  = NULL;
	rnd_ctx  *r_ctx = NULL;	
	int       w_init = 0;
	int       resl;

	lock_inc(&dc_data_lock);

	DbgMsg("dc_format_start\n");

	do
	{
		if ( (hook = dc_find_hook(dev_name)) == NULL ) {
			resl = ST_NF_DEVICE; break;
		}

		wait_object_infinity(&hook->busy_lock);

		if (hook->flags & (F_ENABLED | F_UNSUPRT | F_DISABLE)) {
			resl = ST_ERROR; break;
		}

		/* verify encryption info */
		if ( (crypt->cipher_id >= CF_CIPHERS_NUM) || (crypt->mode_id >= EM_NUM) ||
			 (crypt->prf_id >= PRF_NUM) || (crypt->wp_mode >= WP_NUM) ) 
		{
			resl = ST_ERROR; break;
		}

		if ( (buff = mem_alloc(ENC_BLOCK_SIZE)) == NULL ) {
			resl = ST_NOMEM; break;
		}

		/* temporary disable automounting */
		hook->flags |= F_NO_AUTO_MOUNT;

		/* open volume device */
		if ( (h_dev = io_open_volume(hook->dev_name)) == NULL ) {
			resl = ST_LOCK_ERR; break; 
		}		
		/* lock volume */
		if (io_fs_control(h_dev, FSCTL_LOCK_VOLUME) != ST_OK) {
			resl = ST_LOCK_ERR; break; 
		}

		/* enable automounting */
		hook->flags &= ~F_NO_AUTO_MOUNT;
		/* set encryption info */
		hook->crypt = crypt[0];

		/* init data wiping */
		resl = dc_wipe_init(
			&hook->wp_ctx, hook, ENC_BLOCK_SIZE, crypt->wp_mode
			);

		if (resl == ST_OK) {
			w_init = 1;			
		} else break;

		/* init random context */
		if ( (r_ctx = rnd_fast_init()) == NULL ) {
			resl = ST_NOMEM; break;
		}

		/* wipe first sector and reserved area */
		dc_wipe_process(&hook->wp_ctx, 0, SECTOR_SIZE);
		dc_wipe_process(&hook->wp_ctx, hook->dsk_size - DC_RESERVED_SIZE, DC_RESERVED_SIZE);

		/* random fill reserved sectors */
		dc_random_sectors(
			hook, hook->dsk_size - DC_RESERVED_SIZE, DC_RESERVED_SIZE
			);

		/* create volume header */
		zeroauto(&header, sizeof(header));

		rnd_get_bytes(pv(header.salt),     PKCS5_SALT_SIZE);
		rnd_get_bytes(pv(&header.disk_id), sizeof(u32));
		rnd_get_bytes(pv(header.key_data), DISKKEY_SIZE);

		header.sign     = DC_TRUE_SIGN;
		header.version  = BE16(TC_VOLUME_HEADER_VERSION);
		header.req_ver  = BE16(TC_VOL_REQ_PROG_VERSION);
		header.key_crc  = BE32(crc32(header.key_data, DISKKEY_SIZE));
		header.vol_size = hook->dsk_size - HEADER_SIZE - DC_RESERVED_SIZE;
		header.enc_size = header.vol_size;

		/* write volume header */
		if ( (resl = dc_write_header(hook, &header, 0, password)) != ST_OK ) {
			break;
		}		
		/* write backup header */
		resl = dc_write_header(hook, &header, DC_BACKUP_OFFSET(hook), password);
		
		if (resl != ST_OK) {
			break;
		}
		/* mount device */
		if ( (resl = dc_mount_device(dev_name, password)) != ST_OK ) {
			break;
		}
		
		/* set hook fields */
		hook->flags    |= F_FORMATTING;
		hook->tmp_size  = 0;
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

	if (hook != NULL) {
		KeReleaseMutex(&hook->busy_lock, FALSE);
		dc_deref_hook(hook);
	}

	/* prevent leaks */
	zeroauto(&header, sizeof(dc_header));

	if (h_dev != NULL)
	{
		/* dismount volume */
		io_fs_control(h_dev, FSCTL_DISMOUNT_VOLUME);
		io_fs_control(h_dev, FSCTL_UNLOCK_VOLUME);

		ZwClose(h_dev);
	}		

	lock_dec(&dc_data_lock);

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

		size = (u32)(min(hook->use_size - hook->tmp_size, ENC_BLOCK_SIZE));
		offs = hook->tmp_size + SECTOR_SIZE;
		buff = hook->tmp_buff;

		if (size == 0) {
			dc_format_done(dev_name);
			resl = ST_FINISHED; break;
		}

		if (hook->crypt.wp_mode != wp_mode)
		{
			dc_wipe_free(&hook->wp_ctx);

			resl = dc_wipe_init(
				&hook->wp_ctx, hook, ENC_BLOCK_SIZE, wp_mode
				);

			if (resl == ST_OK) {
				hook->crypt.wp_mode = wp_mode;
			} else {
				dc_wipe_init(&hook->wp_ctx, hook, ENC_BLOCK_SIZE, WP_NONE);
				hook->crypt.wp_mode = WP_NONE;
			}
		}

		/* wipe sectors */
		dc_wipe_process(&hook->wp_ctx, offs, size);

		/* fill buffer from fast PRNG */
		rnd_fast_rand(hook->fmt_rnd, buff, ENC_BLOCK_SIZE);

		/* encrypt buffer with volume key */
		dc_fast_encrypt(
			buff, buff, ENC_BLOCK_SIZE, hook->tmp_size, &hook->dsk_key
			);

		resl = dc_device_rw(
			hook, IRP_MJ_WRITE, buff, ENC_BLOCK_SIZE, offs
			);

		if ( (resl == ST_OK) || (resl == ST_RW_ERR) ) {
			hook->tmp_size += size;
		}

		if ( (resl == ST_MEDIA_CHANGED) || (resl == ST_NO_MEDIA) ) {			
			dc_process_unmount(hook, UM_NOFSCTL);
			resl = ST_FINISHED;
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

int dc_change_pass(
	  wchar_t *dev_name, s8 *old_pass, s8 *new_pass, u8 new_prf
	  )
{
	dc_header header;
	dev_hook *hook    = NULL;
	dc_key   *hdr_key = NULL;
	int       wp_init = 0;
	int       resl;
	wipe_ctx  wipe;	

	lock_inc(&dc_data_lock);
	
	do
	{
		if ( (hook = dc_find_hook(dev_name)) == NULL ) {
			resl = ST_NF_DEVICE; break;
		}

		wait_object_infinity(&hook->busy_lock);

		if ( !(hook->flags & F_ENABLED) ) {
			resl = ST_NO_MOUNT; break;
		}

		if ( (hook->flags & (F_SYNC | F_FORMATTING)) || (new_prf >= PRF_NUM) ) {
			resl = ST_ERROR; break;
		}

		if (hook->vf_version != TC_VOLUME_HEADER_VERSION) {
			resl = ST_INV_VOL_VER; break;
		}

		/* read old volume header */
		resl = dc_device_rw(
			hook, IRP_MJ_READ, &header, sizeof(header), 0
			);	
		
		if (resl != ST_OK) {			
			break;
		}

		/* decrypt volume header */
		hdr_key = dc_dec_known_header(&header, &hook->crypt, old_pass);

		if (hdr_key == NULL) {
			resl = ST_PASS_ERR; break;
		}

		/* init data wipe */
		resl = dc_wipe_init(&wipe, hook, SECTOR_SIZE, WP_GUTMANN);

		if (resl == ST_OK) {
			wp_init = 1;
		} else break;

		hook->crypt.prf_id = new_prf;

		/* wipe volume header */
		dc_wipe_process(&wipe, 0, SECTOR_SIZE);
		/* write new volume header */
		if ( (resl = dc_write_header(hook, &header, 0, new_pass)) != ST_OK ) {
			break;
		}

		/* wipe backup header */
		dc_wipe_process(&wipe, DC_BACKUP_OFFSET(hook), SECTOR_SIZE);
		/* write new backup header */
		resl = dc_write_header(hook, &header, DC_BACKUP_OFFSET(hook), new_pass);
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

	zeroauto(&header, sizeof(header));

	lock_dec(&dc_data_lock);
	
	return resl;
}

int dc_update_volume(s16 *dev_name, s8 *password, dc_ioctl *s_sh)
{
	dev_hook     *hook;
	dc_key       *hdr_key;
	dc_header     header;
	int           resl;

	lock_inc(&dc_data_lock);

	hook = NULL; hdr_key = NULL;
	do
	{
		if ( (hook = dc_find_hook(dev_name)) == NULL ) {
			resl = ST_NF_DEVICE; break;
		}

		wait_object_infinity(&hook->busy_lock);

		if ( !(hook->flags & F_ENABLED) ) {
			resl = ST_NO_MOUNT; break;
		}

		if ( (hook->flags & (F_SYNC | F_FORMATTING)) || 
			 (hook->vf_version >= TC_VOLUME_HEADER_VERSION) ) 
		{
			resl = ST_ERROR; break;
		}

		/* read old volume header */
		resl = dc_device_rw(
			hook, IRP_MJ_READ, &header, sizeof(header), 0
			);	
		
		if (resl != ST_OK) {			
			break;
		}

		/* decrypt volume header */
		hdr_key = dc_dec_known_header(&header, &hook->crypt, password);

		if (hdr_key == NULL) {
			resl = ST_PASS_ERR; break;
		}

		DbgMsg("dc_update_volume ok\n");

		/* create new disk_id */
		rnd_get_bytes(pv(&header.disk_id), sizeof(u32));		

		/* update volume parameters */
		hook->use_size   = hook->dsk_size - HEADER_SIZE - DC_RESERVED_SIZE;
		hook->vf_version = TC_VOLUME_HEADER_VERSION;
		hook->disk_id    = header.disk_id;

		/* fill TC fields */
		header.version     = BE16(TC_VOLUME_HEADER_VERSION);
		header.req_ver     = BE16(TC_VOL_REQ_PROG_VERSION);
		header.hidden_size = 0;
		header.vol_size    = hook->use_size;
		header.enc_start   = 0;
		header.enc_size    = hook->use_size;		

		/* clean all temporary mode fields */
		header.flags        = VF_NONE;
		header.tmp_wp_mode  = 0;
		header.tmp_size     = 0;
		header.tmp_save_off = 0;

		if (s_sh->shrink_val != 0)
		{
			/* set shrink fields in volume header */
			header.flags     |= VF_SHRINK_PENDING;
			header.shrink_off = s_sh->shrink_off;
			header.shrink_val = s_sh->shrink_val;
			/* set hook flag */
			hook->flags |= F_SHRINK_PENDING;
		}

		/* write volume header */
		if ( (resl = dc_write_header(hook, &header, 0, password)) != ST_OK ) {
			break;
		}
		/* write backup header */
		resl = dc_write_header(hook, &header, DC_BACKUP_OFFSET(hook), password);
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

	zeroauto(&header, sizeof(header));

	lock_dec(&dc_data_lock);

	return resl;
}

