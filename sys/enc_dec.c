/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2007-2009 
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
#include "driver.h"
#include "prng.h"
#include "misc.h"
#include "readwrite.h"
#include "crc32.h"
#include "pkcs5.h"
#include "mount.h"
#include "enc_dec.h"
#include "data_wipe.h"
#include "misc_irp.h"
#include "fastmem.h"
#include "fast_crypt.h"
#include "misc_volume.h"
#include "debug.h"
#include "storage.h"
#include "fsf_control.h"

typedef struct _sync_struct {
	KEVENT sync_event;
	int    status;

} sync_struct;

typedef struct _sync_context {
	int finish;
	int saved;
	int winit;

} sync_context;

static
int dc_device_rw_skip_bads(
	   dev_hook *hook, u32 function, void *buff, u32 size, u64 offset
	   )
{
	u32 block;
	int resl;

	resl = dc_device_rw(
		hook, function, buff, size, offset);

	if (resl == ST_RW_ERR)
	{
		while (block = min(size, 4096))
		{
			resl = dc_device_rw(
				hook, function, buff, block, offset);

			if ( (resl == ST_MEDIA_CHANGED) || (resl == ST_NO_MEDIA) ) {
				break;
			}

			buff  = p8(buff) + block;
			size -= block; offset += block;
		}
	}

	return resl;
}

static int dc_enc_update(dev_hook *hook)
{
	u8 *buff = hook->tmp_buff;
	u64 offs = hook->tmp_size;
	u32 size = d32(min(hook->dsk_size - offs, ENC_BLOCK_SIZE));
	int r_resl, w_resl;

	if (size == 0) {
		return ST_FINISHED;
	}

	do
	{
		r_resl = dc_device_rw_skip_bads(
			hook, IRP_MJ_READ, buff, size, offs);

		if ( (r_resl != ST_OK) && (r_resl != ST_RW_ERR) ) {
			break;
		}
		
		dc_fast_encrypt(buff, buff, size, offs, &hook->dsk_key);

		dc_wipe_process(&hook->wp_ctx, offs, size);

		w_resl = dc_device_rw_skip_bads(
			hook, IRP_MJ_WRITE, buff, size, offs);

		if (w_resl == ST_RW_ERR) {
			r_resl = w_resl;
		}
	} while (0);

	if ( (r_resl == ST_OK) || (r_resl == ST_RW_ERR) ) {
		hook->tmp_size += size;
	}
	
	return r_resl;
}

static int dc_re_enc_update(dev_hook *hook)
{
	u8 *buff = hook->tmp_buff;
	u64 offs = hook->tmp_size;
	u32 size = d32(min(hook->dsk_size - offs, ENC_BLOCK_SIZE));	
	int r_resl, w_resl;
	
	if (size == 0) {
		return ST_FINISHED;
	}

	do
	{
		r_resl = dc_device_rw_skip_bads(
			hook, IRP_MJ_READ, buff, size, offs);

		if ( (r_resl != ST_OK) && (r_resl != ST_RW_ERR) ) {
			break;
		}

		/* wipe old data */
		dc_wipe_process(&hook->wp_ctx, offs, size);

		/* re-encrypt data */
		dc_fast_decrypt(buff, buff, size, offs, hook->tmp_key);
		dc_fast_encrypt(buff, buff, size, offs, &hook->dsk_key);

		w_resl = dc_device_rw_skip_bads(
			hook, IRP_MJ_WRITE, buff, size, offs);

		if (w_resl == ST_RW_ERR) {
			r_resl = w_resl;
		}
	} while (0);

	if ( (r_resl == ST_OK) || (r_resl == ST_RW_ERR) ) {
		hook->tmp_size += size;
	}

	return r_resl;
}


static int dc_dec_update(dev_hook *hook)
{
	NTSTATUS status;
	u8      *buff = hook->tmp_buff;
	u32      size = d32(min(hook->tmp_size, ENC_BLOCK_SIZE));
	u64      offs = hook->tmp_size - size;
	int      r_resl, w_resl;
	
	if (size == 0)
	{
		/* write redirected part back to zero offset */
		status = dc_sync_encrypted_io(
			hook, buff, DC_AREA_SIZE, 0, SL_OVERRIDE_VERIFY_VOLUME, IRP_MJ_READ);

		if (NT_SUCCESS(status) == FALSE) {
			return ST_RW_ERR;
		}

		w_resl = dc_device_rw(
			hook, IRP_MJ_WRITE, buff, DC_AREA_SIZE, 0);

		if (w_resl == ST_OK) {
			w_resl = ST_FINISHED;
		}

		return w_resl;
	}

	do
	{
		r_resl = dc_device_rw_skip_bads(
			hook, IRP_MJ_READ, buff, size, offs);
		
		if ( (r_resl != ST_OK) && (r_resl != ST_RW_ERR) ) {
			break;
		}

		dc_fast_decrypt(
			buff, buff, size, offs, &hook->dsk_key);

		w_resl = dc_device_rw_skip_bads(
			hook, IRP_MJ_WRITE, buff, size, offs);

		if (w_resl == ST_RW_ERR) {
			r_resl = w_resl;
		}
	} while (0);

	if ( (r_resl == ST_OK) || (r_resl == ST_RW_ERR) ) {
		hook->tmp_size -= size;
	}

	return r_resl;
}

static void dc_save_enc_state(dev_hook *hook, int finish)
{
	dc_header *header;
		
	DbgMsg("dc_save_enc_state\n");

	if ( (header = fast_alloc(sizeof(dc_header))) == NULL ) {
		return;
	}

	/* copy volume header */
	autocpy(header, &hook->tmp_header, sizeof(dc_header));

	if (finish != 0)
	{
		header->flags      &= ~(VF_TMP_MODE | VF_REENCRYPT);
		header->tmp_size    = 0;
		header->tmp_wp_mode = 0;

		if (hook->flags & F_REENCRYPT) {
			zeroauto(header->key_2, DISKKEY_SIZE); 
			header->alg_2 = 0;
		}
	} else 
	{
		header->flags      |= VF_TMP_MODE;
		header->tmp_size    = hook->tmp_size;
		header->tmp_wp_mode = hook->crypt.wp_mode;

		if (hook->flags & F_REENCRYPT) {
			header->flags |= VF_REENCRYPT;
		} 
	}

	header->hdr_crc = crc32(pv(&header->version), DC_CRC_AREA_SIZE);

	/* encrypt volume header */
	dc_cipher_encrypt(
		pv(header), pv(header), sizeof(dc_header), 0, hook->hdr_key);

	/* save original salt */
	autocpy(header->salt, hook->tmp_header.salt, PKCS5_SALT_SIZE);
	
	/* write volume header */
	dc_device_rw(
		hook, IRP_MJ_WRITE, header, sizeof(dc_header), 0);

	/* prevent leaks */
	zeroauto(header, sizeof(dc_header));
	fast_free(header);
}


static int dc_init_sync_mode(dev_hook *hook, sync_context *ctx)
{
	NTSTATUS status;
	dc_key  *tmp_key;
	u8      *buff = hook->tmp_buff;
	int      resl;
	
	do
	{
		switch (lock_xchg(&hook->sync_init_type, 0))
		{
			case S_INIT_ENC:
				{
					/* initialize encryption process */
					
					/* save old sectors */
					resl = dc_device_rw(
						hook, IRP_MJ_READ, buff, DC_AREA_SIZE, 0);

					if (resl != ST_OK) {
						break;
					}

					status = dc_sync_encrypted_io(
						hook, buff, DC_AREA_SIZE, 0, SL_OVERRIDE_VERIFY_VOLUME, IRP_MJ_WRITE);

					if (NT_SUCCESS(status) == FALSE) {
						resl = ST_RW_ERR; break;
					}
					
					/* wipe old sectors */
					dc_wipe_process(&hook->wp_ctx, 0, DC_AREA_SIZE);
					/* save initial state */
					dc_save_enc_state(hook, 0);
				}
			break;
			case S_INIT_DEC:
			case S_CONTINUE_ENC: 
				{
					resl = ST_OK;
				}
			break;
			case S_INIT_RE_ENC:
				{
					DbgMsg("S_INIT_RE_ENC\n");

					if ( (tmp_key = mem_alloc(sizeof(dc_key))) == NULL ) {
						resl = ST_NOMEM; break;
					}

					/* swap keys */
					autocpy(tmp_key, &hook->dsk_key, sizeof(dc_key));
					autocpy(&hook->dsk_key, hook->tmp_key, sizeof(dc_key));
					autocpy(hook->tmp_key, tmp_key, sizeof(dc_key));
					/* re-initialize keys */
					dc_cipher_reinit(hook->tmp_key);
					dc_cipher_reinit(&hook->dsk_key);

					/* set re-encryption flag */
					hook->flags |= F_REENCRYPT;
					/* wipe old volume header */
					dc_wipe_process(&hook->wp_ctx, 0, DC_AREA_SIZE);
					/* save initial state */
					dc_save_enc_state(hook, 0);
					
					/* prevent leaks */
					zeroauto(tmp_key, sizeof(dc_key));
					mem_free(tmp_key); resl = ST_OK;
				}
			break;
			case S_CONTINUE_RE_ENC:
				{
					DbgMsg("S_CONTINUE_RE_ENC\n");

					if ( (tmp_key = mem_alloc(sizeof(dc_key))) == NULL ) {
						resl = ST_NOMEM; break;
					}

					/* initialize secondary volume key */
					dc_cipher_init(
						(hook->tmp_key = tmp_key), 
						hook->tmp_header.alg_2, hook->tmp_header.key_2);					

					/* set re-encryption flag */
					hook->flags |= F_REENCRYPT; resl = ST_OK;
				}
			break;
		}
	} while (0);

	return resl;
}

static int dc_process_sync_packet(
		     dev_hook *hook, sync_packet *packet, sync_context *ctx)
{
	int new_wp = (int)(packet->param);
	int resl;

	switch (packet->type)
	{
		case S_OP_ENC_BLOCK:
			{
				if (ctx->finish == 0)
				{
					if ( (new_wp != hook->crypt.wp_mode) && (new_wp < WP_NUM) )
					{
						dc_wipe_free(&hook->wp_ctx);

						resl = dc_wipe_init(
							&hook->wp_ctx, hook, ENC_BLOCK_SIZE, new_wp);

						if (resl == ST_OK) 
						{
							hook->crypt.wp_mode = d8(new_wp);
							dc_save_enc_state(hook, 0);
						} else {
							dc_wipe_init(&hook->wp_ctx, hook, ENC_BLOCK_SIZE, WP_NONE);
						}
					}

					if (hook->flags & F_REENCRYPT) {
						resl = dc_re_enc_update(hook);
					} else {
						resl = dc_enc_update(hook);
					}

					if (resl == ST_FINISHED) {
						dc_save_enc_state(hook, 1); ctx->finish = 1;
					} else ctx->saved = 0;
				} else {
					resl = ST_FINISHED;
				}
			}
		break;
		case S_OP_DEC_BLOCK:
			{
				if (hook->flags & F_REENCRYPT) {
					resl = ST_ERROR; break;
				}

				if (ctx->finish == 0)
				{
					if ( (resl = dc_dec_update(hook)) == ST_FINISHED) {
						dc_process_unmount(hook, MF_NOFSCTL | MF_NOSYNC);
						ctx->finish = 1;
					} else ctx->saved = 0;
				} else {
					resl = ST_FINISHED;
				}
			}
		break;
		case S_OP_SYNC:
			{
				if ( (ctx->finish == 0) && (ctx->saved == 0) ) {
					dc_save_enc_state(hook, 0); ctx->saved = 1;
				}
				resl = ST_OK;
			}
		break;
		case S_OP_FINALIZE:
			{
				if ( (ctx->finish == 0) && (ctx->saved == 0) ) {
					dc_save_enc_state(hook, 0); ctx->finish = 1;
				}
				resl = ST_FINISHED;						
			}
		break;
	}

	return resl;
}

static void dc_sync_op_routine(dev_hook *hook)
{
	sync_packet *packet;
	PLIST_ENTRY  entry;
	u8          *buff;
	sync_context sctx;
	int          resl, init_t;
	int          del_storage;
	
	DbgMsg("sync thread started\n");

	lock_inc(&dc_dump_disable);
	dc_reference_hook(hook);

	/* initialize sync mode data */
	InitializeListHead(&hook->sync_req_queue);
	InitializeListHead(&hook->sync_irp_queue);
	KeInitializeSpinLock(&hook->sync_req_lock);

	KeInitializeEvent(
		&hook->sync_req_event, SynchronizationEvent, FALSE);

	/* enable synchronous irp processing */
	hook->flags |= (F_ENABLED | F_SYNC);
	
	zeroauto(&sctx, sizeof(sctx));
	init_t = hook->sync_init_type;
	del_storage = 0;

	/* allocate resources */
	if (buff = mem_alloc(ENC_BLOCK_SIZE))
	{
		hook->tmp_buff = buff;

		resl = dc_wipe_init(
			&hook->wp_ctx, hook, ENC_BLOCK_SIZE, hook->crypt.wp_mode);

		if (resl == ST_OK) 
		{
			sctx.winit = 1;
			/* init sync mode */
			resl = dc_init_sync_mode(hook, &sctx);
		}			 
	} else {
		resl = ST_NOMEM;
	}
	DbgMsg("sync mode initialized\n");
	/* save init status */
	hook->sync_init_status = resl;

	if (resl == ST_OK) 
	{
		/* signal of init finished */
		KeSetEvent(
			&hook->sync_enter_event, IO_NO_INCREMENT, FALSE);		
	} else 
	{
		if ( (init_t == S_INIT_ENC) || (init_t == S_CONTINUE_ENC) || (init_t == S_CONTINUE_RE_ENC) ) {
			hook->flags &= ~(F_ENABLED | F_SYNC | F_REENCRYPT | F_PROTECT_DCSYS);
		} else {
			hook->flags &= ~F_SYNC;
		}
		goto cleanup;
	}

	do
	{
		wait_object_infinity(&hook->sync_req_event);

		do
		{
			if (hook->flags & F_SYNC)
			{
				while (entry = ExInterlockedRemoveHeadList(&hook->sync_irp_queue, &hook->sync_req_lock))
				{
					dc_sync_irp_io(
						hook, CONTAINING_RECORD(entry, IRP, Tail.Overlay.ListEntry));
				}
			}

			if (entry = ExInterlockedRemoveHeadList(&hook->sync_req_queue, &hook->sync_req_lock))
			{
				packet = CONTAINING_RECORD(entry, sync_packet, entry_list);

				/* process packet */
				resl = dc_process_sync_packet(hook, packet, &sctx);

				/* disable synchronous irp processing */
				if (resl == ST_FINISHED) {
					del_storage  = !(hook->flags & F_ENABLED) && 
						            (hook->tmp_header.flags & VF_STORAGE_FILE);
					hook->flags &= ~(F_SYNC | F_REENCRYPT);					
				}

				/* signal of packet completion */
				packet->status = resl;
				
				KeSetEvent(
					&packet->sync_event, IO_NO_INCREMENT, FALSE);

				if ( (resl == ST_MEDIA_CHANGED) || (resl == ST_NO_MEDIA) ) {
					dc_process_unmount(hook, MF_NOFSCTL | MF_NOSYNC);
					resl = ST_FINISHED; sctx.finish = 1;
				}
			}
		} while (entry != NULL);
	} while (hook->flags & F_SYNC);
cleanup:;

	/* pass all IRPs to default routine */
	while (entry = ExInterlockedRemoveHeadList(&hook->sync_irp_queue, &hook->sync_req_lock))
	{
		dc_read_write_irp(
			hook, CONTAINING_RECORD(entry, IRP, Tail.Overlay.ListEntry));
	}

	/* free resources */
	if (sctx.winit != 0) {
		dc_wipe_free(&hook->wp_ctx);
	}

	if (buff != NULL) {
		mem_free(buff);
	}

	/* stop RW thread if needed */
	if ( !(hook->flags & F_ENABLED) ) {
		dc_stop_rw_thread(hook);
	}

	/* prevent leaks */
	wait_object_infinity(&hook->key_lock);

	if (hook->hdr_key != NULL) 
	{
		zeroauto(hook->hdr_key, sizeof(dc_key));
		mem_free(hook->hdr_key);
		hook->hdr_key = NULL;
	}

	if (hook->tmp_key != NULL)
	{
		zeroauto(hook->tmp_key, sizeof(dc_key));
		mem_free(hook->tmp_key);
		hook->tmp_key = NULL;
	}

	zeroauto(&hook->tmp_header, sizeof(hook->tmp_header));
	KeReleaseMutex(&hook->key_lock, FALSE);

	/* report init finished if initialization fails */
	if (resl != ST_FINISHED)
	{
		KeSetEvent(
			&hook->sync_enter_event, IO_NO_INCREMENT, FALSE);	
	}

	if (del_storage != 0) {
		dc_delete_storage(hook);
	}

	dc_deref_hook(hook);
	lock_dec(&dc_dump_disable);

	DbgMsg("exit from sync thread\n");

	PsTerminateSystemThread(STATUS_SUCCESS);
}

int dc_enable_sync_mode(dev_hook *hook)
{
	int resl;

	do
	{
		if (hook->flags & F_SYNC) {
			resl = ST_ERROR; break;
		}

		KeInitializeEvent(
			&hook->sync_enter_event, NotificationEvent, FALSE);		

		resl = start_system_thread(dc_sync_op_routine, hook, NULL);

		if (resl == ST_OK) {
			wait_object_infinity(&hook->sync_enter_event);
			resl = hook->sync_init_status;						
		}
	} while (0);

	return resl;
}

int dc_send_sync_packet(wchar_t *dev_name, u32 type, void *param)
{
	dev_hook    *hook;
	sync_packet *packet;
	int          mutex = 0;
	int          resl;	

	do
	{
		if ( (hook = dc_find_hook(dev_name)) == NULL ) {
			resl = ST_NF_DEVICE; break;
		}

		wait_object_infinity(&hook->busy_lock);

		if ( !(hook->flags & F_SYNC) ) {			
			resl = ST_ERROR; break;
		}

		if ( (hook->flags & F_PREVENT_ENC) && 
			 ((type == S_OP_ENC_BLOCK) || (type == S_OP_DEC_BLOCK)) )
		{
			resl = ST_CANCEL; break;
		}

		if ( (packet = mem_alloc(sizeof(sync_packet))) == NULL ) {
			resl = ST_NOMEM; break;
		}

		KeInitializeEvent(
			&packet->sync_event, NotificationEvent, FALSE);

		packet->type  = type;
		packet->param = param;		

		ExInterlockedInsertTailList(
			&hook->sync_req_queue, &packet->entry_list, &hook->sync_req_lock);

		KeSetEvent(
			&hook->sync_req_event, IO_NO_INCREMENT, FALSE);

		KeReleaseMutex(&hook->busy_lock, FALSE);

		wait_object_infinity(&packet->sync_event);

		resl = packet->status; mutex = 1;
		mem_free(packet);		
	} while (0);

	if (hook != NULL) 
	{		
		if (mutex == 0) {
			KeReleaseMutex(&hook->busy_lock, FALSE);
		}
		dc_deref_hook(hook);
	}

	return resl;
}

void dc_sync_all_encs()
{
	dev_hook *hook;

	if (hook = dc_first_hook())
	{
		do
		{
			dc_send_sync_packet(hook->dev_name, S_OP_SYNC, 0);
		} while (hook = dc_next_hook(hook));
	}
}

int dc_encrypt_start(wchar_t *dev_name, dc_pass *password, crypt_info *crypt)
{
	dc_header *header;
	dev_hook  *hook;
	dc_key    *hdr_key;
	int        resl;
	u64        storage;
				
	DbgMsg("dc_encrypt_start\n");

	header = NULL; hdr_key = NULL;
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

		/* sync device flags with FS filter */
		dc_fsf_set_flags(hook->dev_name, hook->flags);

		/* create redirection storage */
		if ( (resl = dc_create_storage(hook, &storage)) != ST_OK ) {
			break;
		}
		DbgMsg("storage created\n");

		if ( (header = mem_alloc(sizeof(dc_header))) == NULL ) {
			resl = ST_NOMEM; break;
		}

		if ( (hdr_key = mem_alloc(sizeof(dc_key))) == NULL ) {
			resl = ST_NOMEM; break;
		}

		/* create volume header */
		zeroauto(header, sizeof(dc_header));

		rnd_get_bytes(pv(header->salt),     PKCS5_SALT_SIZE);
		rnd_get_bytes(pv(&header->disk_id), sizeof(u32));
		rnd_get_bytes(pv(header->key_1),    DISKKEY_SIZE);

		header->sign     = DC_VOLM_SIGN;
		header->version  = DC_HDR_VERSION;
		header->flags    = VF_TMP_MODE | VF_STORAGE_FILE;
		header->alg_1    = crypt->cipher_id;
		header->stor_off = storage;
		header->use_size = hook->dsk_size;

		/* initialize volume key */
		dc_cipher_init(
			&hook->dsk_key, crypt->cipher_id, header->key_1);

		/* initialize header key */
		dc_init_hdr_key(
			hdr_key, header, crypt->cipher_id, password);

		hook->crypt          = crypt[0];
		hook->use_size       = hook->dsk_size;
		hook->tmp_size       = DC_AREA_SIZE;
		hook->stor_off       = storage;
		hook->vf_version     = DC_HDR_VERSION;
		hook->sync_init_type = S_INIT_ENC;
		hook->hdr_key        = hdr_key;
		hook->disk_id        = header->disk_id;
		hook->flags         |= F_PROTECT_DCSYS;

		/* start syncronous RW helper thread */		
		if ( (resl = dc_start_rw_thread(hook)) != ST_OK ) {
			break;
		}
		/* copy header to temp buffer */
		autocpy(&hook->tmp_header, header, sizeof(dc_header));	
		
		if ( (resl = dc_enable_sync_mode(hook)) != ST_OK ) 
		{
			DbgMsg("sync init error\n");
			zeroauto(&hook->tmp_header, sizeof(dc_header));	
			hdr_key = hook->hdr_key;
		} else {
			hdr_key = NULL;
		}
		/* syncronize with RW thread */
		KeSetEvent(&hook->rw_init_event, IO_NO_INCREMENT, FALSE);
		/* sync device flags with FS filter */
		dc_fsf_set_flags(hook->dev_name, hook->flags);
	} while (0);

	/* prevent leaks */
	if (hdr_key != NULL) {
		zeroauto(hdr_key, sizeof(dc_key));
		mem_free(hdr_key);
	}

	if (header != NULL) {
		zeroauto(header, sizeof(dc_header));
		mem_free(header);
	}

	if (hook != NULL) {
		KeReleaseMutex(&hook->busy_lock, FALSE);
		dc_deref_hook(hook);
	}

	return resl;
}

int dc_reencrypt_start(wchar_t *dev_name, dc_pass *password, crypt_info *crypt)
{
	dc_header *header = NULL;
	crypt_info o_crypt;
	dev_hook  *hook;
	dc_key    *hdr_key = NULL;
	dc_key    *dsk_key = NULL;
	int        resl;

	DbgMsg("dc_reencrypt_start\n");

	do
	{
		if ( (hook = dc_find_hook(dev_name)) == NULL ) {
			resl = ST_NF_DEVICE; break;
		}

		wait_object_infinity(&hook->busy_lock);

		if ( !(hook->flags & F_ENABLED) || 
			  (hook->flags & (F_SYNC | F_FORMATTING | F_CDROM)) ) 
		{
			resl = ST_ERROR; break;
		}

		/* verify encryption info */
		if ( (crypt->cipher_id >= CF_CIPHERS_NUM) || (crypt->wp_mode >= WP_NUM) ) {
			resl = ST_ERROR; break;
		}

		/* allocate new volume key */
		if ( (dsk_key = mem_alloc(sizeof(dc_key))) == NULL ) {
			resl = ST_NOMEM; break;
		}

		/* allocate new header key */
		if ( (hdr_key = mem_alloc(sizeof(dc_key))) == NULL ) {
			resl = ST_NOMEM; break;
		}

		if ( (header = mem_alloc(sizeof(dc_header))) == NULL ) {
			resl = ST_NOMEM; break;
		}

		/* read volume header */
		resl = dc_device_rw(
			hook, IRP_MJ_READ, header, sizeof(dc_header), 0);

		if (resl != ST_OK) {
			break;
		}

		if (dc_decrypt_header(hdr_key, header, password) == 0) {
			resl = ST_PASS_ERR;	break;
		}

		/* copy current volume key to secondary key */
		autocpy(header->key_2, header->key_1, DISKKEY_SIZE);

		/* generate new salt and volume key */
		rnd_get_bytes(header->salt,  PKCS5_SALT_SIZE);		
		rnd_get_bytes(header->key_1, DISKKEY_SIZE);

		/* change other fields */
		header->alg_2  = header->alg_1;
		header->alg_1  = crypt->cipher_id;
		header->flags |= VF_REENCRYPT;

		/* initialize new header key */
		dc_init_hdr_key(
			hdr_key, header, header->alg_1, password);

		/* initialize new volume key */
		dc_cipher_init(
			dsk_key, header->alg_1, header->key_1);

		/* save old encryption info */
		o_crypt = hook->crypt;
		/* set new encryption info */		
		hook->crypt          = *crypt;
		hook->tmp_size       = 0;
		hook->sync_init_type = S_INIT_RE_ENC;
		hook->hdr_key        = hdr_key;
		hook->tmp_key        = dsk_key;
		
		/* copy header to temp buffer */
		autocpy(&hook->tmp_header, header, sizeof(dc_header));
		
		if ( (resl = dc_enable_sync_mode(hook)) != ST_OK ) 
		{
			zeroauto(&hook->tmp_header, sizeof(dc_header));	
			hdr_key = hook->hdr_key;
			dsk_key = hook->tmp_key;
			/* restore encryption info */
			hook->crypt = o_crypt;
		} else {
			hdr_key = NULL;
			dsk_key = NULL;
		}
	} while (0);

	/* prevent leaks */
	if (dsk_key != NULL) {
		zeroauto(dsk_key, sizeof(dc_key));
		mem_free(dsk_key);
	}

	if (hdr_key != NULL) {
		zeroauto(hdr_key, sizeof(dc_key));
		mem_free(hdr_key);
	}

	if (header != NULL) {
		zeroauto(header, sizeof(dc_header));
		mem_free(header);
	}

	if (hook != NULL) {
		KeReleaseMutex(&hook->busy_lock, FALSE);
		dc_deref_hook(hook);
	}

	return resl;
}

int dc_decrypt_start(wchar_t *dev_name, dc_pass *password)
{
	dc_header *header = NULL;
	dev_hook  *hook;
	dc_key    *hdr_key = NULL;
	int        resl;
				
	DbgMsg("dc_decrypt_start\n");

	do
	{
		if ( (hook = dc_find_hook(dev_name)) == NULL ) {
			resl = ST_NF_DEVICE; break;
		}

		wait_object_infinity(&hook->busy_lock);
		
		if ( !(hook->flags & F_ENABLED) || 
			  (hook->flags & (F_SYNC | F_FORMATTING | F_CDROM)) ) 
		{
			resl = ST_ERROR; break;
		}

		if ( (header = mem_alloc(sizeof(dc_header))) == NULL ) {
			resl = ST_NOMEM; break;
		}

		if ( (hdr_key = mem_alloc(sizeof(dc_key))) == NULL ) {
			resl = ST_NOMEM; break;
		}

		/* read volume header */
		resl = dc_device_rw(
			hook, IRP_MJ_READ, header, sizeof(dc_header), 0);

		if (resl != ST_OK) {
			break;
		}

		/* decrypt volume header */
		if (dc_decrypt_header(hdr_key, header, password) == 0) {
			resl = ST_PASS_ERR;	break;
		}

		hook->crypt.cipher_id = d8(header->alg_1);
		hook->crypt.wp_mode   = WP_NONE;
		
		/* copy header to temp buffer */
		autocpy(&hook->tmp_header, header, sizeof(dc_header));

		hook->tmp_size       = hook->dsk_size;
		hook->sync_init_type = S_INIT_DEC;
		hook->hdr_key        = hdr_key;
		
		if ( (resl = dc_enable_sync_mode(hook)) != ST_OK ) 
		{
			zeroauto(&hook->tmp_header, sizeof(dc_header));
			hdr_key = hook->hdr_key;
		} else {
			hdr_key = NULL;
		}
	} while (0);

	/* prevent leaks */
	if (hdr_key != NULL) {
		zeroauto(hdr_key, sizeof(dc_key));
		mem_free(hdr_key);
	}

	if (header != NULL) {
		zeroauto(header, sizeof(dc_header));
		mem_free(header);
	}

	if (hook != NULL) {
		KeReleaseMutex(&hook->busy_lock, FALSE);
		dc_deref_hook(hook);
	}

	return resl;
}
