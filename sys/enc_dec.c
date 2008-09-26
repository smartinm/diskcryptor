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

typedef struct _sync_struct {
	KEVENT sync_event;
	int    status;

} sync_struct;

typedef struct _set_key_struct {
	dc_header *header;
	dc_key    *hdr_key;
	char      *password;

} set_key_struct;

static void dc_sync_irp(dev_hook *hook, PIRP irp)
{
	PIO_STACK_LOCATION irp_sp;
	u64                offset;
	u32                length;
	u64                o1, o3;
	u32                s1, s2, s3;	
	u8                *p1, *p2, *p3;
	u64                tmp, end;
	u8                *buff, *encb;
	NTSTATUS           status;

	irp_sp = IoGetCurrentIrpStackLocation(irp);
	buff   = dc_map_mdl_with_retry(irp->MdlAddress);

	if (buff == NULL) {		
		dc_complete_irp(irp, STATUS_INSUFFICIENT_RESOURCES, 0);
		return;
	}

	if (irp_sp->MajorFunction == IRP_MJ_READ) {
		offset = irp_sp->Parameters.Read.ByteOffset.QuadPart;
		length = irp_sp->Parameters.Read.Length;
	} else 
	{
		offset = irp_sp->Parameters.Write.ByteOffset.QuadPart;
		length = irp_sp->Parameters.Write.Length;
	}

	if ( (length == 0) ||
		 (length & (SECTOR_SIZE - 1)) ||
		 (offset + length > hook->use_size) )
	{
		dc_complete_irp(irp, STATUS_INVALID_PARAMETER, 0);
		return;
	}

	o1  = o3 = 0;
	s1  = s2 = s3 = 0;
	p1  = p2 = p3 = NULL;
	tmp = hook->tmp_size;
	end = offset + length;

	if (hook->flags & F_REENCRYPT)
	{
		if (offset >= tmp) {
			o3 = offset; s3 = length; p3 = buff;
		} else
		{
			if ( (offset+length) > tmp )
			{
				o1 = offset; s1 = (u32)(tmp - offset); p1 = buff;
				o3 = offset + s1; s3 = length - s1; p3 = p1 + s1;
			} else {
				o1 = offset; s1 = length; p1 = buff;
			}
		}

		if (irp_sp->MajorFunction == IRP_MJ_READ) 
		{
			/* read encrypted data */
			status = io_device_rw_block(
				hook->orig_dev, IRP_MJ_READ, buff, length, offset + SECTOR_SIZE, irp_sp->Flags
				);
			
			if (p1 != NULL)	{
				dc_fast_decrypt(p1, p1, s1, o1, &hook->dsk_key);
			}

			if (p3 != NULL) {
				dc_fast_decrypt(p3, p3, s3, o3, hook->tmp_key);
			}
		} else 
		{
			if ( (encb = fast_alloc(length)) == NULL ) {
				status = STATUS_INSUFFICIENT_RESOURCES; goto i_exit;
			}

			if (p1 != NULL)	{
				dc_fast_encrypt(p1, encb + (p1 - buff), s1, o1, &hook->dsk_key);
			}		

			if (p3 != NULL) {				
				dc_fast_encrypt(p3, encb + (p3 - buff), s3, o3, hook->tmp_key);
			}	

			/* write encrypted data */
			status = io_device_rw_block(
				hook->orig_dev, IRP_MJ_WRITE, encb, length, offset + SECTOR_SIZE, irp_sp->Flags
				);

			fast_free(encb);
		}

		goto i_exit;
	}		

	if (offset > tmp) {
		o3 = offset; s3 = length; p3 = buff;
	} else
	{
		if ( (offset <= tmp) && ((offset+length) > tmp) )
		{
			o1 = offset; s1 = (u32)(tmp - offset); p1 = buff;
			s2 = SECTOR_SIZE; p2 = p1 + s1;
			o3 = offset + s1 + s2; s3 = length - s1 - s2; p3 = p2 + s2;
		} else {
			o1 = offset; s1 = length; p1 = buff;
		}		
	} 

	do
	{
		if (irp_sp->MajorFunction == IRP_MJ_READ) 
		{
			/* read encrypted part */
			if (s1 != 0) 
			{
				status = io_device_rw_block(
					hook->orig_dev, IRP_MJ_READ, p1, s1, o1 + SECTOR_SIZE, irp_sp->Flags
					);

				dc_fast_decrypt(p1, p1, s1, o1, &hook->dsk_key);

				if (NT_SUCCESS(status) == FALSE) {
					break;
				}
			}

			/* read temporary part */
			if (s2 != 0) {				
				autocpy(p2, hook->tmp_buff + ENC_BLOCK_SIZE, SECTOR_SIZE); 
				status = STATUS_SUCCESS;
			}

			/* read unencrypted part */
			if (s3 != 0)
			{
				status = io_device_rw_block(
					hook->orig_dev, IRP_MJ_READ, p3, s3, o3, irp_sp->Flags
					);
			}
		} else
		{
			/* write encrypted part */
			if (s1 != 0) 
			{
				if ( (encb = fast_alloc(s1)) == NULL ) {
					status = STATUS_INSUFFICIENT_RESOURCES; break;
				}

				dc_fast_encrypt(p1, encb, s1, o1, &hook->dsk_key);

				status = io_device_rw_block(
					hook->orig_dev, IRP_MJ_WRITE, encb, s1, o1 + SECTOR_SIZE, irp_sp->Flags
					);

				fast_free(encb);

				if (NT_SUCCESS(status) == FALSE) {
					break;
				}
			}

			/* write temporary part */
			if (s2 != 0) 
			{
				DbgMsg(
					"write tmp buffer, CRC %0.8x\n", crc32(p2, SECTOR_SIZE)
					);

				status = io_device_rw_block(
					hook->orig_dev, IRP_MJ_WRITE, p2, SECTOR_SIZE, hook->tmp_save_off, irp_sp->Flags
					);

				autocpy(hook->tmp_buff + ENC_BLOCK_SIZE, p2, SECTOR_SIZE);

				if (NT_SUCCESS(status) == FALSE) {
					break;
				}
			}

			/* write unencrypted part */
			if (s3 != 0)
			{
				status = io_device_rw_block(
					hook->orig_dev, IRP_MJ_WRITE, p3, s3, o3, irp_sp->Flags
					);
			}
		}
	} while (0);
i_exit:;
	if (NT_SUCCESS(status) != FALSE) {
		dc_complete_irp(irp, status, length);
	} else {
		dc_complete_irp(irp, status, 0);
	}
}

void dc_device_rw_skip_bads(
	   dev_hook *hook, u32 function, void *buff, u32 size, u64 offset
	   )
{
	u32 block;
	int resl;

	while (block = min(size, 4096))
	{
		resl = dc_device_rw(
			     hook, function, buff, block, offset
				 );

		if ( (resl == ST_MEDIA_CHANGED) || (resl == ST_NO_MEDIA) ) {
			break;
		}

		buff  = p8(buff) + block;
		size -= block; offset += block;
	}
}

static int dc_enc_update(dev_hook *hook)
{
	u8 *buff = hook->tmp_buff;
	u32 size = (u32)(min(hook->use_size - hook->tmp_size, ENC_BLOCK_SIZE));
	u64 offs = hook->tmp_size + SECTOR_SIZE;
	int r_resl, w_resl;

	if (size == 0) 
	{
		/* wipe reserved sectors */
		dc_wipe_process(
			&hook->wp_ctx, hook->dsk_size - DC_RESERVED_SIZE, DC_RESERVED_SIZE
			);

		/* random fill reserved sectors */
		dc_random_sectors(
			hook, hook->dsk_size - DC_RESERVED_SIZE, DC_RESERVED_SIZE
			);

		return ST_FINISHED;
	}

	/* copy reserved sector from previous block */
	autocpy(buff, buff + ENC_BLOCK_SIZE, SECTOR_SIZE);

	do
	{
		r_resl = dc_device_rw(
			hook, IRP_MJ_READ, buff + SECTOR_SIZE, size, offs
			);

		if (r_resl == ST_RW_ERR)
		{
			dc_device_rw_skip_bads(
				hook, IRP_MJ_READ, buff + SECTOR_SIZE, size, offs
				);
		} else if (r_resl != ST_OK) {
			break;
		}

		dc_fast_encrypt(buff, buff, size, hook->tmp_size, &hook->dsk_key);

		dc_wipe_process(&hook->wp_ctx, offs, size);

		w_resl = dc_device_rw(
			hook, IRP_MJ_WRITE, buff, size, offs
			);

		if (w_resl == ST_RW_ERR) {
			dc_device_rw_skip_bads(hook, IRP_MJ_WRITE, buff, size, offs);
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
	u32 size = (u32)(min(hook->use_size - hook->tmp_size, ENC_BLOCK_SIZE));
	u64 offs = hook->tmp_size + SECTOR_SIZE;
	int r_resl, w_resl;

	if (size == 0) 
	{
		DbgMsg("re-encryption finished\n");

		/* wipe reserved sectors */
		dc_wipe_process(
			&hook->wp_ctx, hook->dsk_size - DC_RESERVED_SIZE, DC_RESERVED_SIZE
			);

		/* random fill reserved sectors */
		dc_random_sectors(
			hook, hook->dsk_size - DC_RESERVED_SIZE, DC_RESERVED_SIZE
			);

		return ST_FINISHED;
	}

	do
	{
		r_resl = dc_device_rw(
			hook, IRP_MJ_READ, buff, size, offs
			);

		if (r_resl == ST_RW_ERR) {
			dc_device_rw_skip_bads(hook, IRP_MJ_READ, buff, size, offs);
		} else if (r_resl != ST_OK) {
			break;
		}

		/* wipe old data */
		dc_wipe_process(&hook->wp_ctx, offs, size);

		/* re-encrypt data */
		dc_fast_decrypt(buff, buff, size, hook->tmp_size, hook->tmp_key);
		dc_fast_encrypt(buff, buff, size, hook->tmp_size, &hook->dsk_key);

		w_resl = dc_device_rw(
			hook, IRP_MJ_WRITE, buff, size, offs
			);

		if (w_resl == ST_RW_ERR) {
			dc_device_rw_skip_bads(hook, IRP_MJ_WRITE, buff, size, offs);
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
	u8 *buff = hook->tmp_buff;
	u32 size = (u32)(min(hook->tmp_size, ENC_BLOCK_SIZE));
	u64 offs = hook->tmp_size - size + SECTOR_SIZE;
	int r_resl, w_resl;
	
	if (size == 0) 
	{
		u8 *z_data;
		u32 z_size;

		/* zero all DC reserved sectors */
		if (hook->vf_version > 2) {
			z_size = HEADER_SIZE + DC_RESERVED_SIZE;
		} else {
			z_size = HEADER_SIZE;
		}

		if (z_data = fast_alloc(z_size))
		{
			zeromem(z_data, z_size);

			dc_device_rw(
				hook, IRP_MJ_WRITE, z_data, z_size, hook->dsk_size - z_size);

			fast_free(z_data);
		}

		w_resl = dc_device_rw(
			hook, IRP_MJ_WRITE, buff + ENC_BLOCK_SIZE, SECTOR_SIZE, 0);
		
		if (w_resl == ST_OK) {
			return ST_FINISHED;
		} else {
			return w_resl;
		}
	}

	do
	{
		r_resl = dc_device_rw(
			hook, IRP_MJ_READ, buff, size, offs
			);
		
		if (r_resl == ST_RW_ERR) {
			dc_device_rw_skip_bads(hook, IRP_MJ_READ, buff, size, offs);
		} else if (r_resl != ST_OK) {
			break;
		}

		if (size != ENC_BLOCK_SIZE) {
			autocpy(buff + size, buff + ENC_BLOCK_SIZE, SECTOR_SIZE);
		}
		
		dc_fast_decrypt(
			buff, buff, size, (offs - SECTOR_SIZE), &hook->dsk_key
			);

		w_resl = dc_device_rw(
			hook, IRP_MJ_WRITE, buff + SECTOR_SIZE, size, offs
			);

		if (w_resl == ST_RW_ERR) 
		{
			dc_device_rw_skip_bads(
				hook, IRP_MJ_WRITE, buff + SECTOR_SIZE, size, offs
				);
			r_resl = w_resl;
		}

		autocpy(buff + ENC_BLOCK_SIZE, buff, SECTOR_SIZE);
	} while (0);

	if ( (r_resl == ST_OK) || (r_resl == ST_RW_ERR) ) {
		hook->tmp_size -= size;
	}

	return r_resl;
}

static void dc_save_enc_state(dev_hook *hook, int finish)
{
	dc_header enc_header;
	
	DbgMsg("dc_save_enc_state\n");

	if (finish != 0)
	{
		hook->tmp_header.sign         = DC_TRUE_SIGN;
		hook->tmp_header.flags       &= ~(VF_TMP_MODE | VF_REENCRYPT);
		hook->tmp_header.tmp_size     = 0;
		hook->tmp_header.tmp_save_off = 0;
		hook->tmp_header.tmp_wp_mode  = 0;

		if (hook->vf_version > 2)
		{
			/* write backup header to backup sector */
			dc_write_header(
				hook, &hook->tmp_header, DC_BACKUP_OFFSET(hook), hook->tmp_pass
				);
		}
	} else 
	{
		hook->tmp_header.flags       |= VF_TMP_MODE;
		hook->tmp_header.tmp_size     = hook->tmp_size;
		hook->tmp_header.tmp_save_off = hook->tmp_save_off;
		hook->tmp_header.tmp_wp_mode  = hook->crypt.wp_mode;

		if (hook->flags & F_REENCRYPT)
		{
			hook->tmp_header.flags |= VF_REENCRYPT;
		} else 
		{
			if (hook->vf_version > 2)
			{
				/* write temporary buffer to last volume sector */
				dc_device_rw(
					hook, IRP_MJ_WRITE, hook->tmp_buff + ENC_BLOCK_SIZE,
					SECTOR_SIZE, hook->tmp_save_off
					);
			}
		}
	}

	/* encrypt volume header */
	autocpy(&enc_header, &hook->tmp_header, sizeof(dc_header));

	dc_cipher_encrypt(
		pv(&enc_header.sign), pv(&enc_header.sign),
		HEADER_ENCRYPTEDDATASIZE, 1, hook->hdr_key
		);

	/* write volume header */
	dc_device_rw(
		hook, IRP_MJ_WRITE, &enc_header, sizeof(dc_header), 0
		);

	/* prevent leaks */
	zeroauto(&enc_header, sizeof(dc_header));
}

typedef struct _sync_context {
	int finish;
	int saved;
	int winit;

} sync_context;

static int dc_init_sync_mode(dev_hook *hook, sync_context *ctx)
{
	dc_key    *tmp_key;
	dc_header  header;
	crypt_info crypt;
	u8        *buff = hook->tmp_buff;
	int        resl;
	
	do
	{
		if (hook->flags & F_REMOVABLE)
		{
			/* save media change count */
			if (io_verify_hook_device(hook) == ST_NO_MEDIA) {
				resl = ST_NO_MEDIA; break;
			}
		}		

		switch (lock_xchg(&hook->sync_init_type, 0))
		{
			case S_INIT_ENC:
				{
					/* initialize encryption process */
					
					/* save old sector */
					resl = dc_device_rw(
						hook, IRP_MJ_READ, buff + ENC_BLOCK_SIZE, SECTOR_SIZE, 0
						);

					if (resl == ST_OK)
					{
						/* wipe old sector */
						dc_wipe_process(&hook->wp_ctx, 0, SECTOR_SIZE);
						/* save initial state */
						dc_save_enc_state(hook, 0);
					}
				}
			break;
			case S_INIT_DEC:
				{
					/* zero temporary buffer */
					zeroauto(buff + ENC_BLOCK_SIZE, SECTOR_SIZE);
					resl = ST_OK;
				}
			break;
			case S_CONTINUE_ENC:
				{
					resl = dc_device_rw(
						hook, IRP_MJ_READ, buff + ENC_BLOCK_SIZE, SECTOR_SIZE, hook->dsk_size - SECTOR_SIZE
						);

					DbgMsg(
						"tmp buffer readed from %u, CRC %0.8x\n", 
						(u32)((hook->dsk_size - SECTOR_SIZE) / SECTOR_SIZE), 
						crc32(buff + ENC_BLOCK_SIZE, SECTOR_SIZE)
						);
				}
			break;
			case S_INIT_RE_ENC:
				{
					DbgMsg("S_INIT_RE_ENC\n");

					if ( (tmp_key = mem_alloc(sizeof(dc_key))) == NULL ) {
						resl = ST_NOMEM; break;
					}

					/* save old header to last volume sector */
					resl = dc_device_rw(
						hook, IRP_MJ_WRITE, &hook->old_header, sizeof(dc_header), hook->tmp_save_off
						);

					if (resl == ST_OK)
					{
						/* swap keys */
						autocpy(tmp_key, &hook->dsk_key, sizeof(dc_key));
						autocpy(&hook->dsk_key, hook->tmp_key, sizeof(dc_key));
						autocpy(hook->tmp_key, tmp_key, sizeof(dc_key));
						/* re-initialize keys */
						dc_cipher_reinit(hook->tmp_key);
						dc_cipher_reinit(&hook->dsk_key);

						/* set re-encryption flag */
						hook->flags |= F_REENCRYPT;
						/* wipe old sector */
						dc_wipe_process(&hook->wp_ctx, 0, SECTOR_SIZE);
						/* save initial state */
						dc_save_enc_state(hook, 0);
					}

					/* prevent leaks */
					zeroauto(tmp_key, sizeof(dc_key));
					mem_free(tmp_key);
				}
			break;
			case S_CONTINUE_RE_ENC:
				{
					DbgMsg("S_CONTINUE_RE_ENC\n");

					/* read old header from last volume sector */
					resl = dc_device_rw(
						hook, IRP_MJ_READ, &header, sizeof(dc_header), hook->tmp_save_off
						);

					if (resl == ST_OK) 
					{
						/* decrypt old header */
						tmp_key = dc_fast_dec_header(&header, &crypt, hook->tmp_pass);

						if (tmp_key != NULL) 
						{
							/* initialize old volume key */
							dc_cipher_init(
								tmp_key, crypt.cipher_id, crypt.mode_id, header.key_data
								);

							hook->tmp_key = tmp_key;
							/* set re-encryption flag */
							hook->flags |= F_REENCRYPT;
						} else resl = ST_ERROR;
					}

					/* prevent leaks */
					zeroauto(&header, sizeof(dc_header));
				}
			break;
		}
	} while (0);

	return resl;
}

static int dc_process_sync_packet(
		     dev_hook *hook, sync_packet *packet, sync_context *ctx
			 )
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
							&hook->wp_ctx, hook, ENC_BLOCK_SIZE, new_wp
							);

						if (resl == ST_OK) 
						{
							hook->crypt.wp_mode = new_wp;
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
						dc_process_unmount(hook, UM_NOFSCTL | UM_NOSYNC);
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
		case S_OP_SET_SHRINK:
			{
				dc_ioctl *s_sh = packet->param;

				/* set shrink fields in volume header */
				hook->tmp_header.flags     |= VF_SHRINK_PENDING;
				hook->tmp_header.shrink_off = s_sh->shrink_off;
				hook->tmp_header.shrink_val = s_sh->shrink_val;
				/* set hook flag */
				hook->flags |= F_SHRINK_PENDING;
				/* save encryption state */
				if (ctx->finish == 0) {
					dc_save_enc_state(hook, 0); ctx->saved = 1;
				}
				resl = ST_OK;
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
	
	DbgMsg("sync thread started\n");

	lock_inc(&dc_data_lock);

	dc_reference_hook(hook);

	/* initialize sync mode data */
	InitializeListHead(&hook->sync_req_queue);
	InitializeListHead(&hook->sync_irp_queue);
	KeInitializeSpinLock(&hook->sync_req_lock);

	KeInitializeEvent(
		&hook->sync_req_event, SynchronizationEvent, FALSE
		);

	/* enable synchronous irp processing */
	hook->flags |= (F_ENABLED | F_SYNC);
	
	zeroauto(&sctx, sizeof(sctx));
	init_t = hook->sync_init_type;

	/* allocate resources */
	if (buff = mem_alloc(ENC_BLOCK_SIZE + SECTOR_SIZE))
	{
		hook->tmp_buff = buff;

		resl = dc_wipe_init(
			&hook->wp_ctx, hook, ENC_BLOCK_SIZE, hook->crypt.wp_mode
			);

		if (resl == ST_OK) 
		{
			sctx.winit = 1;
			/* init sync mode */
			resl = dc_init_sync_mode(hook, &sctx);
		}			 
	} else {
		resl = ST_NOMEM;
	}

	/* save init status */
	hook->sync_init_status = resl;

	if (resl == ST_OK) 
	{
		/* signal of init finished */
		KeSetEvent(
			&hook->sync_enter_event, IO_NO_INCREMENT, FALSE
			);		
	} else 
	{
		if ( (init_t == S_INIT_ENC) || (init_t == S_CONTINUE_ENC) ) {
			hook->flags &= ~(F_ENABLED | F_SYNC);
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
			while (entry = ExInterlockedRemoveHeadList(&hook->sync_irp_queue, &hook->sync_req_lock))
			{
				dc_sync_irp(
					hook, CONTAINING_RECORD(entry, IRP, Tail.Overlay.ListEntry)
					);
			}

			if (entry = ExInterlockedRemoveHeadList(&hook->sync_req_queue, &hook->sync_req_lock))
			{
				packet = CONTAINING_RECORD(entry, sync_packet, entry_list);

				/* process packet */
				resl = dc_process_sync_packet(hook, packet, &sctx);

				/* disable synchronous irp processing */
				if (resl == ST_FINISHED) {					
					hook->flags &= ~(F_SYNC | F_REENCRYPT);
				}

				/* signal of packet completion */
				packet->status = resl;
				
				KeSetEvent(
					&packet->sync_event, IO_NO_INCREMENT, FALSE
					);

				if ( (resl == ST_MEDIA_CHANGED) || (resl == ST_NO_MEDIA) ) {
					dc_process_unmount(hook, UM_NOFSCTL | UM_NOSYNC);
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
			hook->hook_dev, CONTAINING_RECORD(entry, IRP, Tail.Overlay.ListEntry)
			);
	}

	/* free resources */
	if (sctx.winit != 0) {
		dc_wipe_free(&hook->wp_ctx);
	}

	if (buff != NULL) {
		mem_free(buff);
	}

	/* prevent leaks */
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

	zeroauto(&hook->tmp_header, sizeof(dc_header));
	zeroauto(&hook->old_header, sizeof(dc_header));
	zeroauto(&hook->tmp_pass, sizeof(hook->tmp_pass));

	/* report init finished if initialization fails */
	if (resl != ST_FINISHED)
	{
		KeSetEvent(
			&hook->sync_enter_event, IO_NO_INCREMENT, FALSE
			);	
	}

	dc_deref_hook(hook);

	lock_dec(&dc_data_lock);

	DbgMsg("exit from sync thread\n");

	PsTerminateSystemThread(STATUS_SUCCESS);
}

int dc_enable_sync_mode(dev_hook *hook)
{
	int resl;

	lock_inc(&dc_data_lock);

	do
	{
		if (hook->flags & F_SYNC) {
			resl = ST_ERROR; break;
		}

		KeInitializeEvent(
			&hook->sync_enter_event, NotificationEvent, FALSE
			);		

		resl = start_system_thread(
			dc_sync_op_routine, hook, NULL
			);

		if (resl == ST_OK) {
			wait_object_infinity(&hook->sync_enter_event);
			resl = hook->sync_init_status;						
		}
	} while (0);

	lock_dec(&dc_data_lock);

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

		if ( (packet = mem_alloc(sizeof(sync_packet))) == NULL ) {
			resl = ST_NOMEM; break;
		}

		KeInitializeEvent(
			&packet->sync_event, NotificationEvent, FALSE
			);

		packet->type  = type;
		packet->param = param;		

		ExInterlockedInsertTailList(
			&hook->sync_req_queue, &packet->entry_list, &hook->sync_req_lock
			);

		KeSetEvent(
			&hook->sync_req_event, IO_NO_INCREMENT, FALSE
			);

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
			if (hook->flags & F_SYNC) 
			{
				dc_send_sync_packet(
					hook->dev_name, S_OP_SYNC, 0
					);
			}
		} while (hook = dc_next_hook(hook));
	}
}

int dc_encrypt_start(wchar_t *dev_name, char *password, crypt_info *crypt)
{
	dc_header  header;
	dev_hook  *hook;
	dc_key    *hdr_key = NULL;
	int        resl;
				
	DbgMsg("dc_encrypt_start\n");

	lock_inc(&dc_data_lock);

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

		/* create volume header */
		zeroauto(&header, sizeof(header));

		rnd_get_bytes(pv(header.salt),     PKCS5_SALT_SIZE);
		rnd_get_bytes(pv(&header.disk_id), sizeof(u32));
		rnd_get_bytes(pv(header.key_data), DISKKEY_SIZE);

		/* make volume temporary incompatible with TC to 
		   prevent data corruption when mounting 
		*/
		header.sign        = DC_DTMP_SIGN;
		header.version     = BE16(TC_VOLUME_HEADER_VERSION);
		header.req_ver     = BE16(TC_VOL_REQ_PROG_VERSION);
		header.key_crc     = BE32(crc32(header.key_data, DISKKEY_SIZE));
		header.vol_size    = hook->dsk_size - HEADER_SIZE - DC_RESERVED_SIZE;
		header.enc_size    = header.vol_size;
		
		/* initialize volume key */
		dc_cipher_init(
			&hook->dsk_key, crypt->cipher_id, crypt->mode_id, header.key_data
			);

		/* initialize header key */
		if ( (hdr_key = dc_init_hdr_key(crypt, &header, password)) == NULL ) {
			resl = ST_NOMEM; break;
		}

		hook->crypt          = crypt[0];
		hook->tmp_save_off   = hook->dsk_size - SECTOR_SIZE;
		hook->use_size       = hook->dsk_size - HEADER_SIZE - DC_RESERVED_SIZE;
		hook->tmp_size       = 0;
		hook->vf_version     = TC_VOLUME_HEADER_VERSION;
		hook->sync_init_type = S_INIT_ENC;
		hook->hdr_key        = hdr_key;
		hook->disk_id        = header.disk_id;
		
		/* copy header to temp buffer */
		autocpy(&hook->tmp_header, &header, sizeof(dc_header));	
		/* copy volume password */
		strcpy(hook->tmp_pass, password);
		
		if ( (resl = dc_enable_sync_mode(hook)) != ST_OK ) 
		{
			zeroauto(&hook->tmp_header, sizeof(dc_header));	
			zeroauto(&hook->tmp_pass, sizeof(hook->tmp_pass));
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

	zeroauto(&header, sizeof(dc_header));

	if (hook != NULL) {
		KeReleaseMutex(&hook->busy_lock, FALSE);
		dc_deref_hook(hook);
	}

	lock_dec(&dc_data_lock);

	return resl;
}

int dc_reencrypt_start(wchar_t *dev_name, char *password, crypt_info *crypt)
{
	dc_header  header;
	crypt_info o_crypt;
	dev_hook  *hook;
	dc_key    *hdr_key = NULL;
	dc_key    *dsk_key = NULL;
	int        resl;

	DbgMsg("dc_reencrypt_start\n");

	lock_inc(&dc_data_lock);

	do
	{
		if ( (hook = dc_find_hook(dev_name)) == NULL ) {
			resl = ST_NF_DEVICE; break;
		}

		wait_object_infinity(&hook->busy_lock);

		if ( !(hook->flags & F_ENABLED) || (hook->flags & (F_SYNC | F_FORMATTING)) ) {
			resl = ST_ERROR; break;
		}

		/* verify encryption info */
		if ( (crypt->cipher_id >= CF_CIPHERS_NUM) || (crypt->mode_id >= EM_NUM) ||
			 (crypt->prf_id >= PRF_NUM) || (crypt->wp_mode >= WP_NUM) ) 
		{
			resl = ST_ERROR; break;
		}

		if (hook->vf_version != TC_VOLUME_HEADER_VERSION) {
			resl = ST_INV_VOL_VER; break;
		}

		/* allocate new volume key */
		if ( (dsk_key = mem_alloc(sizeof(dc_key))) == NULL ) {
			resl = ST_NOMEM; break;
		}

		/* read volume header */
		resl = dc_device_rw(
			hook, IRP_MJ_READ, &header, sizeof(header), 0
			);

		if (resl != ST_OK) {
			break;
		}

		/* copy header to hook */
		autocpy(&hook->old_header, &header, sizeof(dc_header));

		/* decrypt volume header */
		hdr_key = dc_dec_known_header(&header, &hook->crypt, password);

		if (hdr_key == NULL) {
			resl = ST_PASS_ERR;	break;
		}

		/* generate new salt and volume key */
		rnd_get_bytes(pv(header.salt),     PKCS5_SALT_SIZE);		
		rnd_get_bytes(pv(header.key_data), DISKKEY_SIZE);

		/* change other fields */
		header.sign    = DC_DTMP_SIGN;
		header.key_crc = BE32(crc32(header.key_data, DISKKEY_SIZE));

		/* initialize volume key */
		dc_cipher_init(
			dsk_key, crypt->cipher_id, crypt->mode_id, header.key_data
			);

		/* initialize header key */
		if ( (hdr_key = dc_init_hdr_key(crypt, &header, password)) == NULL ) {
			resl = ST_NOMEM; break;
		}

		/* save old encryption info */
		o_crypt = hook->crypt;
		/* set new encryption info */		
		hook->crypt          = crypt[0];
		hook->tmp_save_off   = hook->dsk_size - SECTOR_SIZE;
		hook->tmp_size       = 0;
		hook->sync_init_type = S_INIT_RE_ENC;
		hook->hdr_key        = hdr_key;
		hook->tmp_key        = dsk_key;
		
		/* copy header to temp buffer */
		autocpy(&hook->tmp_header, &header, sizeof(dc_header));	
		/* copy volume password */
		strcpy(hook->tmp_pass, password);
		
		if ( (resl = dc_enable_sync_mode(hook)) != ST_OK ) 
		{
			zeroauto(&hook->tmp_header, sizeof(dc_header));	
			zeroauto(&hook->old_header, sizeof(dc_header));
			zeroauto(&hook->tmp_pass, sizeof(hook->tmp_pass));
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

	zeroauto(&header, sizeof(dc_header));

	if (hook != NULL) {
		KeReleaseMutex(&hook->busy_lock, FALSE);
		dc_deref_hook(hook);
	}

	lock_dec(&dc_data_lock);

	return resl;
}

int dc_decrypt_start(wchar_t *dev_name, char *password)
{
	dc_header header;
	dev_hook *hook;
	dc_key   *hdr_key = NULL;
	int       resl;
				
	DbgMsg("dc_decrypt_start\n");

	lock_inc(&dc_data_lock);

	do
	{
		if ( (hook = dc_find_hook(dev_name)) == NULL ) {
			resl = ST_NF_DEVICE; break;
		}

		wait_object_infinity(&hook->busy_lock);
		
		if ( !(hook->flags & F_ENABLED) || (hook->flags & (F_SYNC | F_FORMATTING)) ) {
			resl = ST_ERROR; break;
		}

		/* read volume header */
		resl = dc_device_rw(
			hook, IRP_MJ_READ, &header, sizeof(header), 0
			);

		if (resl != ST_OK) {
			break;
		}

		/* decrypt volume header */
		hdr_key = dc_dec_known_header(
			&header, &hook->crypt, password
			);

		if (hdr_key == NULL) {
			resl = ST_PASS_ERR;	break;
		}

		header.sign         = DC_DTMP_SIGN;
		hook->crypt.wp_mode = WP_NONE;
		hook->tmp_save_off  = hook->dsk_size - SECTOR_SIZE;
		
		/* copy header to temp buffer */
		autocpy(&hook->tmp_header, &header, sizeof(dc_header));
		/* copy volume password */
		strcpy(hook->tmp_pass, password);

		hook->tmp_size       = hook->use_size;
		hook->sync_init_type = S_INIT_DEC;
		hook->hdr_key        = hdr_key;
		
		if ( (resl = dc_enable_sync_mode(hook)) != ST_OK ) 
		{
			zeroauto(&hook->tmp_header, sizeof(dc_header));
			zeroauto(&hook->tmp_pass, sizeof(hook->tmp_pass));
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

	zeroauto(&header, sizeof(dc_header));

	if (hook != NULL) {
		KeReleaseMutex(&hook->busy_lock, FALSE);
		dc_deref_hook(hook);
	}

	lock_dec(&dc_data_lock);

	return resl;
}