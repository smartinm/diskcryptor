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

typedef struct _sync_struct {
	KEVENT sync_event;
	int    status;

} sync_struct;

typedef struct _set_key_struct {
	dc_header *header;
	aes_key   *hdr_key;
	char      *password;

} set_key_struct;

#define ENC_BLOCK_SIZE  (1280 * 1024)


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
	buff   = MmGetSystemAddressForMdlSafe(irp->MdlAddress, HighPagePriority);

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
					hook, IRP_MJ_READ, p1, s1, o1 + SECTOR_SIZE, irp_sp->Flags
					);

				aes_lrw_decrypt(
					p1, p1, s1, lrw_index(o1), &hook->dsk_key
					);

				if (NT_SUCCESS(status) == FALSE) {
					break;
				}
			}

			/* read temporary part */
			if (s2 != 0) {				
				fastcpy(p2, hook->tmp_buff + ENC_BLOCK_SIZE, SECTOR_SIZE); 
				status = STATUS_SUCCESS;
			}

			/* read unencrypted part */
			if (s3 != 0)
			{
				status = io_device_rw_block(
					hook, IRP_MJ_READ, p3, s3, o3, irp_sp->Flags
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

				aes_lrw_encrypt(
					p1, encb, s1, lrw_index(o1), &hook->dsk_key
					);

				status = io_device_rw_block(
					hook, IRP_MJ_WRITE, encb, s1, o1 + SECTOR_SIZE, irp_sp->Flags
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
					hook, IRP_MJ_WRITE, p2, SECTOR_SIZE, hook->tmp_save_off, irp_sp->Flags
					);

				fastcpy(hook->tmp_buff + ENC_BLOCK_SIZE, p2, SECTOR_SIZE);

				if (NT_SUCCESS(status) == FALSE) {
					break;
				}
			}

			/* write unencrypted part */
			if (s3 != 0)
			{
				status = io_device_rw_block(
					hook, IRP_MJ_WRITE, p3, s3, o3, irp_sp->Flags
					);
			}
		}
	} while (0);

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
	u32 size = (u32)(min(hook->dsk_size - hook->tmp_size - SECTOR_SIZE, ENC_BLOCK_SIZE));
	u64 offs = hook->tmp_size + SECTOR_SIZE;
	int r_resl, w_resl;

	if (size == 0) {		
		return ST_FINISHED;
	}

	/* copy reserved sector from previous block */
	fastcpy(buff, buff + ENC_BLOCK_SIZE, SECTOR_SIZE);

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

		aes_lrw_encrypt(
			buff, buff, size, lrw_index(hook->tmp_size), &hook->dsk_key
			);

		dc_wipe_process(
			&hook->wp_ctx, offs, size
			);

		w_resl = dc_device_rw(
			hook, IRP_MJ_WRITE, buff, size, offs
			);

		if (w_resl == ST_RW_ERR) 
		{
			dc_device_rw_skip_bads(
				hook, IRP_MJ_WRITE, buff, size, offs
				);

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

		if (z_data = mem_alloc(z_size))
		{
			zeromem(z_data, z_size);

			dc_device_rw(
				hook, IRP_MJ_WRITE, z_data, z_size, hook->dsk_size - z_size
				);

			mem_free(z_data);
		}

		w_resl = dc_device_rw(
			hook, IRP_MJ_WRITE, buff + ENC_BLOCK_SIZE, SECTOR_SIZE, 0
			);
		
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
		
		if (r_resl == ST_RW_ERR)
		{
			dc_device_rw_skip_bads(
				hook, IRP_MJ_READ, buff, size, offs
				);
		} else if (r_resl != ST_OK) {
			break;
		}

		if (size != ENC_BLOCK_SIZE) {
			fastcpy(buff + size, buff + ENC_BLOCK_SIZE, SECTOR_SIZE);
		}
		
		aes_lrw_decrypt(
			buff, buff, size, lrw_index(offs - SECTOR_SIZE), &hook->dsk_key
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

		fastcpy(buff + ENC_BLOCK_SIZE, buff, SECTOR_SIZE);
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
		hook->tmp_header.flags       &= ~VF_TMP_MODE;
		hook->tmp_header.tmp_size     = 0;
		hook->tmp_header.tmp_save_off = 0;
		hook->tmp_header.tmp_wp_mode  = 0;

		if (hook->vf_version > 2)
		{
			/* write backup header to last volume sector */
			dc_write_header(
				hook, &hook->tmp_header, DC_BACKUP_OFFSET(hook), hook->tmp_pass
				);
		}
	} else 
	{
		hook->tmp_header.flags       |= VF_TMP_MODE;
		hook->tmp_header.tmp_size     = hook->tmp_size;
		hook->tmp_header.tmp_save_off = hook->tmp_save_off;
		hook->tmp_header.tmp_wp_mode  = hook->wp_mode;

		if (hook->vf_version > 2)
		{
			/* write temporary buffer to last volume sector */
			dc_device_rw(
				hook, IRP_MJ_WRITE, hook->tmp_buff + ENC_BLOCK_SIZE,
				SECTOR_SIZE, hook->tmp_save_off
				);

			DbgMsg("save tmp buffer to %u, CRC %0.8x\n",
				(u32)(hook->tmp_save_off / SECTOR_SIZE), crc32(hook->tmp_buff + ENC_BLOCK_SIZE, SECTOR_SIZE)
				);
		}
	}

	/* encrypt volume header */
	fastcpy(&enc_header, &hook->tmp_header, sizeof(dc_header));

	aes_lrw_encrypt(
		pv(&enc_header.sign), pv(&enc_header.sign),
		HEADER_ENCRYPTEDDATASIZE, 1, hook->hdr_key
		);

	/* write volume header */
	dc_device_rw(
		hook, IRP_MJ_WRITE, &enc_header, sizeof(dc_header), 0
		);

	/* prevent leaks */
	zeromem(&enc_header, sizeof(dc_header));	
}

static int dc_init_enc(dev_hook *hook)
{
	int resl;

	DbgMsg("dc_init_enc\n");

	/* save old sector */
	resl = dc_device_rw(
		hook, IRP_MJ_READ, hook->tmp_buff + ENC_BLOCK_SIZE, SECTOR_SIZE, 0
		);

	if (resl == ST_OK)	
	{
		/* wipe old sector */
		dc_wipe_process(
			&hook->wp_ctx, 0, SECTOR_SIZE
			);

		dc_save_enc_state(hook, 0);
	} else {
		DbgMsg("dc_init_enc error %d\n", resl);
	}

	return resl;
}


static void dc_sync_op_routine(dev_hook *hook)
{
	sync_packet *packet;
	PLIST_ENTRY  entry;
	u8          *buff;
	int          resl, init_type;
	int          winit, finish, saved;

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
	
	buff = NULL; winit = 0; finish = 0; saved = 0;
	init_type = lock_xchg(&hook->sync_init_type, S_INIT_NONE);
	do
	{
		if (hook->flags & F_REMOVABLE)
		{
			/* save media change count */
			if (io_verify_hook_device(hook) == ST_NO_MEDIA) {
				resl = ST_NO_MEDIA; break;
			}
		}

		/* allocate resources */
		if ( (buff = mem_alloc(ENC_BLOCK_SIZE + SECTOR_SIZE)) == NULL ) {
			resl = ST_NOMEM; break;
		}

		resl = dc_wipe_init(
			&hook->wp_ctx, hook, ENC_BLOCK_SIZE, hook->wp_mode
			);

		if (resl != ST_OK) {
			break;
		} else {
			winit = 1;
		}

		hook->tmp_buff = buff;	

		if (init_type == S_INIT_ENC) 
		{
			/* initialize encryption process */
			if ( (resl = dc_init_enc(hook)) != ST_OK ) {				
				break;
			}
		}

		if (init_type == S_INIT_DEC) {
			zeromem(buff + ENC_BLOCK_SIZE, SECTOR_SIZE);
		}

		if (init_type == S_CONTINUE_ENC)
		{
			DbgMsg("S_CONTINUE_ENC\n");

			resl = dc_device_rw(
				hook, IRP_MJ_READ, buff + ENC_BLOCK_SIZE, SECTOR_SIZE, hook->dsk_size - SECTOR_SIZE
				);

			if (resl != ST_OK) {			
				break;
			}

			DbgMsg(
				"tmp buffer readed from %u, CRC %0.8x\n", 
				(u32)((hook->dsk_size - SECTOR_SIZE) / SECTOR_SIZE), 
				crc32(buff + ENC_BLOCK_SIZE, SECTOR_SIZE)
				);
		}
	} while (0);

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
		if ( (init_type == S_INIT_ENC) || (init_type == S_CONTINUE_ENC) ) {
			hook->flags &= ~(F_ENABLED | F_SYNC);
		} else {
			hook->flags &= ~F_SYNC;
		}
		goto cleanup;
	}

	do
	{
		wait_object_infinity(
			&hook->sync_req_event
			);

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

				switch (packet->type)
				{
					case S_OP_ENC_BLOCK:
						{
							int new_wp = (int)(packet->param);

							if (finish == 0)
							{
								if (new_wp != hook->wp_mode)
								{
									dc_wipe_free(&hook->wp_ctx);

									resl = dc_wipe_init(
										&hook->wp_ctx, hook, ENC_BLOCK_SIZE, new_wp
										);

									if (resl == ST_OK) 
									{
										hook->wp_mode = new_wp;
										dc_save_enc_state(hook, 0);
									} else 
									{
										dc_wipe_init(
											&hook->wp_ctx, hook, ENC_BLOCK_SIZE, WP_NONE
											);
									}
								}

								if ( (resl = dc_enc_update(hook)) == ST_FINISHED) {
									dc_save_enc_state(hook, 1); finish = 1;
								} else {
									saved = 0;
								}
							} else {
								resl = ST_FINISHED;
							}
						}
					break;
					case S_OP_DEC_BLOCK:
						{
							if (finish == 0)
							{
								if ( (resl = dc_dec_update(hook)) == ST_FINISHED) {
									dc_process_unmount(hook, UM_NOFSCTL | UM_NOSYNC);
									finish = 1;
								} else {
									saved = 0;
								}
							} else {
								resl = ST_FINISHED;
							}
						}
					break;
					case S_OP_SYNC:
						{
							if ( (finish == 0) && (saved == 0) ) {
								dc_save_enc_state(hook, 0); saved = 1;
							}
							resl = ST_OK;
						}
					break;
					case S_OP_FINALIZE:
						{
							if ( (finish == 0) && (saved == 0) ) {
								dc_save_enc_state(hook, 0); finish = 1;
							}
							resl = ST_FINISHED;						
						}
					break;
					case S_OP_SET_KEY:
						{
							set_key_struct *skey = packet->param;

							/* copy new volume header */
							fastcpy(&hook->tmp_header, skey->header, sizeof(dc_header));
							/* copy new password */
							strcpy(hook->tmp_pass, skey->password);
							/* copy new header key */
							fastcpy(hook->hdr_key, skey->hdr_key, sizeof(aes_key));
							/* save encryption state */
							if (finish == 0) {
								dc_save_enc_state(hook, 0); saved = 1;
							}
							resl = ST_OK;
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
							if (finish == 0) {
								dc_save_enc_state(hook, 0); saved = 1;
							}
							resl = ST_OK;
						}
					break;
				}

				/* disable synchronous irp processing */
				if (resl == ST_FINISHED) {					
					hook->flags &= ~F_SYNC;
				}

				packet->on_complete(
					hook, packet->cb_param, resl
					);

				if ( (resl == ST_MEDIA_CHANGED) || (resl == ST_NO_MEDIA) ) {
					dc_process_unmount(hook, UM_NOFSCTL | UM_NOSYNC);
					resl = ST_FINISHED; finish = 1;
				}

				mem_free(packet);
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
	if (winit != 0) {
		dc_wipe_free(&hook->wp_ctx);
	}

	if (buff != NULL) {
		mem_free(buff);
	}

	/* prevent leaks */
	if (hook->hdr_key != NULL) 
	{
		zeromem(hook->hdr_key, sizeof(aes_key));
		mem_free(hook->hdr_key);
		hook->hdr_key = NULL;
	}

	zeromem(&hook->tmp_header, sizeof(dc_header));
	zeromem(&hook->tmp_pass, sizeof(hook->tmp_pass));

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



int dc_send_async_packet(
	  wchar_t *dev_name, u32 type, void *param, s_callback on_complete, void *cb_param
	  )
{
	dev_hook    *hook;
	sync_packet *packet;
	int          resl;
	
	do
	{
		if ( (hook = dc_find_hook(dev_name)) == NULL ) {
			resl = ST_NF_DEVICE; break;
		}

		if ( !(hook->flags & F_SYNC) ) {			
			resl = ST_ERROR; break;
		}

		if ( (packet = mem_alloc(sizeof(sync_packet))) == NULL ) {
			resl = ST_NOMEM; break;
		}

		packet->type        = type;
		packet->param       = param;
		packet->on_complete = on_complete;
		packet->cb_param    = cb_param;

		ExInterlockedInsertTailList(
			&hook->sync_req_queue, &packet->entry_list, &hook->sync_req_lock
			);

		KeSetEvent(
			&hook->sync_req_event, IO_NO_INCREMENT, FALSE
			);
		resl = ST_OK;
	} while (0);

	if (hook != NULL) {
		dc_deref_hook(hook);
	}

	return resl;
}

static void dc_sync_complete(
			  dev_hook *hook, sync_struct *sync, int resl
			  )
{
	sync->status = resl;

	KeSetEvent(
		&sync->sync_event, IO_NO_INCREMENT, FALSE
		);
}

int dc_send_sync_packet(wchar_t *dev_name, u32 type, void *param)
{
	sync_struct sync;
	int         resl;

	KeInitializeEvent(
		&sync.sync_event, NotificationEvent, FALSE
		);

	resl = dc_send_async_packet(
		dev_name, type, param, dc_sync_complete, &sync
		);

	if (resl == ST_OK) {
		wait_object_infinity(&sync.sync_event);
		resl = sync.status;
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

int dc_encrypt_start(wchar_t *dev_name, char *password, int wp_mode)
{
	dc_header     header;
	dev_hook     *hook;
	aes_key      *hdr_key = NULL;
	int           resl, lock;
				
	DbgMsg("dc_encrypt_start\n");

	lock_inc(&dc_data_lock);

	do
	{
		if ( (hook = dc_find_hook(dev_name)) == NULL ) {
			resl = ST_NF_DEVICE; break;
		}

		if (hook_lock_acquire(hook, &lock) == 0) {
			resl = ST_DEVICE_BUSY; break;
		}

		if (hook->flags & F_ENABLED) {			
			resl = ST_ERROR; break;
		}

		/* create volume header */
		zeromem(&header, sizeof(header));

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
		aes_lrw_init_key(
			&hook->dsk_key, header.key_data + DISK_IV_SIZE, header.key_data
			);

		/* initialize header key */
		if ( (hdr_key = dc_init_hdr_key(&header, password)) == NULL ) {
			resl = ST_NOMEM; break;
		}

		hook->wp_mode        = wp_mode;
		hook->tmp_save_off   = hook->dsk_size - SECTOR_SIZE;
		hook->use_size       = hook->dsk_size - HEADER_SIZE - DC_RESERVED_SIZE;
		hook->tmp_size       = 0;
		hook->vf_version     = TC_VOLUME_HEADER_VERSION;
		hook->sync_init_type = S_INIT_ENC;
		hook->hdr_key        = hdr_key;
		hook->disk_id        = header.disk_id;
		
		/* copy header to temp buffer */
		fastcpy(&hook->tmp_header, &header, sizeof(dc_header));	
		/* copy volume password */
		strcpy(hook->tmp_pass, password);
		
		if ( (resl = dc_enable_sync_mode(hook)) != ST_OK ) 
		{
			zeromem(&hook->tmp_header, sizeof(dc_header));	
			zeromem(&hook->tmp_pass, hook->tmp_pass);	
			hdr_key = hook->hdr_key;
		} else {
			hdr_key = NULL;
		}
	} while (0);

	/* prevent leaks */
	if (hdr_key != NULL) {
		zeromem(hdr_key, sizeof(aes_key));
		mem_free(hdr_key);
	}

	zeromem(&header, sizeof(dc_header));

	if (hook != NULL) {
		hook_lock_release(hook, lock);
		dc_deref_hook(hook);
	}

	lock_dec(&dc_data_lock);

	return resl;
}

int dc_decrypt_start(wchar_t *dev_name, char *password)
{
	dc_header header;
	dev_hook *hook;
	aes_key  *hdr_key = NULL;
	int       resl, lock;
				
	DbgMsg("dc_decrypt_start\n");

	lock_inc(&dc_data_lock);

	do
	{
		if ( (hook = dc_find_hook(dev_name)) == NULL ) {
			resl = ST_NF_DEVICE; break;
		}

		if (hook_lock_acquire(hook, &lock) == 0) {
			resl = ST_DEVICE_BUSY; break;
		}

		if ( !(hook->flags & F_ENABLED) || (hook->flags & F_SYNC) ) {
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
		if ( (hdr_key = dc_decrypt_header(&header, password)) == NULL ) {
			resl = ST_PASS_ERR;	break;
		}

		header.sign        = DC_DTMP_SIGN;
		hook->wp_mode      = WP_NONE;
		hook->tmp_save_off = hook->dsk_size - SECTOR_SIZE;
		
		/* copy header to temp buffer */
		fastcpy(&hook->tmp_header, &header, sizeof(dc_header));
		/* copy volume password */
		strcpy(hook->tmp_pass, password);

		hook->tmp_size       = hook->use_size;
		hook->sync_init_type = S_INIT_DEC;
		hook->hdr_key        = hdr_key;
		
		if ( (resl = dc_enable_sync_mode(hook)) != ST_OK ) 
		{
			zeromem(&hook->tmp_header, sizeof(dc_header));
			zeromem(&hook->tmp_pass, sizeof(hook->tmp_pass));
			hdr_key = hook->hdr_key;
		} else {
			hdr_key = NULL;
		}
	} while (0);

	/* prevent leaks */
	if (hdr_key != NULL) {
		zeromem(hdr_key, sizeof(aes_key));
		mem_free(hdr_key);
	}

	zeromem(&header, sizeof(dc_header));

	if (hook != NULL) {
		hook_lock_release(hook, lock);
		dc_deref_hook(hook);
	}

	lock_dec(&dc_data_lock);

	return resl;
}


int dc_change_pass(s16 *dev_name, s8 *old_pass, s8 *new_pass)
{
	dc_header      header;
	set_key_struct skey;
	dev_hook      *hook    = NULL;
	aes_key       *hdr_key = NULL;
	aes_key       *new_key = NULL;
	int            resl, lock;
	int            wp_init = 0;
	wipe_ctx       wipe;	

	lock_inc(&dc_data_lock);
	
	do
	{
		if ( (hook = dc_find_hook(dev_name)) == NULL ) {
			resl = ST_NF_DEVICE; break;
		}

		if (hook_lock_acquire(hook, &lock) == 0) {
			resl = ST_DEVICE_BUSY; break;
		}

		if ( !(hook->flags & F_ENABLED) ) {
			resl = ST_NO_MOUNT; break;
		}

		if (hook->vf_version != TC_VOLUME_HEADER_VERSION) {
			resl = ST_INV_VOL_VER; break;
		}

		/* read old volume header  */
		resl = dc_device_rw(
			hook, IRP_MJ_READ, &header, sizeof(header), 0
			);	
		
		if (resl != ST_OK) {			
			break;
		}

		/* decrypt volume header */
		if ( (hdr_key = dc_decrypt_header(&header, old_pass)) == NULL ) {
			resl = ST_PASS_ERR; break;
		}

		if (hook->flags & F_SYNC)
		{
			/* generate new salt */
			rnd_get_bytes(header.salt, PKCS5_SALT_SIZE);

			/* init new header key */
			if ( (new_key = dc_init_hdr_key(&header, new_pass)) == NULL ) {
				resl = ST_NOMEM; break;
			}

			skey.header   = &header;
			skey.hdr_key  = new_key;
			skey.password = new_pass;
			
			resl = dc_send_sync_packet(
				dev_name, S_OP_SET_KEY, &skey
				);			
		} else
		{
			/* init data wipe */
			resl = dc_wipe_init(
				&wipe, hook, SECTOR_SIZE, WP_GUTMANN
				);

			if (resl == ST_OK) {
				wp_init = 1;
			} else break;

			/* wipe volume header */
			dc_wipe_process(&wipe, 0, SECTOR_SIZE);
			/* write new volume header */
			if ( (resl = dc_write_header(hook, &header, 0, new_pass)) != ST_OK ) {
				break;
			}

			/* wipe backup header */
			dc_wipe_process(&wipe, DC_BACKUP_OFFSET(hook), SECTOR_SIZE);
			/* write new backup header */
			resl = dc_write_header(
				hook, &header, DC_BACKUP_OFFSET(hook), new_pass
				);
		}
	} while (0);

	if (wp_init != 0) {
		dc_wipe_free(&wipe);
	}

	if (hook != NULL) {
		hook_lock_release(hook, lock);
		dc_deref_hook(hook);
	}

	/* prevent leaks */
	if (hdr_key != NULL) {
		zeromem(hdr_key, sizeof(aes_key));
		mem_free(hdr_key);
	}

	if (new_key != NULL) {
		zeromem(new_key, sizeof(aes_key));
		mem_free(new_key);
	}

	zeromem(&header, sizeof(header));

	lock_dec(&dc_data_lock);
	
	return resl;
}

int dc_update_volume(s16 *dev_name, s8 *password, dc_ioctl *s_sh)
{
	dev_hook     *hook;
	aes_key      *hdr_key;
	dc_header     header;
	int           resl, lock;

	lock_inc(&dc_data_lock);

	hook = NULL; hdr_key = NULL;
	do
	{
		if ( (hook = dc_find_hook(dev_name)) == NULL ) {
			resl = ST_NF_DEVICE; break;
		}

		if (hook_lock_acquire(hook, &lock) == 0) {
			resl = ST_DEVICE_BUSY; break;
		}

		if ( !(hook->flags & F_ENABLED) ) {
			resl = ST_NO_MOUNT; break;
		}

		if ( (hook->flags & F_SYNC) || (hook->vf_version >= TC_VOLUME_HEADER_VERSION) ) {
			resl = ST_ERROR; break;
		}

		/* read old volume header  */
		resl = dc_device_rw(
			hook, IRP_MJ_READ, &header, sizeof(header), 0
			);	
		
		if (resl != ST_OK) {			
			break;
		}

		/* decrypt volume header */
		if ( (hdr_key = dc_decrypt_header(&header, password)) == NULL ) {
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
		resl = dc_write_header(
			hook, &header, DC_BACKUP_OFFSET(hook), password
			);
	} while (0);

	if (hook != NULL) {
		hook_lock_release(hook, lock);
		dc_deref_hook(hook);
	}

	/* prevent leaks */
	if (hdr_key != NULL) {
		zeromem(hdr_key, sizeof(aes_key));
		mem_free(hdr_key);
	}

	zeromem(&header, sizeof(header));

	lock_dec(&dc_data_lock);

	return resl;
}

