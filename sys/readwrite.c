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
#include "misc_irp.h"
#include "readwrite.h"
#include "fastmem.h"
#include "misc.h"
#include "mount.h"
#include "enc_dec.h"
#include "driver.h"
#include "fast_crypt.h"
#include "debug.h"
#include "misc_mem.h"

typedef struct _sync_q_ctx {
	LIST_ENTRY entry;
	int        is_sync;
	PIRP       io_irp;
	
} sync_q_ctx;

typedef aligned struct _io_packet {
	void      *old_buf;
	PMDL       old_mdl;	
	dev_hook  *hook;
	aligned u8 data[];
	
} io_packet;

static NPAGED_LOOKASIDE_LIST sync_rw_mem;

static
NTSTATUS 
  dc_encrypted_rw_block(
    dev_hook *hook, u32 func, void *buff, u32 size, u64 offset, u32 flags, dc_key *enc_key
	)
{
	NTSTATUS status;
	void    *new_buf;

	new_buf = NULL;
	do
	{
		/* process IO with new memory buffer because 
		   IoBuildSynchronousFsdRequest fails for some system buffers   
		*/
		if ( (new_buf = fast_alloc(size)) == NULL ) {
			status = STATUS_INSUFFICIENT_RESOURCES; break;
		}

		if (func == IRP_MJ_WRITE) 
		{
			if (enc_key != NULL) {
				dc_fast_encrypt(buff, new_buf, size, offset, enc_key);
			} else {
				fastcpy(new_buf, buff, size);
			}
		}

		status = io_device_rw_block(
			hook->orig_dev, func, new_buf, size, offset, flags);

		if ( (NT_SUCCESS(status) != FALSE) && (func == IRP_MJ_READ) ) 
		{
			if (enc_key != NULL) {
				dc_fast_decrypt(new_buf, buff, size, offset, enc_key);
			} else {
				fastcpy(buff, new_buf, size);
			}
		}
	} while (0);

	if (new_buf != NULL) {
		fast_free(new_buf);
	}

	return status;
}

NTSTATUS 
  dc_sync_encrypted_io(
     dev_hook *hook, u8 *buff, u32 size, u64 offset, u32 flags, u32 funct
	 )
{
	NTSTATUS status;
	u64      o1, o2, o3;
	u32      s1, s2, s3;
	u8      *p2, *p3;

	s1 = intersect(&o1, offset, size, 0, DC_AREA_SIZE);
	
	if (hook->flags & F_SYNC) {
		s2 = intersect(&o2, offset, size, DC_AREA_SIZE, (hook->tmp_size - DC_AREA_SIZE));
		s3 = intersect(&o3, offset, size, hook->tmp_size, hook->dsk_size);		
	} else {
		s2 = intersect(&o2, offset, size, DC_AREA_SIZE, hook->dsk_size);
		s3 = 0;
	}
	p2 = buff + s1;
	p3 = p2 + s2;

	/*
	   normal mode:
	    o1:s1 - redirected part
		o2:s2 - encrypted part
		o3:s3 - unencrypted part
	   reencrypt mode:
	   o1:s1 - redirected part
	   o2:s2 - key_1 encrypted part
	   o3:s3 - key_2 encrypted part
	*/

	do
	{
		if (s1 != 0)
		{
			status = dc_sync_encrypted_io(
				hook, buff, s1, hook->stor_off + o1, flags, funct);

			if (NT_SUCCESS(status) == FALSE) {
				break;
			}
		}
		
		if (s2 != 0)
		{
			status = dc_encrypted_rw_block(
				hook, funct, p2, s2, o2, flags, &hook->dsk_key);

			if (NT_SUCCESS(status) == FALSE) {
				break;
			}
		}
		
		if (s3 != 0)
		{
			status = dc_encrypted_rw_block(
				hook, funct, p3, s3, o3, flags, 
				(hook->flags & F_REENCRYPT) ? hook->tmp_key : NULL);
		}
	} while (0);

	return status;
}

void dc_sync_irp_io(dev_hook *hook, PIRP irp)
{
	PIO_STACK_LOCATION irp_sp;
	u64                offset;
	u8                *buff;
	u32                length;
	NTSTATUS           status;

	irp_sp = IoGetCurrentIrpStackLocation(irp);
	buff   = mm_map_mdl_success(irp->MdlAddress);

	if (buff == NULL) {
		dc_release_irp(hook, irp, STATUS_INSUFFICIENT_RESOURCES);
		return;
	}

	if (irp_sp->MajorFunction == IRP_MJ_READ) {
		offset = irp_sp->Parameters.Read.ByteOffset.QuadPart;
		length = irp_sp->Parameters.Read.Length;
	} else 
	{
		offset = irp_sp->Parameters.Write.ByteOffset.QuadPart;
		length = irp_sp->Parameters.Write.Length;

		if ( (hook->flags & F_PROTECT_DCSYS) && 
			 (is_intersect(offset, length, hook->stor_off, DC_AREA_SIZE) != 0) )
		{
			dc_release_irp(hook, irp, STATUS_ACCESS_DENIED);
			return;
		}
	}

	if ( (length == 0) ||
		 (length & (SECTOR_SIZE - 1)) || (offset + length > hook->use_size) )
	{
		dc_release_irp(hook, irp, STATUS_INVALID_PARAMETER);
		return;
	}	

	status = dc_sync_encrypted_io(
		hook, buff, length, offset, irp_sp->Flags, irp_sp->MajorFunction);

	IoReleaseRemoveLock(&hook->remv_lock, irp);

	if (NT_SUCCESS(status) != FALSE) {
		dc_complete_irp(irp, status, length);
	} else {
		dc_complete_irp(irp, status, 0);
	}
}

static void dc_decrypt_complete(PIRP irp, dev_hook *hook)
{
	IoReleaseRemoveLock(&hook->remv_lock, irp);
	IoCompleteRequest(irp, IO_NO_INCREMENT);
}

static
NTSTATUS
  dc_read_complete(
    PDEVICE_OBJECT dev_obj, PIRP irp, void *param
    )
{
	dev_hook          *hook   = dev_obj->DeviceExtension;
	PIO_STACK_LOCATION irp_sp = IoGetCurrentIrpStackLocation(irp);
	ULONG_PTR          length = irp->IoStatus.Information;
	u64                offset = irp_sp->Parameters.Read.ByteOffset.QuadPart;
	PVOID              buff;
	int                succs;

	if (irp->PendingReturned) {
		IoMarkIrpPending(irp);
    }

	if (length != 0)
	{
		if (buff = mm_map_mdl_success(irp->MdlAddress)) 
		{
			if ( (length >= F_OP_THRESOLD) && (dc_cpu_count > 1) )
			{
				succs = dc_parallelized_crypt(
					F_OP_DECRYPT, &hook->dsk_key, 
					buff, buff, length, offset, dc_decrypt_complete, irp, hook);

				if (succs == 0) {
					irp->IoStatus.Status      = STATUS_INSUFFICIENT_RESOURCES;
					irp->IoStatus.Information = 0;
				} else {
					return STATUS_MORE_PROCESSING_REQUIRED;
				}
			} else 
			{
				dc_cipher_decrypt(
					buff, buff, length, offset, &hook->dsk_key);
			}
		} else {			
			irp->IoStatus.Status      = STATUS_INSUFFICIENT_RESOURCES;
			irp->IoStatus.Information = 0;
		}
	}
	IoReleaseRemoveLock(&hook->remv_lock, irp);

    return STATUS_SUCCESS;
}

static
NTSTATUS
  dc_write_complete(
    PDEVICE_OBJECT dev_obj, PIRP irp, io_packet *iopk
    )
{
	IoFreeMdl(irp->MdlAddress);

	irp->MdlAddress = iopk->old_mdl;
	irp->UserBuffer = iopk->old_buf;

	IoReleaseRemoveLock(&iopk->hook->remv_lock, irp);
	fast_free(iopk);

	if (irp->PendingReturned) {
		IoMarkIrpPending(irp);
    }

	return STATUS_SUCCESS;
}	  

static NTSTATUS dc_read_irp(dev_hook *hook, PIRP irp)
{
	PIO_STACK_LOCATION irp_sp;
	PIO_STACK_LOCATION nxt_sp;

	irp_sp = IoGetCurrentIrpStackLocation(irp);
	nxt_sp = IoGetNextIrpStackLocation(irp);
	
	autocpy(nxt_sp, irp_sp, sizeof(IO_STACK_LOCATION));	

	if (hook->flags & F_NO_REDIRECT) {
		nxt_sp->Parameters.Read.ByteOffset.QuadPart += hook->stor_off;
	}
		
	IoSetCompletionRoutine(
		irp, dc_read_complete, NULL, TRUE, TRUE, TRUE);

	return IoCallDriver(hook->orig_dev, irp);
}

static void dc_encrypt_complete(
			  PDEVICE_OBJECT dev_obj, PIRP irp
			  )
{
	IoCallDriver(dev_obj, irp);
}

static NTSTATUS dc_write_irp(dev_hook *hook, PIRP irp)
{
	PIO_STACK_LOCATION irp_sp;
	PIO_STACK_LOCATION nxt_sp;
	NTSTATUS           status;
	u64                offset;
	u32                length;
	PMDL               nmdl;
	PVOID              data;
	io_packet         *iopk;
	int                succs;

	irp_sp = IoGetCurrentIrpStackLocation(irp);
	nxt_sp = IoGetNextIrpStackLocation(irp);
	offset = irp_sp->Parameters.Write.ByteOffset.QuadPart;
	length = irp_sp->Parameters.Write.Length;
		
	nmdl = NULL; data = NULL; iopk = NULL; succs = 0;
	do
	{
		if ( (hook->flags & F_PROTECT_DCSYS) && 
			 (is_intersect(offset, length, hook->stor_off, DC_AREA_SIZE) != 0) ) 
		{
			status = STATUS_ACCESS_DENIED; break;
		}

		data = mm_map_mdl_success(irp->MdlAddress);
		iopk = fast_alloc(length + sizeof(io_packet));
		nmdl = mm_allocate_mdl_success(iopk->data, length);

		if ( (data == NULL) || (iopk == NULL) || (nmdl == NULL) ) {
			status = STATUS_INSUFFICIENT_RESOURCES; break;
		}

		/* copy IRP stack */
		autocpy(nxt_sp, irp_sp, sizeof(IO_STACK_LOCATION));

		if (hook->flags & F_NO_REDIRECT) {
			nxt_sp->Parameters.Write.ByteOffset.QuadPart += hook->stor_off;
		}

		MmBuildMdlForNonPagedPool(nmdl);

		iopk->old_buf   = irp->UserBuffer;
		iopk->old_mdl   = irp->MdlAddress;
		iopk->hook      = hook;
		irp->UserBuffer = iopk->data;
		irp->MdlAddress = nmdl;

		IoSetCompletionRoutine(
			irp, dc_write_complete,	iopk, TRUE, TRUE, TRUE);

		if ( (length >= F_OP_THRESOLD) && (dc_cpu_count > 1) )
		{
			IoMarkIrpPending(irp);

			succs = dc_parallelized_crypt(
				F_OP_ENCRYPT, &hook->dsk_key, data, 
				iopk->data, length, offset, dc_encrypt_complete, hook->orig_dev, irp);

			if (succs == 0) {
				irp->MdlAddress = iopk->old_mdl;
				irp->UserBuffer = iopk->old_buf;
				status = STATUS_INSUFFICIENT_RESOURCES;
			} else {
				status = STATUS_PENDING;
			}
		} else
		{
			dc_cipher_encrypt(data, iopk->data, length, offset, &hook->dsk_key);

			status = IoCallDriver(hook->orig_dev, irp);
			succs  = 1;
		}
	} while (0);

	if (succs == 0) 
	{
		if (nmdl != NULL) { IoFreeMdl(nmdl); }
		if (iopk != NULL) { fast_free(iopk); }

		IoSetCompletionRoutine(
			irp, NULL, NULL, FALSE, FALSE, FALSE);

		dc_release_irp(hook, irp, status);
	}

	return status;
}

static void dc_sync_rw_thread(dev_hook *hook)
{
	PLIST_ENTRY entry;
	sync_q_ctx *q_ctx;
	PIRP        irp;
	
	/* initialization wait */
	wait_object_infinity(&hook->rw_init_event);
	
	DbgMsg("sync_rw_thread initialized\n");

	/* irp processing loop */
	do
	{
		wait_object_infinity(&hook->rw_work_event);
		do
		{
			if (entry = ExInterlockedRemoveHeadList(&hook->rw_queue_head, &hook->rw_queue_lock))
			{
				q_ctx = CONTAINING_RECORD(entry, sync_q_ctx, entry);
				irp   = q_ctx->io_irp;

				if (q_ctx->is_sync == 0) 
				{
					if (IoGetCurrentIrpStackLocation(irp)->MajorFunction == IRP_MJ_READ) {
						dc_read_irp(hook, irp);
					} else {
						dc_write_irp(hook, irp);
					}
				} else {
					dc_sync_irp_io(hook, irp);
				}
				ExFreeToNPagedLookasideList(&sync_rw_mem, q_ctx);
			}
		} while (entry != NULL);
	} while (hook->flags & F_ENABLED);

	DbgMsg("sync_rw_thread terminated\n");

	PsTerminateSystemThread(STATUS_SUCCESS);
}

int dc_start_rw_thread(dev_hook *hook)
{
	if (hook->rw_thread != NULL) {
		return ST_ERROR;
	}
	/* initialize */
	KeInitializeEvent(&hook->rw_init_event, NotificationEvent, FALSE);
	KeInitializeEvent(&hook->rw_work_event, SynchronizationEvent, FALSE);
	InitializeListHead(&hook->rw_queue_head);
	KeInitializeSpinLock(&hook->rw_queue_lock);
	/* start syncronous RW helper thread */
	return start_system_thread(dc_sync_rw_thread, hook, &hook->rw_thread);
}

void dc_stop_rw_thread(dev_hook *hook)
{
	if (hook->rw_thread != NULL) {
		KeSetEvent(&hook->rw_work_event, IO_NO_INCREMENT, FALSE);
		ZwWaitForSingleObject(hook->rw_thread, FALSE, NULL);
		ZwClose(hook->rw_thread); hook->rw_thread = NULL;
	}
}

NTSTATUS dc_read_write_irp(dev_hook *hook, PIRP irp)
{
	PIO_STACK_LOCATION irp_sp;
    sync_q_ctx        *q_ctx;
	u64                offset;
	u32                length;
	int                is_sync;

	/* reseed RNG on first 1000 I/O operations for collect initial entropy */
	if (lock_inc(&dc_io_count) < 1000) {
		rnd_reseed_now();
	}

	irp_sp = IoGetCurrentIrpStackLocation(irp);

	if ( hook->flags & (F_DISABLE | F_FORMATTING) ) {
		return dc_release_irp(hook, irp, STATUS_INVALID_DEVICE_STATE);
	}

	if (hook->flags & F_SYNC)
	{
		IoMarkIrpPending(irp);

		ExInterlockedInsertTailList(
			&hook->sync_irp_queue, &irp->Tail.Overlay.ListEntry, &hook->sync_req_lock);

		KeSetEvent(
			&hook->sync_req_event, IO_DISK_INCREMENT, FALSE);

		return STATUS_PENDING;
	}

	if ( !(hook->flags & F_ENABLED) )
	{
		/* probe for mount new volume */
		if ( (hook->flags & (F_UNSUPRT | F_NO_AUTO_MOUNT)) || (hook->mnt_probed != 0) ) {
			return dc_forward_irp(hook, irp);
		} else {
			return dc_probe_mount(hook, irp);
		}
	}

	if (irp_sp->MajorFunction == IRP_MJ_READ) {
		offset = irp_sp->Parameters.Read.ByteOffset.QuadPart;
		length = irp_sp->Parameters.Read.Length;
	} else {
		offset = irp_sp->Parameters.Write.ByteOffset.QuadPart;
		length = irp_sp->Parameters.Write.Length;
	}

	if ( (length == 0) ||
		 (length & (SECTOR_SIZE - 1)) || (offset + length > hook->use_size) )
	{
		return dc_release_irp(hook, irp, STATUS_INVALID_PARAMETER);		
	}

	is_sync = (offset < DC_AREA_SIZE) && !(hook->flags & F_NO_REDIRECT);

	if ( (is_sync == 0) && (dc_cpu_count > 1) )
	{
		if (irp_sp->MajorFunction == IRP_MJ_READ) {
			return dc_read_irp(hook, irp);
		} else {
			return dc_write_irp(hook, irp);
		}
	}
	if ( (q_ctx = ExAllocateFromNPagedLookasideList(&sync_rw_mem)) == NULL ) {
		return dc_release_irp(hook, irp, STATUS_INSUFFICIENT_RESOURCES);
	} 
	q_ctx->io_irp  = irp;
	q_ctx->is_sync = is_sync;

	IoMarkIrpPending(irp);

	ExInterlockedInsertTailList(
		&hook->rw_queue_head, &q_ctx->entry, &hook->rw_queue_lock);

	KeSetEvent(
		&hook->rw_work_event, IO_DISK_INCREMENT, FALSE);
	
	return STATUS_PENDING;
}

void dc_init_rw()
{
	ExInitializeNPagedLookasideList(
		&sync_rw_mem, mm_alloc_success, NULL, 0, sizeof(sync_q_ctx), '5_cd', 0);
}

void dc_free_rw()
{
	ExDeleteNPagedLookasideList(&sync_rw_mem);
}