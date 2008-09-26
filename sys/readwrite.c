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
#include "misc_irp.h"
#include "readwrite.h"
#include "fastmem.h"
#include "misc.h"
#include "mount.h"
#include "enc_dec.h"
#include "driver.h"
#include "fast_crypt.h"

static void dc_decrypt_complete(PIRP irp, void *param)
{
	IoCompleteRequest(irp, IO_NO_INCREMENT);
}

static
NTSTATUS
  dc_read_complete(
    IN PDEVICE_OBJECT dev_obj,
    IN PIRP           irp,
    IN void          *param
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
		if (buff = dc_map_mdl_with_retry(irp->MdlAddress)) 
		{
			if (length >= F_OP_THRESOLD)
			{
				succs = dc_parallelized_crypt(
					F_OP_DECRYPT, &hook->dsk_key, buff, buff, 
					length, offset, dc_decrypt_complete, irp, NULL
					);

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

    return STATUS_SUCCESS;
}

static
NTSTATUS
  dc_write_complete(
    IN PDEVICE_OBJECT dev_obj,
    IN PIRP           irp,
    IN io_packet     *iopk
    )
{
	IoFreeMdl(irp->MdlAddress);

	irp->MdlAddress = iopk->old_mdl;
	irp->UserBuffer = iopk->old_buf;

	fast_free(iopk);

	if (irp->PendingReturned) {
		IoMarkIrpPending(irp);
    }

	return STATUS_SUCCESS;
}


NTSTATUS 
  dc_read_irp(
     IN dev_hook *hook,
	 IN PIRP      irp
	 )
{
	PIO_STACK_LOCATION irp_sp;
	PIO_STACK_LOCATION nxt_sp;

	irp_sp  = IoGetCurrentIrpStackLocation(irp);
	nxt_sp  = IoGetNextIrpStackLocation(irp);
	
	autocpy(nxt_sp, irp_sp, sizeof(IO_STACK_LOCATION));

	nxt_sp->Parameters.Read.ByteOffset.QuadPart += HEADER_SIZE;

	IoSetCompletionRoutine(
		irp, dc_read_complete, NULL, TRUE, TRUE, TRUE
		);

	return IoCallDriver(hook->orig_dev, irp);
}


static void dc_encrypt_complete(
			  PDEVICE_OBJECT device, PIRP irp
			  )
{
	IoCallDriver(device, irp);
}

NTSTATUS 
  dc_write_irp(
     IN dev_hook *hook,
	 IN PIRP      irp
	 )
{
	PIO_STACK_LOCATION irp_sp;
	PIO_STACK_LOCATION nxt_sp;
	ULONGLONG          offset;
	ULONG              length;	
	NTSTATUS           status = STATUS_INSUFFICIENT_RESOURCES;
	PMDL               mdl    = NULL;
	PVOID              data;
	io_packet         *iopk;
	int                succs;
		
	irp_sp  = IoGetCurrentIrpStackLocation(irp);
	nxt_sp  = IoGetNextIrpStackLocation(irp);
	offset  = irp_sp->Parameters.Write.ByteOffset.QuadPart;
	length  = irp_sp->Parameters.Write.Length;
	data    = dc_map_mdl_with_retry(irp->MdlAddress);
	
	autocpy(nxt_sp, irp_sp, sizeof(IO_STACK_LOCATION));

	if ( (data != NULL) && 
		 (iopk = fast_alloc(length + sizeof(io_packet))) )
	{
		if (mdl = dc_allocate_mdl_with_retry(iopk->data, length))
		{
			MmBuildMdlForNonPagedPool(mdl);

			iopk->old_buf   = irp->UserBuffer;
			iopk->old_mdl   = irp->MdlAddress;
			irp->UserBuffer = iopk->data;
			irp->MdlAddress = mdl;

			nxt_sp->Parameters.Write.ByteOffset.QuadPart += HEADER_SIZE;

			IoSetCompletionRoutine(
				irp, dc_write_complete,	iopk, TRUE, TRUE, TRUE);

			if (length >= F_OP_THRESOLD) 
			{
				IoMarkIrpPending(irp);				

				succs = dc_parallelized_crypt(
					F_OP_ENCRYPT, &hook->dsk_key, data, iopk->data, 
					length, offset, dc_encrypt_complete, hook->orig_dev, irp
					);

				if (succs == 0) 
				{
					irp->MdlAddress = iopk->old_mdl;
					irp->UserBuffer = iopk->old_buf;

					IoFreeMdl(mdl);
					fast_free(iopk);

					IoSetCompletionRoutine(
						irp, NULL, NULL, FALSE, FALSE, FALSE);

					dc_complete_irp(irp, status, 0);
				} else {
					status = STATUS_PENDING;
				}
			} else 
			{
				dc_cipher_encrypt(
					data, iopk->data, length, offset, &hook->dsk_key);			

				status = IoCallDriver(hook->orig_dev, irp);			
			}
		} else {
			fast_free(iopk);
			dc_complete_irp(irp, status, 0);
		}	
	} else {
		dc_complete_irp(irp, status, 0);
	}

	return status;
}


NTSTATUS
  dc_read_write_irp(
     IN PDEVICE_OBJECT dev_obj, 
	 IN PIRP           irp
	 )
{
	PIO_STACK_LOCATION irp_sp;
	dev_hook          *hook;
	ULONGLONG          offset;
	ULONG              length;
	NTSTATUS           status;	

	/* reseed RNG on first 1000 I/O operations for collect initial entropy */
	if (lock_inc(&dc_io_count) < 1000) {
		rnd_reseed_now();
	}
		
	if (dev_obj == dc_device)
	{
		return dc_complete_irp(
			      irp, STATUS_DRIVER_INTERNAL_ERROR, 0
				  );
	}

	irp_sp = IoGetCurrentIrpStackLocation(irp);
	hook   = dev_obj->DeviceExtension;

	if ( hook->flags & (F_DISABLE | F_FORMATTING) )
	{
		return dc_complete_irp(
			      irp, STATUS_INVALID_DEVICE_STATE, 0
				  );
	}

	if (hook->flags & F_SYNC)
	{
		IoMarkIrpPending(irp);

		ExInterlockedInsertTailList (
			&hook->sync_irp_queue, &irp->Tail.Overlay.ListEntry, &hook->sync_req_lock
			);

		KeSetEvent(
			&hook->sync_req_event, IO_DISK_INCREMENT, FALSE
			);

		status = STATUS_PENDING;
	} else 
	{
		if ( !(hook->flags & F_ENABLED) ) 
		{
			/* probe for mount new volume */
			if ( (hook->flags & (F_UNSUPRT | F_NO_AUTO_MOUNT)) || (hook->mnt_probed != 0) ) {
				return dc_forward_irp(dev_obj, irp);
			} else {
				return dc_probe_mount(dev_obj, irp);
			}
		} else 
		{
			if (irp_sp->MajorFunction == IRP_MJ_READ) {
				offset = irp_sp->Parameters.Read.ByteOffset.QuadPart;
				length = irp_sp->Parameters.Read.Length;
			} else {
				offset = irp_sp->Parameters.Write.ByteOffset.QuadPart;
				length = irp_sp->Parameters.Write.Length;
			}

			if ( (length == 0) ||
				 (length & (SECTOR_SIZE - 1)) ||
				 (offset + length > hook->use_size) )
			{
				return dc_complete_irp(
					irp, STATUS_INVALID_PARAMETER, 0
					); 
			}

			if (irp_sp->MajorFunction == IRP_MJ_READ) {
				status = dc_read_irp(hook, irp);
			} else {
				status = dc_write_irp(hook, irp);
			}
		}
	}

	return status;
}
