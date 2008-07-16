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

typedef struct _crypt_thread {
	KEVENT     io_msg_event;
	u32        n_cpu;
	LIST_ENTRY io_list_head;
	KSPIN_LOCK io_spin_lock;
	HANDLE     h_thread;

} crypt_thread;

typedef struct _crypt_req {
	LIST_ENTRY         op_list_entry;
	int                op_type;
	u32                op_blocks;
	void              *src_buf;
	void              *dst_buf;
	size_t             buf_size;
	struct _crypt_req *main_req;
	PIRP               req_irp;
	dev_hook          *req_hook;
	u64                req_offs;

} crypt_req;

static crypt_thread         *crypt_threads;
static u32                   num_threads;  
static NPAGED_LOOKASIDE_LIST crypt_req_mem;
static int                   queue_enabled;
static int                   queue_inited;
static KMUTEX                queue_setup_mutex;

#define CR_OP_READ  0
#define CR_OP_WRITE 1
#define CPU_B_SIZE  4096

static void dc_io_queue_thread(crypt_thread *tp_block)
{
	PLIST_ENTRY entry;
	crypt_req  *c_req, *m_req;
	int         read;

	KeSetSystemAffinityThread(
		(KAFFINITY)(1 << (tp_block->n_cpu))
		);

	do
	{
		wait_object_infinity(
			&tp_block->io_msg_event
			);

		do
		{
			if (entry = ExInterlockedRemoveHeadList(&tp_block->io_list_head, &tp_block->io_spin_lock))
			{
				c_req = CONTAINING_RECORD(entry, crypt_req, op_list_entry);
				read  = (c_req->op_type == CR_OP_READ);
				m_req = c_req->main_req;

				if (read != 0)
				{
					aes_lrw_decrypt(
						c_req->src_buf, c_req->dst_buf, c_req->buf_size,
						lrw_index(c_req->req_offs), &c_req->req_hook->dsk_key
						);
				} else
				{
					aes_lrw_encrypt(
						c_req->src_buf, c_req->dst_buf, c_req->buf_size,
						lrw_index(c_req->req_offs), &c_req->req_hook->dsk_key
						);
				}

				if (lock_dec(&m_req->op_blocks) == 0) 
				{
					if (read != 0)
					{
						IoCompleteRequest(
							c_req->req_irp, IO_NO_INCREMENT
							);
					} else
					{
						IoCallDriver(
							c_req->req_hook->orig_dev, c_req->req_irp
							);
					}

					ExFreeToNPagedLookasideList(&crypt_req_mem, m_req);
				}

				if (c_req != m_req) {
					ExFreeToNPagedLookasideList(&crypt_req_mem, c_req);
				}
			}
		} while (entry != NULL);
	} while (queue_enabled != 0);

	PsTerminateSystemThread(STATUS_SUCCESS);
}

static int dc_queue_encrypted_io(
		     int  op_type, u8 *io_src, u8 *io_dst, size_t io_size,
			 PIRP io_irp, dev_hook *io_hook, u64 io_offs
			 )
{
	crypt_thread *tp_block;
	crypt_req    *req, *main_req;
	size_t        mb_size, cb_size;
	u32           m_cpu, n_cpu;
	int           succs;

	mb_size = _align(io_size / num_threads, CPU_B_SIZE);
	m_cpu   = (u32)((io_size / mb_size) + ((io_size % mb_size) != 0));
	succs   = 1;

	for (n_cpu = 0; n_cpu < m_cpu; n_cpu++)
	{
		cb_size  = min(mb_size, io_size);
		tp_block = &crypt_threads[n_cpu];

		if ( (req = ExAllocateFromNPagedLookasideList(&crypt_req_mem)) == NULL ) {
			succs = 0; break;
		}

		if (n_cpu == 0) {
			main_req = req;
		}

		req->op_type   = op_type;
		req->op_blocks = m_cpu;
		req->src_buf   = io_src;
		req->dst_buf   = io_dst;
		req->buf_size  = cb_size;
		req->main_req  = main_req;
		req->req_irp   = io_irp;
		req->req_hook  = io_hook;
		req->req_offs  = io_offs;

		ExInterlockedInsertTailList (
			&tp_block->io_list_head, &req->op_list_entry, &tp_block->io_spin_lock
			);

		KeSetEvent(
			&tp_block->io_msg_event, IO_DISK_INCREMENT, FALSE
			);

		io_src  += cb_size, io_dst += cb_size, 
		io_offs += cb_size, io_size -= cb_size;
	}

	return succs;
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
		if (buff = MmGetSystemAddressForMdlSafe(irp->MdlAddress, HighPagePriority)) 
		{
			if ( (queue_enabled != 0) && (length > CPU_B_SIZE) )
			{
				succs = dc_queue_encrypted_io(
					CR_OP_READ, buff, buff, length, irp, hook, offset
					);

				if (succs == 0) {
					irp->IoStatus.Status      = STATUS_INSUFFICIENT_RESOURCES;
					irp->IoStatus.Information = 0;
				} else {
					return STATUS_MORE_PROCESSING_REQUIRED;
				}
			} else 
			{
				aes_lrw_decrypt(
					buff, buff, length, lrw_index(offset), &hook->dsk_key
					);
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
	
	fastcpy(nxt_sp, irp_sp, sizeof(IO_STACK_LOCATION));

	nxt_sp->Parameters.Read.ByteOffset.QuadPart += HEADER_SIZE;

	IoSetCompletionRoutine(
		irp, dc_read_complete, NULL, TRUE, TRUE, TRUE
		);

	return IoCallDriver(hook->orig_dev, irp);
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
	data    = MmGetSystemAddressForMdlSafe(irp->MdlAddress, HighPagePriority);
	
	fastcpy(nxt_sp, irp_sp, sizeof(IO_STACK_LOCATION));

	if ( (data != NULL) && 
		 (iopk = fast_alloc(length + sizeof(io_packet))) )
	{
		if (mdl = IoAllocateMdl(iopk->data, length, FALSE, FALSE, NULL))
		{
			MmBuildMdlForNonPagedPool(mdl);

			iopk->old_buf   = irp->UserBuffer;
			iopk->old_mdl   = irp->MdlAddress;
			irp->UserBuffer = iopk->data;
			irp->MdlAddress = mdl;

			nxt_sp->Parameters.Write.ByteOffset.QuadPart += HEADER_SIZE;

			IoSetCompletionRoutine(
				irp, dc_write_complete,	iopk, TRUE, TRUE, TRUE
				);

			if ( (queue_enabled != 0) && (length > CPU_B_SIZE) ) 
			{
				IoMarkIrpPending(irp);				

				succs = dc_queue_encrypted_io(
					CR_OP_WRITE, data, iopk->data, length, irp, hook, offset
					);

				if (succs == 0) 
				{
					irp->MdlAddress = iopk->old_mdl;
					irp->UserBuffer = iopk->old_buf;

					IoFreeMdl(mdl);
					fast_free(iopk);

					IoSetCompletionRoutine(
						irp, NULL, NULL, FALSE, FALSE, FALSE
						);

					dc_complete_irp(irp, status, 0);
				} else {
					status = STATUS_PENDING;
				}
			} else 
			{
				aes_lrw_encrypt(
					data, iopk->data, length, lrw_index(offset), &hook->dsk_key
					);			

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

	if (hook->flags & F_DISABLE) 
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
			if ( (hook->flags & F_UNSUPRT) || (hook->mnt_probed != 0) ) {
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

int dc_setup_io_queue(u32 conf_flags)
{
	crypt_thread *tp_block;
	int           resl;
	u32           i;	

	if (queue_inited == 0)
	{
		num_threads = KeNumberProcessors;

		if ( (crypt_threads = mem_alloc(num_threads * sizeof(crypt_thread))) == NULL ) {
			return ST_NOMEM;
		}

		KeInitializeMutex(
			&queue_setup_mutex, 0
			);

		ExInitializeNPagedLookasideList(
			&crypt_req_mem, NULL, NULL, 0, sizeof(crypt_req), 0, 0
			);

		queue_inited = 1;
	}

	wait_object_infinity(&queue_setup_mutex);

	do
	{
		if (conf_flags & CONF_QUEUE_IO)
		{
			if (queue_enabled != 0) {
				resl = ST_OK; break;
			}							

			for (i = 0; i < num_threads; i++) 
			{
				tp_block = &crypt_threads[i];
				tp_block->n_cpu = i;

				InitializeListHead(
					&tp_block->io_list_head
					);

				KeInitializeEvent(
					&tp_block->io_msg_event, SynchronizationEvent, FALSE
					);

				KeInitializeSpinLock(
					&tp_block->io_spin_lock
					);

				resl = start_system_thread(
					dc_io_queue_thread, tp_block, &tp_block->h_thread
					);

				if (resl != ST_OK) {
					break;
				}
			}
			queue_enabled = (resl == ST_OK);
		} else
		{
			if (lock_xchg(&queue_enabled, 0) == 0) {
				resl = ST_OK; break;
			}
			
			/* stop existing threads and free resources */
			for (i = 0; i < num_threads; i++) 
			{
				tp_block = &crypt_threads[i];

				KeSetEvent(
					&tp_block->io_msg_event, IO_NO_INCREMENT, FALSE
					);

				ZwWaitForSingleObject(
					tp_block->h_thread, FALSE, NULL
					);

				ZwClose(tp_block->h_thread);
			}
			resl = ST_OK;
		}
	} while (0);		

	KeReleaseMutex(&queue_setup_mutex, FALSE);

	return resl;
}