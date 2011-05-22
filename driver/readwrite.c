/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2007-2010
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

#include <ntifs.h>
#include "defines.h"
#include "devhook.h"
#include "misc_irp.h"
#include "readwrite.h"
#include "misc.h"
#include "mount.h"
#include "enc_dec.h"
#include "driver.h"
#include "fast_crypt.h"
#include "debug.h"
#include "misc_mem.h"

#define SSD_PAGE_SIZE				4096
#define SSD_ERASE_BLOCK_SIZE		(128 * 1024)

#define CHUNK_READ_THRESHOLD		(128 * 1024)
#define CHUNK_READ_CHUNK_SIZE		(512 * 1024)
#define CHUNK_MIN_READ_SIZE			(64 * 1024)
#define CHUNK_READ_ALIGN			SSD_PAGE_SIZE

#define CHUNK_WRITE_THRESHOLD		(128 * 1024)
#define CHUNK_WRITE_CHUNK_SIZE		SSD_ERASE_BLOCK_SIZE
#define CHUNK_WRITE_ALIGN			SSD_ERASE_BLOCK_SIZE

#define IS_CHUNKING_NEEDED(_length, _is_read) ( \
	(((_is_read) != 0) && ((_length) >= CHUNK_READ_THRESHOLD)) || \
	(((_is_read) == 0) && ((_length) >= CHUNK_WRITE_THRESHOLD)) )

typedef struct _io_context {
	dev_hook *hook;
	PIRP      orig_irp;
	PIRP      new_irp;
	char     *buff;
	char     *new_buff;
	u32       length;    /* request length    */
	u64       offset;    /* request disk offset */
	u32       completed; /* IO completed bytes */
	u32       encrypted; /* encrypted bytes */
	u32       refs;
	int       expected;

	u64      chunk_diskof;
	u32      chunk_length;
	u32      chunk_offset;
	xts_key *chunk_key;
	int      chunk_nocont; /* this is discontinuous chunk */

	u64      write_offset;
	u32      write_length;

	int        is_writing;
	KSPIN_LOCK write_lock;

	int      is_sync;
	KEVENT   done_event;
	NTSTATUS status;

	WORK_QUEUE_ITEM work_item;

} io_context;

/* function types declaration */
WORKER_THREAD_ROUTINE io_async_read_chunk;
IO_COMPLETION_ROUTINE io_chunk_read_complete;
WORKER_THREAD_ROUTINE io_write_next_chunk;
IO_COMPLETION_ROUTINE io_chunk_write_complete;
WORKER_THREAD_ROUTINE io_async_encrypt_chunk;

#define io_context_addref(_ctx)      ( lock_inc(&(_ctx)->refs) )
#define io_set_status(_ctx, _status) ( (_ctx)->status = (_status) )

static NPAGED_LOOKASIDE_LIST io_context_mem;

static void io_context_deref(io_context *ctx)
{
	if (lock_dec(&ctx->refs) != 0) {
		return;
	}
	/* complete the original irp */
	if (NT_SUCCESS(ctx->status) != FALSE) {
		ctx->orig_irp->IoStatus.Status = STATUS_SUCCESS;
		ctx->orig_irp->IoStatus.Information = ctx->length;
	} else {
		ctx->orig_irp->IoStatus.Status = ctx->status;
		ctx->orig_irp->IoStatus.Information = ctx->length;
	}
	IoCompleteRequest(ctx->orig_irp, IO_DISK_INCREMENT);

	/* free resources */
	IoReleaseRemoveLock(&ctx->hook->remv_lock, ctx->orig_irp);
	lock_dec(&ctx->hook->io_depth);
	
	if (ctx->new_irp != NULL) {
		IoFreeIrp(ctx->new_irp);
	}
	if (ctx->new_buff != NULL) {
		mm_free(ctx->new_buff);
	}
	/* set completion event if needed */
	if (ctx->is_sync != 0) {
		KeSetEvent(&ctx->done_event, IO_NO_INCREMENT, FALSE);
	} else {
		ExFreeToNPagedLookasideList(&io_context_mem, ctx);
	}
}

static u32 io_read_chunk_length(io_context *ctx)
{
	u32 remain = ctx->length - ctx->completed;
	u32 length = min(remain / 2, CHUNK_READ_CHUNK_SIZE);

	/* don't create chunks that are too small */
	if (remain - length < CHUNK_MIN_READ_SIZE) {
		length += remain - length;
	}
	/* increase the first chunk's size so subsequent chunks start aligned */
	if ( (ctx->chunk_offset == 0) && ((ctx->offset + length) & (CHUNK_READ_ALIGN-1)) ) {
		length += CHUNK_READ_ALIGN - ((ctx->offset + length) & (CHUNK_READ_ALIGN-1));
	}
	return length;
}

static u32 io_write_chunk_length(io_context *ctx)
{
	u32 length = CHUNK_WRITE_CHUNK_SIZE;

	/* increase the first chunk's size so subsequent chunks start aligned */
	if ( (ctx->chunk_offset == 0) && ((ctx->offset + length) & (CHUNK_WRITE_ALIGN-1)) ) {
		length += CHUNK_WRITE_ALIGN - ((ctx->offset + length) & (CHUNK_WRITE_ALIGN-1));
	}
	return length;
}

static void io_async_make_chunk(io_context *ctx, int is_read)
{
	dev_hook *hook = ctx->hook;
	u32       done = is_read != 0 ? ctx->completed : ctx->encrypted;
	
	ctx->chunk_diskof = ctx->offset + done;
	ctx->chunk_offset = done;
	ctx->chunk_key    = &hook->dsk_key;
	ctx->chunk_nocont = 0;

	/* handle redirected sectors */
	if ( !(hook->flags & F_NO_REDIRECT) && (ctx->chunk_diskof < hook->head_len) )
	{
		ctx->chunk_diskof += hook->stor_off;
		ctx->chunk_length = hook->head_len;
		ctx->chunk_nocont = 1;
	} else 
	{
		if ( (dc_conf_flags & CONF_ENABLE_SSD_OPT) && (hook->flags & F_SSD) &&
			 (hook->io_depth == 1) && (ctx->expected != 0) && IS_CHUNKING_NEEDED(ctx->length, is_read) )
		{
			if (is_read != 0) {
				ctx->chunk_length = io_read_chunk_length(ctx);
			} else {
				ctx->chunk_length = io_write_chunk_length(ctx);
			}
		} else {
			ctx->chunk_length = ctx->length;
		}
	}
	/* handle partial encrypted state */
	if (hook->flags & F_SYNC) 
	{
		if (ctx->chunk_diskof >= hook->tmp_size) {
			ctx->chunk_key = (hook->flags & F_REENCRYPT) ? hook->tmp_key : NULL;			
		} else
		{
			if (ctx->chunk_diskof + ctx->chunk_length > hook->tmp_size) {
				ctx->chunk_length = d32(hook->tmp_size - ctx->chunk_diskof);
			}
		}
	}
	if (ctx->chunk_length > ctx->length - done) {
		ctx->chunk_length = ctx->length - done;
	}
}

static NTSTATUS io_chunk_read_complete(PDEVICE_OBJECT dev_obj, PIRP irp, io_context *ctx)
{
	dev_hook  *hook   = ctx->hook;
	char      *buff   = ctx->buff + ctx->chunk_offset;
	NTSTATUS   status = irp->IoStatus.Status;
	u64        offset = ctx->chunk_diskof;
	u32        size   = d32(irp->IoStatus.Information);
		
	/* free mdl from the chunk irp */
	IoFreeMdl(irp->MdlAddress); irp->MdlAddress	= NULL;

	/* update completed length */
	ctx->completed += ctx->chunk_length;

	if (NT_SUCCESS(status) != FALSE)
	{
		if (ctx->completed < ctx->length)
		{
			/* reinitialize IRP */
			IoReuseIrp(irp, STATUS_SUCCESS);
			/* start next chunk if not completed */
			io_context_addref(ctx);
			io_async_read_chunk(ctx);
		}
		/* decrypt chunk if needed */
		if (ctx->chunk_key != NULL) 
		{
			io_context_addref(ctx);

			if (hook->flags & F_NO_REDIRECT) {
				offset -= hook->head_len;
			}			
			cp_parallelized_crypt(
				0, ctx->chunk_key, io_context_deref, ctx, buff, buff, size, offset);
		}
	}
	/* set completion status if read completed */
	if ( (NT_SUCCESS(status) == FALSE) || (ctx->completed == ctx->length) ) {
		io_set_status(ctx, status);
	}
	io_context_deref(ctx); return STATUS_MORE_PROCESSING_REQUIRED;
}

static void io_async_read_chunk(io_context *ctx)
{
	PIO_STACK_LOCATION new_sp;
	PIRP               new_irp, old_irp;
	PMDL               new_mdl;
	char              *pbuf_va;

	if (KeGetCurrentIrql() >= DISPATCH_LEVEL) {
		ExInitializeWorkItem(&ctx->work_item, io_async_read_chunk, ctx);
		ExQueueWorkItem(&ctx->work_item, CriticalWorkQueue);
		return;
	}
	new_irp = ctx->new_irp;
	old_irp = ctx->orig_irp;
	new_sp  = IoGetNextIrpStackLocation(new_irp);

	io_async_make_chunk(ctx, 1);

	new_sp->MajorFunction = IRP_MJ_READ;
	new_sp->Flags         = IoGetCurrentIrpStackLocation(old_irp)->Flags;
	new_sp->Parameters.Read.Length              = ctx->chunk_length;
	new_sp->Parameters.Read.ByteOffset.QuadPart = ctx->chunk_diskof;
	
	pbuf_va = p8(MmGetMdlVirtualAddress(old_irp->MdlAddress)) + ctx->chunk_offset;
	new_mdl = mm_allocate_mdl_success(pbuf_va, ctx->chunk_length);

	if (new_mdl == NULL) {
		io_set_status(ctx, STATUS_INSUFFICIENT_RESOURCES);
		io_context_deref(ctx); 
		return;
	}
	IoBuildPartialMdl(old_irp->MdlAddress, new_mdl, pbuf_va, ctx->chunk_length);
	new_irp->MdlAddress = new_mdl;

	IoSetCompletionRoutine(new_irp, io_chunk_read_complete, ctx, TRUE, TRUE, TRUE);
	IoCallDriver(ctx->hook->orig_dev, new_irp);
}

static NTSTATUS io_chunk_write_complete(PDEVICE_OBJECT dev_obj, PIRP irp, io_context *ctx)
{
	KLOCK_QUEUE_HANDLE lock_queue;
	int                need_write;

	/* free mdl from the chunk irp */
	IoFreeMdl(irp->MdlAddress); irp->MdlAddress	= NULL;

	if (NT_SUCCESS(irp->IoStatus.Status) != FALSE)
	{
		KeAcquireInStackQueuedSpinLock(&ctx->write_lock, &lock_queue);

		/* update pointers */
		ctx->write_offset += ctx->write_length;
		ctx->completed    += ctx->write_length;
		ctx->write_length  = ctx->encrypted - ctx->completed;		
		need_write = ctx->is_writing = (ctx->write_length != 0);

		KeReleaseInStackQueuedSpinLock(&lock_queue);

		if ( (ctx->chunk_nocont != 0) && (ctx->completed < ctx->length) )
		{
			ctx->write_offset = ctx->offset + ctx->completed;
			ctx->chunk_nocont = 0;
			io_context_addref(ctx);
			io_async_encrypt_chunk(ctx);
		}
		if (need_write != 0) 
		{
			/* reinitialize IRP */
			IoReuseIrp(irp, STATUS_SUCCESS);
			/* start next chunk if not completed */
			io_context_addref(ctx);
			io_write_next_chunk(ctx);
		}
	}
	io_context_deref(ctx); return STATUS_MORE_PROCESSING_REQUIRED;
}

static void io_write_next_chunk(io_context *ctx)
{
	PIO_STACK_LOCATION new_sp;
	PIRP               new_irp;

	if (KeGetCurrentIrql() >= DISPATCH_LEVEL)	{
		ExInitializeWorkItem(&ctx->work_item, io_write_next_chunk, ctx);
		ExQueueWorkItem(&ctx->work_item, CriticalWorkQueue);
		return;
	}
	new_irp = ctx->new_irp;
	new_sp  = IoGetNextIrpStackLocation(new_irp);

	new_sp->MajorFunction = IRP_MJ_WRITE;
	new_sp->Flags         = IoGetCurrentIrpStackLocation(ctx->orig_irp)->Flags;
	new_sp->Parameters.Write.Length              = ctx->write_length;
	new_sp->Parameters.Write.ByteOffset.QuadPart = ctx->write_offset;
	
	new_irp->MdlAddress = 
		mm_allocate_mdl_success(ctx->new_buff + ctx->completed, ctx->write_length);

	if (new_irp->MdlAddress == NULL) {
		io_set_status(ctx, STATUS_INSUFFICIENT_RESOURCES);
		io_context_deref(ctx);
		return;
	}
	MmBuildMdlForNonPagedPool(new_irp->MdlAddress);
	IoSetCompletionRoutine(new_irp, io_chunk_write_complete, ctx, TRUE, TRUE, TRUE);
	IoCallDriver(ctx->hook->orig_dev, new_irp);
}

static void io_chunk_encrypt_complete(io_context *ctx)
{
	KLOCK_QUEUE_HANDLE lock_queue;
	int                need_write;
	
	if (ctx->chunk_offset == 0) {
		ctx->write_offset = ctx->chunk_diskof;
	}
	KeAcquireInStackQueuedSpinLock(&ctx->write_lock, &lock_queue);

	/* update encrypted length */
	ctx->encrypted += ctx->chunk_length;

	if (ctx->is_writing == 0) {
		ctx->write_length = ctx->encrypted - ctx->completed;
		need_write = ctx->is_writing = 1;
	} else {
		need_write = 0;
	}
	KeReleaseInStackQueuedSpinLock(&lock_queue);

	if (need_write != 0) {
		io_context_addref(ctx); 
		io_write_next_chunk(ctx);
	}
	/* encrypt next chunk if needed */
	if ( (ctx->chunk_nocont == 0) && (ctx->encrypted < ctx->length) ) {
		io_context_addref(ctx);
		io_async_encrypt_chunk(ctx);
	}
	io_context_deref(ctx);
}

static void io_async_encrypt_chunk(io_context *ctx)
{
	char *in_buf, *out_buf;
	u32   length;
	u64   offset;
			
	io_async_make_chunk(ctx, 0);
	
	out_buf = ctx->new_buff + ctx->encrypted;
	in_buf = ctx->buff + ctx->encrypted;
	length = ctx->chunk_length;
	offset = ctx->chunk_diskof;
		
	if (ctx->chunk_key != NULL)
	{
		if (ctx->hook->flags & F_NO_REDIRECT) {
			offset -= ctx->hook->head_len;
		}
		/* enqueue encryption of this chunk */
		cp_parallelized_crypt(
			1, ctx->chunk_key, io_chunk_encrypt_complete, ctx, in_buf, out_buf, length, offset);
	} else {
		memcpy(out_buf, in_buf, length);
		io_chunk_encrypt_complete(ctx);
	}
}

NTSTATUS io_encrypted_irp_io(dev_hook *hook, PIRP irp, int is_sync)
{
	PIO_STACK_LOCATION irp_sp = IoGetCurrentIrpStackLocation(irp);
	NTSTATUS           status = STATUS_PENDING;
	io_context        *ctx;

	/* allocate IO context */
	if ( (ctx = ExAllocateFromNPagedLookasideList(&io_context_mem)) == NULL ) {
		return dc_release_irp(hook, irp, STATUS_INSUFFICIENT_RESOURCES);
	}
	memset(ctx, 0, sizeof(io_context));
	
	ctx->orig_irp = irp;
	ctx->hook = hook;
	ctx->refs = 1;
	lock_inc(&hook->io_depth);

	if (ctx->is_sync = is_sync) {
		KeInitializeEvent(&ctx->done_event, NotificationEvent, FALSE);
	}
	if (irp_sp->MajorFunction == IRP_MJ_READ) {
		ctx->offset = irp_sp->Parameters.Read.ByteOffset.QuadPart;
		ctx->length = irp_sp->Parameters.Read.Length;
	} else 
	{
		ctx->offset = irp_sp->Parameters.Write.ByteOffset.QuadPart;
		ctx->length = irp_sp->Parameters.Write.Length;

		if ( !(hook->flags & F_NO_REDIRECT) && 
			  (is_intersect(ctx->offset, ctx->length, hook->stor_off, hook->head_len) != 0) )
		{
			status = STATUS_ACCESS_DENIED; goto on_fail;
		}
	}
	if ( (ctx->length == 0) || 
		 (ctx->length & (SECTOR_SIZE - 1)) || (ctx->offset + ctx->length > hook->use_size) )
	{
		status = STATUS_INVALID_PARAMETER; goto on_fail;
	}
	if (lock_xchg64(&hook->expect_off, ctx->offset + ctx->length) == ctx->offset) {
		ctx->expected = 1;
	}
	if (hook->flags & F_NO_REDIRECT) {
		ctx->offset += hook->head_len;
	}
	ctx->new_irp = mm_allocate_irp_success(hook->orig_dev->StackSize);
	ctx->buff    = mm_map_mdl_success(irp->MdlAddress);
	
	if ( (ctx->new_irp == NULL) || (ctx->buff == NULL) ) {
		status = STATUS_INSUFFICIENT_RESOURCES; goto on_fail;
	}
	IoMarkIrpPending(irp);

	if (irp_sp->MajorFunction == IRP_MJ_READ) {
		io_async_read_chunk(ctx);
	} else 
	{
		if ( (ctx->new_buff = mm_alloc(ctx->length, MEM_FAST | MEM_SUCCESS)) == NULL ) {
			status = STATUS_INSUFFICIENT_RESOURCES; goto on_fail;
		}
		KeInitializeSpinLock(&ctx->write_lock);
		io_async_encrypt_chunk(ctx);
	}

do_exit:
	if (is_sync != 0) 
	{
		KeWaitForSingleObject(&ctx->done_event, Executive, KernelMode, FALSE, NULL);
		status = ctx->status;		
		ExFreeToNPagedLookasideList(&io_context_mem, ctx);
	}
	return status;

on_fail:
	io_set_status(ctx, status);
	io_context_deref(ctx); 
	goto do_exit;
}


NTSTATUS io_read_write_irp(dev_hook *hook, PIRP irp)
{
	/* reseed RNG on first 1000 I/O operations for collect initial entropy */
	if (lock_inc(&dc_io_count) < 1000) {
		cp_rand_reseed();
	}
	if (hook->flags & (F_DISABLE | F_FORMATTING)) {
		return dc_release_irp(hook, irp, STATUS_INVALID_DEVICE_STATE);
	}
	if (hook->flags & F_SYNC)
	{
		IoMarkIrpPending(irp);

		ExInterlockedInsertTailList(
			&hook->sync_irp_queue, &irp->Tail.Overlay.ListEntry, &hook->sync_req_lock);

		KeSetEvent(&hook->sync_req_event, IO_DISK_INCREMENT, FALSE);

		return STATUS_PENDING;
	}	
	if ((hook->flags & F_ENABLED) == 0)
	{
		/* probe for mount new volume */
		if ( (hook->flags & (F_UNSUPRT | F_NO_AUTO_MOUNT)) || (hook->mnt_probed != 0) ) 
		{
			if (IS_DEVICE_BLOCKED(hook) != 0) {
				return dc_release_irp(hook, irp, STATUS_ACCESS_DENIED);
			}
			return dc_forward_irp(hook, irp);
		}
		return dc_probe_mount(hook, irp);
	}	
	return io_encrypted_irp_io(hook, irp, 0);
}

void io_init()
{
	ExInitializeNPagedLookasideList(
		&io_context_mem, mm_alloc_success, NULL, 0, sizeof(io_context), '5_cd', 0);	
}

void io_free()
{
	ExDeleteNPagedLookasideList(&io_context_mem);
}