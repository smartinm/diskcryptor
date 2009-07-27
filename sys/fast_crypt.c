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
#include "driver.h"
#include "misc.h"
#include "crypto.h"
#include "fast_crypt.h"
#include "pkcs5.h"
#include "crc32.h"
#include "debug.h"
#include "misc_mem.h"

typedef struct _wt_item {
	LIST_ENTRY       entry;
	int              operation;
	struct _wt_item *main;
	u32              blocks;
	callback_ex      on_complete;
	void            *param1;
	void            *param2;

	dc_key  *key;
	u8      *src_buf;
	u8      *dst_buf;
	u64      offset;
	size_t   length;

} wt_item;

typedef struct _wt_data {
	KEVENT     io_msg_event;
	LIST_ENTRY io_list_head;
	KSPIN_LOCK io_spin_lock;
	HANDLE     h_thread;
	u32        io_count;

} wt_data;

static NPAGED_LOOKASIDE_LIST pool_req_mem;
static wt_data              *pool_data;
static wt_data              *pool_free;
static int                   pool_enabled;

static void dc_worker_thread(wt_data *w_data)
{
	PLIST_ENTRY entry;
	wt_item    *c_req, *m_req;

	do
	{
		wait_object_infinity(&w_data->io_msg_event);

		do
		{
			if (entry = ExInterlockedRemoveHeadList(&w_data->io_list_head, &w_data->io_spin_lock))
			{
				c_req = CONTAINING_RECORD(entry, wt_item, entry);
				m_req = c_req->main;

				if (m_req->operation == F_OP_ENCRYPT)
				{
					dc_cipher_encrypt(
						c_req->src_buf, c_req->dst_buf, c_req->length, c_req->offset, c_req->key);
				} else 
				{
					dc_cipher_decrypt(
						c_req->src_buf, c_req->dst_buf, c_req->length, c_req->offset, c_req->key);
				}

				if (lock_dec(&m_req->blocks) == 0) {
					m_req->on_complete(m_req->param1, m_req->param2);
					ExFreeToNPagedLookasideList(&pool_req_mem, m_req);
				}

				/* free work item */
				if (c_req != m_req) {
					ExFreeToNPagedLookasideList(&pool_req_mem, c_req);
				}

				lock_dec(&w_data->io_count);
			}
		} while (entry != NULL);
	} while (pool_enabled != 0);

	PsTerminateSystemThread(STATUS_SUCCESS);
}

static void dc_send_work_item(wt_item *req)
{
	wt_data *thread;
	int      i;

	thread = &pool_data[0];

	for (i = 1; i < dc_cpu_count; i++)
	{
		if (pool_data[i].io_count < thread->io_count ) {
			thread = &pool_data[i];
		}
	}

	lock_inc(&thread->io_count);

	ExInterlockedInsertTailList (
		&thread->io_list_head, &req->entry, &thread->io_spin_lock);

	KeSetEvent(
		&thread->io_msg_event, IO_DISK_INCREMENT, FALSE);
}

int dc_parallelized_crypt(
	  int  op_type, dc_key *key,
	  u8  *io_src, u8 *io_dst, size_t io_size, u64 io_offs,
	  callback_ex on_complete, void *param1, void *param2
	  )
{
	wt_item *req, *main_req;
	size_t   mb_size, cb_size;
	size_t   x_off;
	u32      m_cpu;
	
	mb_size = _align(io_size / dc_cpu_count, F_MIN_REQ);
	m_cpu   = d32((io_size / mb_size) + ((io_size % mb_size) != 0));
	x_off   = 0;
		
goto begin;
	do
	{
		x_off += cb_size, io_size -= cb_size;
		
		if (io_size == 0) {
			break;
		}
begin:;		
		cb_size = min(mb_size, io_size);		
		
		if ( (req = ExAllocateFromNPagedLookasideList(&pool_req_mem)) == NULL) {
			return 0;
		}

		if (x_off == 0) 
		{
			main_req         = req;
			req->operation   = op_type;
			req->blocks      = m_cpu;
			req->on_complete = on_complete;
			req->param1      = param1;
			req->param2      = param2;
		}

		req->main    = main_req;			
		req->key     = key;
		req->src_buf = io_src + x_off;
		req->dst_buf = io_dst + x_off;
		req->offset  = io_offs + x_off;
		req->length  = cb_size;

		dc_send_work_item(req);
	} while (1);

	return 1;
}

static void dc_fast_op_complete(PKEVENT sync_event, void *param)
{
	KeSetEvent(sync_event, IO_NO_INCREMENT, FALSE);
}

void dc_fast_crypt_op(
	   int op, u8 *in, u8 *out, size_t len, u64 offset, dc_key *key
	   )
{
	KEVENT sync_event;
	int    succs;

	if ( (len >= F_OP_THRESOLD) && (dc_cpu_count > 1) )
	{
		KeInitializeEvent(
			&sync_event, NotificationEvent, FALSE);

		succs = dc_parallelized_crypt(
			op, key, in, out, len, offset, dc_fast_op_complete, &sync_event, NULL
			);

		if (succs != 0) {
			wait_object_infinity(&sync_event);		
		} else {
			goto docrypt;
		}
	} else 
	{
docrypt:;
		if (op == F_OP_ENCRYPT) {
			dc_cipher_encrypt(in, out, len, offset, key);
		} else {
			dc_cipher_decrypt(in, out, len, offset, key);
		}
	}
}

void dc_free_fast_crypt()
{
	int i;

	/* disable thread pool */
	if (lock_xchg(&pool_enabled, 0) == 0) {
		return;
	}

	/* stop all threads */
	for (i = 0; i < dc_cpu_count; i++) 
	{
		if (pool_data[i].h_thread != NULL) {
			KeSetEvent(&pool_data[i].io_msg_event, IO_NO_INCREMENT, FALSE);
			ZwWaitForSingleObject(pool_data[i].h_thread, FALSE, NULL);
			ZwClose(pool_data[i].h_thread);
		}
	}

	/* free memory */
	ExDeleteNPagedLookasideList(&pool_req_mem);
	mem_free(pool_data);
}

int dc_init_fast_crypt()
{
	int resl, i;
	
	/* allocate memory */
	if ( (pool_data = mem_alloc(sizeof(wt_data) * dc_cpu_count)) == NULL ) {
		return ST_NOMEM;
	}
	zeromem(pool_data, sizeof(wt_data) * dc_cpu_count);

	ExInitializeNPagedLookasideList(
		&pool_req_mem, mm_alloc_success, NULL, 0, sizeof(wt_item), '3_cd', 0);

	pool_enabled = 1;

	/* start worker threads */
	for (i = 0; i < dc_cpu_count; i++)
	{
		InitializeListHead(&pool_data[i].io_list_head);
		KeInitializeSpinLock(&pool_data[i].io_spin_lock);

		KeInitializeEvent(
			&pool_data[i].io_msg_event, SynchronizationEvent, FALSE);

		resl = start_system_thread(
			dc_worker_thread, &pool_data[i], &pool_data[i].h_thread);

		if (resl != ST_OK) {
			dc_free_fast_crypt(); break;
		}
	}

	return resl;
}