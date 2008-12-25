#include <ntifs.h>
#include "defines.h"
#include "driver.h"
#include "misc.h"
#include "crypto.h"
#include "fast_crypt.h"
#include "pkcs5.h"
#include "crc32.h"
#include "debug.h"

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
static int                   pool_num;
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

	for (i = 1; i < pool_num; i++)
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
	u32      m_cpu, timeout;
	
	mb_size = _align(io_size / pool_num, F_MIN_REQ);
	m_cpu   = (u32)((io_size / mb_size) + ((io_size % mb_size) != 0));
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
		timeout = DC_MEM_RETRY_TIMEOUT;

		do
		{
			if (req = ExAllocateFromNPagedLookasideList(&pool_req_mem)) {
				break;
			}

			dc_delay(DC_MEM_RETRY_TIME); timeout -= DC_MEM_RETRY_TIME;
		} while (timeout != 0);

		if (req == NULL) {
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

	if ( (len >= F_OP_THRESOLD) && (pool_num > 1) )
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
	for (i = 0; i < pool_num; i++) 
	{
		if (pool_data[i].h_thread)
		{
			KeSetEvent(
				&pool_data[i].io_msg_event, IO_NO_INCREMENT, FALSE);

			ZwWaitForSingleObject(
				pool_data[i].h_thread, FALSE, NULL);

			ZwClose(pool_data[i].h_thread);
		}
	}

	/* free memory */
	ExDeleteNPagedLookasideList(&pool_req_mem);
	mem_free(pool_data);
}

int dc_init_fast_crypt()
{
	KAFFINITY cpu_mask;
	int       resl, i;
	u32       n;

	/* get number of processors in system */
	cpu_mask = KeQueryActiveProcessors();
	pool_num = 0;

	for (n = 0; n < sizeof(KAFFINITY) * 8; n++) {
		pool_num += bittest(cpu_mask, n);
	}

	DbgMsg("%d processors detected\n", pool_num);

	/* allocate memory */
	if ( (pool_data = mem_alloc(sizeof(wt_data) * pool_num)) == NULL ) {
		return ST_NOMEM;
	}

	zeromem(pool_data, sizeof(wt_data) * pool_num);

	ExInitializeNPagedLookasideList(
		&pool_req_mem, NULL, NULL, 0, sizeof(wt_item), '3_cd', 0);

	pool_enabled = 1;

	/* start worker threads */
	for (i = 0; i < pool_num; i++)
	{
		InitializeListHead(
			&pool_data[i].io_list_head);

		KeInitializeSpinLock(
			&pool_data[i].io_spin_lock);

		KeInitializeEvent(
			&pool_data[i].io_msg_event, SynchronizationEvent, FALSE);

		resl = start_system_thread(
			dc_worker_thread, &pool_data[i], &pool_data[i].h_thread);

		if (resl != ST_OK) 
		{
			dc_free_fast_crypt();
			break;
		}
	}

	return resl;
}