#ifndef _DEVHOOK_
#define _DEVHOOK_

#include <ntdddisk.h>
#include <ntddstor.h>
#include <ntddvol.h>
#include "defines.h"
#include "crypto.h"
#include "driver.h"
#include "data_wipe.h"


typedef aligned struct _dev_hook
{
	PDEVICE_OBJECT orig_dev;
	PDEVICE_OBJECT pdo_dev;
	PDEVICE_OBJECT hook_dev;
	IO_REMOVE_LOCK remv_lock;
	LIST_ENTRY     hooks_list;

	wchar_t        dev_name[MAX_DEVICE + 1];

	dc_key         dsk_key;

	u32            flags;
	u32            disk_id;
	u16            vf_version;   /* volume format version */

	KEVENT         paging_count_event;
	LONG           paging_count;
	
	u32            chg_count;    /* media changes count */
	u32            max_chunk;
	int            mnt_probed;
	int            mnt_probe_cnt;

	crypt_info     crypt;
	wipe_ctx       wp_ctx;
	rnd_ctx       *fmt_rnd;

	u8            *tmp_buff;
	dc_key        *hdr_key;
	dc_key        *tmp_key;
	dc_header      tmp_header;
    dc_header      old_header;
	char           tmp_pass[MAX_PASSWORD + 1];

	u64            tmp_size;
	u64            dsk_size;
	u64            use_size;
	u64            tmp_save_off;

	KMUTEX         busy_lock;

	int            sync_init_type;
	int            sync_init_status; /* sync mode init status */

	/* fields for synchronous requests processing */
	LIST_ENTRY     sync_req_queue;
	LIST_ENTRY     sync_irp_queue;
	KSPIN_LOCK     sync_req_lock;
	KEVENT         sync_req_event;
	KEVENT         sync_enter_event;

} dev_hook;

dev_hook *dc_find_hook(wchar_t *dev_name);

void dc_insert_hook(dev_hook *hook);
void dc_remove_hook(dev_hook *hook);

void dc_reference_hook(dev_hook *hook);
void dc_deref_hook(dev_hook *hook);

dev_hook *dc_first_hook();
dev_hook *dc_next_hook(dev_hook *hook);

void dc_init_devhook();

#endif