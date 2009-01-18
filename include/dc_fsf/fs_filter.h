#ifndef _FS_FILTER_H_
#define _FS_FILTER_H_

#include "sys\driver.h"

typedef aligned struct _dc_fs_hook {
	PDEVICE_OBJECT orig_dev;
	PDEVICE_OBJECT hook_dev;
	PDRIVER_OBJECT fs_drv;
	LIST_ENTRY     entry_list;
	u32            flags;
	u64            dcsys_id;
	PETHREAD       my_thread;
	wchar_t        dev_name[MAX_DEVICE + 1];

} dc_fs_hook;

NTSTATUS
  dc_fsf_create(
     PDEVICE_OBJECT dev_obj, PIRP irp
	 );

NTSTATUS
  dc_fsf_fsctl(
     PDEVICE_OBJECT dev_obj, PIRP irp
	 );

NTSTATUS
  dc_fsf_dirctl(
     PDEVICE_OBJECT dev_obj, PIRP irp
	 );

NTSTATUS dc_init_fsf();

void dc_fsf_set_flags(wchar_t *dev_name, u32 flags);
void dc_fsf_sync_all();

#endif