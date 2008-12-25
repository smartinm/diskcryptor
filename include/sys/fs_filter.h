#ifndef _FS_FILTER_H_
#define _FS_FILTER_H_

NTSTATUS
  dc_fsf_create(
     PDEVICE_OBJECT dev_obj, PIRP irp
	 );

NTSTATUS
  dc_fsf_fsctl(
     PDEVICE_OBJECT dev_obj, PIRP irp
	 );

void dc_fsf_sync_flags(wchar_t *dev_name);
void dc_init_fsf();

#endif