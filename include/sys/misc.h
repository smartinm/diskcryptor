#ifndef _MISC_
#define _MISC_

#include "devhook.h"

NTSTATUS 
  io_device_control(
    dev_hook *hook, u32 ctl_code, void *in_data, u32 in_size, void *out_data, u32 out_size
	);

HANDLE io_open_volume(wchar_t *dev_name);

NTSTATUS io_device_rw_block(
			PDEVICE_OBJECT device, u32 func, void *buff, u32 size, u64 offset, u32 io_flags
			);

int io_verify_hook_device(dev_hook *hook);

int dc_device_rw(
	  dev_hook *hook, u32 function, void *buff, u32 size, u64 offset
	  );

void wait_object_infinity(void *wait_obj);

int start_system_thread(
		PKSTART_ROUTINE thread_start,
		PVOID           context,
		HANDLE         *handle
		);

int dc_set_default_security(HANDLE h_object);

int dc_resolve_link(
	  wchar_t *sym_link, wchar_t *target, u16 length
	  );

int dc_get_mount_point(
      dev_hook *hook, wchar_t *buffer, u16 length
	  );

void dc_query_object_name(
	   void *object, wchar_t *buffer, u16 length
	   );

u32   intersect(u64 *i_st, u64 start1, u32 size1, u64 start2, u64 size2);
void  dc_delay(u32 msecs);
void *dc_map_mdl_with_retry(PMDL mdl);
PMDL  dc_allocate_mdl_with_retry(void *data, u32 size);


#endif