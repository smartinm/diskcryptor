#ifndef _MISC_H_
#define _MISC_H_

void wait_object_infinity(void *wait_obj);

NTSTATUS 
  dc_complete_irp(
    PIRP irp, NTSTATUS status, ULONG_PTR bytes
	);

NTSTATUS
  dc_forward_irp(
     PDEVICE_OBJECT dev_obj, PIRP irp
	 );

NTSTATUS
  dc_forward_irp_sync(
     PDEVICE_OBJECT dev_obj, PIRP irp
	 );

HANDLE dc_open_storage(wchar_t *dev_name);

void dc_query_object_name(
	   void *object, wchar_t *buffer, u16 length
	   );

#endif