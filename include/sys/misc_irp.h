#ifndef _MISC_IRP_
#define _MISC_IRP_

typedef struct _sync_data {
	KEVENT   sync_event;
	NTSTATUS status;

} sync_data;

NTSTATUS 
  dc_complete_irp(
    PIRP irp, NTSTATUS status, ULONG_PTR bytes
	);

NTSTATUS
  dc_forward_irp(
     PDEVICE_OBJECT dev_obj, PIRP irp
	 );

NTSTATUS
  dc_invalid_irp(
     PDEVICE_OBJECT dev_obj, PIRP irp
	 );

NTSTATUS
  dc_forward_irp_sync(
     PDEVICE_OBJECT dev_obj, PIRP irp
	 );

NTSTATUS
  dc_create_close_irp(
     PDEVICE_OBJECT dev_obj, PIRP irp
	 );

NTSTATUS
  dc_power_irp(
     PDEVICE_OBJECT dev_obj, PIRP irp
	 );

#endif