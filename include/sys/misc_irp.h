#ifndef _MISC_IRP_
#define _MISC_IRP_

typedef struct _sync_data {
	KEVENT   sync_event;
	NTSTATUS status;

} sync_data;

NTSTATUS 
  dc_complete_irp(
     IN PIRP      irp,
	 IN NTSTATUS  status,
	 IN ULONG_PTR bytes
	 );

NTSTATUS
  dc_forward_irp(
     IN PDEVICE_OBJECT dev_obj, 
	 IN PIRP           irp
	 );

NTSTATUS
  dc_forward_irp_sync(
     IN PDEVICE_OBJECT dev_obj, 
	 IN PIRP           irp
	 );

NTSTATUS
  dc_create_close_irp(
     IN PDEVICE_OBJECT dev_obj, 
	 IN PIRP           irp
	 );

NTSTATUS
  dc_power_irp(
     IN PDEVICE_OBJECT dev_obj, 
	 IN PIRP           irp
	 );

#endif