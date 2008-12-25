#ifndef _PNP_IRP_
#define _PNP_IRP_

NTSTATUS
  dc_pnp_irp(
     PDEVICE_OBJECT dev_obj, PIRP irp
	 );

NTSTATUS
  dc_add_device(
     PDRIVER_OBJECT drv_obj, PDEVICE_OBJECT dev_obj
	 );

#endif