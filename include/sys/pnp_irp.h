#ifndef _PNP_IRP_
#define _PNP_IRP_

NTSTATUS
  dc_pnp_irp(
     IN PDEVICE_OBJECT dev_obj, 
	 IN PIRP           irp
	 );

NTSTATUS
   dc_add_device(
      IN PDRIVER_OBJECT drv_obj,
      IN PDEVICE_OBJECT dev_obj
      );

#endif