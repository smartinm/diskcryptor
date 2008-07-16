#ifndef _IO_CONTROL_
#define _IO_CONTROL_

NTSTATUS
  dc_io_control_irp(
     IN PDEVICE_OBJECT dev_obj, 
	 IN PIRP           irp
	 );

#endif