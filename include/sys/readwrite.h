#ifndef _READWRITE_
#define _READWRITE_

typedef aligned struct _io_packet
{
	PVOID     old_buf;
	PMDL      old_mdl;	
	CHAR      data[];
	
} io_packet;

NTSTATUS 
  dc_read_irp(
     IN dev_hook *hook,
	 IN PIRP      irp
	 );

NTSTATUS 
  dc_write_irp(
     IN dev_hook *hook,
	 IN PIRP      irp
	 );

NTSTATUS
  dc_read_write_irp(
     IN PDEVICE_OBJECT dev_obj, 
	 IN PIRP           irp
	 );


#endif