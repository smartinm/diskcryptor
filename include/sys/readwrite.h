#ifndef _READWRITE_
#define _READWRITE_

NTSTATUS 
  dc_sync_encrypted_io(
     dev_hook *hook, u8 *buff, u32 size, u64 offset, u32 flags, u32 funct
	 );

NTSTATUS dc_read_write_irp(dev_hook *hook, PIRP irp);

void dc_sync_irp_io(dev_hook *hook, PIRP irp);


#endif
