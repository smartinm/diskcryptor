#ifndef _READWRITE_
#define _READWRITE_

NTSTATUS 
  dc_sync_encrypted_io(
     dev_hook *hook, u8 *buff, u32 size, u64 offset, u32 flags, u32 funct
	 );

NTSTATUS dc_read_write_irp(dev_hook *hook, PIRP irp);

void dc_sync_irp_io(dev_hook *hook, PIRP irp);
int  dc_start_rw_thread(dev_hook *hook);
void dc_stop_rw_thread(dev_hook *hook);
void dc_init_rw();
void dc_free_rw();


#endif
