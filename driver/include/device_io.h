#ifndef _DEVICE_IO_H_
#define _DEVICE_IO_H_

NTSTATUS io_device_control(IN  PDEVICE_OBJECT DeviceObject,
	                       IN  ULONG          IoControlCode,
						   IN  PVOID          InputBuffer OPTIONAL,
						   IN  ULONG          InputBufferLength,
						   OUT PVOID          OutputBuffer OPTIONAL,
						   IN  ULONG          OutputBufferLength
						   );

HANDLE   io_open_device(wchar_t *dev_name);
int      io_hook_ioctl(dev_hook *hook, u32 code, void *p_in, u32 sz_in, void *p_out, u32 sz_out);
NTSTATUS io_device_rw(PDEVICE_OBJECT dev_obj, void *buff, u32 length, u64 offset, int is_read);
int      io_hook_rw(dev_hook *hook, void *buff, u32 length, u64 offset, int is_read);
int      io_hook_rw_skip_bads(dev_hook *hook, void *buff, u32 length, u64 offset, int is_read);

#endif