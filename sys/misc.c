/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2007-2008 
    * ntldr <ntldr@freed0m.org> PGP key ID - 0xC48251EB4F8E4E6E
    *

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <ntifs.h>
#include <ntdddisk.h>
#include <stdio.h>
#include <stdarg.h>
#include "defines.h"
#include "driver.h"
#include "misc.h"
#include "devhook.h"
#include "fastmem.h"

#ifdef DBG_COM

#define   DEFAULT_BAUD_RATE    115200
#define   SER_RBR(x)   ((x)+0)
#define   SER_THR(x)   ((x)+0)
#define   SER_DLL(x)   ((x)+0)
#define   SER_IER(x)   ((x)+1)
#define   SER_DLM(x)   ((x)+1)
#define   SER_IIR(x)   ((x)+2)
#define   SER_LCR(x)   ((x)+3)
#define   SR_LCR_CS5 0x00
#define   SR_LCR_CS6 0x01
#define   SR_LCR_CS7 0x02
#define   SR_LCR_CS8 0x03
#define   SR_LCR_ST1 0x00
#define   SR_LCR_ST2 0x04
#define   SR_LCR_PNO 0x00
#define   SR_LCR_POD 0x08
#define   SR_LCR_PEV 0x18
#define   SR_LCR_PMK 0x28
#define   SR_LCR_PSP 0x38
#define   SR_LCR_BRK 0x40
#define   SR_LCR_DLAB 0x80
#define   SER_MCR(x)   ((x)+4)
#define   SR_MCR_DTR 0x01
#define   SR_MCR_RTS 0x02
#define   SER_LSR(x)   ((x)+5)
#define   SR_LSR_DR  0x01
#define   SR_LSR_TBE 0x20
#define   SER_MSR(x)   ((x)+6)
#define   SR_MSR_CTS 0x10
#define   SR_MSR_DSR 0x20
#define   SER_SCR(x)   ((x)+7)
#define   COM_BASE (0x3F8)
#endif

NTSTATUS 
  io_device_control(
    dev_hook *hook, u32 ctl_code, void *in_data, u32 in_size, void *out_data, u32 out_size
	)
{
	KEVENT          sync_event;
	IO_STATUS_BLOCK io_status;
	NTSTATUS        status;
	PIRP            irp;

	KeInitializeEvent(
		&sync_event, NotificationEvent, FALSE
		);

	irp = IoBuildDeviceIoControlRequest(
		ctl_code, hook->orig_dev, in_data, in_size, 
		out_data, out_size, FALSE, &sync_event, &io_status
		);

	if (irp != NULL)
	{
		status = IoCallDriver(hook->orig_dev, irp);

		if (status == STATUS_PENDING) {
			wait_object_infinity(&sync_event);				
			status = io_status.Status;
		}
	} else {
		status = STATUS_INSUFFICIENT_RESOURCES;
	}

	return status;
}

int io_fs_control(
	   HANDLE h_device, u32 ctl_code
	   )
{
	PFILE_OBJECT       f_obj;
	PDEVICE_OBJECT     dev_obj;
	IO_STATUS_BLOCK    io_status;
	PIO_STACK_LOCATION irp_sp;
	NTSTATUS           status;
	KEVENT             sync_event;
	PIRP               irp;
	int                resl;
	
	KeInitializeEvent(
		&sync_event, NotificationEvent, FALSE
		);

	f_obj = NULL; irp = NULL;
	do
	{
		status = ObReferenceObjectByHandle(
			h_device, 0, NULL, KernelMode, &f_obj, NULL
			);

		if (NT_SUCCESS(status) == FALSE) {
			resl = ST_ERROR; break;
		}

		dev_obj = IoGetRelatedDeviceObject(f_obj);

		irp = IoBuildDeviceIoControlRequest(
			ctl_code, dev_obj, NULL, 0, NULL, 0, FALSE, &sync_event, &io_status
			);

		if (irp == NULL) {
			resl = ST_NOMEM; break;
		}

		irp_sp                = IoGetNextIrpStackLocation(irp);
		irp_sp->FileObject    = f_obj;
		irp_sp->MajorFunction = IRP_MJ_FILE_SYSTEM_CONTROL;
		irp_sp->MinorFunction = IRP_MN_USER_FS_REQUEST;

		status = IoCallDriver(dev_obj, irp);

		if (status == STATUS_PENDING) {
			wait_object_infinity(&sync_event);
			status = io_status.Status;
		}

		if (NT_SUCCESS(status) != FALSE) {
			resl = ST_OK;
		} else {
			resl = ST_ERROR;
		}
	} while (0);

	if (f_obj != NULL) {
		ObDereferenceObject(f_obj);
	}

	return resl;
}


HANDLE io_open_volume(wchar_t *dev_name)
{
	UNICODE_STRING    u_name;
	OBJECT_ATTRIBUTES obj;
	IO_STATUS_BLOCK   io_status;
	HANDLE            handle;
	NTSTATUS          status;

	RtlInitUnicodeString(
		&u_name, dev_name
		);

	InitializeObjectAttributes(
		&obj, &u_name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL
		);

	status = ZwCreateFile(
		&handle, SYNCHRONIZE | GENERIC_READ, &obj, &io_status, NULL,
		FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0
		);

	if (NT_SUCCESS(status) == FALSE) {
		handle = NULL;
	}

	return handle;
}

int io_verify_hook_device(dev_hook *hook)
{
	NTSTATUS status;
	u32      chg_count;

	status = io_device_control(
		hook, IOCTL_DISK_CHECK_VERIFY, NULL, 0, &chg_count, sizeof(chg_count)
		);

	if (NT_SUCCESS(status) != FALSE) 
	{
		if (lock_xchg(&hook->chg_count, chg_count) != chg_count) {
			return ST_MEDIA_CHANGED;
		} else {
			return ST_OK;
		}
	} else {
		return ST_NO_MEDIA;
	}
}

NTSTATUS io_device_rw_block(
			dev_hook *hook, u32 func, void *buff, u32 size, u64 offset, u32 io_flags
			)
{
	IO_STATUS_BLOCK io_status;
	NTSTATUS        status;
	PIRP            irp;
	KEVENT          sync_event;
	void           *new_buf;
	
	new_buf = NULL;
	do
	{
		KeInitializeEvent(
			&sync_event, NotificationEvent,  FALSE
			);

		/* process IO with new memory buffer because 
		   IoBuildSynchronousFsdRequest fails for some system buffers   
		*/
		if ( (new_buf = fast_alloc(size)) == NULL ) {
			status = STATUS_INSUFFICIENT_RESOURCES; break;
		}

		if (func == IRP_MJ_WRITE) {
			fastcpy(new_buf, buff, size);
		}

		irp = IoBuildSynchronousFsdRequest(
			func, hook->orig_dev, new_buf, size, pv(&offset), &sync_event, &io_status
			);

		if (irp == NULL) {
			status = STATUS_INSUFFICIENT_RESOURCES; break;
		}

		IoGetNextIrpStackLocation(irp)->Flags |= io_flags;

		status = IoCallDriver(hook->orig_dev, irp);

		if (status == STATUS_PENDING) {
			wait_object_infinity(&sync_event);
			status = io_status.Status;
		}

		if ( (NT_SUCCESS(status) != FALSE) && (func == IRP_MJ_READ) ) {
			fastcpy(buff, new_buf, size);
		} 
	} while (0);

	if (new_buf != NULL) {
		fast_free(new_buf);
	}

	return status;
}

int dc_device_rw(
	  dev_hook *hook, u32 function, void *buff, u32 size, u64 offset
	  )
{
	STORAGE_ADAPTER_DESCRIPTOR sd;
	STORAGE_PROPERTY_QUERY     sq;
	u32                        blen;
	int                        resl;
	NTSTATUS                   status;
	u32                        max_trans;

	if (hook->max_chunk == 0) 
	{
		/* get MaximumTransferLength */
		sq.PropertyId = StorageAdapterProperty;
		sq.QueryType  = PropertyStandardQuery;

		status = io_device_control(
			hook, IOCTL_STORAGE_QUERY_PROPERTY, &sq, sizeof(sq), &sd, sizeof(sd)
			);

		if (NT_SUCCESS(status) != FALSE) {
			hook->max_chunk = sd.MaximumTransferLength;
			max_trans       = hook->max_chunk;			
		} else {
			max_trans = 32768;
		}
	} else {
		max_trans = hook->max_chunk;
	}

	for (resl = ST_OK; size != 0;)
	{
		blen = min(size, max_trans);
		
		status = io_device_rw_block(
			hook, function, buff, blen, offset, 0
			);

		if (NT_SUCCESS(status) == FALSE)
		{
			if ( (hook->flags & F_REMOVABLE) || (status == STATUS_VERIFY_REQUIRED) )
			{
				if ( (status == STATUS_NO_SUCH_DEVICE) || 
					 (status == STATUS_DEVICE_DOES_NOT_EXIST) || 
					 (status == STATUS_NO_MEDIA_IN_DEVICE) )
				{
					resl = ST_NO_MEDIA; break;
				}

				if ( (resl = io_verify_hook_device(hook)) != ST_OK ) {
					break;
				}
				
				status = io_device_rw_block(
					hook, function, buff, blen, offset, SL_OVERRIDE_VERIFY_VOLUME
					);

				if (NT_SUCCESS(status) == FALSE) {				
					resl = ST_RW_ERR; break;
				}
			} else {
				resl = ST_RW_ERR; break;
			}
		}

		buff  = p8(buff) + blen; 
		size -= blen; offset += blen;
	}

	return resl;
}

void wait_object_infinity(void *wait_obj)
{
	KeWaitForSingleObject(
		wait_obj, Executive, KernelMode, FALSE, NULL
		);
}


int start_system_thread(
		PKSTART_ROUTINE thread_start,
		PVOID           context,
		HANDLE         *handle
		)
{
	OBJECT_ATTRIBUTES obj;
	HANDLE            h_thread;
	NTSTATUS          status;
	int               resl;

	InitializeObjectAttributes(
		&obj, NULL, OBJ_KERNEL_HANDLE, NULL, NULL
		);

	status = PsCreateSystemThread(
		&h_thread, THREAD_ALL_ACCESS, &obj, NULL, NULL, thread_start, context
		);

	if (NT_SUCCESS(status)) 
	{
		if (handle != NULL) {
			handle[0] = h_thread;
		} else {
			ZwClose(h_thread);
		}
		resl = ST_OK;		
	} else {
		resl = ST_ERR_THREAD;
	}

	return resl;
}


int dc_set_security(
	  PDEVICE_OBJECT device
	  )
{
	SID_IDENTIFIER_AUTHORITY autort = SECURITY_NT_AUTHORITY;
	PSID                     adm_sid;
	PSID                     sys_sid;
	PACL                     sys_acl;
	HANDLE                   handle;
	ULONG                    dacl_sz;
	NTSTATUS                 status;
	SECURITY_DESCRIPTOR      sc_desc;
	int                      resl;

	adm_sid = NULL; sys_sid = NULL; 
	sys_acl = NULL; handle = NULL;

	do
	{
		adm_sid = mem_alloc(RtlLengthRequiredSid(2));
		sys_sid = mem_alloc(RtlLengthRequiredSid(1));

		if ( (adm_sid == NULL) || (sys_sid == NULL) ) {
			resl = ST_NOMEM; break;
		}

		RtlInitializeSid(adm_sid, &autort, 2); 
		RtlInitializeSid(sys_sid, &autort, 1);

		RtlSubAuthoritySid(adm_sid, 0)[0] = SECURITY_BUILTIN_DOMAIN_RID;
		RtlSubAuthoritySid(adm_sid, 1)[0] = DOMAIN_ALIAS_RID_ADMINS;
		RtlSubAuthoritySid(sys_sid, 0)[0] = SECURITY_LOCAL_SYSTEM_RID;

		dacl_sz = sizeof(ACL) + (2 * sizeof(ACCESS_ALLOWED_ACE)) +
			SeLengthSid(adm_sid) + SeLengthSid(sys_sid) + 8;
		
		if ( (sys_acl = mem_alloc(dacl_sz)) == NULL) {
			resl = ST_NOMEM; break;
		}

		status = RtlCreateAcl(
			sys_acl, dacl_sz, ACL_REVISION
			);

		if (NT_SUCCESS(status) == FALSE) {
			resl = ST_ERROR; break;
		}

		status = RtlAddAccessAllowedAce(
			sys_acl, ACL_REVISION, GENERIC_ALL, sys_sid
			);

		if (NT_SUCCESS(status) == FALSE) {
			resl = ST_ERROR; break;
		}

		status = RtlAddAccessAllowedAce(
			sys_acl, ACL_REVISION, GENERIC_ALL, adm_sid
			);

		if (NT_SUCCESS(status) == FALSE) {
			resl = ST_ERROR; break;
		}

		status = RtlCreateSecurityDescriptor( 
			&sc_desc, SECURITY_DESCRIPTOR_REVISION1 
			);

		if (NT_SUCCESS(status) == FALSE) {
			resl = ST_ERROR; break;
		}

		status = RtlSetDaclSecurityDescriptor( 
			&sc_desc, TRUE, sys_acl, FALSE 
			);

		if (NT_SUCCESS(status) == FALSE) {
			resl = ST_ERROR; break;
		}

		status = ObOpenObjectByPointer(
			device, OBJ_KERNEL_HANDLE, NULL, GENERIC_ALL, NULL, KernelMode, &handle
			);

		if (NT_SUCCESS(status) == FALSE) {
			handle = NULL; resl = ST_ERROR; break;
		}
		
		status = ZwSetSecurityObject(
			handle, DACL_SECURITY_INFORMATION, &sc_desc
			);

		if (NT_SUCCESS(status) != FALSE) {
			resl = ST_OK;
		} else {
			resl = ST_ERROR;
		}
	} while (0);

	if (handle != NULL) {
		ZwClose(handle);
	}

	if (sys_acl != NULL) {
		mem_free(sys_acl);
	}

	if (adm_sid != NULL) {
		mem_free(adm_sid);
	}

	if (sys_sid != NULL) {
		mem_free(sys_sid);
	}

	return resl;
}

int dc_resolve_link(
	  wchar_t *sym_link, wchar_t *target, u16 length
	  )
{
	UNICODE_STRING    u_name;
	OBJECT_ATTRIBUTES obj;
	NTSTATUS          status;
	HANDLE            handle;
	int               resl;

	RtlInitUnicodeString(
		&u_name, sym_link
		);

	InitializeObjectAttributes(
		&obj, &u_name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL
		);

	do
	{
		status = ZwOpenSymbolicLinkObject(
			&handle, GENERIC_READ, &obj 
			);

		if (NT_SUCCESS(status) == FALSE) {
			handle = NULL; resl = ST_ERROR; break;
		}

		u_name.Buffer        = target;
		u_name.Length        = 0;
		u_name.MaximumLength = length - 2;

		status = ZwQuerySymbolicLinkObject(
			handle, &u_name, NULL 
			);

		if (NT_SUCCESS(status) == FALSE) {
			resl = ST_ERROR; break;
		} else {
			resl = ST_OK;
		}

		target[u_name.Length >> 1] = 0;
	} while (0);

	if (handle != NULL) {
		ZwClose(handle);
	}

	return resl;
}

int dc_get_mount_point(
      dev_hook *hook, wchar_t *buffer, u16 length
	  )
{
	NTSTATUS       status;
	UNICODE_STRING name;
	int            resl;

	status = RtlVolumeDeviceToDosName(
		hook->orig_dev, &name
		);

	buffer[0] = 0; resl = ST_ERROR;

	if (NT_SUCCESS(status) != FALSE) 
	{
		if (name.Length < length) {
			memcpy(buffer, name.Buffer, name.Length);
			buffer[name.Length >> 1] = 0; 
			resl = ST_OK;
		} 
		ExFreePool(name.Buffer);
	}

	return resl;
}

#ifdef DBG_COM

void dc_com_dbg_init()
{
	u32 divisor;
	u8  lcr;
	
	/* set baud rate and data format (8N1) */

	/*  turn on DTR and RTS  */
    WRITE_PORT_UCHAR(pv(SER_MCR(COM_BASE)), SR_MCR_DTR | SR_MCR_RTS);

	/* set DLAB */
    lcr = READ_PORT_UCHAR(pv(SER_LCR(COM_BASE))) | SR_LCR_DLAB;
    WRITE_PORT_UCHAR(pv(SER_LCR(COM_BASE)), lcr);

	/* set baud rate */
    divisor = 115200 / DEFAULT_BAUD_RATE;
    WRITE_PORT_UCHAR(pv(SER_DLL(COM_BASE)), divisor & 0xff);
    WRITE_PORT_UCHAR(pv(SER_DLM(COM_BASE)), (divisor >> 8) & 0xff);

	/* reset DLAB and set 8N1 format */
    WRITE_PORT_UCHAR(pv(SER_LCR(COM_BASE)), 
		SR_LCR_CS8 | SR_LCR_ST1 | SR_LCR_PNO);

	/* read junk out of the RBR */
	READ_PORT_UCHAR(pv(SER_RBR(COM_BASE)));
}

void com_putchar(char ch) 
{
	if (ch == '\n') {
		com_putchar('\r');
	}

	while ((READ_PORT_UCHAR (pv(SER_LSR(COM_BASE))) & SR_LSR_TBE) == 0);

	WRITE_PORT_UCHAR(pv(SER_THR(COM_BASE)), ch);
}

void com_print(char *format, ...)
{
	char    dbg_msg[MAX_PATH];
	char   *msg = dbg_msg;
	va_list args;

	va_start(args, format);

	_vsnprintf(
		dbg_msg, 
		sizeof(dbg_msg), 
		format, 
		args
		);

	va_end(args);

	while (*msg) {
		com_putchar(*msg++);
	}	
}
#endif
