/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2009 
    * ntldr <PGP key ID - 0xC48251EB4F8E4E6E>
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
#include <stdio.h>
#include "defines.h"
#include "misc.h"
#include "fs_filter.h"

extern PDEVICE_OBJECT dc_fsf_device;

void wait_object_infinity(void *wait_obj)
{
	KeWaitForSingleObject(
		wait_obj, Executive, KernelMode, FALSE, NULL);
}

NTSTATUS 
  dc_complete_irp(
    PIRP irp, NTSTATUS status, ULONG_PTR bytes
	)
{
	irp->IoStatus.Status      = status;
	irp->IoStatus.Information = bytes;

	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return status;
}

NTSTATUS
  dc_forward_irp(
     PDEVICE_OBJECT dev_obj, PIRP irp
	 )
{
	dc_fs_hook *hook = dev_obj->DeviceExtension;
	
	if (dev_obj == dc_fsf_device) {
		return dc_complete_irp(irp, STATUS_INVALID_DEVICE_REQUEST, 0);
	} else {
		IoSkipCurrentIrpStackLocation(irp);
		return IoCallDriver(hook->orig_dev, irp);
	}
}

void dc_query_object_name(
	   void *object, wchar_t *buffer, u16 length
	   )
{
	u8                       buf[256];
	POBJECT_NAME_INFORMATION inf = pv(buf);
	u32                      bytes;
	NTSTATUS                 status;

	status = ObQueryNameString(
		object, inf, sizeof(buf), &bytes);

	if (NT_SUCCESS(status) != FALSE) {
		bytes = min(length, inf->Name.Length);
		mincpy(buffer, inf->Name.Buffer, bytes);
		buffer[bytes >> 1] = 0;
	} else {
		buffer[0] = 0;
	}
}

HANDLE dc_open_storage(wchar_t *dev_name)
{
	UNICODE_STRING    u_name;
	OBJECT_ATTRIBUTES obj;
	IO_STATUS_BLOCK   iosb;
	wchar_t           f_name[MAX_PATH];
	HANDLE            h_file = NULL;
	
	_snwprintf(
		f_name, sizeof_w(f_name), L"%s\\$dcsys$", dev_name);

	f_name[sizeof_w(f_name) - 1] = 0;

	RtlInitUnicodeString(&u_name, f_name);

	InitializeObjectAttributes(
		&obj, &u_name, OBJ_KERNEL_HANDLE, NULL, NULL);

	ZwCreateFile(
		&h_file, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &obj, &iosb, NULL, 0, 0, FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);
	
	return h_file;
}

static
NTSTATUS
  dc_sync_complete(
    PDEVICE_OBJECT dev_obj, PIRP irp, PKEVENT sync
	)
{
	KeSetEvent(sync, IO_NO_INCREMENT, FALSE);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
  dc_forward_irp_sync(
     PDEVICE_OBJECT dev_obj, PIRP irp
	 )
{
	dc_fs_hook *fs_h = dev_obj->DeviceExtension;
	KEVENT      sync;
	NTSTATUS    status;

	KeInitializeEvent(
		&sync, NotificationEvent, FALSE);

	IoCopyCurrentIrpStackLocationToNext(irp);

    IoSetCompletionRoutine(
		irp, dc_sync_complete, &sync, TRUE, TRUE, TRUE);

	status = IoCallDriver(fs_h->orig_dev, irp);

    if (status == STATUS_PENDING) {
		wait_object_infinity(&sync);
		status = irp->IoStatus.Status;
    }

	return status;
}
