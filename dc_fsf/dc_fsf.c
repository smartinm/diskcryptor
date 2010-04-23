/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2009
    * ntldr <ntldr@diskcryptor.net> PGP key ID - 0xC48251EB4F8E4E6E
    *

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 3 as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <ntifs.h>
#include <stdlib.h>
#include <stdio.h>
#include "defines.h"
#include "fs_filter.h"
#include "misc.h"
#include "dc_fsf.h"

PDRIVER_OBJECT dc_fsf_driver;
PDEVICE_OBJECT dc_fsf_device;
GETDEVFLAGS    dc_get_flags;
u32            dc_conf_flags;

static void dc_fsf_set_conf(u32 conf)
{
	dc_conf_flags = conf;
}

static
NTSTATUS dc_fsf_control_irp(PDEVICE_OBJECT dev_obj, PIRP irp)
{
	PIO_STACK_LOCATION irp_sp;
	fsf_functl        *data;
	u32                in_len, out_len;
	u32                code;

	if (dev_obj != dc_fsf_device) {
		return dc_forward_irp(dev_obj, irp);
	}

	irp_sp  = IoGetCurrentIrpStackLocation(irp);
	data    = irp->AssociatedIrp.SystemBuffer;
	in_len  = irp_sp->Parameters.DeviceIoControl.InputBufferLength;
	out_len = irp_sp->Parameters.DeviceIoControl.OutputBufferLength;
	code    = irp_sp->Parameters.DeviceIoControl.IoControlCode;

	if ( (code != DC_FSF_FUNCTL) || (irp->RequestorMode != KernelMode) ||
		(in_len != sizeof(fsf_functl)) || (out_len != sizeof(fsf_functl)) )
	{
		return dc_complete_irp(irp, STATUS_INVALID_DEVICE_REQUEST, 0);
	}

	dc_get_flags    = data->get_flags;
	data->set_flags = dc_fsf_set_flags;
	data->set_conf  = dc_fsf_set_conf;

	if (dc_get_flags != NULL) {
		dc_fsf_sync_all();
	}

	return dc_complete_irp(irp, STATUS_SUCCESS, sizeof(fsf_functl));
}

static
NTSTATUS dc_fsf_create_irp(PDEVICE_OBJECT dev_obj, PIRP irp)
{
	if (dev_obj != dc_fsf_device) {
		return dc_fsf_create(dev_obj, irp);
	}

	return dc_complete_irp(irp, STATUS_SUCCESS, 0);
}

static
NTSTATUS dc_fsf_close_irp(PDEVICE_OBJECT dev_obj, PIRP irp)
{
	if (dev_obj != dc_fsf_device) {
		return dc_forward_irp(dev_obj, irp);
	}

	return dc_complete_irp(irp, STATUS_SUCCESS, 0);
}

NTSTATUS 
  DriverEntry(
	IN PDRIVER_OBJECT  DriverObject,
    IN PUNICODE_STRING RegistryPath
	)
{
	UNICODE_STRING dev_name_u;
	NTSTATUS       status;
	u32            num;

	dc_fsf_driver = DriverObject;

	for (num = 0; num <= IRP_MJ_MAXIMUM_FUNCTION; num++) {
		DriverObject->MajorFunction[num] = dc_forward_irp;
	}

	DriverObject->MajorFunction[IRP_MJ_CREATE]              = dc_fsf_create_irp;
	DriverObject->MajorFunction[IRP_MJ_CLOSE]               = dc_fsf_close_irp;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]      = dc_fsf_control_irp;
	DriverObject->MajorFunction[IRP_MJ_DIRECTORY_CONTROL]   = dc_fsf_dirctl;
	DriverObject->MajorFunction[IRP_MJ_FILE_SYSTEM_CONTROL] = dc_fsf_fsctl;

	RtlInitUnicodeString(&dev_name_u, DC_FSF_DEVICE_NAME);

	status = IoCreateDevice(
		DriverObject, 0, &dev_name_u, FILE_DEVICE_UNKNOWN, 0, FALSE, &dc_fsf_device);

	if (NT_SUCCESS(status) == FALSE) {
		return status;
	}

	dc_fsf_device->Flags |= DO_BUFFERED_IO;
	dc_fsf_device->Flags &= ~DO_DEVICE_INITIALIZING;

	status = dc_init_fsf();

	if (NT_SUCCESS(status) == FALSE) {
		IoDeleteDevice(dc_fsf_device);
	}

	return status;
}

