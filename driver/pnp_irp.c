/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2007-2008 
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
#include "defines.h"
#include "devhook.h"
#include "driver.h"
#include "misc.h"
#include "misc_irp.h"
#include "mount.h"
#include "prng.h"
#include "dump_hook.h"
#include "enc_dec.h"
#include "debug.h"
#include "pnp_irp.h"

static
NTSTATUS dc_pnp_usage_irp(dev_hook *hook, PIRP irp)
{
	DEVICE_USAGE_NOTIFICATION_TYPE usage;
	PIO_STACK_LOCATION             irp_sp;
	NTSTATUS                       status;
	int                            setpg;
	int                            complete;
	BOOLEAN                        inpath;
	PDEVICE_OBJECT                 dev_obj;

	dev_obj  = hook->hook_dev;
	irp_sp   = IoGetCurrentIrpStackLocation(irp);
	usage    = irp_sp->Parameters.UsageNotification.Type;
	inpath   = irp_sp->Parameters.UsageNotification.InPath;
	complete = 0;

	if (usage != DeviceUsageTypePaging)
	{
		if (inpath) {
			dump_usage_notify(hook, usage);
		}

		if (usage == DeviceUsageTypeHibernation) 
		{
			if ( (dc_is_vista_or_later != 0) && (dump_is_pverent_hibernate() != 0) ) {
				/* preventing hibernate if memory contain sensitive data */
				status = STATUS_UNSUCCESSFUL; complete = 1;
			}
			
			if (inpath) {
				hook->flags |= F_HIBERNATE;
			} else {
				hook->flags &= ~F_HIBERNATE;
			}			
		}

		if (complete != 0) {
			status = dc_complete_irp(irp, status, 0);
		} else {
			IoSkipCurrentIrpStackLocation(irp);
			status = IoCallDriver(hook->orig_dev, irp);
		}
	} else
	{
		/* wait on the paging path event */
		wait_object_infinity(&hook->paging_count_event);

		/* 
		   if removing last paging device, need to set DO_POWER_PAGABLE
		   bit here, and possible re-set it below on failure.
		*/
		setpg = 0;

		if ( (inpath == FALSE) && (hook->paging_count == 1) ) {
			dev_obj->Flags |= DO_POWER_PAGABLE; setpg = 1;
		}

		/* send the irp synchronously */
		status = dc_forward_irp_sync(hook, irp);

		/* 
		   now deal with the failure and success cases.
		   note that we are not allowed to fail the irp
		   once it is sent to the lower drivers.
		*/

		if (NT_SUCCESS(status)) 
		{
			IoAdjustPagingPathCount(&hook->paging_count, inpath);

			if ( (inpath == TRUE) && (hook->paging_count == 1) ) {
				/* first paging file addition */
				dev_obj->Flags &= ~DO_POWER_PAGABLE;
			}
		} else {
			/* cleanup the changes done above */
			if (setpg == 1) {
				dev_obj->Flags &= ~DO_POWER_PAGABLE;
			}
		}

		/* set the event so the next one can occur. */

		KeSetEvent(
			&hook->paging_count_event, IO_NO_INCREMENT, FALSE);

		/* and complete the irp */
		dc_complete_irp(
			irp, status, irp->IoStatus.Information);
	}

	IoReleaseRemoveLock(&hook->remv_lock, irp);

	return status;
}

NTSTATUS dc_pnp_irp(dev_hook *hook, PIRP irp)
{
	PIO_STACK_LOCATION irp_sp;
	NTSTATUS           status;
	int                is_sync;
		
	irp_sp  = IoGetCurrentIrpStackLocation(irp);
	is_sync = 0;
	
	switch (irp_sp->MinorFunction)
	{
		case IRP_MN_REMOVE_DEVICE:
		case IRP_MN_SURPRISE_REMOVAL:
			{
				dc_set_pnp_state(hook, Deleted);
				IoReleaseRemoveLockAndWait(&hook->remv_lock, irp);

				DbgMsg("remove device %ws\n", hook->dev_name);

				IoSkipCurrentIrpStackLocation(irp);
				status = IoCallDriver(hook->orig_dev, irp);
				
				dc_process_unmount(hook, MF_NOFSCTL);
				dc_remove_hook(hook);

				IoDetachDevice(hook->orig_dev);
				IoDeleteDevice(hook->hook_dev);
			}
		break;
		case IRP_MN_DEVICE_USAGE_NOTIFICATION:
			{
				status = dc_pnp_usage_irp(hook, irp);
			}
		break;
		case IRP_MN_START_DEVICE:
			{
				status = dc_forward_irp_sync(hook, irp);

				if (NT_SUCCESS(status) != FALSE)
				{
					if (hook->orig_dev->Characteristics & FILE_REMOVABLE_MEDIA) {
						hook->hook_dev->Characteristics |= FILE_REMOVABLE_MEDIA;
						hook->flags |= F_REMOVABLE;
					}
					dc_set_pnp_state(hook, Started);
				}
				is_sync = 1;
			}
		break;
		case IRP_MN_STOP_DEVICE:
			{
				dc_set_pnp_state(hook, Stopped);

				status = dc_forward_irp_sync(hook, irp);

				if ( (NT_SUCCESS(status) == FALSE) && (hook->pnp_state == Stopped) ) {
					dc_restore_pnp_state(hook);
				}
				is_sync = 1;
			}
		break;
		default:
			{
				status = dc_forward_irp(hook, irp);
			}
		break;
	}

	if (is_sync != 0) {
		dc_complete_irp(irp, status, irp->IoStatus.Information);
		IoReleaseRemoveLock(&hook->remv_lock, irp);
	}

	return status;
}

NTSTATUS dc_add_device(PDRIVER_OBJECT drv_obj, PDEVICE_OBJECT pdo_dev)
{
	PDEVICE_OBJECT high_dev = IoGetAttachedDeviceReference(pdo_dev);
	PDEVICE_OBJECT hook_dev, device, nextdev;
	dev_hook      *hook;
	NTSTATUS       status;

	/* reseed PRNG on device attach */
	cp_rand_reseed();
	
	/* create FDO device */
	status = IoCreateDevice(drv_obj, sizeof(dev_hook), NULL, high_dev->DeviceType, FILE_DEVICE_SECURE_OPEN, FALSE, &hook_dev);
	if (NT_SUCCESS(status) == FALSE) { hook_dev = NULL; goto exit; }
	memset(hook = hook_dev->DeviceExtension, 0, sizeof(dev_hook));
	/* get device object name */
	if (high_dev->DeviceType == FILE_DEVICE_CD_ROM)
	{
		for (device = high_dev; device != NULL; device = nextdev) {
			dc_query_object_name(device, hook->dev_name, sizeof(hook->dev_name));
			nextdev = wcsncmp(hook->dev_name, L"\\Device\\CdRom", 13) != 0 ? IoGetLowerDeviceObject(device) : NULL;
			if (device != high_dev) ObDereferenceObject(device);
		}
	} else {
		dc_query_object_name(pdo_dev, hook->dev_name, sizeof(hook->dev_name));
	}
	/* attach device */
	hook->hook_dev = hook_dev;
	hook->pdo_dev  = pdo_dev;
	hook->orig_dev = IoAttachDeviceToDeviceStack(hook_dev, pdo_dev);
	if (hook->orig_dev == NULL) { status = STATUS_UNSUCCESSFUL; goto exit; }

	/* complete initializaion */
	if (high_dev->Characteristics & FILE_REMOVABLE_MEDIA) hook->flags |= F_REMOVABLE;
	if (high_dev->DeviceType == FILE_DEVICE_CD_ROM) hook->flags |= F_CDROM;
	
	IoInitializeRemoveLock(&hook->remv_lock, 0, 0, 0);
	KeInitializeEvent(&hook->paging_count_event, NotificationEvent, TRUE);

	KeInitializeMutex(&hook->busy_lock, 0);
	KeInitializeMutex(&hook->key_lock, 0);

	hook_dev->Characteristics |= high_dev->Characteristics & FILE_REMOVABLE_MEDIA;
	hook_dev->Flags |= high_dev->Flags & (DO_BUFFERED_IO | DO_DIRECT_IO | DO_POWER_PAGABLE);
	hook_dev->Flags &= ~DO_DEVICE_INITIALIZING;	

	DbgMsg("dc_add_device %ws\n", hook->dev_name);
	dc_insert_hook(hook);	
exit:
	if (NT_SUCCESS(status) == FALSE && hook_dev != NULL) {
		IoDeleteDevice(hook_dev);
	}
	ObDereferenceObject(high_dev);
	return status;
}
