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


static
NTSTATUS
  dc_pnp_remove_irp(
     IN PDEVICE_OBJECT dev_obj, 
	 IN PIRP           irp
	 )
{
	dev_hook *hook = dev_obj->DeviceExtension;
	NTSTATUS  status;
	
	DbgMsg("dc_pnp_remove_irp\n");
	
	IoReleaseRemoveLockAndWait(&hook->remv_lock, irp);

	if (NT_SUCCESS(status = dc_forward_irp(dev_obj, irp))) 
	{
		dc_process_unmount(hook, UM_NOFSCTL);
		dc_remove_hook(hook);

		IoDetachDevice(hook->orig_dev);
		IoDeleteDevice(dev_obj);
	}

	return status;
}

static
NTSTATUS
  dc_pnp_usage_irp(
     IN PDEVICE_OBJECT dev_obj, 
	 IN PIRP           irp
	 )
{
	DEVICE_USAGE_NOTIFICATION_TYPE usage;
	PIO_STACK_LOCATION             irp_sp;
	dev_hook                      *hook;
	NTSTATUS                       status;
	int                            setpg;
	int                            complete;
	BOOLEAN                        inpath;

	hook     = dev_obj->DeviceExtension;
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
			/* preventing hibernate if memory contain sensitive data */
			if (dc_data_lock != 0) {
				status = STATUS_UNSUCCESSFUL; complete = 1;
			} else 
			{
				if (is_hiber_crypt() == 0) 
				{
					if (dc_num_mount() != 0) {
						status = STATUS_UNSUCCESSFUL; complete = 1;
					} else {
						/* clear pass cache to prevent leaks */
						dc_clean_pass_cache();
					}
				}
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
			status = dc_forward_irp(dev_obj, irp);
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

		status = dc_forward_irp_sync(dev_obj, irp);

		/* 
		   now deal with the failure and success cases.
		   note that we are not allowed to fail the irp
		   once it is sent to the lower drivers.
		*/

		if (NT_SUCCESS(status)) 
		{
			IoAdjustPagingPathCount(
				&hook->paging_count, inpath
				);

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
			&hook->paging_count_event, IO_NO_INCREMENT, FALSE
			);

		/* and complete the irp */
		dc_complete_irp(
			irp, status, irp->IoStatus.Information
			);
	}

	return status;
}

NTSTATUS
  dc_pnp_irp(
     IN PDEVICE_OBJECT dev_obj, 
	 IN PIRP           irp
	 )
{
	PIO_STACK_LOCATION irp_sp;
	dev_hook          *hook;
	NTSTATUS           status;
	USHORT             funct;
		
	if (dev_obj == dc_device)
	{
		return dc_complete_irp(
			      irp, STATUS_DRIVER_INTERNAL_ERROR, 0
				  );
	}

	irp_sp = IoGetCurrentIrpStackLocation(irp);
	hook   = dev_obj->DeviceExtension;
	funct  = irp_sp->MinorFunction;
	
	status = IoAcquireRemoveLock(&hook->remv_lock, irp);
    
	if (NT_SUCCESS(status) == FALSE) {
        return dc_complete_irp(irp, status, 0);
    }

	if ( (funct == IRP_MN_REMOVE_DEVICE) ||
		 (funct == IRP_MN_SURPRISE_REMOVAL) )
	{
		status = dc_pnp_remove_irp(dev_obj, irp);		
	} else
	{
		if (funct == IRP_MN_DEVICE_USAGE_NOTIFICATION) {
			status = dc_pnp_usage_irp(dev_obj, irp);
		} else {
			status = dc_forward_irp(dev_obj, irp);
		}
		
		IoReleaseRemoveLock(&hook->remv_lock, irp); 
	}

	return status;
}


NTSTATUS
   dc_add_device(
      IN PDRIVER_OBJECT drv_obj,
      IN PDEVICE_OBJECT dev_obj
      )
{
	NTSTATUS                 status;
	ULONG                    size;
	CHAR                     buf[512];
	POBJECT_NAME_INFORMATION inf      = (void*)buf;
	PDEVICE_OBJECT           hook_dev = NULL;
	dev_hook                *hook     = NULL;
	int                      succs    = 0;

	rnd_reseed_now();

	do
	{
		zeroauto(buf, sizeof(buf));

		status = ObQueryNameString(
			       dev_obj, inf, sizeof(buf), &size
				   );

		if (NT_SUCCESS(status) == FALSE) {
			break;
		}	

		DbgMsg("add device %ws\n", inf->Name.Buffer);

		status = IoCreateDevice(
			drv_obj, sizeof(dev_hook), NULL, FILE_DEVICE_DISK, 
			FILE_DEVICE_SECURE_OPEN, FALSE, &hook_dev
			);

		if (NT_SUCCESS(status) == FALSE) {
			break;
		}

		zeroauto(hook_dev->DeviceExtension, sizeof(dev_hook));

		hook           = hook_dev->DeviceExtension;
		hook->hook_dev = hook_dev;
		hook->pdo_dev  = dev_obj;
		hook->orig_dev = IoAttachDeviceToDeviceStack(hook_dev, dev_obj);
		
		if (hook->orig_dev == NULL) {
			break;
		}

		if (dev_obj->Characteristics & FILE_REMOVABLE_MEDIA) {
			hook->flags |= F_REMOVABLE;
		} 

		hook_dev->DeviceType      = hook->orig_dev->DeviceType;
		hook_dev->Characteristics = hook->orig_dev->Characteristics;
		hook_dev->Flags          |= (DO_DIRECT_IO | DO_POWER_PAGABLE); 
		
		IoInitializeRemoveLock(&hook->remv_lock, 0, 0, 0);

		KeInitializeEvent(
			&hook->paging_count_event, NotificationEvent, TRUE
			);

		KeInitializeMutex(&hook->busy_lock, 0);

		wcscpy(hook->dev_name, inf->Name.Buffer);

		hook_dev->Flags &= ~DO_DEVICE_INITIALIZING;

		dc_insert_hook(hook); succs = 1;
	} while (0);

	if ( (succs == 0) && (hook_dev != NULL) ) {
		IoDeleteDevice(hook_dev);
	} 

	return STATUS_SUCCESS;
}
