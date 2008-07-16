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
#include "misc_irp.h"
#include "misc.h"
#include "driver.h"
#include "mount.h"
#include "enc_dec.h"
#include "mem_lock.h"

NTSTATUS 
  dc_complete_irp(
     IN PIRP      irp,
	 IN NTSTATUS  status,
	 IN ULONG_PTR bytes
	 )
{
	irp->IoStatus.Status      = status;
	irp->IoStatus.Information = bytes;

	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return status;
}

NTSTATUS
  dc_forward_irp(
     IN PDEVICE_OBJECT dev_obj, 
	 IN PIRP           irp
	 )
{
	dev_hook *hook;

	if (dev_obj == dc_device)
	{
		return dc_complete_irp(
			      irp,
				  STATUS_DRIVER_INTERNAL_ERROR, 0
				  );
	}

	hook = dev_obj->DeviceExtension;

	IoSkipCurrentIrpStackLocation(irp);

	return IoCallDriver(hook->orig_dev, irp);
}


static
NTSTATUS
  dc_sync_complete(
    IN PDEVICE_OBJECT dev_obj,
    IN PIRP           irp,
    IN PKEVENT        sync
    )
{
	KeSetEvent(sync, IO_NO_INCREMENT, FALSE);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
  dc_forward_irp_sync(
     IN PDEVICE_OBJECT dev_obj, 
	 IN PIRP           irp
	 )
{
	dev_hook *hook = dev_obj->DeviceExtension;
	KEVENT    sync;
	NTSTATUS  status;

	KeInitializeEvent(
		&sync, NotificationEvent, FALSE
		);

	IoCopyCurrentIrpStackLocationToNext(irp);

    IoSetCompletionRoutine(
		irp, dc_sync_complete,
		&sync, TRUE, TRUE, TRUE
		);

	status = IoCallDriver(hook->orig_dev, irp);

    if (status == STATUS_PENDING) 
	{
		wait_object_infinity(&sync);

		status = irp->IoStatus.Status;
    }

	return status;
}


NTSTATUS
  dc_create_close_irp(
     IN PDEVICE_OBJECT dev_obj, 
	 IN PIRP           irp
	 )
{
	PIO_STACK_LOCATION irp_sp;

	if (dev_obj == dc_device)
	{
		irp_sp = IoGetCurrentIrpStackLocation(irp);

		if (irp_sp->MajorFunction == IRP_MJ_CLOSE) {
			dc_sync_all_encs();
			dc_clean_locked_mem(irp_sp->FileObject);
		}

		return dc_complete_irp(
			      irp, STATUS_SUCCESS, 0
				  );
	} else {
		return dc_forward_irp(dev_obj, irp);
	}
}

NTSTATUS
  dc_power_irp(
     IN PDEVICE_OBJECT dev_obj, 
	 IN PIRP           irp
	 )
{
	dev_hook          *hook;
	NTSTATUS           status;
	PIO_STACK_LOCATION irp_sp;

    if (dev_obj == dc_device)
	{
		return dc_complete_irp(
			      irp, STATUS_SUCCESS, 0
				  );
	} else
	{
		hook   = dev_obj->DeviceExtension;
		irp_sp = IoGetCurrentIrpStackLocation(irp);
		status = IoAcquireRemoveLock(&hook->remv_lock, irp);

		if (NT_SUCCESS(status) == FALSE)
		{
			irp->IoStatus.Status = status;
			PoStartNextPowerIrp(irp);
			IoCompleteRequest(irp, IO_NO_INCREMENT);			
		} else
		{
			/* disabled because some users get strange BSODs
			if ( (irp_sp->MinorFunction == IRP_MN_SET_POWER) &&
				 (irp_sp->Parameters.Power.Type == SystemPowerState) &&
				 (irp_sp->Parameters.Power.State.SystemState == PowerSystemShutdown) ) 
			{
				dc_clean_pass_cache();
				dc_clean_keys();		
			}*/

			PoStartNextPowerIrp(irp);
			IoSkipCurrentIrpStackLocation(irp);

			status = PoCallDriver(hook->orig_dev, irp);

			IoReleaseRemoveLock(&hook->remv_lock, irp);
		}
	}

	return status;
}
