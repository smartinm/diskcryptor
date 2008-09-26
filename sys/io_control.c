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
#include "mount.h"
#include "prng.h"
#include "benchmark.h"
#include "misc_irp.h"
#include "enc_dec.h"
#include "misc.h"
#include "debug.h"
#include "readwrite.h"
#include "mem_lock.h"
#include "misc_volume.h"

static int dc_ioctl_process(
			  u32 code, dc_ioctl *data
			  )
{
	int resl = ST_ERROR;

	switch (code)
	{
		case DC_CTL_ADD_PASS:
			{
				if (data->passw1[0] != 0) {
					dc_add_password(data->passw1);
				}

				resl = ST_OK;
			} 
		break;
		case DC_CTL_MOUNT:
			{
				resl = dc_mount_device(
					data->device, data->passw1
					);

				if ( (resl == ST_OK) && (dc_conf_flags & CONF_CACHE_PASSWORD) ) {
					dc_add_password(data->passw1);
				}
			}
		break;
		case DC_CTL_MOUNT_ALL:
			{
				data->n_mount = dc_mount_all(data->passw1);
				resl          = ST_OK;

				if ( (data->n_mount != 0) && (dc_conf_flags & CONF_CACHE_PASSWORD) ) {
					dc_add_password(data->passw1);
				}
			}
		break;
		case DC_CTL_UNMOUNT:
			{
				resl = dc_unmount_device(
					data->device, (data->force & UM_FORCE)
					);
			}
		break;
		case DC_CTL_CHANGE_PASS:
			{
				resl = dc_change_pass(
					data->device, data->passw1, data->passw2, data->crypt.prf_id
					);

				if ( (resl == ST_OK) && (dc_conf_flags & CONF_CACHE_PASSWORD) ) {
					dc_add_password(data->passw2);
				}
			}
		break;
		case DC_CTL_ENCRYPT_START:
			{
				resl = dc_encrypt_start(
					data->device, data->passw1, &data->crypt
					);

				if ( (resl == ST_OK) && (dc_conf_flags & CONF_CACHE_PASSWORD) ) {
					dc_add_password(data->passw1);
				}
			}
		break;
		case DC_CTL_DECRYPT_START:
			{
				resl = dc_decrypt_start(data->device, data->passw1);
			}
		break;
		case DC_CTL_RE_ENC_START:
			{
				resl = dc_reencrypt_start(
					data->device, data->passw1, &data->crypt
					);
			}
		break;
		case DC_CTL_ENCRYPT_STEP:
			{
				resl = dc_send_sync_packet(
					data->device, S_OP_ENC_BLOCK, pv(data->crypt.wp_mode)
					);
			}
		break;
		case DC_CTL_DECRYPT_STEP:
			{
				resl = dc_send_sync_packet(
					data->device, S_OP_DEC_BLOCK, 0
					);
			}
		break; 
		case DC_CTL_SYNC_STATE:
			{
				resl = dc_send_sync_packet(
					data->device, S_OP_SYNC, 0
					);
			}
		break;
		case DC_CTL_RESOLVE:
			{
				while (dc_resolve_link(
					data->device, data->device, sizeof(data->device)) == ST_OK)
				{
					resl = ST_OK;
				}
			}
		break;
		case DC_CTL_UPDATE_VOLUME:
			{
				resl = dc_update_volume(
					data->device, data->passw1, data
					); 
			}
		break;
		case DC_CTL_SET_SHRINK:
			{
				resl = dc_send_sync_packet(
					data->device, S_OP_SET_SHRINK, data
					);
			}
		break;
		case DC_FORMAT_START:
			{
				resl = dc_format_start(
					data->device, data->passw1, &data->crypt
					);

				if ( (resl == ST_OK) && (dc_conf_flags & CONF_CACHE_PASSWORD) ) {
					dc_add_password(data->passw1);
				}
			}
		break;
		case DC_FORMAT_STEP:
			{
				resl = dc_format_step(
					data->device, data->crypt.wp_mode
					);
			}
		break;
		case DC_FORMAT_DONE:
			{
				resl = dc_format_done(data->device);
			}
		break;
	}

	return resl;
}

static
NTSTATUS
  dc_drv_control_irp(
     IN PDEVICE_OBJECT dev_obj, 
	 IN PIRP           irp
	 )
{
	PIO_STACK_LOCATION  irp_sp  = IoGetCurrentIrpStackLocation(irp);
	NTSTATUS            status  = STATUS_INVALID_DEVICE_REQUEST;
	void               *data    = irp->AssociatedIrp.SystemBuffer;
	u32                 in_len  = irp_sp->Parameters.DeviceIoControl.InputBufferLength;
	u32                 out_len = irp_sp->Parameters.DeviceIoControl.OutputBufferLength;
	u32                 code    = irp_sp->Parameters.DeviceIoControl.IoControlCode;
	u32                 bytes   = 0;
	
	switch (code)
	{
		case DC_GET_VERSION:
			{
				if (out_len == sizeof(u32)) 
				{
					p32(data)[0] = DC_DRIVER_VER;
					bytes        = sizeof(u32);
					status       = STATUS_SUCCESS;
				}
			}
		break;
		case DC_CTL_CLEAR_PASS:
			{
				dc_clean_pass_cache();
				status = STATUS_SUCCESS;
			}
		break;		
		case DC_CTL_UNMOUNT_ALL:
			{
				dc_unmount_all(UM_FORCE);
				status = STATUS_SUCCESS;
			}
		break;
		case DC_CTL_STATUS:
			{
				dc_ioctl  *dctl = data;
				dc_status *stat = data;
				dev_hook  *hook;

				if ( (in_len == sizeof(dc_ioctl)) && (out_len == sizeof(dc_status)) )
				{
					dctl->device[MAX_DEVICE] = 0;

					if (hook = dc_find_hook(dctl->device))
					{
						if (hook->pdo_dev->Flags & DO_SYSTEM_BOOT_PARTITION) {
							hook->flags |= F_SYSTEM;
						}

						dc_get_mount_point(
							hook, stat->mnt_point, sizeof(stat->mnt_point)
							);

						stat->crypt        = hook->crypt;
						stat->dsk_size     = hook->dsk_size;
						stat->tmp_size     = hook->tmp_size;
						stat->flags        = hook->flags;
						stat->disk_id      = hook->disk_id;
						stat->paging_count = hook->paging_count;
						stat->vf_version   = hook->vf_version;
						status             = STATUS_SUCCESS; 
						bytes              = sizeof(dc_status);

						dc_deref_hook(hook);
					}
				}
			}
		break;
		case DC_CTL_ADD_SEED:
			{
				 if (in_len != 0) 
				 {
					 rnd_add_buff(data, in_len);
					 status = STATUS_SUCCESS;
					 /* prevent leaks */
					 zeromem(data, in_len);
				 }
			}
		break;
		case DC_CTL_GET_RAND:
			{
				if (out_len != 0)
				{
					rnd_get_bytes(pv(data), out_len);
					
					status = STATUS_SUCCESS;
					bytes  = out_len;
				}
			}
		break;
		case DC_CTL_BENCHMARK:
			{
				 if ( (in_len == sizeof(crypt_info)) && (out_len == sizeof(dc_bench)) )
				 {
					 if (dc_k_benchmark(pv(data), pv(data)) == ST_OK) {
						 status = STATUS_SUCCESS; 
						 bytes  = sizeof(dc_bench);
					 }
				 }
			}
		break;
		case DC_CTL_BSOD:
			{
				lock_inc(&dc_data_lock);
				dc_clean_pass_cache();
				dc_clean_locked_mem(NULL);
				dc_clean_keys();

				KeBugCheck(IRQL_NOT_LESS_OR_EQUAL);
			}
		break;
		case DC_CTL_GET_CONF:
			{
				dc_conf *conf = data;

				if (out_len == sizeof(dc_conf)) {
					conf->conf_flags = dc_conf_flags;
					conf->load_flags = dc_load_flags;
					status = STATUS_SUCCESS;
					bytes  = sizeof(dc_conf);
				}
			}
		break;
		case DC_CTL_SET_CONF:
			{
				dc_conf *conf = data;

				if (in_len == sizeof(dc_conf))
				{
					dc_conf_flags = conf->conf_flags;
					status        = STATUS_SUCCESS;			

					if ( !(dc_conf_flags & CONF_CACHE_PASSWORD) ) {
						dc_clean_pass_cache();
					}
				}
			}
		break;
		case DC_CTL_LOCK_MEM:
			{
				dc_lock_ctl *smem = data;

				if ( (in_len == sizeof(dc_lock_ctl)) && (out_len == in_len) )
				{
					smem->resl = dc_lock_mem(
						smem->data, smem->size, irp_sp->FileObject
						);

					status = STATUS_SUCCESS;
					bytes  = sizeof(dc_lock_ctl);
				}
			}
		break;
		case DC_CTL_UNLOCK_MEM:
			{
				dc_lock_ctl *smem = data;

				if ( (in_len == sizeof(dc_lock_ctl)) && (out_len == in_len) )
				{
					smem->resl = dc_unlock_mem(
						smem->data, irp_sp->FileObject
						);

					status = STATUS_SUCCESS;
					bytes  = sizeof(dc_lock_ctl);
				}
			}
		break; 
		case DC_BACKUP_HEADER:
			{
				dc_backup_ctl *back = data;
				
				if ( (in_len == sizeof(dc_backup_ctl)) && (out_len == in_len) )
				{
					back->passw1[MAX_PASSWORD] = 0;
					back->device[MAX_DEVICE]   = 0;

					back->status = dc_backup_header(
						back->device, back->passw1, back->backup
						);

					/* prevent leaks */
					zeroauto(back->passw1, sizeof(back->passw1));

					status = STATUS_SUCCESS;
					bytes  = sizeof(dc_backup_ctl);
				}
			}
		break;
		case DC_RESTORE_HEADER:
			{
				dc_backup_ctl *back = data;
				
				if ( (in_len == sizeof(dc_backup_ctl)) && (out_len == in_len) )
				{
					back->passw1[MAX_PASSWORD] = 0;
					back->device[MAX_DEVICE]   = 0;

					back->status = dc_restore_header(
						back->device, back->passw1, back->backup
						);

					/* prevent leaks */
					zeroauto(back->passw1, sizeof(back->passw1));

					status = STATUS_SUCCESS;
					bytes  = sizeof(dc_backup_ctl);
				}
			}
		break;
		default: 
			{
				dc_ioctl *dctl = data;

				if ( (in_len == sizeof(dc_ioctl)) && (out_len == sizeof(dc_ioctl)) )
				{					
					/* limit null-terminated strings length */
					dctl->passw1[MAX_PASSWORD] = 0;
					dctl->passw2[MAX_PASSWORD] = 0;
					dctl->device[MAX_DEVICE]   = 0;
					
					/* process IOCTL */
					dctl->status = dc_ioctl_process(code, dctl);

					/* prevent leaks  */
					zeroauto(dctl->passw1, sizeof(dctl->passw1));
					zeroauto(dctl->passw2, sizeof(dctl->passw2));

					status = STATUS_SUCCESS;
					bytes  = sizeof(dc_ioctl);
				}
			}
		break;
	}

	return dc_complete_irp(
		      irp, status, bytes
			  );
}

static void dc_verify_ioctl_complete(
			  dev_hook *hook, PIRP irp, int resl
			  )
{
	hook->dsk_size      = 0;
	hook->use_size      = 0;
	hook->mnt_probed    = 0;
	hook->mnt_probe_cnt = 0;

	IoCompleteRequest(irp, IO_NO_INCREMENT);
}

static
NTSTATUS
  dc_ioctl_complete(
    IN PDEVICE_OBJECT dev_obj,
    IN PIRP           irp,
    IN PVOID          param
    )
{
	PIO_STACK_LOCATION irp_sp;
	dev_hook          *hook;
	u32                ioctl;
	NTSTATUS           status;

	irp_sp = IoGetCurrentIrpStackLocation(irp);
	hook   = dev_obj->DeviceExtension;
	ioctl  = irp_sp->Parameters.DeviceIoControl.IoControlCode;
	status = irp->IoStatus.Status;

	if (irp->PendingReturned) {
		IoMarkIrpPending(irp);
	}

	if ( NT_SUCCESS(status) && (hook->flags & F_ENABLED) && 
		 !(hook->flags & F_SHRINK_PENDING) && (irp->RequestorMode == UserMode) )
	{
		switch (ioctl)
		{
			case IOCTL_DISK_GET_LENGTH_INFO:
			  {
				  PGET_LENGTH_INFORMATION gl = pv(irp->AssociatedIrp.SystemBuffer);
				  gl->Length.QuadPart = hook->use_size;
			  }
		    break;
			case IOCTL_DISK_GET_PARTITION_INFO:
			  {
				  PPARTITION_INFORMATION pi = pv(irp->AssociatedIrp.SystemBuffer);
				  pi->PartitionLength.QuadPart = hook->use_size;				
			  }
		    break;
			case IOCTL_DISK_GET_PARTITION_INFO_EX:
			  {
				  PPARTITION_INFORMATION_EX pi = pv(irp->AssociatedIrp.SystemBuffer);				  
				  pi->PartitionLength.QuadPart = hook->use_size;				  
			  }
		    break;
		}
	}

	if ( (hook->flags & F_REMOVABLE) && (ioctl == IOCTL_DISK_CHECK_VERIFY) )
	{
		if (!NT_SUCCESS(status) && (hook->dsk_size != 0)) 
		{
			DbgMsg("media removed\n");

			dc_process_unmount_async(
				hook, dc_verify_ioctl_complete, irp
				);

			return STATUS_MORE_PROCESSING_REQUIRED;
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS
  dc_io_control_irp(
     IN PDEVICE_OBJECT dev_obj, 
	 IN PIRP           irp
	 )
{
	dev_hook *hook;
		
	if (dev_obj == dc_device) 
	{
		return dc_drv_control_irp(
			      dev_obj, irp
				  );				 
	}

	hook = dev_obj->DeviceExtension;

	IoCopyCurrentIrpStackLocationToNext(irp);

	IoSetCompletionRoutine(
		irp, dc_ioctl_complete,
		NULL, TRUE, TRUE, TRUE
		);

	return IoCallDriver(hook->orig_dev, irp);
}
