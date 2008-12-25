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
#include "crypto.h"
#include "pkcs5.h"
#include "crc32.h"
#include "enc_dec.h"
#include "misc_irp.h"
#include "readwrite.h"
#include "mount.h"
#include "fast_crypt.h"
#include "misc_volume.h"
#include "debug.h"
#include "fs_filter.h"

typedef struct _dsk_pass {
	struct _dsk_pass *next;
	dc_pass           pass;
	
} dsk_pass;

typedef struct _mount_ctx {
	WORK_QUEUE_ITEM  wrk_item;
	PDEVICE_OBJECT   dev_obj;
	PIRP             irp;
	s_callback       on_complete;
	void            *param;
	dev_hook        *hook;
	
} mount_ctx;

static dsk_pass *f_pass;
static ERESOURCE p_resource;


void dc_add_password(dc_pass *pass)
{
	dsk_pass *d_pass;

	if (pass->size != 0)
	{
		KeEnterCriticalRegion();
		ExAcquireResourceExclusiveLite(&p_resource, TRUE);

		for (d_pass = f_pass; d_pass; d_pass = d_pass->next)
		{
			if (IS_EQUAL_PASS(pass, &d_pass->pass)) {
				break;
			}
		}

		if ( (d_pass == NULL) && (d_pass = mem_alloc(sizeof(dsk_pass))) )
		{
			autocpy(&d_pass->pass, pass, sizeof(dc_pass));

			d_pass->next = f_pass;
			f_pass       = d_pass;
		}

		ExReleaseResourceLite(&p_resource);
		KeLeaveCriticalRegion();
	}
}

void dc_clean_pass_cache()
{
	dsk_pass *d_pass;
	dsk_pass *c_pass;
	int       loirql;

	if (loirql = (KeGetCurrentIrql() == PASSIVE_LEVEL)) {
		KeEnterCriticalRegion();
		ExAcquireResourceExclusiveLite(&p_resource, TRUE);
	}

	for (d_pass = f_pass; d_pass;)
	{
		c_pass = d_pass;
		d_pass = d_pass->next;

		zeroauto(c_pass, sizeof(dsk_pass));

		if (loirql != 0) {
			mem_free(c_pass);
		}
	}

	f_pass = NULL;

	if (loirql != 0) {
		ExReleaseResourceLite(&p_resource);
		KeLeaveCriticalRegion();
	}
}

void dc_clean_keys() 
{
	dev_hook *hook;
	dev_hook *next;

	if (next = dc_first_hook()) 
	{
		do 
		{
			hook = next;
			next = dc_next_hook(hook);

			zeroauto(&hook->dsk_key,    sizeof(dc_key));
			zeroauto(&hook->tmp_header, sizeof(dc_header));
			
			if (hook->hdr_key != NULL) {
				zeroauto(hook->hdr_key, sizeof(dc_key));
			}
			if (hook->tmp_key != NULL) {
				zeroauto(hook->tmp_key, sizeof(dc_key));
			}
		} while (next != NULL);
	} 
}

void dc_init_hdr_key(dc_key *hdr_key, dc_header *header, int cipher, dc_pass *password)
{
	u8 dk[DISKKEY_SIZE];
	
	sha512_pkcs5_2(
		1000, password->pass, password->size, 
		header->salt, PKCS5_SALT_SIZE, dk, PKCS_DERIVE_MAX);

	dc_cipher_init(hdr_key, cipher, dk);

	/* prevent leaks */
	zeroauto(dk, sizeof(dk));
}


static u64 dc_get_dev_size(dev_hook *hook)
{
	PARTITION_INFORMATION    pti;
	PARTITION_INFORMATION_EX ptix;
	NTSTATUS                 status;
	
	status = io_device_control(
		hook, IOCTL_DISK_GET_PARTITION_INFO_EX, NULL, 0, &ptix, sizeof(ptix));

	if (NT_SUCCESS(status) == FALSE) 
	{
		status = io_device_control(
			hook, IOCTL_DISK_GET_PARTITION_INFO, NULL, 0, &pti, sizeof(pti));

		if (NT_SUCCESS(status) != FALSE) {
			return pti.PartitionLength.QuadPart;
		} else {
			return 0;
		}		
	} else {
		return ptix.PartitionLength.QuadPart;
	}
}

static
int dc_probe_decrypt(
	  dev_hook *hook, dc_header *header, dc_key **res_key, dc_pass *password
	  )
{
	dc_key   *hdr_key;
	dsk_pass *d_pass;	
	int       resl, succs;

	hdr_key = NULL; succs = 0;
	do
	{
		/* read volume header */
		resl = dc_device_rw(
			hook, IRP_MJ_READ, header, sizeof(dc_header), 0);
		
		if (resl != ST_OK) {
			break;
		}

		if ( (hdr_key = mem_alloc(sizeof(dc_key))) == NULL ) {
			resl = ST_NOMEM; break;
		}

		/* derive header key and decrypt header */
		do
		{
			if (password != NULL)
			{
				/* probe mount with entered password */
				if (succs = dc_decrypt_header(hdr_key, header, password)) {
					break;
				}
			}

			KeEnterCriticalRegion();
			ExAcquireResourceSharedLite(&p_resource, TRUE);

			/* probe mount with cached passwords */
			for (d_pass = f_pass; d_pass; d_pass = d_pass->next)
			{
				if (succs = dc_decrypt_header(hdr_key, header, &d_pass->pass)) {
					break;
				}
			}

			ExReleaseResourceLite(&p_resource);
			KeLeaveCriticalRegion();
		} while (0);

		if (succs != 0) 
		{
			*res_key = hdr_key; hdr_key = NULL; resl = ST_OK; 
		} else {
			resl = ST_PASS_ERR;
		}
	} while (0);

	/* prevent leaks */
	if (hdr_key != NULL) {
		zeroauto(hdr_key, sizeof(dc_key));
		mem_free(hdr_key);
	}

	return resl;
}

int dc_mount_device(wchar_t *dev_name, dc_pass *password)
{
	dc_header    *hcopy;
	dev_hook     *hook = NULL;
	dc_key       *hdr_key = NULL;
	DISK_GEOMETRY dg;
	NTSTATUS      status;
	int           resl;
	
	DbgMsg("dc_mount_device %ws\n", dev_name);

	do 
	{
		if ( (hook = dc_find_hook(dev_name)) == NULL ) {
			resl = ST_NF_DEVICE; break;
		}

		wait_object_infinity(&hook->busy_lock);		

		if (hook->flags & F_ENABLED) {
			resl = ST_ALR_MOUNT; break;
		}

		if (hook->flags & (F_UNSUPRT | F_DISABLE | F_FORMATTING)) {
			resl = ST_ERROR; break;
		}

		status = io_device_control(
			hook, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &dg, sizeof(dg));

		if (NT_SUCCESS(status) == FALSE) {
			resl = ST_RW_ERR; break;
		}

		if (dg.BytesPerSector > SECTOR_SIZE) {
			hook->flags |= F_UNSUPRT; resl = ST_ERROR; break;
		}

		if (hook->dsk_size = dc_get_dev_size(hook)) {
			hook->use_size = hook->dsk_size;
			hook->tmp_size = 0;
		} else {
			resl = ST_RW_ERR; break;
		}

		if ( (hcopy = mem_alloc(sizeof(dc_header))) == NULL ) {
			resl = ST_NOMEM; break;
		}

		resl = dc_probe_decrypt(
			hook, hcopy, &hdr_key, password);

		if (resl != ST_OK) {			
			break;
		}
		
		DbgMsg("hdr_key %x\n", hdr_key);

		/* initialize volume key */
		dc_cipher_init(
			&hook->dsk_key, hcopy->alg_1, hcopy->key_1);

		DbgMsg("device mounted\n");

		hook->crypt.cipher_id = hcopy->alg_1;
		hook->disk_id         = hcopy->disk_id;
		hook->vf_version      = hcopy->version;
		hook->stor_off        = hcopy->stor_off;
		hook->tmp_size        = 0;
		hook->use_size        = hcopy->use_size;

		DbgMsg("hook->vf_version %d\n", hook->vf_version);
		DbgMsg("flags %x\n", hcopy->flags);

		if (hcopy->flags & VF_STORAGE_FILE) {
			hook->flags |= F_PROTECT_DCSYS;
		}

		if (hcopy->flags & VF_TMP_MODE)
		{
			hook->tmp_size      = hcopy->tmp_size;
			hook->hdr_key       = hdr_key;
			hook->crypt.wp_mode = hcopy->tmp_wp_mode;			

			if (hcopy->flags & VF_REENCRYPT) {
				hook->sync_init_type = S_CONTINUE_RE_ENC;
			} else {
				hook->sync_init_type = S_CONTINUE_ENC;
			}
				
			/* copy decrypted header to device data */
			autocpy(&hook->tmp_header, hcopy, sizeof(dc_header));
				
			if ( (resl = dc_enable_sync_mode(hook)) != ST_OK ) 
			{
				zeroauto(&hook->tmp_header, sizeof(dc_header));
				hdr_key = hook->hdr_key;
			} else  {				
				hdr_key = NULL; /* prevent key wiping */
			}
		} else {			
			hook->flags |= F_ENABLED; resl = ST_OK;
		}
		/* sync device flags with FS filter */
		dc_fsf_sync_flags(hook->dev_name);
	} while (0);

	/* prevent leaks */
	if (hdr_key != NULL) {
		zeroauto(hdr_key, sizeof(dc_key));
		mem_free(hdr_key);
	}

	if (hcopy != NULL) {
		zeroauto(hcopy, sizeof(dc_header));
		mem_free(hcopy);
	}

	if (hook != NULL) {
		KeReleaseMutex(&hook->busy_lock, FALSE);
		dc_deref_hook(hook);
	}	

	return resl;
}

/*
   this routine process unmounting the device
   unmount options:
    UM_NOFSCTL - unmount without reporting to FS
	UM_FORCE   - force unmounting
*/
int dc_process_unmount(dev_hook *hook, int opt)
{
	IO_STATUS_BLOCK iosb;
	NTSTATUS        status;
	HANDLE          h_dev = NULL;
	int             resl;

	DbgMsg("dc_process_unmount\n");
	
	if ( !(hook->flags & F_ENABLED) ) {
		return ST_NO_MOUNT;
	}

	wait_object_infinity(&hook->busy_lock);

	do
	{
		if (hook->flags & F_FORMATTING) {
			dc_format_done(hook->dev_name);
		}

		if ( !(hook->flags & F_SYSTEM) && !(opt & UM_NOFSCTL) )
		{
			h_dev = io_open_volume(hook->dev_name);

			if ( (h_dev == NULL) && !(opt & UM_FORCE) )	{
				resl = ST_LOCK_ERR; break;
			}

			if (h_dev != NULL)
			{
				status = ZwFsControlFile(
					h_dev, NULL, NULL, NULL, &iosb, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0);

				if ( (NT_SUCCESS(status) == FALSE) && !(opt & UM_FORCE) ) {
					resl = ST_LOCK_ERR; break;
				}

				ZwFsControlFile(
					h_dev, NULL, NULL, NULL, &iosb, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0);
			}
		}

		if ( !(opt & UM_NOSYNC) )
		{
			/* temporary disable IRP processing */
			hook->flags |= F_DISABLE;

			/* wait for pending IRPs completion */
			while (hook->io_pending != 0) {
				dc_delay(20);
			}

			if (hook->flags & F_SYNC) {
				/* send signal to syncronous mode thread */
				dc_send_sync_packet(hook->dev_name, S_OP_FINALIZE, 0);
			}			
		}

		hook->flags    &= ~(F_ENABLED | F_SYNC | F_REENCRYPT | F_PROTECT_DCSYS);
		hook->use_size  = hook->dsk_size;
		hook->tmp_size  = 0;
		resl            = ST_OK;

		/* sync device flags with FS filter */
		dc_fsf_sync_flags(hook->dev_name);
		/* prevent leaks */
		zeroauto(&hook->dsk_key, sizeof(dc_key));

		if ( !(opt & UM_NOSYNC) ) {
			/* enable IRP processing */
			hook->flags &= ~F_DISABLE;
		}
	} while (0);

	if (h_dev != NULL) {
		ZwClose(h_dev);
	}

	KeReleaseMutex(&hook->busy_lock, FALSE);
	
	return resl;
}

static void unmount_thread_proc(mount_ctx *mnt) 
{
	int resl;

	DbgMsg("unmount_thread_proc\n");

	resl = dc_process_unmount(mnt->hook, UM_NOFSCTL);
	mnt->on_complete(mnt->hook, mnt->param, resl);
	dc_deref_hook(mnt->hook);
	mem_free(mnt);

	PsTerminateSystemThread(STATUS_SUCCESS);
}

static void unmount_item_proc(mount_ctx *mnt)
{
	int resl;

	DbgMsg("unmount_item_proc\n");

	resl = start_system_thread(unmount_thread_proc, mnt, NULL);

	if (resl != ST_OK) {
		mnt->on_complete(mnt->hook, mnt->param, resl);
		dc_deref_hook(mnt->hook);
		mem_free(mnt);
	}
}

void dc_process_unmount_async(
		dev_hook *hook, s_callback on_complete, void *param
		)
{
	mount_ctx *mnt;

	DbgMsg("dc_process_unmount_async\n");

	if ( (mnt = mem_alloc(sizeof(mount_ctx))) == NULL ) {
		on_complete(hook, param, ST_NOMEM);
	} else
	{
		mnt->on_complete = on_complete;
		mnt->param       = param;
		mnt->hook        = hook;

		dc_reference_hook(hook);

		ExInitializeWorkItem(
			&mnt->wrk_item, unmount_item_proc, mnt);

		ExQueueWorkItem(
			&mnt->wrk_item, DelayedWorkQueue);
	}
}


int dc_unmount_device(wchar_t *dev_name, int force)
{
	dev_hook *hook;
	int       resl;

	DbgMsg("dc_unmount_device %ws\n", dev_name);

	if (hook = dc_find_hook(dev_name)) 
	{
		if (IS_UNMOUNTABLE(hook)) {
			resl = dc_process_unmount(hook, force);
		} else {
			resl = ST_UNMOUNTABLE;
		}
		dc_deref_hook(hook);
	} else {
		resl = ST_NF_DEVICE;
	}

	return resl;
}

void dc_unmount_all(int force)
{
	dev_hook *hook;

	if (hook = dc_first_hook()) 
	{
		do 
		{
			if (IS_UNMOUNTABLE(hook)) {
				dc_process_unmount(hook, force);
			}
		} while (hook = dc_next_hook(hook));
	}
}

int dc_mount_all(dc_pass *password)
{
	dev_hook *hook;
	int       num = 0;

	if (hook = dc_first_hook()) 
	{
		do 
		{
			if (dc_mount_device(hook->dev_name, password) == ST_OK) {
				num++;
			}
		} while (hook = dc_next_hook(hook));
	}

	return num;
}

int dc_num_mount()
{
	dev_hook *hook;
	int       num = 0;

	if (hook = dc_first_hook()) 
	{
		do 
		{
			num += (hook->flags & F_ENABLED);		
		} while (hook = dc_next_hook(hook));
	}

	return num;
}

static void mount_item_proc(mount_ctx *mnt)
{
	PDEVICE_OBJECT dev_obj;
	dev_hook      *hook;	
	int            resl;
		
	dev_obj = mnt->dev_obj;
	hook    = dev_obj->DeviceExtension;

	resl = dc_mount_device(hook->dev_name, NULL);

	if ( (resl != ST_RW_ERR) && (resl != ST_MEDIA_CHANGED) && (resl != ST_NO_MEDIA) ) {
		hook->mnt_probed = 1;
	}

	if (resl != ST_OK)
	{
		if (lock_inc(&hook->mnt_probe_cnt) > MAX_MNT_PROBES) {
			hook->mnt_probed = 1;
		}
	}

	if (hook->flags & F_ENABLED) {
		dc_read_write_irp(dev_obj, mnt->irp);
	} else {
		dc_forward_irp(dev_obj, mnt->irp);
	}

	lock_dec(&hook->io_pending);
	mem_free(mnt);
}

NTSTATUS dc_probe_mount(dev_hook *hook, PIRP irp)
{
	mount_ctx *mnt;

	if ( (mnt = mem_alloc(sizeof(mount_ctx))) == NULL ) {
		lock_dec(&hook->io_pending);
		return dc_complete_irp(irp, STATUS_INSUFFICIENT_RESOURCES, 0);
	}

	IoMarkIrpPending(irp);

	mnt->dev_obj = hook->hook_dev;
	mnt->irp     = irp;
		
	ExInitializeWorkItem(
		&mnt->wrk_item, mount_item_proc, mnt);

	ExQueueWorkItem(
		&mnt->wrk_item, DelayedWorkQueue);

	return STATUS_PENDING;
}

void dc_init_mount()
{
	ExInitializeResourceLite(&p_resource);
	f_pass = NULL;
}
