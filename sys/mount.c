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

typedef struct _dsk_pass {
	struct _dsk_pass *next;
	char              pass[MAX_PASSWORD + 1];
	
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


void dc_add_password(char *pass)
{
	dsk_pass *d_pass;

	if (pass[0] != 0)
	{
		KeEnterCriticalRegion();
		ExAcquireResourceExclusiveLite(&p_resource, TRUE);

		for (d_pass = f_pass; d_pass; d_pass = d_pass->next)
		{
			if (strcmp(d_pass->pass, pass) == 0) {
				break;
			}
		}

		if ( (d_pass == NULL) && (d_pass = mem_alloc(sizeof(dsk_pass))) )
		{
			strcpy(d_pass->pass, pass);

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

			zeroauto(&hook->dsk_key, sizeof(dc_key));
			zeroauto(&hook->tmp_header, sizeof(dc_header));
			zeroauto(&hook->old_header, sizeof(dc_header));
			zeroauto(&hook->tmp_pass, sizeof(hook->tmp_pass));
			
			if (hook->hdr_key != NULL) {
				zeroauto(hook->hdr_key, sizeof(dc_key));
			}
			if (hook->tmp_key != NULL) {
				zeroauto(hook->tmp_key, sizeof(dc_key));
			}
		} while (next != NULL);
	} 
}

dc_key *dc_init_hdr_key(crypt_info *crypt, dc_header *header, char *password)
{
	u8      dk[DISKKEY_SIZE];
	dc_key *hdr_key;

	if ( (hdr_key = mem_alloc(sizeof(dc_key))) == NULL ) {
		return NULL;
	}

	pkcs5_2_prf(
		crypt->prf_id, -1, password, strlen(password), 
		header->salt, PKCS5_SALT_SIZE, dk, PKCS_DERIVE_MAX
		);

	dc_cipher_init(
		hdr_key, crypt->cipher_id, crypt->mode_id, dk
		);

	/* prevent leaks */
	zeroauto(dk, sizeof(dk));

	return hdr_key;
}


static u64 dc_get_dev_size(dev_hook *hook)
{
	PARTITION_INFORMATION    pti;
	PARTITION_INFORMATION_EX ptix;
	NTSTATUS                 status;
	
	status = io_device_control(
		hook, IOCTL_DISK_GET_PARTITION_INFO_EX, NULL, 0, &ptix, sizeof(ptix)
		);

	if (NT_SUCCESS(status) == FALSE) 
	{
		status = io_device_control(
			hook, IOCTL_DISK_GET_PARTITION_INFO, NULL, 0, &pti, sizeof(pti)
			);

		if (NT_SUCCESS(status) != FALSE) {
			return pti.PartitionLength.QuadPart;
		} else {
			return 0;
		}		
	} else {
		return ptix.PartitionLength.QuadPart;
	}
}

int dc_write_header(
	  dev_hook *hook, dc_header *header, u64 offset, char *password
	  )
{
	dc_header t_header;
	dc_key   *hdr_key;
	int       resl;

	do
	{
		/* copy header to new buffer */
		autocpy(&t_header, header, sizeof(dc_header));

		/* add volume header to random pool because RNG not 
		   have sufficient entropy at boot time 
		*/
		rnd_add_buff(header, sizeof(dc_header));
		/* generate new salt */
		rnd_get_bytes(t_header.salt, PKCS5_SALT_SIZE);

		/* init new header key */
		if ( (hdr_key = dc_init_hdr_key(&hook->crypt, &t_header, password)) == NULL ) {
			resl = ST_NOMEM; break;
		}

		/* encrypt header with new key */
		dc_cipher_encrypt(
			pv(&t_header.sign), pv(&t_header.sign), HEADER_ENCRYPTEDDATASIZE, 1, hdr_key
			);

		/* write header */
		resl = dc_device_rw(
			hook, IRP_MJ_WRITE, &t_header, sizeof(dc_header), offset
			);
	} while (0);

	/* prevent leaks */
	if (hdr_key != NULL) {
		zeroauto(hdr_key, sizeof(dc_key));
		mem_free(hdr_key);
	}

	zeroauto(&t_header, sizeof(t_header));

	return resl;
}

dc_key *dc_dec_known_header(
		  dc_header *header, crypt_info *crypt, char *password
		  )
{
	dc_key *hdr_key;
	int     succs = 0;
	
	if ( (hdr_key = dc_init_hdr_key(crypt, header, password)) == NULL ) {
		return NULL;
	}

	do
	{
		dc_cipher_decrypt(
			pv(&header->sign), pv(&header->sign), 
			HEADER_ENCRYPTEDDATASIZE, 0, hdr_key 
			);

		/* Magic 'TRUE' or 'DTMP' */
		if ( (header->sign != DC_TRUE_SIGN) && (header->sign != DC_DTMP_SIGN) ) {
			break;
		}

		/* Check CRC of the key set */
		if (BE32(header->key_crc) != crc32(header->key_data, DISKKEY_SIZE)) {
			break;
		}
		succs = 1;
	} while (0);

	if (succs == 0) {
		zeroauto(hdr_key, sizeof(dc_key));
		mem_free(hdr_key); 
		hdr_key = NULL;
	}
	
	return hdr_key;
}



static
int dc_get_header_and_restory_copy(
	  dev_hook *hook, dc_header *header, dc_key **res_key, char *res_pass,
	  u64 offset, u64 copy_offset, char *password
	  )
{
	dsk_pass  *d_pass;	
	dc_header  b_header;
	dc_key    *hdr_key = NULL;
	dc_key    *bkf_key = NULL;
	int        resl, b_resl;
	
	do
	{
		resl = dc_device_rw(
			hook, IRP_MJ_READ, header, sizeof(dc_header), offset
			);
		
		if (resl != ST_OK) {			
			break;
		}

		/* derive header key and decrypt header */
		do
		{
			if ( (password != NULL) && (password[0] != 0) )
			{
				/* probe mount with entered password */
				if (hdr_key = dc_fast_dec_header(header, &hook->crypt, password)) {
					strcpy(res_pass, password); break;
				}
			}

			KeEnterCriticalRegion();
			ExAcquireResourceSharedLite(&p_resource, TRUE);

			/* probe mount with cached passwords */
			for (d_pass = f_pass; d_pass; d_pass = d_pass->next)
			{
				if (hdr_key = dc_fast_dec_header(header, &hook->crypt, d_pass->pass)) {
					strcpy(res_pass, d_pass->pass); break;
				}
			}

			ExReleaseResourceLite(&p_resource);
			KeLeaveCriticalRegion();
		} while (0);

		/* check backup header and fix it */
		if ( (hdr_key != NULL) && (BE16(header->version) > 2) && !(header->flags & VF_TMP_MODE) )
		{
			DbgMsg("check backup header\n");
			
			b_resl = dc_device_rw(
				hook, IRP_MJ_READ, &b_header, sizeof(b_header), copy_offset
				);

			if (b_resl != ST_OK) {
				break;
			}

			bkf_key = dc_dec_known_header(
				&b_header, &hook->crypt, res_pass
				);

			if (bkf_key != NULL) {
				DbgMsg("backup header ok\n");
				break;
			}
			DbgMsg("backup header error\n");

			/* restore backup header */
			dc_write_header(hook, header, copy_offset, res_pass);
		}
	} while (0);

	if ( (resl == ST_OK) && (hdr_key == NULL) ) {
		resl = ST_PASS_ERR;
	}

	/* save header key */
	res_key[0] = hdr_key;

	/* prevent leaks */
	if (bkf_key != NULL) {
		zeroauto(bkf_key, sizeof(dc_key));
		mem_free(bkf_key);
	}
	
	zeroauto(&b_header, sizeof(b_header));

	return resl;
}

static 
void dc_delayed_shrink(
	   dev_hook *hook, dc_header *hcopy, char *pass
	   )
{
	NTSTATUS status;
	u8       buff[SECTOR_SIZE];

	DbgMsg("dc_delayed_shrink\n");

	do
	{
		/* read first FS sector */
		status = io_device_rw_block(
			hook->hook_dev, IRP_MJ_READ, buff, sizeof(buff), 0, SL_OVERRIDE_VERIFY_VOLUME
			);

		if (NT_SUCCESS(status) == FALSE) {
			break;
		}

		/* set new FS sectors count */
		p32(buff + hcopy->shrink_off)[0] = hcopy->shrink_val;

		/* write first FS sector */
		io_device_rw_block(
			hook->hook_dev, IRP_MJ_WRITE, buff, sizeof(buff), 0, SL_OVERRIDE_VERIFY_VOLUME
			);
	} while (0);

	/* clean shrink flags */
	hcopy->flags     &= ~VF_SHRINK_PENDING;
	hcopy->shrink_off = 0;
	hcopy->shrink_val = 0;	
	/* save volume header and backup header */
	dc_write_header(hook, hcopy, 0, pass);
	dc_write_header(hook, hcopy, DC_BACKUP_OFFSET(hook), pass);
}

int dc_mount_device(wchar_t *dev_name, char *password)
{
	dc_header     hcopy;
	char          pass[MAX_PASSWORD + 1];
	dev_hook     *hook = NULL;
	dc_key       *hdr_key = NULL;
	DISK_GEOMETRY dg;
	NTSTATUS      status;
	int           resl;
	
	DbgMsg("dc_mount_device %ws\n", dev_name);

	lock_inc(&dc_data_lock);

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
			hook, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &dg, sizeof(dg)
			);

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

		resl = dc_get_header_and_restory_copy(
			hook, &hcopy, &hdr_key, pass, 0, DC_BACKUP_OFFSET(hook), password
			);

		if (resl == ST_PASS_ERR)
		{
			resl = dc_get_header_and_restory_copy(
				hook, &hcopy, &hdr_key, pass, DC_BACKUP_OFFSET(hook), 0, password
				);
		}
		
		if (resl != ST_OK) {			
			break;
		}
		
		DbgMsg("hdr_key %x\n", hdr_key);

		dc_cipher_init(
			&hook->dsk_key, hook->crypt.cipher_id, 
			hook->crypt.mode_id, hcopy.key_data
			);

		DbgMsg("device mounted\n");

		hook->disk_id    = hcopy.disk_id;
		hook->vf_version = BE16(hcopy.version);

		DbgMsg("hook->vf_version %d\n", hook->vf_version);
		DbgMsg("flags %x\n", hcopy.flags);

		if (hook->vf_version == 2) {
			hook->use_size = hook->dsk_size - HEADER_SIZE;
		} else {
			hook->use_size = hook->dsk_size - HEADER_SIZE - DC_RESERVED_SIZE;
		}

		if (hcopy.flags & VF_TMP_MODE)
		{
			hook->tmp_size       = hcopy.tmp_size;
			hook->tmp_save_off   = hcopy.tmp_save_off;
			hook->hdr_key        = hdr_key;
			hook->crypt.wp_mode  = hcopy.tmp_wp_mode;			

			if (hcopy.flags & VF_REENCRYPT) {
				hook->sync_init_type = S_CONTINUE_RE_ENC;
			} else {
				hook->sync_init_type = S_CONTINUE_ENC;
			}
				
			/* copy decrypted header and password to device data */
			autocpy(&hook->tmp_header, &hcopy, sizeof(dc_header));
			strcpy(hook->tmp_pass, pass);
				
			if ( (resl = dc_enable_sync_mode(hook)) != ST_OK ) 
			{
				zeroauto(&hook->tmp_header, sizeof(dc_header));
				zeroauto(&hook->tmp_pass, sizeof(hook->tmp_pass));
				hdr_key = hook->hdr_key;
			} else 
			{
				if ( (hcopy.flags & VF_SHRINK_PENDING) && (hook->vf_version == TC_VOLUME_HEADER_VERSION) ) 
				{
					dc_delayed_shrink(hook, &hcopy, pass);
					/* copy changed header to device data */
					autocpy(&hook->tmp_header, &hcopy, sizeof(dc_header));
				}
				hdr_key = NULL; /* prevent key wiping */
			}
		} else {
			hook->flags |= F_ENABLED; resl = ST_OK;
		}			
	} while (0);

	/* prevent leaks */
	if (hdr_key != NULL) {
		zeroauto(hdr_key, sizeof(dc_key));
		mem_free(hdr_key);
	}

	zeroauto(pass, sizeof(pass));
	zeroauto(&hcopy,  sizeof(dc_header));

	if (hook != NULL) {
		KeReleaseMutex(&hook->busy_lock, FALSE);
		dc_deref_hook(hook);
	}	

	lock_dec(&dc_data_lock);

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
	HANDLE h_dev = NULL;
	int    resl;

	DbgMsg("dc_process_unmount\n");
	
	if ( !(hook->flags & F_ENABLED) ) {
		return ST_NO_MOUNT;
	}

	if ( !(opt & UM_NOSYNC) ) {
		wait_object_infinity(&hook->busy_lock);
	}

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
				if ( (io_fs_control(h_dev, FSCTL_LOCK_VOLUME) != ST_OK) && !(opt & UM_FORCE) ) {
					resl = ST_LOCK_ERR; break;
				}

				io_fs_control(h_dev, FSCTL_DISMOUNT_VOLUME);
			}
		}

		if ( (hook->flags & F_SYNC) && !(opt & UM_NOSYNC) )
		{
			/* temporary disable IRP processing */
			hook->flags |= F_DISABLE;

			/* send signal to syncronous mode thread */
			dc_send_sync_packet(hook->dev_name, S_OP_FINALIZE, 0);

			/* enable IRP processing */
			hook->flags &= ~F_DISABLE;
		}		

		hook->flags    &= ~(F_ENABLED | F_SYNC | F_REENCRYPT);
		hook->use_size  = hook->dsk_size;
		hook->tmp_size  = 0;
		resl            = ST_OK;

		/* prevent leaks */
		zeroauto(&hook->dsk_key, sizeof(dc_key));
	} while (0);

	if (h_dev != NULL) {
		ZwClose(h_dev);
	}

	if ( !(opt & UM_NOSYNC) ) {
		KeReleaseMutex(&hook->busy_lock, FALSE);
	}
	
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
			&mnt->wrk_item, unmount_item_proc, mnt
			);

		ExQueueWorkItem(
			&mnt->wrk_item, DelayedWorkQueue
			);
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

int dc_mount_all(s8 *password)
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

	mem_free(mnt);
}

NTSTATUS
  dc_probe_mount(
     IN PDEVICE_OBJECT dev_obj, 
	 IN PIRP           irp
	 )
{
	mount_ctx *mnt;

	if ( (mnt = mem_alloc(sizeof(mount_ctx))) == NULL ) 
	{
		return dc_complete_irp(
			irp, STATUS_INSUFFICIENT_RESOURCES, 0
			);
	}

	IoMarkIrpPending(irp);

	mnt->dev_obj = dev_obj;
	mnt->irp     = irp;
		
	ExInitializeWorkItem(
		&mnt->wrk_item, mount_item_proc, mnt
		);

	ExQueueWorkItem(
		&mnt->wrk_item, DelayedWorkQueue
		);

	return STATUS_PENDING;
}

void dc_init_mount()
{
	ExInitializeResourceLite(&p_resource);
	f_pass = NULL;
}
