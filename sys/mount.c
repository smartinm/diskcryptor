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

typedef struct _dsk_pass {
	struct _dsk_pass *next;
	char              pass[MAX_PASSWORD + 1];
	
} dsk_pass;

typedef struct _mount_ctx {
	WORK_QUEUE_ITEM  wrk_item;
	PDEVICE_OBJECT   dev_obj;
	PIRP             irp;
	
} mount_ctx;

typedef struct _unm_struct {
	s_callback on_complete;
	void      *param;

} unm_struct;

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

		zeromem(c_pass, sizeof(dsk_pass));

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

			zeromem(&hook->dsk_key, sizeof(aes_key));
			zeromem(&hook->tmp_header, sizeof(dc_header));
			zeromem(&hook->tmp_pass, sizeof(hook->tmp_pass));
			
			if (hook->hdr_key != NULL) {
				zeromem(hook->hdr_key, sizeof(aes_key));
			}
		} while (next != NULL);
	} 
}

aes_key *dc_init_hdr_key(dc_header *header, char *password)
{
	u8       dk[DISKKEY_SIZE];
	aes_key *hdr_key;

	if ( (hdr_key = mem_alloc(sizeof(aes_key))) == NULL ) {
		return NULL;
	}

	sha1_pkcs5_2(
		password, strlen(password), 
		header->salt, PKCS5_SALT_SIZE, 
		2000, dk, DISK_IV_SIZE + MAX_KEY_SIZE
		);

	aes_lrw_init_key(
		hdr_key, dk + DISK_IV_SIZE, dk
		);

	zeromem(dk, sizeof(dk));

	return hdr_key;
}

aes_key *dc_decrypt_header(dc_header *header, char *password)	   
{
	aes_key *hdr_key;
	int      succs = 0;
	
	if ( (hdr_key = dc_init_hdr_key(header, password)) == NULL ) {
		return NULL;
	}

	do
	{
		aes_lrw_decrypt(
			pv(&header->sign), pv(&header->sign), 
			HEADER_ENCRYPTEDDATASIZE, 1, hdr_key 
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
		zeromem(hdr_key, sizeof(aes_key));
		mem_free(hdr_key); 
		hdr_key = NULL;
	}
	
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
	aes_key  *hdr_key;
	int       resl;

	do
	{
		/* copy header to new buffer */
		fastcpy(&t_header, header, sizeof(dc_header));

		/* generate new salt */
		rnd_get_bytes(t_header.salt, PKCS5_SALT_SIZE);

		/* init new header key */
		if ( (hdr_key = dc_init_hdr_key(&t_header, password)) == NULL ) {
			resl = ST_NOMEM; break;
		}

		/* encrypt header with new key */
		aes_lrw_encrypt(
			pv(&t_header.sign), pv(&t_header.sign), HEADER_ENCRYPTEDDATASIZE, 1, hdr_key
			);

		/* write header */
		resl = dc_device_rw(
			hook, IRP_MJ_WRITE, &t_header, sizeof(dc_header), offset
			);
	} while (0);

	/* prevent leaks */
	if (hdr_key != NULL) {
		zeromem(hdr_key, sizeof(aes_key));
		mem_free(hdr_key);
	}

	zeromem(&t_header, sizeof(t_header));

	return resl;
}

static
int dc_get_header_and_restory_copy(
	  dev_hook *hook, dc_header *hcopy, aes_key **res_key, char *res_pass,
	  u64 offset, u64 copy_offset, char *password
	  )
{
	dsk_pass *d_pass;	
	dc_header v_header;
	dc_header b_header;
	aes_key  *hdr_key = NULL;
	aes_key  *bkf_key = NULL;
	int       resl, b_resl;

	do
	{
		resl = dc_device_rw(
			hook, IRP_MJ_READ, &v_header, sizeof(v_header), offset
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
				fastcpy(hcopy, &v_header, sizeof(dc_header));
				
				if (hdr_key = dc_decrypt_header(hcopy, password)) {
					strcpy(res_pass, password); break;
				}
			}

			KeEnterCriticalRegion();
			ExAcquireResourceSharedLite(&p_resource, TRUE);

			/* probe mount with cached passwords */
			for (d_pass = f_pass; d_pass; d_pass = d_pass->next)
			{
				fastcpy(hcopy, &v_header, sizeof(dc_header));

				if (hdr_key = dc_decrypt_header(hcopy, d_pass->pass)) {
					strcpy(res_pass, d_pass->pass); break;
				}
			}

			ExReleaseResourceLite(&p_resource);
			KeLeaveCriticalRegion();
		} while (0);

		/* check backup header and fix it */
		if ( (hdr_key != NULL) && (BE16(hcopy->version) > 2) && !(hcopy->flags & VF_TMP_MODE) )
		{
			DbgMsg("check backup header\n");
			
			b_resl = dc_device_rw(
				hook, IRP_MJ_READ, &b_header, sizeof(b_header), copy_offset
				);

			if (b_resl != ST_OK) {
				break;
			}

			if (bkf_key = dc_decrypt_header(&b_header, res_pass)) {
				DbgMsg("backup header ok\n");
				break;
			}
			DbgMsg("backup header error\n");

			/* add volume header to random pool because RNG not 
			   have sufficient entropy at boot time 
			*/
			rnd_add_buff(hcopy, sizeof(dc_header));

			/* restore backup header */
			dc_write_header(hook, hcopy, copy_offset, res_pass);
		}
	} while (0);

	if ( (resl == ST_OK) && (hdr_key == NULL) ) {
		resl = ST_PASS_ERR;		
	}

	/* save header key */
	res_key[0] = hdr_key;

	/* prevent leaks */
	if (bkf_key != NULL) {
		zeromem(bkf_key, sizeof(aes_key));
		mem_free(bkf_key);
	}

	zeromem(&v_header, sizeof(v_header));
	zeromem(&b_header, sizeof(b_header));

	return resl;
}

static 
void dc_delayed_shrink(
	   dev_hook *hook, dc_header *hcopy, char *pass
	   )
{
	u8  buff[SECTOR_SIZE];
	int resl;

	if ( (hcopy->flags & VF_TMP_MODE) && (hcopy->tmp_size == 0) )
	{
		/* read temp sector */
		resl = dc_device_rw(
			hook, IRP_MJ_READ, &buff, sizeof(buff), hcopy->tmp_save_off
			);

		if (resl == ST_OK)
		{
			/* set new FS sectors count */
			p32(buff + hcopy->shrink_off)[0] = hcopy->shrink_val;

			/* write temp sector */
			dc_device_rw(
				hook, IRP_MJ_WRITE, &buff, sizeof(buff), hcopy->tmp_save_off
				);
		}		
	} else
	{
		/* read first FS sector */
		resl = dc_device_rw(
			hook, IRP_MJ_READ, &buff, sizeof(buff), SECTOR_SIZE
			);

		if (resl == ST_OK)
		{
			aes_lrw_decrypt(
				buff, buff, SECTOR_SIZE, lrw_index(0), &hook->dsk_key
				);

			/* set new FS sectors count */
			p32(buff + hcopy->shrink_off)[0] = hcopy->shrink_val;

			aes_lrw_encrypt(
				buff, buff, SECTOR_SIZE, lrw_index(0), &hook->dsk_key
				);

			/* write first FS sector */
			dc_device_rw(
				hook, IRP_MJ_WRITE, &buff, sizeof(buff), SECTOR_SIZE
				);
		}
	}

	/* clean shrink flags */
	hcopy->flags     &= ~VF_SHRINK_PENDING;
	hcopy->shrink_off = 0;
	hcopy->shrink_val = 0;
	/* save volume header and backup header */
	dc_write_header(hook, hcopy, 0, pass);
	dc_write_header(hook, hcopy, DC_BACKUP_OFFSET(hook), pass);
}

int dc_mount_device(wchar_t *dev_name, char *passwod)
{
	dc_header     hcopy;
	char          pass[MAX_PASSWORD + 1];
	dev_hook     *hook    = NULL;
	aes_key      *hdr_key = NULL;
	DISK_GEOMETRY dg;
	NTSTATUS      status;
	int           resl, lock;
	
	DbgMsg("dc_mount_device %ws\n", dev_name);

	lock_inc(&dc_data_lock);

	do 
	{
		if ( (hook = dc_find_hook(dev_name)) == NULL ) {
			resl = ST_NF_DEVICE; break;
		}

		if (hook_lock_acquire(hook, &lock) == 0) {
			resl = ST_DEVICE_BUSY; break;
		}

		if (hook->flags & F_ENABLED) {
			resl = ST_ALR_MOUNT; break;
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
			hook, &hcopy, &hdr_key, pass, 0, DC_BACKUP_OFFSET(hook), passwod
			);
	
		if (resl == ST_PASS_ERR)
		{
			resl = dc_get_header_and_restory_copy(
				hook, &hcopy, &hdr_key, pass, DC_BACKUP_OFFSET(hook), 0, passwod
				);
		}
		
		if (resl != ST_OK) {			
			break;
		}
		
		DbgMsg("hdr_key %x\n", hdr_key);

		aes_lrw_init_key(
		   &hook->dsk_key, hcopy.key_data + DISK_IV_SIZE, hcopy.key_data
		   );

		DbgMsg("device mounted\n");

		hook->disk_id    = hcopy.disk_id;
		hook->wp_mode    = hcopy.tmp_wp_mode;
		hook->vf_version = BE16(hcopy.version);

		DbgMsg("hook->vf_version %d\n", hook->vf_version);
		DbgMsg("flags %x\n", hcopy.flags);

		if (hook->vf_version == 2) {
			hook->use_size = hook->dsk_size - HEADER_SIZE;
		} else 
		{
			if (hcopy.flags & VF_SHRINK_PENDING) {
				dc_delayed_shrink(hook, &hcopy, pass);
			}

			hook->use_size = hook->dsk_size - HEADER_SIZE - DC_RESERVED_SIZE;
		}
			
		if (hcopy.flags & VF_TMP_MODE)
		{
			hook->tmp_size       = hcopy.tmp_size;
			hook->tmp_save_off   = hcopy.tmp_save_off;
			hook->hdr_key        = hdr_key;
			hook->sync_init_type = S_CONTINUE_ENC;
				
			/* copy decrypted header and password to device data */
			fastcpy(&hook->tmp_header, &hcopy, sizeof(dc_header));
			strcpy(hook->tmp_pass, pass);
				
			if ( (resl = dc_enable_sync_mode(hook)) != ST_OK ) 
			{
				zeromem(&hook->tmp_header, sizeof(dc_header));
				zeromem(&hook->tmp_pass, sizeof(hook->tmp_pass));
				hdr_key = hook->hdr_key;
			} else {
				hdr_key = NULL; /* prevent key wiping */
			}
		} else {
			hook->flags |= F_ENABLED; resl = ST_OK;
		}
	} while (0);

	if (hook != NULL) {
		hook_lock_release(hook, lock);
		dc_deref_hook(hook);
	}

	/* prevent leaks */
	if (hdr_key != NULL) {
		zeromem(hdr_key, sizeof(aes_key));
		mem_free(hdr_key);
	}

	zeromem(pass, sizeof(pass));
	zeromem(&hcopy,  sizeof(dc_header));

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

	DbgMsg("dc_process_unmount at IRQL %d\n", KeGetCurrentIrql());
	
	if ( !(hook->flags & F_ENABLED) ) {
		return ST_NO_MOUNT;
	}

	do
	{
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
			dc_send_sync_packet(
				hook->dev_name, S_OP_FINALIZE, 0
				);

			/* enable IRP processing */
			hook->flags &= ~F_DISABLE;
		}

		hook->flags    &= ~(F_ENABLED | F_SYNC);
		hook->use_size  = hook->dsk_size;
		hook->tmp_size  = 0;
		resl            = ST_OK;

		/* prevent leaks */
		zeromem(&hook->dsk_key, sizeof(aes_key));
	} while (0);

	if (h_dev != NULL) {
		ZwClose(h_dev);
	}
	
	return resl;
}

static void dc_unmount_callback(
			  dev_hook *hook, unm_struct *unm, int resl
			  )
{
	if (hook->flags & F_SYNC) {
		// enable IRP processing
		hook->flags &= ~F_DISABLE;
	}

	hook->flags    &= ~(F_ENABLED | F_SYNC);
	hook->use_size  = hook->dsk_size;
	hook->tmp_size  = 0;

	unm->on_complete(
		hook, unm->param, resl
		);
	
	/* prevent leaks */
	zeromem(&hook->dsk_key, sizeof(aes_key));

	mem_free(unm);
}

void dc_process_unmount_async(
		dev_hook *hook, s_callback on_complete, void *param
		)
{
	unm_struct *unm;
	int         resl;

	if ( !(hook->flags & (F_ENABLED | F_SYNC)) ) {
		on_complete(hook, param, ST_NO_MOUNT); return;
	}

	if ( (unm = mem_alloc(sizeof(unm_struct))) == NULL ) {
		on_complete(hook, param, ST_NOMEM); return;
	}

	unm->on_complete = on_complete;
	unm->param       = param;

	if (hook->flags & F_SYNC)
	{
		// temporary disable IRP processing 
		hook->flags |= F_DISABLE;

		// send signal to syncronous mode thread
		resl = dc_send_async_packet(
			hook->dev_name, S_OP_FINALIZE, 0, dc_unmount_callback, unm 
			);

		if (resl != ST_OK) {
			dc_unmount_callback(hook, unm, resl);
		}
	} else {
		dc_unmount_callback(hook, unm, ST_OK);
	}
}


int dc_unmount_device(wchar_t *dev_name, int force)
{
	dev_hook *hook;
	int       resl, lock;

	DbgMsg("dc_unmount_device %ws\n", dev_name);

	if (hook = dc_find_hook(dev_name)) 
	{
		if (hook_lock_acquire(hook, &lock) != 0) 
		{
			if (IS_UNMOUNTABLE(hook)) {
				resl = dc_process_unmount(hook, force);
			} else {
				resl = ST_UNMOUNTABLE;
			}			
		} else {
			resl = ST_DEVICE_BUSY;
		}		

		hook_lock_release(hook, lock);
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

		dc_forward_irp(dev_obj, mnt->irp);
	} else {
		dc_read_write_irp(dev_obj, mnt->irp);
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
