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

#include <windows.h>
#include <stdio.h>
#include "..\sys\driver.h"
#include "..\boot\boot.h"
#include "mbrinst.h"
#include "dcres.h"
#include "misc.h"
#include "ntdll.h"
#include "iso_fs.h"

#define OLD_SIGN      0x69EADBF4
#define NEW_SIGN      0x20B60251
#define DC_ISO_SIZE   1835008
#define BOOT_MAX_SIZE (2048 * 1024)
#define K64_SIZE      (64 * 1024)

u64 dc_dsk_get_size(int dsk_num, int precision) 
{
	HANDLE           hdisk = NULL;
	u64              mid, size  = 0;
	u64              high, low;
	u64              bps, pos;
	u32              bytes;
	DISK_GEOMETRY_EX dgx;
	DISK_GEOMETRY    dg;
	u8               buff[SECTOR_SIZE];

	do
	{
		if ( (hdisk = dc_disk_open(dsk_num)) == NULL ) {
			break;
		}
		
		if (DeviceIoControl(
			 hdisk, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, 
			 NULL, 0, &dgx, sizeof(dgx), &bytes, NULL)) 
		{
			size = dgx.DiskSize.QuadPart; break;
		}

		if (DeviceIoControl(
			 hdisk, IOCTL_DISK_GET_DRIVE_GEOMETRY, 
			 NULL, 0, &dg, sizeof(dg), &bytes, NULL)) 
		{
			bps  = dg.BytesPerSector;
			high = (u64)dg.SectorsPerTrack * (u64)dg.TracksPerCylinder * bps;
			size = high * dg.Cylinders.QuadPart;
			high = (high + size) / bps;
			low  = size / bps;			

			/* binary search disk space in hidden cylinder */
			if (precision != 0) 
			{
				do
				{
					mid = (high + low) / 2;
					pos = mid * bps;

					SetFilePointer(
						hdisk, (u32)(pos), &p32(&pos)[1], FILE_BEGIN
						);

					if (ReadFile(hdisk, buff, sizeof(buff), &bytes, NULL) != FALSE) {
						low = mid+1; 
					} else {
						high = mid-1;
					}

					if (high <= low) {
						size = low * bps;
						break;
					}
				} while (1);
			}
			break;
		}		
	} while (0);

	if (hdisk != NULL) {
		CloseHandle(hdisk);
	}

	return size;
}

static
ldr_config *dc_find_conf(char *data, int size)
{
	ldr_config *cnf;
	ldr_config *conf = NULL;

	for (; size > sizeof(ldr_config); size--, data++) 
	{
		cnf = pv(data);

		if ( (cnf->sign1 == 0x1434A669) && (cnf->sign2 == 0x7269DA46) &&
			 (cnf->sign3 == 0x342C8006) && (cnf->sign4 == 0x1280A744)) 
		{
			conf = cnf;
			break;
		}
	}

	return conf;
}

int dc_make_iso(wchar_t *file)
{
	u8   *isobuf = NULL;
	int   bootsz, ldrsz;
	void *boot, *loader;	
	int   resl;

	do
	{
		struct iso_primary_descriptor *pd, *bd, *td;
		struct iso_path_table         *pt;
		struct iso_directory_record   *dr;
		struct iso_validation_entry   *ve;
		struct iso_initial_entry      *ie;
		
		if ( (isobuf = malloc(DC_ISO_SIZE)) == NULL ) {
			resl = ST_NOMEM;
			break;
		}

		if ( (boot = dc_extract_rsrc(&bootsz, IDR_MBR)) == NULL ) {
			resl = ST_ERROR;
			break;
		}
			
		if ( (loader = dc_extract_rsrc(&ldrsz, IDR_DCLDR)) == NULL ) {
			resl = ST_ERROR;
			break;
		}

		/*
		  for more information please read 
		    http://users.pandora.be/it3.consultants.bvba/handouts/ISO9960.html
			http://www.phoenix.com/NR/rdonlyres/98D3219C-9CC9-4DF5-B496-A286D893E36A/0/specscdrom.pdf
		*/

		zeroauto(isobuf, DC_ISO_SIZE);
		pd = addof(isobuf, 0x8000);
		bd = addof(isobuf, 0x8800);
		td = addof(isobuf, 0x9000);
		pt = addof(isobuf, 0xA000);
		dr = addof(isobuf, 0xC000);
		ve = addof(isobuf, 0xC800);
		ie = addof(isobuf, 0xC820);
		/* primary volume descriptor */
		pd->type[0] = ISO_VD_PRIMARY;
		strcpy(pd->id, ISO_STANDARD_ID);
		pd->version[0] = 1;
		strcpy(pd->volume_id, "DiskCryptor boot disk           ");
		p32(pd->volume_space_size)[0] = DC_ISO_SIZE / ISOFS_BLOCK_SIZE;
		p32(pd->volume_space_size)[1] = BE32(DC_ISO_SIZE / ISOFS_BLOCK_SIZE);
		p32(pd->volume_set_size)[0] = 0x01000001;
		p32(pd->volume_sequence_number)[0] = 0x01000001;
		p32(pd->logical_block_size)[0] = 0x00080800;
		pd->path_table_size[0] = 0x0A;
		pd->path_table_size[7] = 0x0A;
		pd->type_l_path_table[0] = 0x14;
		pd->root_directory_record[0] = 0x22;
		pd->root_directory_record[2] = 0x18;
		/* boot record volume descriptor */
		bd->type[0] = ISO_VD_BOOT;
		strcpy(bd->id, ISO_STANDARD_ID);
		bd->version[0] = 1;
		strcpy(bd->system_id, "EL TORITO SPECIFICATION");
		bd->volume_id[31] = 0x19;
		/* volume descriptor set terminator */
		td->type[0] = ISO_VD_END;
		strcpy(td->id, ISO_STANDARD_ID);
		td->version[0] = 1;
		/* iso path table */
		pt->name_len[0] = 1;
		pt->extent[0] = 0x18;
		pt->parent[0] = 1;
		/* root directory record */
		dr[0].length[0] = sizeof(struct iso_directory_record);
		dr[0].ext_attr_length[0] = 0x18;
		dr[0].extent[6] = 0x18;
		dr[0].size[0] = 0x08;
		dr[0].size[5] = 0x08;
		dr[0].date[6] = 0x02;
		dr[0].interleave[0] = 0x01;
		p32(dr[0].volume_sequence_number + 2)[0] = 0x00000101;
		dr[1].length[0] = sizeof(struct iso_directory_record);
		dr[1].ext_attr_length[0] = 0x18;
		dr[1].extent[6] = 0x18;
		dr[1].size[0] = 0x08;
		dr[1].size[5] = 0x08;
		dr[1].date[6] = 0x02;
		dr[1].interleave[0] = 0x01;
		p32(dr[1].volume_sequence_number + 2)[0] = 0x00010101;
		/* validation entry */
		ve->header_id[0] = 1;
		ve->checksumm[0] = 0xAA;
		ve->checksumm[1] = 0x55;
		ve->key_byte1[0] = 0x55;
		ve->key_byte2[0] = 0xAA;
		/* initial/default entry */
		ie->boot_indicator[0] = 0x88;
		ie->media_type[0] = 0x02; /* 1.44m diskette emulation */
		ie->sector_count[0] = 1;
		ie->load_rba[0] = 26; /* sector number */
		/* copy boot sector */
		autocpy(isobuf + 0xD000, boot, SECTOR_SIZE);
		/* copy bootloader */
		mincpy(isobuf + 0xD200, loader, ldrsz);

		/* write image to file */
		resl = save_file(file, isobuf, DC_ISO_SIZE);
	} while (0);

	if (isobuf != NULL) {
		free(isobuf);
	}

	return resl;
}

int dc_make_pxe(wchar_t *file)
{
	u8   *isobuf = NULL;
	int   ldrsz, resl;
	void *loader;
	
	do
	{
		if ( (loader = dc_extract_rsrc(&ldrsz, IDR_DCLDR)) == NULL ) {
			resl = ST_ERROR; break;
		}
		/* write image to file */
		resl = save_file(file, loader, ldrsz);
	} while (0);

	if (isobuf != NULL) {
		free(isobuf);
	}

	return resl;
}


int dc_get_boot_disk(int *dsk_num)
{
	HANDLE    device = NULL;
	drive_inf info;
	int       resl;

	do
	{
		resl = dc_get_drive_info(
			L"\\\\.\\GLOBALROOT\\ArcName\\multi(0)disk(0)rdisk(0)partition(1)", &info
			);

		if ( (resl != ST_OK) || (info.dsk_type == DSK_DYN_SPANNED) ) {
			resl = ST_NF_BOOT_DEV; break;
		} else {
			*dsk_num = info.disks[0].number;			
		}

	} while (0);

	if (device != INVALID_HANDLE_VALUE) {
		CloseHandle(device);
	}

	return resl;
}

static int dc_format_media_and_set_boot(
			 HANDLE h_device, wchar_t *root, int dsk_num, DISK_GEOMETRY *dg
			 )
{
	u8                        buff[sizeof(DRIVE_LAYOUT_INFORMATION) + 
		                           sizeof(PARTITION_INFORMATION) * 3];
	PDRIVE_LAYOUT_INFORMATION dli = pv(buff);
	u64                       d_size;
	u32                       bytes;
	int                       resl, succs;
	int                       locked;
	u8                        mbr_sec[SECTOR_SIZE];
	
	locked = 0;
	do
	{
		d_size = (u64)dg->Cylinders.QuadPart * (u64)dg->SectorsPerTrack * 
			     (u64)dg->TracksPerCylinder  * SECTOR_SIZE;

		if (d_size < K64_SIZE) {
			resl = ST_NF_SPACE; break;
		}

		succs = DeviceIoControl(
			h_device, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0, &bytes, NULL
			);

		if (succs == 0) {
			resl = ST_LOCK_ERR; break;
		} else {
			locked = 1;
		}

		DeviceIoControl(
			h_device, IOCTL_DISK_DELETE_DRIVE_LAYOUT, NULL, 0, NULL, 0, &bytes, NULL
			);

		zeroauto(mbr_sec, sizeof(mbr_sec));
		zeroauto(buff, sizeof(buff));

		resl = dc_disk_write(
			h_device, mbr_sec, sizeof(mbr_sec), 0
			);

		if (resl != ST_OK) {
			break;
		}

		dli->PartitionCount = 4;
		dli->Signature      = 0;
		dli->PartitionEntry[0].StartingOffset.QuadPart  = K64_SIZE;
		dli->PartitionEntry[0].PartitionLength.QuadPart = d_size - K64_SIZE;
		dli->PartitionEntry[0].HiddenSectors            = 0;
		dli->PartitionEntry[0].PartitionNumber          = 0;
		dli->PartitionEntry[0].PartitionType            = PARTITION_FAT32;
		dli->PartitionEntry[0].BootIndicator            = TRUE;
		dli->PartitionEntry[0].RecognizedPartition      = TRUE;
		dli->PartitionEntry[0].RewritePartition         = TRUE;

		succs = DeviceIoControl(
			h_device, IOCTL_DISK_SET_DRIVE_LAYOUT, dli, sizeof(buff), NULL, 0, &bytes, NULL
			);

		if (succs == 0) {
			resl = ST_ERROR; break;
		}

		DeviceIoControl(
			h_device, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0, &bytes, NULL
			);

		succs = DeviceIoControl(
			h_device, FSCTL_UNLOCK_VOLUME, NULL, 0, NULL, 0, &bytes, NULL
			);

		if (succs != 0) {
			locked = 0;
		}

		CloseHandle(h_device); h_device = NULL;

		if ( (resl = dc_format_fs(root, L"FAT32")) != ST_OK ) {
			break;
		}
		
		resl = dc_set_mbr(dsk_num, 1);		
	} while(0);

	if (locked != 0) 
	{
		DeviceIoControl(
			h_device, FSCTL_UNLOCK_VOLUME, NULL, 0, NULL, 0, &bytes, NULL
			);
	}

	if (h_device != NULL) {
		CloseHandle(h_device);
	}

	return resl;
}

static int dc_is_mbr_present(int dsk_num)
{
	HANDLE hdisk;
	dc_mbr mbr;
	int    resl;

	do
	{
		if ( (hdisk = dc_disk_open(dsk_num)) == NULL ) {
			resl = ST_ERROR; break;
		}

		if ( (resl = dc_disk_read(hdisk, &mbr, sizeof(mbr), 0)) != ST_OK ) {
			break;
		}

		if ( (mbr.magic != 0xAA55) || (dc_fs_type(pv(&mbr)) != FS_UNK) ) {
			resl = ST_MBR_ERR; break;
		} else {
			resl = ST_OK;
		}
	} while (0);

	if (hdisk != NULL) {
		CloseHandle(hdisk);
	}

	return resl;
}

int dc_set_boot(wchar_t *root, int format)
{
	wchar_t               disk[MAX_PATH];
	HANDLE                hdisk   = NULL;
	int                   resl, succs;
	u32                   bytes;	
	DISK_GEOMETRY         dg;
	STORAGE_DEVICE_NUMBER d_num;
	
	if (root[0] != L'\\') 
	{
		_snwprintf(
			disk, sizeof_w(disk), L"\\\\.\\%c:", root[0]
			);
	} else {
		wcsncpy(disk, root, sizeof_w(disk));
	}

	do
	{
		/* open partition */
		hdisk = CreateFile(
			disk, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL
			);

		if (hdisk == INVALID_HANDLE_VALUE) {			
			resl  = ST_ACCESS_DENIED;
			hdisk = NULL; break;
		}

		succs = DeviceIoControl(
			hdisk, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &dg, sizeof(dg), &bytes, NULL
			);

		if (succs == 0) {
			resl = ST_ERROR; break;
		}

		if (dg.MediaType != RemovableMedia) {
			resl = ST_INV_MEDIA_TYPE; break;
		}

		if (dg.BytesPerSector > SECTOR_SIZE) {
			resl = ST_INV_SECT; break;
		}

		succs = DeviceIoControl(
			hdisk, IOCTL_STORAGE_GET_DEVICE_NUMBER, NULL, 0, &d_num, sizeof(d_num), &bytes, NULL
			);

		if (succs == 0) {
			resl = ST_ERROR; break;
		}

		if (format == 0) 
		{
			if (dc_is_mbr_present(d_num.DeviceNumber) != ST_OK) {
				resl = ST_FORMAT_NEEDED; break;
			}

			if ( (resl = dc_set_mbr(d_num.DeviceNumber, 1)) == ST_NF_SPACE )
			{
				if ( (resl = dc_set_mbr(d_num.DeviceNumber, 0)) == ST_NF_SPACE ) {
					resl = ST_FORMAT_NEEDED;
				}
			}
		} else
		{
			resl  = dc_format_media_and_set_boot(hdisk, disk, d_num.DeviceNumber, &dg);
			hdisk = NULL;
		}	
	} while (0);

	if (hdisk != NULL) {
		CloseHandle(hdisk);
	}

	return resl;
}

int dc_set_mbr(int dsk_num, int begin)
{
	dc_mbr      mbr;
	dc_mbr      old_mbr;
	u64         dsk_sze;
	u64         max_end;
	u64         min_str;
	u64         ldr_off;
	ldr_config *conf;
	pt_ent     *pt;
	void       *data;
	int         size, i;
	int         resl;
	HANDLE      hdisk;

	hdisk = NULL;
	do
	{
		/* if dsk_num == -1 then find boot disk */
		if (dsk_num == -1) 
		{
			if ( (resl = dc_get_boot_disk(&dsk_num)) != ST_OK ) {				
				break;
			}
		}

		if ( (hdisk = dc_disk_open(dsk_num)) == NULL ) {
			break;
		}

		if (data = dc_extract_rsrc(&size, IDR_MBR)) {
			autocpy(&mbr, data, sizeof(mbr));
		} else {
			resl = ST_ERROR; break;
		}

		if ( (data = dc_extract_rsrc(&size, IDR_DCLDR)) == NULL ) {			
			resl = ST_ERROR; break;
		}

		if ( (conf = dc_find_conf(data, size)) == NULL ) {
			resl = ST_ERROR; break;
		}

		/* get disk size */
		if ( (dsk_sze = dc_dsk_get_size(dsk_num, 1)) == 0 ) {			
			resl = ST_IO_ERROR; break;
		}

		/* read disk MBR */
		if ( (resl = dc_disk_read(hdisk, &old_mbr, sizeof(old_mbr), 0)) != ST_OK ) {			
			break;
		}

		if (old_mbr.magic != 0xAA55) {			
			resl = ST_MBR_ERR; break;
		}

		if ( (old_mbr.sign == NEW_SIGN) || (old_mbr.old_sign == OLD_SIGN) ) {			
			resl = ST_BLDR_INSTALLED; break;
		}

		/* fins free space before and after partitions */
		min_str = 64; max_end = 0;
		for (i = 0, max_end = 0; i < 4; i++) 
		{
			if ( (pt = &old_mbr.pt[i])->prt_size == 0 ) {
				continue;
			}

			min_str = min(min_str, pt->start_sect);
			max_end = max(max_end, pt->start_sect + pt->prt_size);
		}

		max_end *= SECTOR_SIZE; min_str *= SECTOR_SIZE;

		if (begin != 0) 
		{
			if (min_str < size + SECTOR_SIZE) {
				resl = ST_NF_SPACE; break;
			}

			ldr_off = SECTOR_SIZE;		
		} else 
		{
			ldr_off = dsk_sze - size - (8 * SECTOR_SIZE); /* reserve last 8 sectors for LDM data */

			if (max_end > ldr_off) {
				resl = ST_NF_SPACE; break;
			}
		}		

		/* save old MBR */
		autocpy(conf->save_mbr, &old_mbr, sizeof(old_mbr));

		/* prepare new MBR */
		autocpy(mbr.data2, old_mbr.data2, sizeof(mbr.data2));

		mbr.set.sector = ldr_off / SECTOR_SIZE;
		mbr.set.numb   = size / SECTOR_SIZE;

		/* write bootloader data */
		if ( (resl = dc_disk_write(hdisk, data, size, ldr_off)) != ST_OK ) {
			break;
		}

		if ( (resl = dc_disk_write(hdisk, &mbr, sizeof(mbr), 0)) != ST_OK ) {
			break;
		}
	} while (0);

	if (hdisk != NULL) {
		CloseHandle(hdisk);
	}

	return resl;
}

static
int get_ldr_body_ptr(
	   HANDLE hdisk, dc_mbr *mbr, u64 *start, int *size
	   )
{
	int resl;

	do
	{
		if ( (resl = dc_disk_read(hdisk, mbr, sizeof(dc_mbr), 0)) != ST_OK ) {
			break;
		}

		if (mbr->magic != 0xAA55) {
			resl = ST_MBR_ERR; break;
		}

		if ( (mbr->sign != NEW_SIGN) && (mbr->old_sign != OLD_SIGN) ) {
			resl = ST_BLDR_NOTINST; break;
		}

		if (mbr->sign == NEW_SIGN) {
			*start = mbr->set.sector * SECTOR_SIZE;
			*size  = mbr->set.numb   * SECTOR_SIZE;
		} else {
			*start = 0;
			*size  = mbr->old_offs;
		}
		resl = ST_OK;
	} while (0);

	return resl;
}

int dc_get_mbr_config(
	  int dsk_num, wchar_t *file, ldr_config *conf
	  )
{
	ldr_config *cnf, *def;
	HANDLE      hfile, hdisk;
	void       *data, *dat2;
	int         size, resl;
	dc_mbr      mbr;		
	u64         offs;
	u32         bytes;

	hfile = NULL; hdisk = NULL; data = NULL;
	do
	{
		/* if dsk_num == -1 then find boot disk */
		if (dsk_num == -1) 
		{
			if ( (resl = dc_get_boot_disk(&dsk_num)) != ST_OK ) {
				break;
			}
		}

		if (file != NULL) 
		{
			/* open file */
			hfile = CreateFile(
				file, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL
				);

			if (hfile == INVALID_HANDLE_VALUE) {
				resl  = ST_NF_FILE;
				hfile = NULL; break;
			}

			/* get size of file */
			size = GetFileSize(hfile, NULL);

			if ( (size == 0) || (size > BOOT_MAX_SIZE) ) {
				resl = ST_INV_BLDR_SIZE; break;
			}
		} else 
		{
			if ( (hdisk = dc_disk_open(dsk_num)) == NULL ) {
				break;
			}

			/* get bootloader body offset */
			if ( (resl = get_ldr_body_ptr(hdisk, &mbr, &offs, &size)) != ST_OK ) {
				break;
			}
		}

		/* load bootloader body */
		if ( (data = malloc(size)) == NULL ) {
			resl = ST_NOMEM; break;
		}
		
		if (file != NULL) 
		{
			/* read bootloader body from file */
			if (ReadFile(hfile, data, size, &bytes, NULL) == FALSE) {
				resl = ST_IO_ERROR; break;
			}
		} else 
		{
			/* read bootloader body from disk */
			if ( (resl = dc_disk_read(hdisk, data, size, offs)) != ST_OK ) {				
				break;
			}
		}

		/* find bootloader config */
		if ( (cnf = dc_find_conf(data, size)) == NULL ) {
			resl = ST_BLDR_NO_CONF; break;
		}

		if ( (file != NULL) || (mbr.sign == NEW_SIGN) ) 
		{
			autocpy(conf, cnf, sizeof(ldr_config));

			if (conf->ldr_ver < 32) { /* timeout field been added in 32 version */
				conf->timeout = 0;
			}
		} else 
		{
			/* load new bootloader */
			if ( (dat2 = dc_extract_rsrc(&size, IDR_DCLDR)) == NULL ) {
				resl = ST_ERROR; break;		
			}

			/* get default config */
			if ( (def = dc_find_conf(dat2, size)) == NULL ) {
				resl = ST_ERROR; break;
			}

			/* combine old and default config */
			autocpy(conf, def, sizeof(ldr_config));
			strcpy(conf->eps_msg, cnf->eps_msg);
			strcpy(conf->err_msg, cnf->err_msg);
			conf->ldr_ver = cnf->ldr_ver;
		}
		resl = ST_OK;
	} while (0);

	if (data != NULL) {
		free(data);
	}

	if (hfile != NULL) {
		CloseHandle(hfile);
	}

	if (hdisk != NULL) {
		CloseHandle(hdisk);
	}

	return resl;
}

int dc_set_mbr_config(
	  int dsk_num, wchar_t *file, ldr_config *conf
	  )
{
	HANDLE      hfile, hdisk;
	int         size, resl;
	ldr_config *cnf;	
	dc_mbr      mbr;
	void       *data;	
	u64         offs;
	u32         bytes;	

	hdisk = NULL; hfile = NULL; data = NULL;
	do
	{
		/* if dsk_num == -1 then find boot disk */
		if (dsk_num == -1) 
		{
			if ( (resl = dc_get_boot_disk(&dsk_num)) != ST_OK ) {
				break;
			}
		}

		if (file != NULL) 
		{
			/* open file */
			hfile = CreateFile(
				file, GENERIC_READ | GENERIC_WRITE, 
				FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL
				);

			if (hfile == INVALID_HANDLE_VALUE) {
				resl  = ST_NF_FILE;
				hfile = NULL; break;
			}

			/* get size of file */
			size = GetFileSize(hfile, NULL);

			if ( (size == 0) || (size > BOOT_MAX_SIZE) ) {
				resl = ST_INV_BLDR_SIZE; break;
			}
		} else 
		{
			if ( (hdisk = dc_disk_open(dsk_num)) == NULL ) {
				break;
			}
			/* get bootloader body offset */
			if ( (resl = get_ldr_body_ptr(hdisk, &mbr, &offs, &size)) != ST_OK ) {
				break;
			}
		}

		if ( (file == NULL) && (mbr.sign != NEW_SIGN) ) {
			resl = ST_BLDR_OLD_VER; break;
		}

		/* load bootloader body */
		if ( (data = malloc(size)) == NULL ) {
			resl = ST_NOMEM; break;
		}

		if (file != NULL) 
		{
			/* read bootloader body from file */
			if (ReadFile(hfile, data, size, &bytes, NULL) == FALSE) {
				resl = ST_IO_ERROR; break;
			}
		} else 
		{
			/* read bootloader body from disk */
			if ( (resl = dc_disk_read(hdisk, data, size, offs)) != ST_OK ) {
				break;
			}
		}

		/* find bootloader config */
		if ( (cnf = dc_find_conf(data, size)) == NULL ) {
			resl = ST_BLDR_NO_CONF; break;
		}

		/* copy new values to config */
		autocpy(cnf, conf, sizeof(ldr_config));
		/* set unchangeable fields to default */
		cnf->sign1 = CFG_SIGN1; cnf->sign2 = CFG_SIGN2;
		cnf->sign3 = CFG_SIGN3; cnf->sign4 = CFG_SIGN4;
		cnf->ldr_ver = DC_BOOT_VER;
		
		if (file != NULL) 
		{
			/* save bootloader body to file */
			SetFilePointer(hfile, 0, NULL, FILE_BEGIN);
			SetEndOfFile(hfile);

			if (WriteFile(hfile, data, size, &bytes, NULL) == FALSE) {
				resl = ST_IO_ERROR; break;
			}
		} else 
		{
			/* save bootloader body to disk */
			if ( (resl = dc_disk_write(hdisk, data, size, offs)) != ST_OK ) {
				break;
			}
		}
		resl = ST_OK;
	} while (0);

	if (data != NULL) {
		free(data);
	}

	if (hfile != NULL) {
		CloseHandle(hfile);
	}

	if (hdisk != NULL) {
		CloseHandle(hdisk);
	}

	return resl;
}

int dc_mbr_config_by_partition(
      wchar_t *root, int set_conf, ldr_config *conf
	  )
{
	HANDLE        hdisk;
	wchar_t       name[MAX_PATH];
	DISK_GEOMETRY dg;
	drive_inf     info;
	int           resl, succs;
	u32           bytes;
	
	if (root[0] != L'\\')
	{
		_snwprintf(
			name, sizeof_w(name), L"\\\\.\\%c:", root[0]
			);
	} else {
		wcsncpy(name, root, sizeof_w(name));
	}

	info.dsk_num = 0;
	do
	{
		/* open partition */
		hdisk = CreateFile(
			name, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL
			);

		if (hdisk == INVALID_HANDLE_VALUE) {			
			resl  = ST_ACCESS_DENIED;
			hdisk = NULL; break;
		}

		succs = DeviceIoControl(
			hdisk, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &dg, sizeof(dg), &bytes, NULL
			);

		if (succs == 0) {
			resl = ST_ERROR; break;
		}

		if ( (dg.MediaType == FixedMedia) || (dg.MediaType == RemovableMedia) )
		{
			if ( (resl = dc_get_drive_info(name, &info)) != ST_OK ) {
				break;
			}
		} else  {
			resl = ST_INV_MEDIA_TYPE; break;		
		}

		if (set_conf != 0) {
			resl = dc_set_mbr_config(info.disks[0].number, NULL, conf);
		} else {
			resl = dc_get_mbr_config(info.disks[0].number, NULL, conf);
		}
	} while (0);

	if (hdisk != NULL) {
		CloseHandle(hdisk);
	}

	return resl;
}


int dc_unset_mbr(int dsk_num)
{
	dc_mbr      mbr;
	dc_mbr      old_mbr;
	int         size, resl;
	ldr_config *conf;
	void       *data;
	u64         offs;
	HANDLE      hdisk;

	data = NULL; hdisk = NULL;
	do
	{
		/* if dsk_num == -1 then find boot disk */
		if (dsk_num == -1) 
		{
			if ( (resl = dc_get_boot_disk(&dsk_num)) != ST_OK ) {				
				break;
			}
		}

		if ( (hdisk = dc_disk_open(dsk_num)) == NULL ) {
			break;
		}

		/* get bootloader body offset */
		if ( (resl = get_ldr_body_ptr(hdisk, &mbr, &offs, &size)) != ST_OK ) {			
			break;
		}

		if (mbr.sign == NEW_SIGN)
		{
			/* uninstall new bootloader */
			if ( (data = malloc(size)) == NULL ) {
				resl = ST_NOMEM; break;
			}

			/* read bootloader body */
			if ( (resl = dc_disk_read(hdisk, data, size, offs)) != ST_OK ) {				
				break;
			}

			if ( (conf = dc_find_conf(data, size)) == NULL ) {				
				resl = ST_BLDR_NO_CONF; break;
			}

			/* copy saved old MBR */
			autocpy(&old_mbr, conf->save_mbr, sizeof(old_mbr));

			/* copy new partition table to old MBR */
			autocpy(old_mbr.data2, mbr.data2, sizeof(mbr.data2));

			/* write new MBR */
			if ( (resl = dc_disk_write(hdisk, &old_mbr, sizeof(old_mbr), 0)) != ST_OK ) {				
				break;
			}

			/* zero bootloader sectors */
			zeroauto(&mbr, sizeof(mbr));
			
			for (; size; size -= SECTOR_SIZE, offs += SECTOR_SIZE) {
				dc_disk_write(hdisk, &mbr, sizeof(mbr), offs);
			}
			resl = ST_OK;
		} else 
		{
			/* uninstall old bootloader */		
			
			/* read saved old MBR */
			if ( (resl = dc_disk_read(hdisk, &old_mbr, sizeof(old_mbr), size)) != ST_OK ) {
				break;
			}

			/* copy new partition table to old MBR */
			autocpy(old_mbr.data2, mbr.data2, sizeof(mbr.data2));

			/* write new MBR */
			if ( (resl = dc_disk_write(hdisk, &old_mbr, sizeof(old_mbr), 0)) != ST_OK ) {
				break;
			}

			/* zero bootloader sectors */
			zeroauto(&mbr, sizeof(mbr));
			
			for (; size; size -= SECTOR_SIZE ) {
				dc_disk_write(hdisk, &mbr, sizeof(mbr), size);
			}
			resl = ST_OK;
		}

	} while (0);

	if (data != NULL) {
		free(data);
	}

	if (hdisk != NULL) {
		CloseHandle(hdisk);
	}

	return resl;

}

int dc_update_boot(int dsk_num)
{
	ldr_config conf;
	int        resl;

	do
	{
		if ( (resl = dc_get_mbr_config(dsk_num, NULL, &conf)) != ST_OK ) {
			break;
		}

		/* set partition boot method if old bootloader found */
		if (conf.ldr_ver <= 2) {
			conf.boot_type = BT_ACTIVE;
		}

		if ( (resl = dc_unset_mbr(dsk_num)) != ST_OK ) {
			break;
		}

		if ( (resl = dc_set_mbr(dsk_num, 0)) != ST_OK )
		{
			if ( (resl = dc_set_mbr(dsk_num, 1)) != ST_OK ) {
				break;
			}
		}

		resl = dc_set_mbr_config(dsk_num, NULL, &conf);
	} while (0);

	return resl;
}



int dc_get_drive_info(
	  wchar_t *w32_name, drive_inf *info
	  )
{
	PARTITION_INFORMATION_EX ptix;
	PARTITION_INFORMATION    pti;
	STORAGE_DEVICE_NUMBER    dnum;
	u8                       buff[4096];
	PVOLUME_DISK_EXTENTS     ext = pv(buff);
	u32                      bytes, i;	
	int                      resl;
	int                      succs;
	HANDLE                   hdisk;

	zeroauto(info, sizeof(drive_inf));
	
	do
	{
		hdisk = CreateFile(
			w32_name, SYNCHRONIZE | GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 
			NULL, OPEN_EXISTING, 0, NULL
			);

		if (hdisk == INVALID_HANDLE_VALUE) {
			resl = ST_ERROR; break;
		}

		succs = DeviceIoControl(
			hdisk, IOCTL_DISK_GET_PARTITION_INFO_EX, NULL, 0, &ptix, sizeof(ptix), &bytes, NULL
			);

		if (succs != 0) 
		{
			/*	if (ptix.PartitionStyle = PARTITION_STYLE_GPT) {
				info->use_gpt = 1;
			 */
			info->dsk_num  = ptix.PartitionNumber;
			info->par_size = ptix.PartitionLength.QuadPart;				
		} else 
		{
			succs = DeviceIoControl(
				hdisk, IOCTL_DISK_GET_PARTITION_INFO, NULL, 0, &pti, sizeof(pti), &bytes, NULL
				);

			if (succs == 0) {
				resl = ST_IO_ERROR; break;
			}

			info->use_gpt  = 0;
			info->dsk_num  = pti.PartitionNumber;
			info->par_size = pti.PartitionLength.QuadPart;
		}

		succs = DeviceIoControl(
			hdisk, IOCTL_STORAGE_GET_DEVICE_NUMBER, NULL, 0, &dnum, sizeof(dnum), &bytes, NULL
			);

		if (succs != 0) {
			info->dsk_num         = 1;
			info->dsk_type        = DSK_BASIC;
			info->par_numb        = dnum.PartitionNumber;
			info->disks[0].number = dnum.DeviceNumber;
			info->disks[0].size   = dc_dsk_get_size(dnum.DeviceNumber, 0);
		} else 
		{
			succs = DeviceIoControl(
				hdisk, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, NULL, 0, ext, sizeof(buff), &bytes, NULL
				);
				
			if (succs != 0) 
			{
				for (i = 0; i < ext->NumberOfDiskExtents; i++) {
					info->disks[i].number    = ext->Extents[i].DiskNumber;
					info->disks[i].prt_start = ext->Extents[i].StartingOffset.QuadPart;
					info->disks[i].prt_size  = ext->Extents[i].ExtentLength.QuadPart;
					info->disks[i].size      = dc_dsk_get_size(info->disks[i].number, 0);
				}

				if ( (info->dsk_num = ext->NumberOfDiskExtents) == 1 ) {
					info->dsk_type = DSK_DYN_SIMPLE;
				} else {
					info->dsk_type = DSK_DYN_SPANNED;
				}
			} else {
				resl = ST_IO_ERROR; break;
			}
		}
		resl = ST_OK;
	} while (0);

	if (hdisk != INVALID_HANDLE_VALUE) {
		CloseHandle(hdisk);
	}

	return resl;
}

