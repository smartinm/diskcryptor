/*
    *
    * DiskCryptor - open source partition encryption tool
	* Copyright (c) 2008
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
#include "defines.h"
#include "..\sys\driver.h"
#include "shrink.h"
#include "misc.h"

static wchar_t *ntfs_metafiles[] = {
	L"$Extend\\$ObjId",
	L"$Extend\\$Quota",
	L"$Extend\\$Reparse",
	L"$AttrDef",
	L"$BadClus",
	L"$Bitmap",
	L"$LogFile",
	L"$MFT",
	L"$MFTMirr",
	L"$Secure",
	L"$UpCase",
	L"$Volume"
};

typedef struct _sh_params {
	u64         sh_start;
	u64         sh_end;
	u32         sh_count;
	u32         cls_size;  /* volume cluster size */
	u32         cls_total; /* total number of clusters on volume */
	int         fs_type;   /* file system type */
	HANDLE      h_dev;
	sh_callback callback;
	void       *param;

} sh_params;

static int is_cls_used(VOLUME_BITMAP_BUFFER *map, u64 cls)
{
	if (cls < (u64)map->BitmapSize.QuadPart) {
		return (map->Buffer[cls / 8] & (1 << (cls % 8))) != 0;
	} else {
		return 0;
	}
}

static void *dc_get_volume_bitmap(sh_params *sh)
{
	STARTING_LCN_INPUT_BUFFER inb;
	VOLUME_BITMAP_BUFFER     *map;
	u32                       bytes;
	int                       succs;

	bytes = sizeof(VOLUME_BITMAP_BUFFER) +
		    sizeof(map->Buffer) * sh->cls_total;

	if (map = malloc(bytes))
	{
		inb.StartingLcn.QuadPart = 0;

		succs = DeviceIoControl(
			sh->h_dev, FSCTL_GET_VOLUME_BITMAP, 
			&inb, sizeof(inb), map, bytes, &bytes, NULL
			);

		if (succs == 0) {
			free(map); map = NULL;
		}
	}

	return map;
}

static 
int dc_get_free_clusters(
		u32 count, sh_params *sh, u64 *f_lcn
		)
{
	VOLUME_BITMAP_BUFFER *map;
	u64                   i, j;
	int                   b_free;
	int                   resl;

	do
	{
		if ( (map = dc_get_volume_bitmap(sh)) == NULL ) {
			resl = ST_NOMEM; break;
		}

		/* find first free block */
		resl = ST_NF_SPACE;

		for (i = 0; i < sh->sh_start - count; i++)
		{
			b_free = 1;
			
			for (j = 0; j < count; j++) 
			{
				if (is_cls_used(map, i + j) != 0) {
					b_free = 0; break;
				}
			}

			if (b_free != 0) {
				f_lcn[0] = i; resl = ST_OK; break;
			}
		}
	} while (0);

	if (map != 0) {
		free(map);
	}

	return resl;
}

static u32 num_clusters_used(sh_params *sh)
{
	VOLUME_BITMAP_BUFFER *map;
	u64                   cls;
	u32                   num;

	num = 0; map = NULL;
	do
	{
		if ( (map = dc_get_volume_bitmap(sh)) == NULL ) {
			break;
		}

		/* check clusters usage */
		for (cls = sh->sh_start; cls < sh->sh_end; cls++) {
			num += is_cls_used(map, cls);
		}
	} while (0);

	if (map != NULL) {
		free(map);
	}

	return num;
}

static 
int dc_move_clusters(
	  HANDLE h_file, sh_params *sh, u64 s_lcn, u32 count, u64 vcn
	  )
{
	MOVE_FILE_DATA mvd;
	u64            d_lcn, i;
	int            resl, succs;
	u32            bytes;

	if (dc_get_free_clusters(count, sh, &d_lcn) == ST_OK)
	{
		mvd.FileHandle           = h_file;
		mvd.ClusterCount         = count;
		mvd.StartingVcn.QuadPart = vcn;
		mvd.StartingLcn.QuadPart = d_lcn;

		succs = DeviceIoControl(
			sh->h_dev, FSCTL_MOVE_FILE, &mvd, sizeof(mvd), NULL, 0, &bytes, NULL
			);

		if (succs != 0) {
			resl = ST_OK;
		} else {
			resl = ST_ERROR;
		}
	} else
	{
		for (i = 0; i < count; i++)
		{
			if (dc_get_free_clusters(1, sh, &d_lcn) != ST_OK) {
				resl = ST_ERROR; break;
			}

			mvd.FileHandle           = h_file;
			mvd.ClusterCount         = 1;
			mvd.StartingVcn.QuadPart = vcn + i;
			mvd.StartingLcn.QuadPart = d_lcn;

			succs = DeviceIoControl(
				sh->h_dev, FSCTL_MOVE_FILE, &mvd, sizeof(mvd), NULL, 0, &bytes, NULL
				);

			if (succs != 0) {
				resl = ST_OK;
			} else {
				resl = ST_ERROR; break;
			}
		}
	}

	return resl;
}

static 
int dc_check_and_move_file(
	  HANDLE h_file, sh_params *sh
	  )
{
	STARTING_VCN_INPUT_BUFFER  inb;
	RETRIEVAL_POINTERS_BUFFER *rpb;
	u8                         buff[sizeof(rpb->Extents) * 400];
    u64                        pre_vcn, lcn, end;
	u64                        s_lcn, vcn, count;
	u32                        bytes, error, i;
	int                        succs, resl, retry;

	rpb = pv(buff); resl = ST_OK; pre_vcn = 0;
	retry = 0;	
	do
	{
		inb.StartingVcn.QuadPart = pre_vcn;

		succs = DeviceIoControl(
			h_file, FSCTL_GET_RETRIEVAL_POINTERS, 
			&inb, sizeof(inb), rpb, sizeof(buff), &bytes, NULL
			);

		if (succs == 0) 
		{
			if ( (error = GetLastError()) != ERROR_MORE_DATA ) {
				break;
			}
		} else {
			error = ERROR_SUCCESS;
		}

		for (i = 0; i < rpb->ExtentCount; i++) 
		{
			count = rpb->Extents[i].NextVcn.QuadPart - pre_vcn;
			lcn   = rpb->Extents[i].Lcn.QuadPart;
			end   = lcn + count;

			if (lcn != -1) 
			{
				if ( ((lcn >= sh->sh_start) && (lcn < sh->sh_end)) || 
					 ((end > sh->sh_start) && (end <= sh->sh_end)) )
				{
					s_lcn = (lcn >= sh->sh_start) ? lcn: sh->sh_start;
					count = min(sh->sh_end - s_lcn, count - s_lcn + lcn);
					vcn   = pre_vcn + (s_lcn - lcn);

					resl = dc_move_clusters(
						h_file, sh, s_lcn, (u32)count, vcn
						);

					if (resl == ST_OK) 
					{
						if (sh->sh_count > count) {
							sh->sh_count -= (u32)count;
						} else {
							sh->sh_count = 0;
						}
					} else {
						break;
					}
				}
			}
			pre_vcn = rpb->Extents[i].NextVcn.QuadPart;			
		}
	} while ( (error == ERROR_MORE_DATA) && (++retry < 1000) );

	return resl;
}

static 
int dc_analyze_file(
	  wchar_t *path, u32 attributes, sh_params *sh
	  )
{
	HANDLE h_file;
	int    resl, i;

	if (attributes & FILE_ATTRIBUTE_DIRECTORY) 
	{
		h_file = CreateFile(
			path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL
			);
	} else 
	{
		h_file = CreateFile(
			path, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING | FILE_FLAG_BACKUP_SEMANTICS, NULL 
			);
	}

	if (h_file != INVALID_HANDLE_VALUE) 
	{
		/* retry move file 5 times */
		for (i = 0; i < 5; i++) 
		{
			if (dc_check_and_move_file(h_file, sh) == ST_OK) {
				break;
			}
		}

		CloseHandle(h_file);
		resl = ST_OK;
	} else {
		resl = ST_ERROR;
	}

	return resl;
}

static 
void dc_free_clusters(
	   wchar_t *dir, sh_params *sh
	   )	  
{
	WIN32_FIND_DATA data;
	HANDLE          h_find;
	wchar_t         path[MAX_PATH * 2];

	_snwprintf(
		path, sizeof_w(path), L"%s\\*", dir
		);

	h_find = FindFirstFile(path, &data);
	
	if (h_find != INVALID_HANDLE_VALUE)
	{
		do
		{
			if ( (wcscmp(data.cFileName, L".") == 0) || (wcscmp(data.cFileName, L"..") == 0) ) {
				continue;
			}

			if (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
				continue;
			}

			_snwprintf(
				path, sizeof_w(path), L"%s\\%s", dir, data.cFileName
				);			

			if (sh->callback != NULL) 
			{
				if (sh->callback(SHRINK_STEP, sh->param, path, ST_OK) != ST_OK) {
					sh->sh_count = 0; break;
				}
			}

			if (dc_analyze_file(path, data.dwFileAttributes, sh) != ST_OK) 
			{
				/* If unsuccesful then try again with the short filename. I don't know why,
				   but CreateFile can fail on long filenames with special characters,
				   and succeed on the short filename. 
			    */
				if (data.cAlternateFileName[0] != 0) 
				{
					_snwprintf(
						path, sizeof_w(path), L"%s\\%s", dir, data.cAlternateFileName
						);

					dc_analyze_file(path, data.dwFileAttributes, sh);
				}
			}

			if ( (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && (sh->sh_count != 0) ) {
				dc_free_clusters(path, sh);
			}

			if (sh->sh_count == 0) {
				break;
			}
		} while (FindNextFile(h_find, &data) != 0);

		FindClose(h_find);
	}
}

static
void dc_move_meta_files(
	   wchar_t *root, sh_params *sh
	   )
{
	wchar_t path[MAX_PATH];
	int     i;

	for (i = 0; i < sizeof(ntfs_metafiles) / sizeof(wchar_t*); i++)
	{
		_snwprintf(
			path, sizeof_w(path), L"%s\\%s", root, ntfs_metafiles[i]
			);

		dc_analyze_file(path, 0, sh);
	}
}

static
int dc_get_max_sector_number(
	  HANDLE hdisk, int fs_type, u64 *max_fs, u64 *max_part
	  )
{
	PARTITION_INFORMATION    pti;
	PARTITION_INFORMATION_EX ptix;
	NTFS_VOLUME_DATA_BUFFER  ntb;
	u8                       head[SECTOR_SIZE];
	int                      succs;
	int                      resl;
	u32                      bytes;

	do
	{
		/* get number of partition sectors */
		succs = DeviceIoControl(
			hdisk, IOCTL_DISK_GET_PARTITION_INFO_EX, NULL, 0, &ptix, sizeof(ptix), &bytes, NULL
			);

		if (succs == 0)
		{
			succs = DeviceIoControl(
				hdisk, IOCTL_DISK_GET_PARTITION_INFO, NULL, 0, &pti, sizeof(pti), &bytes, NULL
				);

			if (succs != 0) {
				max_part[0] = pti.PartitionLength.QuadPart / SECTOR_SIZE;
			} else {
				resl = ST_ERROR; break;
			}
		} else {
			max_part[0] = ptix.PartitionLength.QuadPart / SECTOR_SIZE;
		}

		if (fs_type == FS_NTFS)
		{
			/* get maximum NTFS volume sector */
			succs = DeviceIoControl(
				hdisk, FSCTL_GET_NTFS_VOLUME_DATA, NULL, 0, &ntb, sizeof(ntb), &bytes, NULL
				);

			if (succs == 0) {
				resl = ST_ERROR; break;
			} else {
				max_fs[0] = ntb.NumberSectors.QuadPart;
			}
			resl = ST_OK; break;
		}

		/* read volume header */
		if ( (resl = dc_disk_read(hdisk, head, sizeof(head), 0)) != ST_OK ) {
			break;
		}

		if (fs_type == FS_FAT12) {
			max_fs[0] = p16(head + 0x13)[0];
			break;
		}

		if (fs_type == FS_FAT16) 
		{
			if (p32(head + 0x20)[0] != 0) {
				max_fs[0] = p32(head + 0x20)[0];
			} else {
				max_fs[0] = p16(head + 0x13)[0];
			}
			break;
		}

		if (fs_type == FS_FAT32) {
			max_fs[0] = p32(head + 0x20)[0]; 
			break;
		}
		resl = ST_ERROR;
	} while (0);

	return resl;
}

int dc_shrink_volume(
	  wchar_t *root, u32 shrink_size, sh_callback callback, void *param, sh_data *shd
	  )
{
	SHRINK_VOLUME_INFORMATION shi;
	wchar_t   v_name[MAX_PATH];
	HANDLE    h_device = NULL;
	u32       spc, bps, frc, ttc;
	int       resl, sh_need, fs;
	u8        vhdr[SECTOR_SIZE];
	u32       bytes, sh_clus;
	int       is_vista, succs;
	u64       max_fs, max_part;
	u32       sectors;
	sh_params sh;	

	enable_privilege(SE_BACKUP_NAME);
			
	sh_need = 0; is_vista = is_win_vista();
	do
	{
		_snwprintf(
			v_name, sizeof_w(v_name), L"%s\\", root
			);

		if (GetDiskFreeSpace(v_name, &spc, &bps, &frc, &ttc) == FALSE) {
			resl = ST_ERROR; break;
		}

		if (bps != SECTOR_SIZE) {
			resl = ST_INV_SECT; break;
		}
		
		sectors = shrink_size / SECTOR_SIZE;
		sh_clus = (sectors / spc) + ((sectors % spc) != 0);
		
		if (frc < sh_clus) {
			resl = ST_NF_PT_SPACE; break;
		}

		h_device = CreateFile(
			root, GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL
			);

		if (h_device == INVALID_HANDLE_VALUE) {
			h_device = NULL; resl = ST_ACCESS_DENIED;
			break;
		}

		/* read volume header */
		if ( (resl = dc_disk_read(h_device, vhdr, sizeof(vhdr), 0)) != ST_OK ) {
			break;
		}

		resl = dc_get_max_sector_number(
			h_device, (fs = dc_fs_type(vhdr)), &max_fs, &max_part
			);

		if (resl != ST_OK) {
			break;
		}

		if (max_fs + sectors <= max_part) {
			/* shrinking not needed */
			shd->sh_pend = 0; resl = ST_OK; break;
		}

		sh.sh_start  = ttc - sh_clus;
		sh.sh_end    = ttc;
		sh.cls_size  = spc * bps;
		sh.cls_total = ttc;
		sh.h_dev     = h_device;
		sh.callback  = callback;
		sh.param     = param;
		sh.fs_type   = fs;
		sh.sh_count  = num_clusters_used(&sh);
		sh_need      = (sh.sh_count != 0);

		if ( (is_vista != 0) && (fs == FS_NTFS) )
		{
			shi.ShrinkRequestType  = ShrinkPrepare;
			shi.Flags              = 0;
			shi.NewNumberOfSectors = sh.sh_start * spc;

			succs = DeviceIoControl(
				h_device, FSCTL_SHRINK_VOLUME, &shi, sizeof(shi), NULL, 0, &bytes, NULL
				);

			if (succs == 0) {
				resl = ST_CLUS_USED; break;
			}
		}

		if (sh_need != 0)
		{
			if (callback != NULL) {
				callback(SHRINK_BEGIN, param, NULL, ST_OK);
			}

			if (fs == FS_NTFS) {
				dc_move_meta_files(v_name, &sh);
			}

			if (sh.sh_count != 0) {
				dc_free_clusters(v_name, &sh);
			}

			if (num_clusters_used(&sh) != 0) {
				resl = ST_CLUS_USED; break;
			}
		}		

		if ( (is_vista != 0) && (fs == FS_NTFS) )
		{
			shi.ShrinkRequestType  = ShrinkCommit;
			shi.Flags              = 0;
			shi.NewNumberOfSectors = 0;

			succs = DeviceIoControl(
				h_device, FSCTL_SHRINK_VOLUME, &shi, sizeof(shi), NULL, 0, &bytes, NULL
				);

			if (succs == 0) {
				resl = ST_CLUS_USED; break;
			}

			/* delayed shrinking not needed */
			shd->sh_pend = 0;
		} else 
		{
			switch (fs) 
			{
				case FS_FAT12:
					{
						p16(vhdr + 0x13)[0] -= (u16)(sh_clus * spc);
						/* set shrink pending params */
						shd->offset = 0x13;
						shd->value  = p32(vhdr + 0x13)[0];
					}
				break;
				case FS_FAT16:
					{
						if (p32(vhdr + 0x20)[0] != 0) 
						{
							p32(vhdr + 0x20)[0] -= (sh_clus * spc);
							/* set shrink pending params */
							shd->offset = 0x20;
							shd->value  = p32(vhdr + 0x20)[0];
						} else 
						{
							p16(vhdr + 0x13)[0] -= (u16)(sh_clus * spc);
							/* set shrink pending params */
							shd->offset = 0x13;
							shd->value  = p32(vhdr + 0x13)[0];
						}
					}
				break;
				case FS_FAT32:
					{
						p32(vhdr + 0x20)[0] -= (sh_clus * spc);	
						/* set shrink pending params */
						shd->offset = 0x20;
						shd->value  = p32(vhdr + 0x20)[0];
					}
				break;
				case FS_NTFS:
					{
						/* update 'total sectors' value in NTFS header */
						p64(vhdr + 0x28)[0] -= (sh_clus * spc);

						/* write NTFS backup header */
						dc_disk_write(
							h_device, vhdr, sizeof(vhdr), (sh.sh_start * spc) * SECTOR_SIZE
							);

						/* delayed shrinking not needed */
						shd->sh_pend = 0;
					}
				break;
			}

			if ( (fs == FS_NTFS) || (shd->sh_pend == 0) ) 
			{
				/* write volume header */
				if ( (resl = dc_disk_write(h_device, vhdr, sizeof(vhdr), 0)) != ST_OK ) {
					break;
				}
			} 
		}
		resl = ST_OK;
	} while (0);

	if ( (sh_need != 0) && (callback != NULL) ) {
		callback(SHRINK_END, param, NULL, resl);
	}

	if (h_device != NULL) {
		CloseHandle(h_device);
	}

	return resl;
}