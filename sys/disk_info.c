/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2010
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
#include <ntddcdrm.h>
#include <ntddscsi.h>
#include <ntdddisk.h>
#include <ata.h>
#include "defines.h"
#include "devhook.h"
#include "disk_info.h"
#include "misc.h"
#include "device_io.h"
#include "debug.h"

int dc_verify_device(dev_hook *hook)
{
	u32 chg_count;

	if (io_hook_ioctl(hook, IOCTL_DISK_CHECK_VERIFY, NULL, 0, &chg_count, sizeof(chg_count)) == ST_OK)
	{
		if (lock_xchg(&hook->chg_count, chg_count) != chg_count) {
			return ST_MEDIA_CHANGED;
		} else {
			return ST_OK;
		}
	} else {
		return ST_NO_MEDIA;
	}
}

static u32 dc_get_device_mtl(dev_hook *hook)
{
	STORAGE_ADAPTER_DESCRIPTOR sd;
	STORAGE_PROPERTY_QUERY     sq;
	IO_SCSI_CAPABILITIES       sc;
	u32                        max_chunk = 0;

	sq.PropertyId = StorageAdapterProperty;
	sq.QueryType  = PropertyStandardQuery;
	
	if (io_hook_ioctl(hook, IOCTL_STORAGE_QUERY_PROPERTY, &sq, sizeof(sq), &sd, sizeof(sd)) == ST_OK) {
		max_chunk = min(sd.MaximumTransferLength, sd.MaximumPhysicalPages * PAGE_SIZE);
	}
	if (max_chunk == 0)
	{
		if (io_hook_ioctl(hook, IOCTL_SCSI_GET_CAPABILITIES, NULL, 0, &sc, sizeof(sc)) == ST_OK) {
			max_chunk = min(sc.MaximumTransferLength, sc.MaximumPhysicalPages * PAGE_SIZE);
		}
	}
	if (max_chunk < 1024) {
		max_chunk = 32768; /* safe value */
	}
	return max_chunk;
}

static int dc_is_this_ssd(dev_hook *hook)
{
	STORAGE_PROPERTY_QUERY         query = { StorageDeviceSeekPenaltyProperty,  PropertyStandardQuery };
	DEVICE_SEEK_PENALTY_DESCRIPTOR seek  = {0};
	char                           buff[sizeof(ATA_PASS_THROUGH_EX) + sizeof(IDENTIFY_DEVICE_DATA)] = {0};
    PATA_PASS_THROUGH_EX           pata = pv(buff);
	PIDENTIFY_DEVICE_DATA          idat = pv(buff + sizeof(ATA_PASS_THROUGH_EX));
	int                            resl;

	resl = io_hook_ioctl(hook, IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query), &seek, sizeof(seek));

	if ( (resl == ST_OK) && (seek.Version >= sizeof(seek)) && (seek.Size >= sizeof(seek)) ) {
		DbgMsg("seek.IncursSeekPenalty %d\n", seek.IncursSeekPenalty);
		return seek.IncursSeekPenalty == FALSE;
	}
	pata->Length             = sizeof(ATA_PASS_THROUGH_EX);
	pata->DataBufferOffset   = sizeof(ATA_PASS_THROUGH_EX);
	pata->DataTransferLength = sizeof(IDENTIFY_DEVICE_DATA);
	pata->AtaFlags           = ATA_FLAGS_DATA_IN;
	pata->TimeOutValue       = 2;
	pata->CurrentTaskFile[6] = IDE_COMMAND_IDENTIFY;

	if (io_hook_ioctl(hook, IOCTL_ATA_PASS_THROUGH, buff, sizeof(buff), buff, sizeof(buff)) != ST_OK) {
		return 0;
	} else {
		DbgMsg("idat->NominalMediaRotationRate %d\n", idat->NominalMediaRotationRate);
	}
	return idat->NominalMediaRotationRate == 1;
}

int dc_fill_disk_info(dev_hook *hook)
{
	PARTITION_INFORMATION    pti;
	PARTITION_INFORMATION_EX ptix;
	DISK_GEOMETRY_EX         dgx;
	DISK_GEOMETRY            dg;
	u64                      d_size;

	if (hook->pnp_state != Started) {
		return ST_RW_ERR;
	}
	if (hook->flags & F_CDROM)
	{
		if (io_hook_ioctl(hook, IOCTL_CDROM_GET_DRIVE_GEOMETRY, NULL, 0, &dg, sizeof(dg)) != ST_OK) {
			return ST_RW_ERR;
		}
		if (io_hook_ioctl(hook, IOCTL_CDROM_GET_DRIVE_GEOMETRY_EX, NULL, 0, &dgx, sizeof(dgx)) == ST_OK) {
			d_size = dgx.DiskSize.QuadPart;
		} else {
			d_size = d64(dg.Cylinders.QuadPart) * d64(dg.TracksPerCylinder) * 
				     d64(dg.SectorsPerTrack) * d64(dg.BytesPerSector);
		}
	} else
	{
		if (io_hook_ioctl(hook, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &dg, sizeof(dg)) != ST_OK) {
			return ST_RW_ERR;
		}
		if (io_hook_ioctl(hook, IOCTL_DISK_GET_PARTITION_INFO_EX, NULL, 0, &ptix, sizeof(ptix)) != ST_OK)
		{
			if (io_hook_ioctl(hook, IOCTL_DISK_GET_PARTITION_INFO, NULL, 0, &pti, sizeof(pti)) != ST_OK) {
				return ST_RW_ERR;
			}
			d_size = pti.PartitionLength.QuadPart;
		} else {
			d_size = ptix.PartitionLength.QuadPart;
		}
	}
	if ( (hook->flags & F_REMOVABLE) && (dc_verify_device(hook) == ST_NO_MEDIA) ) {
		return ST_NO_MEDIA;
	}
	hook->dsk_size   = d_size;
	hook->bps        = dg.BytesPerSector;
	hook->chg_last_v = hook->chg_count;
	hook->max_chunk  = dc_get_device_mtl(hook);
	hook->head_len   = max(sizeof(dc_header), hook->bps);

	if ( (hook->flags & (F_REMOVABLE | F_CDROM)) == 0 ) {
		if (dc_is_this_ssd(hook) != 0) hook->flags |= F_SSD;
	}	
	return ST_OK;
}