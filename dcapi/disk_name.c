/*
    *
    * DiskCryptor - open source partition encryption tool
	* Copyright (c) 2009
	* ntldr <ntldr@diskcryptor.net> PGP key ID - 0xC48251EB4F8E4E6E
    * partial copyright Juergen Schmied and Jon Griffiths

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
#include <aclapi.h>
#include <ntddscsi.h>
#include <stdio.h>
#include "drv_ioctl.h"
#include "misc.h"
#include "disk_name.h"

#pragma pack(push, 1)

#define IDENTIFY_BUFFER_SIZE  512

#define DFP_GET_VERSION          0x00074080
#define DFP_SEND_DRIVE_COMMAND   0x0007c084
#define DFP_RECEIVE_DRIVE_DATA   0x0007c088

typedef struct _GETVERSIONOUTPARAMS
{
   BYTE bVersion;      // Binary driver version.
   BYTE bRevision;     // Binary driver revision.
   BYTE bReserved;     // Not used.
   BYTE bIDEDeviceMap; // Bit map of IDE devices.
   DWORD fCapabilities; // Bit mask of driver capabilities.
   DWORD dwReserved[4]; // For future use.
} GETVERSIONOUTPARAMS, *PGETVERSIONOUTPARAMS, *LPGETVERSIONOUTPARAMS;

#define IDE_ATAPI_IDENTIFY  0xA1  //  Returns ID sector for ATAPI.
#define IDE_ATA_IDENTIFY    0xEC  //  Returns ID sector for ATA.

#pragma pack(pop)

static void id_sector_to_name(char *name, char *id_s)
{
	int i, j;

	for (j = 0, i = 27 * 2; i <= 46 * 2; i += 2) {
		name[j++] = id_s[i+1]; name[j++] = id_s[i];
	}
	
	name[j] = 0;

	for (i = j - 1; i > 0 && name[i] == ' '; i--) {
		name[i] = 0;
	}
}

static int get_hdd_name_ata(HANDLE hdisk, int dsk_num, char *name)
{
	GETVERSIONOUTPARAMS verp;
	SENDCMDINPARAMS     scip;
	u32                 bytes;
	int                 succs, resl;
	u8                  id_cmd;
	u8                  buff[sizeof(SENDCMDOUTPARAMS) + IDENTIFY_BUFFER_SIZE];
	PSENDCMDOUTPARAMS   id_out = pv(buff);

	do
	{
		succs = DeviceIoControl(
			hdisk, DFP_GET_VERSION, NULL, 0, &verp, sizeof(verp), &bytes, NULL);

		if ( (succs == 0) || (verp.bIDEDeviceMap == 0) ) {
			resl = ST_ERROR; break;
		}

		id_cmd = (verp.bIDEDeviceMap >> dsk_num & 0x10) ? IDE_ATAPI_IDENTIFY : IDE_ATA_IDENTIFY;
		zeroauto(&scip, sizeof(scip));
        zeroauto(buff, sizeof(buff));

		scip.cBufferSize = IDENTIFY_BUFFER_SIZE;
		scip.irDriveRegs.bSectorCountReg  = 1;
		scip.irDriveRegs.bSectorNumberReg = 1;
		scip.irDriveRegs.bDriveHeadReg = 0xA0 | ((dsk_num & 1) << 4);
		scip.irDriveRegs.bCommandReg   = id_cmd;
		scip.bDriveNumber = dsk_num;
		scip.cBufferSize  = IDENTIFY_BUFFER_SIZE;

		succs = DeviceIoControl(
			hdisk, DFP_RECEIVE_DRIVE_DATA, &scip, sizeof(scip),	id_out, sizeof(buff), &bytes, NULL);

		if (succs == 0) {
			resl = ST_ERROR; break;
		}
		id_sector_to_name(name, id_out->bBuffer); resl = ST_OK;
	} while (0);

	return resl;
}

static int get_hdd_name_scsi(HANDLE hdisk, char *name)
{
	SCSI_ADAPTER_BUS_INFO bi[128]; 
	SCSI_INQUIRY_DATA    *data;
	u32                   bytes;
	int                   succs, i;

	succs = DeviceIoControl(
			hdisk, IOCTL_SCSI_GET_INQUIRY_DATA, NULL, 0, &bi, sizeof(bi), &bytes, NULL);

	if ( (succs == 0) || (bi[0].BusData[0].InquiryDataOffset == 0) ) {
		return ST_ERROR;
	}

	data = addof(&bi, bi[0].BusData[0].InquiryDataOffset);
	zeroauto(name, MAX_PATH);
	if (data->InquiryDataLength > 8) {
		mincpy(name, data->InquiryData + 8, min(data->InquiryDataLength - 8, 0x16));
	}
	for (i = d32(strlen(name)) - 1; i > 0 && name[i] == ' '; i--) {
		name[i] = 0;
	}
	return ST_OK;
}

int dc_get_hdd_name(
	  int dsk_num, wchar_t *name, size_t max_name
	  )
{
	DISK_GEOMETRY dg;
	HANDLE        hdisk;
	char          c_name[MAX_PATH];
	int           resl, succs;
	u32           bytes;	

	do
	{
		if ( (hdisk = dc_disk_open(dsk_num)) == NULL ) {
			resl = ST_ACCESS_DENIED; break;
		}

		if ( (get_hdd_name_ata(hdisk, dsk_num, c_name) != ST_OK) &&
			 (get_hdd_name_scsi(hdisk, c_name) != ST_OK) )
		{
			succs = DeviceIoControl(
				hdisk, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &dg, sizeof(dg), &bytes, NULL);

			if (succs == 0) {
				resl = ST_IO_ERROR; break;
			}

			if (dg.MediaType == RemovableMedia) 
			{
				_snwprintf(
					name, max_name, L"Removable Medium %d", dsk_num);
			} else
			{
				_snwprintf(
					name, max_name, L"Hard disk %d", dsk_num);
			}		
		} else {
			mbstowcs(name, c_name, max_name);			
		}
		resl = ST_OK;
	} while (0);

	if (hdisk != NULL) {
		CloseHandle(hdisk);
	}

	return resl;
}
