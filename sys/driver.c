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
#include <stdlib.h>
#include <stdio.h>
#include "defines.h"
#include "pkcs5.h"
#include "tests.h"
#include "crypto.h"
#include "crc32.h"
#include "driver.h"
#include "prng.h"
#include "misc.h"
#include "fastmem.h"
#include "dump_hook.h"
#include "misc_irp.h"
#include "devhook.h"
#include "readwrite.h"
#include "enc_dec.h"
#include "io_control.h"
#include "pnp_irp.h"
#include "boot_pass.h"
#include "mount.h"
#include "mem_lock.h"
#include "fast_crypt.h"
#include "debug.h"

PDRIVER_OBJECT dc_driver;
PDEVICE_OBJECT dc_device;
u32            dc_os_type;	   
u32            dc_data_lock;  /* dc_data_lock > 0 if memory contain sensitive data */
u32            dc_io_count;
u32            dc_conf_flags; /* config flags readed from registry */
u32            dc_load_flags; /* other flags setted by driver      */

static void dc_automount_thread(void *param)
{
	LARGE_INTEGER time;

	/* wait 0.5 sec */
	time.QuadPart = 500 * -10000;
	KeDelayExecutionThread(KernelMode, FALSE, &time);

	/* complete automounting */
	dc_mount_all(NULL);

	/* clean cached passwords */
	if ( !(dc_conf_flags & CONF_CACHE_PASSWORD) ) {
		dc_clean_pass_cache();
	}

	PsTerminateSystemThread(STATUS_SUCCESS);
}

static
void dc_reinit_routine(
	   IN PDRIVER_OBJECT drv_obj,
	   IN PVOID          context,
	   IN u32            count
	   )
{
	start_system_thread(
		dc_automount_thread, NULL, NULL);
}

static void dc_load_config(
			  PUNICODE_STRING reg_path
			  )
{
	u8                             buff[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(dc_conf_flags)];
	PKEY_VALUE_PARTIAL_INFORMATION info = pv(buff);
	u32                            bytes;
	HANDLE                         h_key;
	OBJECT_ATTRIBUTES              obj;
	NTSTATUS                       status;
	UNICODE_STRING                 u_name;

	InitializeObjectAttributes(
		&obj, reg_path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL
		);

	status = ZwOpenKey(
		&h_key, GENERIC_READ, &obj
		);

	if (NT_SUCCESS(status) != FALSE)
	{
		RtlInitUnicodeString(&u_name, L"Flags");

		status = ZwQueryValueKey(
			h_key, &u_name, KeyValuePartialInformation, info, sizeof(buff), &bytes
			);

		if (NT_SUCCESS(status) != FALSE) {			
			autocpy(&dc_conf_flags, info->Data, sizeof(dc_conf_flags));
		}

		ZwClose(h_key);
	}
}

NTSTATUS 
  DriverEntry(
	IN PDRIVER_OBJECT  DriverObject,
    IN PUNICODE_STRING RegistryPath
	)
{
	UNICODE_STRING dev_name_u;	
	UNICODE_STRING dos_name_u;
	NTSTATUS       status;
	ULONG          maj_ver;
	ULONG          min_ver;
	int            num;

	PsGetVersion(
		&maj_ver, &min_ver, NULL, NULL);

	dc_os_type = OS_UNK; status = STATUS_DRIVER_INTERNAL_ERROR;

	if ( (maj_ver == 5) && (min_ver == 0) ) {
		dc_os_type = OS_WIN2K;
	}

	if (maj_ver == 6) {
		dc_os_type = OS_VISTA;
	}	

	RtlInitUnicodeString(
		&dev_name_u, DC_DEVICE_NAME);

	RtlInitUnicodeString(
		&dos_name_u, DC_LINK_NAME);

	dc_driver = DriverObject;

#ifdef DBG_MSG
	dc_dbg_init();
#endif
	DbgMsg("dcrypt.sys started\n");

	dc_init_crypto();
	dc_init_devhook(); dc_init_mount();
	fastmem_init(); mem_lock_init();
	dc_get_boot_pass();
	dc_load_config(RegistryPath);

	for (num = 0; num <= IRP_MJ_MAXIMUM_FUNCTION; num++) {
		DriverObject->MajorFunction[num] = dc_forward_irp;
	}

	DriverObject->MajorFunction[IRP_MJ_CREATE]         = dc_create_close_irp;
	DriverObject->MajorFunction[IRP_MJ_CLOSE]          = dc_create_close_irp;
	DriverObject->MajorFunction[IRP_MJ_READ]           = dc_read_write_irp;
	DriverObject->MajorFunction[IRP_MJ_WRITE]          = dc_read_write_irp;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = dc_io_control_irp;
	DriverObject->MajorFunction[IRP_MJ_PNP]            = dc_pnp_irp; 
	DriverObject->MajorFunction[IRP_MJ_POWER]          = dc_power_irp;
	DriverObject->DriverExtension->AddDevice           = dc_add_device;	

	do
	{
#ifdef CRYPT_TESTS
		/* test crypto primitives */
		if (crypto_self_test() == 0) {
			break;
		}
#endif
		/* init random number generator */
		if (rnd_init_prng() != ST_OK) {
			break;
		}

		/* initialize crashdump port driver hooking */
		if (dump_hook_init() == 0) {
			break;
		}

		if (dc_init_fast_crypt() != ST_OK) {
			break;
		}
					
		status = IoCreateDevice(
			dc_driver, 0, &dev_name_u, FILE_DEVICE_UNKNOWN, 0, FALSE, &dc_device);

		if (NT_SUCCESS(status) == FALSE) {
			break;
		}

		if (dc_set_security(dc_device) != ST_OK) {
			break;
		}

		dc_device->Flags               |= DO_BUFFERED_IO;
		dc_device->AlignmentRequirement = FILE_WORD_ALIGNMENT;
		dc_device->Flags               &= ~DO_DEVICE_INITIALIZING;

		status = IoCreateSymbolicLink(
			       &dos_name_u, &dev_name_u);

		if (NT_SUCCESS(status) == FALSE) {
			break;
		}

		/* register reinit routine for complete automounting and clear cached passwords */
		IoRegisterDriverReinitialization(dc_driver, dc_reinit_routine, NULL);
	} while (0);

	/* secondary reseed PRNG after all operations */
	rnd_reseed_now();

	if (NT_SUCCESS(status) == FALSE)
	{
		IoDeleteSymbolicLink(&dos_name_u);

		if (dc_device != NULL) {
			IoDeleteDevice(dc_device);
		}

		dc_free_fast_crypt();
		fastmem_free();		
	} 

	return status;
}

