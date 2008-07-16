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
#include "dump_hook.h"
#include "driver.h"
#include "crypto.h"
#include "misc.h"
#include "mount.h"
#include "mem_lock.h"

typedef struct _dump_context
{
    PDUMP_DRIVER_OPEN          OpenRoutine;
	PDUMP_DRIVER_WRITE         WriteRoutine;
    PDUMP_DRIVER_WRITE_PENDING WritePendingRoutine;
	PDUMP_DRIVER_FINISH        FinishRoutine;
	dev_hook                  *hook;
	u64                        part_offset;

} dump_context;

typedef NTSTATUS (*dump_entry)(
      IN PVOID               unk, 
	  IN PDUMP_STACK_CONTEXT stack
	  );

static PLIST_ENTRY  ps_loaded_mod_list;
static PVOID        dump_mem;
static PMDL         dump_mdl;
static PVOID        dump_imgbase;
static FAST_MUTEX   dump_sync;
static dump_entry   dump_old_entry;
static dump_context dump_ctx[2];

#define DUMP_MEM_SIZE 4096 * 16

#ifdef _M_IX86 /* x86 jumper code */
 static u8 jmp_code[] = 
	 "\x8B\x44\x24\x08\x8B\x4C\x24\x04\x50\x51\x68\x00"
	 "\x00\x00\x00\xBA\x00\x00\x00\x00\xFF\xD2\xC2\x08\x00";
 #define DEST_OFF 16  /* destination address offset in code  */
 #define PARM_OFF 11  /* additional parameter offset in code */
#else         /* x64 jumper code */
 static u8 jmp_code[] = 
	 "\x4C\x8B\xC2\x48\x8B\xD1\x48\xB8\x00\x00\x00\x00\x00\x00"
	 "\x00\x00\x48\xB9\x00\x00\x00\x00\x00\x00\x00\x00\x48\xFF\xE0";
 #define DEST_OFF 8   /* destination address offset in code  */
 #define PARM_OFF 18  /* additional parameter offset in code */
#endif                                                            

typedef struct _entry_hook {
	dump_entry old_entry;
	u8         code[50];

} entry_hook;


static
int img_cmp(
	IN PUNICODE_STRING img_name,
	IN PWCHAR          cmp_name
	)
{
	u16 size = (u16)(wcslen(cmp_name) * 2);

	return (img_name->Length >= size) &&
		   (memcmp(img_name->Buffer, cmp_name, size) == 0);
}

static
PLDR_DATA_TABLE_ENTRY
  find_image(void *img_base)
{
	PLIST_ENTRY           entry;
	PLDR_DATA_TABLE_ENTRY table;
	PLDR_DATA_TABLE_ENTRY found = NULL;

	entry = ps_loaded_mod_list->Flink;

	while (entry != ps_loaded_mod_list)
	{
		table = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		entry = entry->Flink;

		if (table->DllBase == img_base) {
			found = table;
			break;
		}
	}

	return found;
}

static
void dump_encrypt_buffer(
	      IN dev_hook *hook,
		  IN u64       offset, 
		  IN PMDL      mdl
		  )
{
	PVOID buff = mdl->MappedSystemVa;
	ULONG size = MmGetMdlByteCount(mdl);

	if (size > DUMP_MEM_SIZE) {
		KeBugCheck(STATUS_BUFFER_OVERFLOW);
	}
	
	aes_lrw_encrypt(
		buff, dump_mem, size,
		lrw_index(offset), 
		&hook->dsk_key
		); 
		
	MmInitializeMdl(
		dump_mdl, dump_mem, size
		);

	dump_mdl->MdlFlags = mdl->MdlFlags;
}

static
NTSTATUS
   dump_write_routine(
       IN PLARGE_INTEGER disk_offset,
	   IN PMDL           mdl,
	   IN int            index
	   )
{
	dev_hook     *hook = dump_ctx[index].hook;
	LARGE_INTEGER offs;
	PMDL          nmdl;
	NTSTATUS      status;

	if (hook->flags & F_ENABLED) 
	{
		dump_encrypt_buffer(
			hook, disk_offset->QuadPart, mdl
			);

		offs.QuadPart = disk_offset->QuadPart + HEADER_SIZE;
		nmdl          = dump_mdl;
	} else  {
		offs.QuadPart = disk_offset->QuadPart;
		nmdl          = mdl;
	}

	status = dump_ctx[index].WriteRoutine(&offs, nmdl);

	zeromem(dump_mem, DUMP_MEM_SIZE);

	return status;
}

static
NTSTATUS
   dump_write_pend_routine(
       IN LONG           action,
	   IN PLARGE_INTEGER disk_offset,
	   IN PMDL           mdl,
	   IN PVOID          local_data,
	   IN int            index
	   )
{
	dev_hook     *hook = dump_ctx[index].hook;
	LARGE_INTEGER offs;
	PMDL          nmdl;
	NTSTATUS      status;
	
	if (disk_offset && mdl) 
	{
		if (hook->flags & F_ENABLED) 
		{
			dump_encrypt_buffer(
				hook, disk_offset->QuadPart, mdl
				);

			offs.QuadPart = disk_offset->QuadPart + HEADER_SIZE;
			nmdl          = dump_mdl;
		} else {
			offs.QuadPart = disk_offset->QuadPart;
			nmdl          = mdl;
		}

		status = dump_ctx[index].WritePendingRoutine(
			         action, &offs, nmdl, local_data
					 );

		if (status == STATUS_SUCCESS) {
			zeromem(dump_mem, DUMP_MEM_SIZE);
		}
	} else {
		status = dump_ctx[index].WritePendingRoutine(
			         action, disk_offset, mdl, local_data
					 );
	}

	return status;
}


static
NTSTATUS
   dump_crash_write(
       IN PLARGE_INTEGER disk_offset,
	   IN PMDL           mdl
	   )
{
	return dump_write_routine(
		disk_offset, mdl, 0
		);
}

static
NTSTATUS
   dump_hiber_write(
       IN PLARGE_INTEGER disk_offset,
	   IN PMDL           mdl
	   )
{
	return dump_write_routine(
		disk_offset, mdl, 1
		);
}

static
NTSTATUS
   dump_crash_write_pend(
       IN LONG           action,
	   IN PLARGE_INTEGER disk_offset,
	   IN PMDL           mdl,
	   IN PVOID          local_data
	   )
{
	return dump_write_pend_routine(
		action, disk_offset, mdl, local_data, 0
		);
}


static
NTSTATUS
   dump_hiber_write_pend(
       IN LONG           action,
	   IN PLARGE_INTEGER disk_offset,
	   IN PMDL           mdl,
	   IN PVOID          local_data
	   )
{
	return dump_write_pend_routine(
		action, disk_offset, mdl, local_data, 1
		);
}

static void dump_crash_finish(void)
{
	if (dump_ctx[0].FinishRoutine != NULL) {
		dump_ctx[0].FinishRoutine();
	}

	dc_clean_pass_cache();
	dc_clean_locked_mem(NULL);
	dc_clean_keys();

	zeromem(dump_mem, DUMP_MEM_SIZE);
}

static void dump_hiber_finish(void)
{
	if (dump_ctx[1].FinishRoutine != NULL) {
		dump_ctx[1].FinishRoutine();
	}

	dc_clean_pass_cache();
	dc_clean_locked_mem(NULL);
	dc_clean_keys();

	zeromem(dump_mem, DUMP_MEM_SIZE);	
}

int is_dump_crypt() 
{
	return (dump_ctx[0].hook != NULL) && 
		   (dump_ctx[0].hook->flags & F_ENABLED);
}

int is_hiber_crypt() 
{
	return (dump_ctx[1].hook != NULL) && 
		   (dump_ctx[1].hook->flags & F_ENABLED);
}

static
BOOLEAN
   dump_crash_open(
       IN LARGE_INTEGER part_offs
	   )
{
	int allow = 1;

	/* prevent dumping if memory contain sensitive data */
	if (dc_data_lock != 0) {
		allow = 0;
	}

	if (is_dump_crypt() == 0) 
	{
		if (dc_num_mount() == 0) {
			/* clear pass cache to prevent leaks */
			dc_clean_pass_cache(); 
		} else {
			allow = 0;
		}
	}

	if ( (allow != 0) && (dump_ctx[0].OpenRoutine) ) {
		return dump_ctx[0].OpenRoutine(part_offs);
	} else {
		return FALSE;
	}
}

static
NTSTATUS
  dump_driver_entry(
      IN entry_hook         *ehook,
      IN PVOID               unk, 
	  IN PDUMP_STACK_CONTEXT stack
	  )
{
	PDUMP_INITIALIZATION_CONTEXT init;
	NTSTATUS                     status = STATUS_UNSUCCESSFUL;
	int                          idx;
	
	if (ehook->old_entry) {
		status = ehook->old_entry(unk, stack);
		ehook->old_entry = NULL;
	}

	if (NT_SUCCESS(status) && (unk == NULL) && (stack != NULL) )
	{
		init = &stack->Init; idx = 0;

		if (stack->UsageType == DeviceUsageTypeHibernation) {
			idx++;
		} else {
			if (stack->UsageType != DeviceUsageTypeDumpFile) {
				idx += (init->CrashDump == FALSE);
			}
		}

		dump_ctx[idx].OpenRoutine         = init->OpenRoutine;
		dump_ctx[idx].WriteRoutine        = init->WriteRoutine;
		dump_ctx[idx].WritePendingRoutine = init->WritePendingRoutine;		
		dump_ctx[idx].FinishRoutine       = init->FinishRoutine;
		
		if (idx == 0) 
		{
			if (init->WriteRoutine) {
				init->WriteRoutine = dump_crash_write;
			}
			if (init->WritePendingRoutine) {
				init->WritePendingRoutine = dump_crash_write_pend;
			}
			init->OpenRoutine   = dump_crash_open;
			init->FinishRoutine = dump_crash_finish;
		} else
		{
			if (init->WriteRoutine) {
				init->WriteRoutine = dump_hiber_write;
			}
			if (init->WritePendingRoutine) {
				init->WritePendingRoutine = dump_hiber_write_pend;
			}

			init->FinishRoutine = dump_hiber_finish;
		}
	}

	return status;
}

static
void hook_dump_entry()
{
	PLDR_DATA_TABLE_ENTRY table;
	entry_hook           *ehook;

	ExAcquireFastMutex(&dump_sync);

	if ( (dump_imgbase != NULL) && 
		 (table = find_image(dump_imgbase)) )
	{
		if ( (table->BaseDllName.Buffer != NULL) && 
			 (table->EntryPoint != NULL) )
		{
			if (img_cmp(&table->BaseDllName, L"dump_") || 
				img_cmp(&table->BaseDllName, L"hiber_") ) 
			{
				if (ehook = mem_alloc(sizeof(entry_hook)))
				{
					memcpy(ehook->code, jmp_code, sizeof(jmp_code));
					ppv(ehook->code + DEST_OFF)[0] = dump_driver_entry;
					ppv(ehook->code + PARM_OFF)[0] = ehook;
					ehook->old_entry  = table->EntryPoint;
					table->EntryPoint = pv(ehook->code);					
				}
			}
		}

		dump_imgbase = NULL;
	}

	ExReleaseFastMutex(&dump_sync);
}

static
void load_img_routine(
	     IN PUNICODE_STRING img_name,
		 IN HANDLE          pid,
		 IN PIMAGE_INFO     img_info
		 )
{
	if (img_info->SystemModeImage) 
	{
		if (dc_os_type == OS_WIN2K) {
			hook_dump_entry();
			dump_imgbase = img_info->ImageBase;
		} else {
			dump_imgbase = img_info->ImageBase;
			hook_dump_entry();
		}
	}
}



void dump_usage_notify(
	     IN dev_hook                      *hook,
		 IN DEVICE_USAGE_NOTIFICATION_TYPE type
		 )
{
	if (type == DeviceUsageTypeDumpFile) {
		dump_ctx[0].hook = hook;
	}

	if (type == DeviceUsageTypeHibernation) {
		dump_ctx[1].hook = hook;
	}

	if (dc_os_type == OS_WIN2K) {
		hook_dump_entry();
	}
}

int dump_hook_init()
{
	PLDR_DATA_TABLE_ENTRY table;
	PHYSICAL_ADDRESS      high_addr;
	PLIST_ENTRY           entry;
	NTSTATUS              status;
	int                   resl = 0;

	ExInitializeFastMutex(&dump_sync);

	ExAcquireFastMutex(&dump_sync);

	/* find PsLoadedModuleListHead */
	entry = ((PLIST_ENTRY)(dc_driver->DriverSection))->Flink;

	while (entry != dc_driver->DriverSection)
	{
		table = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		entry = entry->Flink;

		if ( (table->BaseDllName.Length == 0x18) && 
			 (p32(table->BaseDllName.Buffer)[0] == 0x0074006E) )
		{
			ps_loaded_mod_list = pv(table->InLoadOrderLinks.Blink);
			break;
		}
	}

	ExReleaseFastMutex(&dump_sync);

	do
	{
		if (ps_loaded_mod_list == NULL) {
			break;
		}

		status = PsSetLoadImageNotifyRoutine(load_img_routine);

		if (NT_SUCCESS(status) == FALSE) {
			break;
		}

		high_addr.HighPart = 0;
		high_addr.LowPart  = 0xFFFFFFFF;

		dump_mem = MmAllocateContiguousMemory(
			DUMP_MEM_SIZE, high_addr
			);

		if (dump_mem == NULL) {
			break;
		}

		dump_mdl = IoAllocateMdl(
			dump_mem, DUMP_MEM_SIZE, FALSE, FALSE, NULL
			); 

		if (dump_mdl == NULL) {
			break;
		}

		zeromem(dump_mem, DUMP_MEM_SIZE);
		MmBuildMdlForNonPagedPool(dump_mdl); 
		resl = 1;
	} while (0);

	if (resl == 0) 
	{
		if (dump_mdl != NULL) {
			IoFreeMdl(dump_mdl);
		}

		if (dump_mem != NULL) {
			MmFreeContiguousMemory(dump_mem);
		}
	}

	return resl;	
}