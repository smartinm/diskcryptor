/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2007-2009 
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
#include "defines.h"
#include "dump_hook.h"
#include "driver.h"
#include "xts_fast.h"
#include "misc.h"
#include "mount.h"
#include "mem_lock.h"
#include "debug.h"
#include "misc_mem.h"

typedef struct _dump_context
{
    PDUMP_DRIVER_OPEN          OpenRoutine;
	PDUMP_DRIVER_WRITE         WriteRoutine;
	PDUMP_DRIVER_WRITE_PENDING WritePendingRoutine;
	PDUMP_DRIVER_FINISH        FinishRoutine;
	dev_hook                  *hook;
	int                        pg_init;
	int                        pg_pending;
	void                      *a_data;

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
static dump_context dump_crash_ctx;
static dump_context dump_hiber_ctx;

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


static int img_cmp(PUNICODE_STRING img_name, wchar_t *cmp_name)
{
	size_t size = wcslen(cmp_name) * 2;
	
	return (img_name->Length >= size) && (memcmp(img_name->Buffer, cmp_name, size) == 0);
}

static PLDR_DATA_TABLE_ENTRY find_image(void *img_base)
{
	PLIST_ENTRY           entry;
	PLDR_DATA_TABLE_ENTRY table;

	for (entry = ps_loaded_mod_list->Flink; entry != ps_loaded_mod_list;)
	{
		table = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		entry = entry->Flink;		
		if (table->DllBase == img_base) return table;
	}
	return NULL;
}


static NTSTATUS dump_mem_write(dump_context *dump, u32 size, u64 offset)
{
	NTSTATUS status;

	MmInitializeMdl(dump_mdl, dump_mem, size);

	dump_mdl->MappedSystemVa = dump_mem;
	dump_mdl->MdlFlags       = MDL_SOURCE_IS_NONPAGED_POOL | MDL_MAPPED_TO_SYSTEM_VA;

	if (dump->pg_init != 0) 
	{
		if (dump->pg_pending != 0) 
		{
			status = dump->WritePendingRoutine(IO_DUMP_WRITE_FINISH, NULL, NULL, dump->a_data);			
			if (NT_SUCCESS(status) != FALSE) dump->pg_pending = 0;
		}
		status = dump->WritePendingRoutine(IO_DUMP_WRITE_START, pv(&offset), dump_mdl, dump->a_data);
		if (NT_SUCCESS(status) != FALSE) dump->pg_pending = 1;
	} else {
		status = dump->WriteRoutine(pv(&offset), dump_mdl);
		memset(dump_mem, 0, DUMP_MEM_SIZE);
	}
	return status;
}

static NTSTATUS dump_disk_write(dump_context *dump, void *buff, u32 size, u64 offset)
{
	memcpy(dump_mem, buff, size); 
	return dump_mem_write(dump, size, offset);
}

static NTSTATUS dump_single_write(dump_context *dump, void *buff, u32 size, u64 offset, xts_key *key)
{
	xts_encrypt(buff, dump_mem, size, offset, key);
	return dump_mem_write(dump, size, offset);
}

static NTSTATUS dump_encrypted_write(dump_context *dump, u8 *buff, u32 size, u64 offset)
{
	dev_hook *hook = dump->hook;
	NTSTATUS  status;
	u64       o1, o2, o3;
	u32       s1, s2, s3;
	u8       *p2, *p3;
	
	s1 = d32(intersect(&o1, offset, size, 0, hook->head_len));
	
	if (hook->flags & F_SYNC) {
		s2 = d32(intersect(&o2, offset, size, hook->head_len, (hook->tmp_size - hook->head_len)));
		s3 = d32(intersect(&o3, offset, size, hook->tmp_size, hook->dsk_size));		
	} else {
		s2 = d32(intersect(&o2, offset, size, hook->head_len, hook->dsk_size));
		s3 = 0;
	}
	p2 = buff + s1;
	p3 = p2 + s2;

	/*
	   normal mode:
	    o1:s1 - redirected part
		o2:s2 - encrypted part
		o3:s3 - unencrypted part
	   reencrypt mode:
	   o1:s1 - redirected part
	   o2:s2 - key_1 encrypted part
	   o3:s3 - key_2 encrypted part
	*/

	do
	{
		if (s1 != 0) {
			status = dump_encrypted_write(dump, buff, s1, hook->stor_off + o1);
			if (NT_SUCCESS(status) == FALSE) break;
		}
		if (s2 != 0) {
			status = dump_single_write(dump, p2, s2, o2, &hook->dsk_key);
			if (NT_SUCCESS(status) == FALSE) break;
		}
		if (s3 != 0)
		{
			if (hook->flags & F_REENCRYPT) {
				status = dump_single_write(dump, p3, s3, o3, hook->tmp_key);
			} else {
				status = dump_disk_write(dump, p3, s3, o3);
			}
		}
	} while (0);

	return status;
}

static NTSTATUS dump_write_routine(dump_context *dump, u64 offset, PMDL mdl, void *a_data)
{
	void    *buff = mdl->MappedSystemVa;
	u32      size = mdl->ByteCount;
	NTSTATUS status;

	if (size > DUMP_MEM_SIZE) {
		KeBugCheck(STATUS_BUFFER_OVERFLOW);
	}
	dump->a_data = a_data;

	if (dump->hook->flags & F_ENABLED) {
		status = dump_encrypted_write(dump, buff, size, offset);
	} else {
		status = dump_disk_write(dump, buff, size, offset);
	}
	return status;
}

static NTSTATUS dump_crash_write(PLARGE_INTEGER disk_offset, PMDL mdl)
{
	return dump_write_routine(&dump_crash_ctx, disk_offset->QuadPart, mdl, NULL);
}

static NTSTATUS dump_hiber_write(PLARGE_INTEGER disk_offset, PMDL mdl)
{
	return dump_write_routine(&dump_hiber_ctx, disk_offset->QuadPart, mdl, NULL);
}

static NTSTATUS
   dump_crash_write_pend(
       IN LONG           action,
	   IN PLARGE_INTEGER disk_offset,
	   IN PMDL           mdl,
	   IN PVOID          local_data
	   )
{
	dump_context *dump = &dump_crash_ctx;
	NTSTATUS      status;
	
	if (action == IO_DUMP_WRITE_START) {
		status = dump_write_routine(dump, disk_offset->QuadPart, mdl, local_data);	
	} else
	{
		status = dump->WritePendingRoutine(action, disk_offset, dump_mdl, local_data);

		if (NT_SUCCESS(status) != FALSE)
		{
			dump->pg_init    |=  (action == IO_DUMP_WRITE_INIT);
			dump->pg_pending &= ~(action == IO_DUMP_WRITE_FINISH);
		}	
	}
	return status;
}

static NTSTATUS
   dump_hiber_write_pend(
       IN LONG           action,
	   IN PLARGE_INTEGER disk_offset,
	   IN PMDL           mdl,
	   IN PVOID          local_data
	   )
{
	dump_context *dump = &dump_hiber_ctx;
	NTSTATUS      status;
	
	if (action == IO_DUMP_WRITE_START) {
		status = dump_write_routine(dump, disk_offset->QuadPart, mdl, local_data);	
	} else
	{
		status = dump->WritePendingRoutine(action, disk_offset, dump_mdl, local_data);

		if (NT_SUCCESS(status) != FALSE)
		{
			dump->pg_init    |=  (action == IO_DUMP_WRITE_INIT);
			dump->pg_pending &= ~(action == IO_DUMP_WRITE_FINISH);
		}	
	}
	return status;
}

static void dump_crash_finish(void)
{
	/* call to original FinishRoutine */
	if (dump_crash_ctx.FinishRoutine != NULL) dump_crash_ctx.FinishRoutine();
	/* zero all sensitive data */
	dc_clean_pass_cache();
	mm_unlock_user_memory(NULL, NULL);
	dc_clean_keys();
	/* zero dump data */
	burn(dump_mem, DUMP_MEM_SIZE);
}

static void dump_hiber_finish(void)
{
	/* call to original FinishRoutine */
	if (dump_hiber_ctx.FinishRoutine != NULL) dump_hiber_ctx.FinishRoutine();
	/* reset dump context */
	dump_hiber_ctx.pg_init    = 0;
	dump_hiber_ctx.pg_pending = 0;
	dump_hiber_ctx.a_data     = NULL;
	/* zero all sensitive data */
	dc_clean_pass_cache();
	mm_unlock_user_memory(NULL, NULL);
	dc_clean_keys();
	/* zero dump data */
	burn(dump_mem, DUMP_MEM_SIZE);	
}

static int is_dump_crypt() 
{
	return (dump_crash_ctx.hook != NULL) && (dump_crash_ctx.hook->flags & F_ENABLED);
}

static dev_hook *dc_get_sys_hook()
{
	dev_hook *hook = NULL;
	dev_hook *find;

	for (find = dc_first_hook(); find != NULL; find = dc_next_hook(find)) {
		if (find->pdo_dev->Flags & DO_SYSTEM_BOOT_PARTITION) hook = find;
	}
	return hook;
}

static int is_hiber_crypt()
{
	dev_hook *hook = dump_hiber_ctx.hook == NULL ? dc_get_sys_hook() : dump_hiber_ctx.hook;
	return (hook != NULL) && (hook->flags & F_ENABLED);
}

int dump_is_pverent_hibernate()
{
	if (is_hiber_crypt() == 0) 
	{
		if (dc_num_mount() == 0) {
			/* clear password cache to prevent leaks */
			dc_clean_pass_cache();
		} else return 1;
	}
	return 0;
}

static BOOLEAN dump_crash_open(LARGE_INTEGER part_offs)
{
	int allow = (dc_dump_disable == 0);

	/* prevent dumping if memory contain sensitive data */
	if (is_dump_crypt() == 0) 
	{
		if (dc_num_mount() == 0) {
			/* clear pass cache to prevent leaks */
			dc_clean_pass_cache(); 
		} else {
			allow = 0;
		}
	}

	if ( (allow != 0) && (dump_crash_ctx.OpenRoutine) ) {
		return dump_crash_ctx.OpenRoutine(part_offs);
	} else {
		return FALSE;
	}
}

static BOOLEAN dump_hiber_open(LARGE_INTEGER part_offs)
{
	if (dump_hiber_ctx.hook == NULL) {
		dump_hiber_ctx.hook = dc_get_sys_hook();
	}
	if (dump_hiber_ctx.OpenRoutine != NULL) {
		return dump_hiber_ctx.OpenRoutine(part_offs);
	} else {
		return FALSE;
	}
}

static NTSTATUS
  dump_driver_entry(
      IN entry_hook         *ehook,
      IN PVOID               unk, 
	  IN PDUMP_STACK_CONTEXT stack
	  )
{
	PDUMP_INITIALIZATION_CONTEXT init;
	NTSTATUS                     status = STATUS_UNSUCCESSFUL;
	int                          is_hiber;
	
	if (ehook->old_entry) {
		status = ehook->old_entry(unk, stack);
		ehook->old_entry = NULL;
	}

	if (NT_SUCCESS(status) && (unk == NULL) && (stack != NULL) )
	{
		init = &stack->Init; is_hiber = 0;

		if (stack->UsageType == DeviceUsageTypeHibernation) {
			is_hiber = 1;
		} else if (stack->UsageType != DeviceUsageTypeDumpFile) {
			is_hiber = (init->CrashDump == FALSE);
		}

		if (is_hiber == 0) 
		{
			dump_crash_ctx.OpenRoutine         = init->OpenRoutine;
			dump_crash_ctx.WriteRoutine        = init->WriteRoutine;
			dump_crash_ctx.WritePendingRoutine = init->WritePendingRoutine;
			dump_crash_ctx.FinishRoutine       = init->FinishRoutine;

			if (init->WriteRoutine != NULL) {
				init->WriteRoutine = dump_crash_write;
			}
			if (init->WritePendingRoutine != NULL) {
				init->WritePendingRoutine = dump_crash_write_pend;
			}
			init->OpenRoutine   = dump_crash_open;
			init->FinishRoutine = dump_crash_finish;
		} else
		{
			dump_hiber_ctx.OpenRoutine         = init->OpenRoutine;
			dump_hiber_ctx.WriteRoutine        = init->WriteRoutine;
			dump_hiber_ctx.WritePendingRoutine = init->WritePendingRoutine;
			dump_hiber_ctx.FinishRoutine       = init->FinishRoutine;

			if (init->WriteRoutine) {
				init->WriteRoutine = dump_hiber_write;
			}
			if (init->WritePendingRoutine) {
				init->WritePendingRoutine = dump_hiber_write_pend;
			}
			init->FinishRoutine = dump_hiber_finish;
			init->OpenRoutine   = dump_hiber_open;
		}
	}

	return status;
}

static void hook_dump_entry()
{
	PLDR_DATA_TABLE_ENTRY table;
	entry_hook           *ehook;

	ExAcquireFastMutex(&dump_sync);

	if (dump_imgbase != NULL && (table = find_image(dump_imgbase)))
	{
		if (table->BaseDllName.Buffer != NULL && table->EntryPoint != NULL &&
			img_cmp(&table->BaseDllName, L"dump_") || img_cmp(&table->BaseDllName, L"hiber_"))
		{
			if (ehook = mm_alloc(sizeof(entry_hook), 0))
			{
				memcpy(ehook->code, jmp_code, sizeof(jmp_code));
				ppv(ehook->code + DEST_OFF)[0] = dump_driver_entry;
				ppv(ehook->code + PARM_OFF)[0] = ehook;
				ehook->old_entry  = table->EntryPoint;
				table->EntryPoint = pv(ehook->code);					
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
	if (img_info->SystemModeImage) {
		dump_imgbase = img_info->ImageBase;
		hook_dump_entry();
	}
}


void dump_usage_notify(dev_hook *hook, DEVICE_USAGE_NOTIFICATION_TYPE type)
{
	if (type == DeviceUsageTypeDumpFile)    dump_crash_ctx.hook = hook;
	if (type == DeviceUsageTypeHibernation) dump_hiber_ctx.hook = hook;
}

int dump_hook_init(PDRIVER_OBJECT drv_obj)
{
	PLDR_DATA_TABLE_ENTRY table;
	PHYSICAL_ADDRESS      high_addr;
	PLIST_ENTRY           entry;
	NTSTATUS              status;
	int                   resl = 0;

	ExInitializeFastMutex(&dump_sync);

	ExAcquireFastMutex(&dump_sync);

	/* find PsLoadedModuleListHead */
	entry = ((PLIST_ENTRY)(drv_obj->DriverSection))->Flink;

	while (entry != drv_obj->DriverSection)
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
		if (ps_loaded_mod_list == NULL) break;

		status = PsSetLoadImageNotifyRoutine(load_img_routine);
		if (NT_SUCCESS(status) == FALSE) break;

		high_addr.HighPart = 0;
		high_addr.LowPart  = 0xFFFFFFFF;

		dump_mem = MmAllocateContiguousMemory(DUMP_MEM_SIZE, high_addr);
		if (dump_mem == NULL) break;
		dump_mdl = IoAllocateMdl(dump_mem, DUMP_MEM_SIZE, FALSE, FALSE, NULL); 
		if (dump_mdl == NULL) break;

		MmBuildMdlForNonPagedPool(dump_mdl);
		memset(dump_mem, 0, DUMP_MEM_SIZE);
		resl = 1;
	} while (0);

	if (resl == 0) {
		if (dump_mdl != NULL) IoFreeMdl(dump_mdl);
		if (dump_mem != NULL) MmFreeContiguousMemory(dump_mem);
	}
	return resl;	
}
