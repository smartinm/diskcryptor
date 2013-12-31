/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2007-2013
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
#include "dump_hook.h"
#include "debug.h"
#include "mount.h"
#include "misc.h"
#include "misc_mem.h"

typedef NTSTATUS (*PDUMPDRIVERENTRY)(IN PVOID unknown, IN PDUMP_STACK_CONTEXT dumpStack);
#define DUMP_MEM_SIZE (4096*16)

static PLIST_ENTRY    p_PsLoadedModuleListHead;
static volatile PVOID p_crash_DriverEntry[4];
static volatile LONG  crash_hooks_count;
static volatile PVOID p_hiber_DriverEntry[4];
static volatile LONG  hiber_hooks_count;
static PUCHAR         dump_hook_mem;
static PMDL           dump_hook_mdl;

// original dump driver handlers
static PDUMP_DRIVER_OPEN          old_OpenRoutine;
static PDUMP_DRIVER_WRITE         old_WriteRoutine;
static PDUMP_DRIVER_WRITE_PENDING old_WritePendingRoutine;
static PDUMP_DRIVER_FINISH        old_FinishRoutine;
static BOOLEAN                    hibernation_progress; // TRUE is hibernation, FALSE is crash dumping in progress
static dev_hook*                  operation_hook;

static void dump_hook_encrypt_data(IN PMDL           Mdl,
	                               IN PLARGE_INTEGER DiskByteOffset)
{
	PUCHAR    p_data = (PUCHAR) MmGetSystemAddressForMdlSafe(Mdl, HighPagePriority);
	ULONG     length = MmGetMdlByteCount(Mdl);
	ULONGLONG offset = DiskByteOffset->QuadPart;

	// check input data pointer and length
	if (p_data == NULL || length > DUMP_MEM_SIZE || (length % XTS_SECTOR_SIZE) != 0) {
		KeBugCheckEx(STATUS_BUFFER_OVERFLOW, (ULONG_PTR)operation_hook, (ULONG_PTR)p_data, length, 0);
	}
	
	if (operation_hook->flags & F_NO_REDIRECT) {
		// not used, the data are moved forward on the header length
		DiskByteOffset->QuadPart += operation_hook->head_len;
	} else
	{
		// writing to redirected area are not supported
		if (offset < operation_hook->head_len) {
			KeBugCheckEx(STATUS_NOT_SUPPORTED, (ULONG_PTR)operation_hook, (ULONG_PTR)offset, length, 0);
		}
	}

	if ((operation_hook->flags & F_SYNC) && (offset + length > operation_hook->tmp_size))
	{
		ULONG     part1_length = offset < operation_hook->tmp_size ? (ULONG)(operation_hook->tmp_size - offset) : 0;
		ULONGLONG part2_offset = offset < operation_hook->tmp_size ? operation_hook->tmp_size : offset;
		ULONG     part2_length = length - part1_length;

		if (part1_length != 0) { // write to part encrypted with master key
			xts_encrypt(p_data, dump_hook_mem, part1_length, offset, &operation_hook->dsk_key);
		}
		if (part2_length != 0) { // write to part encrypted with temporary key
			xts_encrypt(p_data + part1_length, dump_hook_mem + part1_length, part2_length, part2_offset, operation_hook->tmp_key);
		}
	} else { // write only to encrypted part
		xts_encrypt(p_data, dump_hook_mem, length, offset, &operation_hook->dsk_key);
	}

	// initialize new dump MDL with encrypted data
	MmInitializeMdl(dump_hook_mdl, dump_hook_mem, Mdl->ByteCount);
	dump_hook_mdl->MappedSystemVa = dump_hook_mem;
	dump_hook_mdl->MdlFlags       = MDL_SOURCE_IS_NONPAGED_POOL | MDL_MAPPED_TO_SYSTEM_VA;
}

static NTSTATUS dump_hook_new_WriteRoutine(IN PLARGE_INTEGER DiskByteOffset,
	                                       IN PMDL           Mdl)
{
	if (operation_hook != NULL && DiskByteOffset && Mdl)
	{
		dump_hook_encrypt_data(Mdl, DiskByteOffset);
		return old_WriteRoutine(DiskByteOffset, dump_hook_mdl);
	} else {
		return old_WriteRoutine(DiskByteOffset, Mdl);
	}
}

static NTSTATUS dump_hook_new_WritePendingRoutine(IN LONG           Action,
	                                              IN PLARGE_INTEGER DiskByteOffset,
												  IN PMDL           Mdl,
												  IN PVOID          LocalData)
{
	if (operation_hook != NULL)
	{
		if (Action == IO_DUMP_WRITE_START && DiskByteOffset && Mdl) {
			dump_hook_encrypt_data(Mdl, DiskByteOffset);
			return old_WritePendingRoutine(IO_DUMP_WRITE_START, DiskByteOffset, dump_hook_mdl, LocalData);
		} else {
			return old_WritePendingRoutine(Action, NULL, NULL, LocalData);
		}
	} else {
		return old_WritePendingRoutine(Action, DiskByteOffset, Mdl, LocalData);
	}
}

static void dump_hook_new_FinishRoutine(void)
{
	// call to original FinishRoutine
	if (old_FinishRoutine != NULL) old_FinishRoutine();

	// zero all sensitive data
	mm_clean_secure_memory();
	dc_clean_keys();
	RtlSecureZeroMemory(dump_hook_mem, DUMP_MEM_SIZE);
}

static BOOLEAN dump_hook_new_OpenRoutine(IN LARGE_INTEGER PartitionOffset)
{
	DbgMsg("dump_hook_new_OpenRoutine, PartitionOffset=%I64x\n", PartitionOffset);

	if (dc_prepare_for_dumping(hibernation_progress, TRUE, (PVOID *)&operation_hook) == FALSE) {
		DbgMsg("dumping operation are not allowed\n");
		return FALSE;
	}
	return ( old_OpenRoutine != NULL ? old_OpenRoutine(PartitionOffset) : FALSE );
}

static NTSTATUS dump_hook_new_DriverEntry(IN volatile PVOID*     p_old_DriverEntry,
	                                      IN PVOID               unknown, 
	                                      IN PDUMP_STACK_CONTEXT dumpStack)
{
#ifdef _M_IX86
	PDUMPDRIVERENTRY old_DriverEntry = (PDUMPDRIVERENTRY)_InterlockedExchange((volatile LONG*)p_old_DriverEntry, 0);
#else
	PDUMPDRIVERENTRY old_DriverEntry = (PDUMPDRIVERENTRY)_InterlockedExchangePointer(p_old_DriverEntry, NULL);
#endif
	NTSTATUS         status = ( old_DriverEntry ? old_DriverEntry(unknown, dumpStack) : STATUS_UNSUCCESSFUL );

	if (NT_SUCCESS(status) == FALSE) {
		DbgMsg("old_DriverEntry fails, status=%0.8x\n", status);
		return status;
	}

	if (unknown != NULL || dumpStack == NULL) {
		DbgMsg("invalid parameters in new_DriverEntry, unknown=%p, dumpStack=%p\n", unknown, dumpStack);
		return status;
	}

	// determine current operation
	hibernation_progress = (dumpStack->UsageType == DeviceUsageTypeHibernation) ||
		                   (dumpStack->UsageType != DeviceUsageTypeDumpFile && dumpStack->Init.CrashDump == FALSE);

	// save original dump driver functions and setup dump_hook handlers
	if (dumpStack->Init.OpenRoutine != dump_hook_new_OpenRoutine) {
		old_OpenRoutine = dumpStack->Init.OpenRoutine;
		dumpStack->Init.OpenRoutine = dump_hook_new_OpenRoutine;
	}
	if (dumpStack->Init.FinishRoutine != dump_hook_new_FinishRoutine) {
		old_FinishRoutine = dumpStack->Init.FinishRoutine;
		dumpStack->Init.FinishRoutine = dump_hook_new_FinishRoutine;
	}
	if (dumpStack->Init.WriteRoutine && dumpStack->Init.WriteRoutine != dump_hook_new_WriteRoutine) {
		old_WriteRoutine = dumpStack->Init.WriteRoutine;
		dumpStack->Init.WriteRoutine = dump_hook_new_WriteRoutine;
	}
	if (dumpStack->Init.WritePendingRoutine && dumpStack->Init.WritePendingRoutine != dump_hook_new_WritePendingRoutine) {
		old_WritePendingRoutine = dumpStack->Init.WritePendingRoutine;
		dumpStack->Init.WritePendingRoutine = dump_hook_new_WritePendingRoutine;
	}
	DbgMsg("dump driver functions hooked, hibernation_progress=%d\n", hibernation_progress);
	return status;
}

static NTSTATUS dump_hook_new_crash_DriverEntry_0(IN PVOID               unknown, 
	                                              IN PDUMP_STACK_CONTEXT dumpStack)
{
	return dump_hook_new_DriverEntry(&p_crash_DriverEntry[0], unknown, dumpStack);
}
static NTSTATUS dump_hook_new_crash_DriverEntry_1(IN PVOID               unknown, 
	                                              IN PDUMP_STACK_CONTEXT dumpStack)
{
	return dump_hook_new_DriverEntry(&p_crash_DriverEntry[1], unknown, dumpStack);
}
static NTSTATUS dump_hook_new_crash_DriverEntry_2(IN PVOID               unknown, 
	                                              IN PDUMP_STACK_CONTEXT dumpStack)
{
	return dump_hook_new_DriverEntry(&p_crash_DriverEntry[2], unknown, dumpStack);
}
static NTSTATUS dump_hook_new_crash_DriverEntry_3(IN PVOID               unknown, 
	                                              IN PDUMP_STACK_CONTEXT dumpStack)
{
	return dump_hook_new_DriverEntry(&p_crash_DriverEntry[3], unknown, dumpStack);
}
static NTSTATUS dump_hook_new_hiber_DriverEntry_0(IN PVOID               unknown, 
	                                              IN PDUMP_STACK_CONTEXT dumpStack)
{
	return dump_hook_new_DriverEntry(&p_hiber_DriverEntry[0], unknown, dumpStack);
}
static NTSTATUS dump_hook_new_hiber_DriverEntry_1(IN PVOID               unknown, 
	                                              IN PDUMP_STACK_CONTEXT dumpStack)
{
	return dump_hook_new_DriverEntry(&p_hiber_DriverEntry[1], unknown, dumpStack);
}
static NTSTATUS dump_hook_new_hiber_DriverEntry_2(IN PVOID               unknown, 
	                                              IN PDUMP_STACK_CONTEXT dumpStack)
{
	return dump_hook_new_DriverEntry(&p_hiber_DriverEntry[2], unknown, dumpStack);
}
static NTSTATUS dump_hook_new_hiber_DriverEntry_3(IN PVOID               unknown, 
	                                              IN PDUMP_STACK_CONTEXT dumpStack)
{
	return dump_hook_new_DriverEntry(&p_hiber_DriverEntry[3], unknown, dumpStack);
}

static PLDR_DATA_TABLE_ENTRY dump_hook_find_loader_entry(PVOID ImageBase)
{
	PLDR_DATA_TABLE_ENTRY ldr_entry = NULL;
	PLIST_ENTRY           entry;

	KeEnterCriticalRegion();

	for (entry = p_PsLoadedModuleListHead->Flink; entry != p_PsLoadedModuleListHead; entry = entry->Flink)
	{
		if ( ((PLDR_DATA_TABLE_ENTRY)entry)->DllBase == ImageBase ) {
			ldr_entry = (PLDR_DATA_TABLE_ENTRY)entry;
			break;
		}
	}
	KeLeaveCriticalRegion();
	return ldr_entry;
}

static void dump_hook_notify_image(IN PUNICODE_STRING FullImageName, 
	                               IN HANDLE          ProcessId,
								   IN PIMAGE_INFO     ImageInfo)
{
	PLDR_DATA_TABLE_ENTRY ldr_entry;
	ULONG                 i;
	
	if (ImageInfo->SystemModeImage == 0 || ImageInfo->ImageBase == NULL) return;
	if ((ldr_entry = dump_hook_find_loader_entry(ImageInfo->ImageBase)) == NULL) return;
	if (ldr_entry->BaseDllName.Buffer == NULL || ldr_entry->EntryPoint == NULL) return;

	if (ldr_entry->BaseDllName.Length <= 5*sizeof(wchar_t)) return;
	
	if (ldr_entry->BaseDllName.Length > 5*sizeof(wchar_t) && _wcsnicmp(ldr_entry->BaseDllName.Buffer, L"dump_", 5) == 0)
	{
		i = InterlockedIncrement(&crash_hooks_count) % (sizeof(p_crash_DriverEntry) / sizeof(p_crash_DriverEntry[0]));
		p_crash_DriverEntry[i] = ldr_entry->EntryPoint;

		switch (i) {
			case 0: ldr_entry->EntryPoint = dump_hook_new_crash_DriverEntry_0; break;
			case 1: ldr_entry->EntryPoint = dump_hook_new_crash_DriverEntry_1; break;
			case 2: ldr_entry->EntryPoint = dump_hook_new_crash_DriverEntry_2; break;
			case 3: ldr_entry->EntryPoint = dump_hook_new_crash_DriverEntry_3; break;
			default:
				KeBugCheck(STATUS_INTERNAL_ERROR);
		}
		DbgMsg("crashdump driver loaded, i=%d, BaseDllName=%wZ, FullDllName=%wZ\n", i, &ldr_entry->BaseDllName, &ldr_entry->FullDllName);
	}

	if (ldr_entry->BaseDllName.Length > 5*sizeof(wchar_t) && _wcsnicmp(ldr_entry->BaseDllName.Buffer, L"hiber_", 5) == 0)
	{
		i = InterlockedIncrement(&hiber_hooks_count) % (sizeof(p_hiber_DriverEntry) / sizeof(p_hiber_DriverEntry[0]));
		p_hiber_DriverEntry[i] = ldr_entry->EntryPoint;

		switch (i) {
			case 0: ldr_entry->EntryPoint = dump_hook_new_hiber_DriverEntry_0; break;
			case 1: ldr_entry->EntryPoint = dump_hook_new_hiber_DriverEntry_1; break;
			case 2: ldr_entry->EntryPoint = dump_hook_new_hiber_DriverEntry_2; break;
			case 3: ldr_entry->EntryPoint = dump_hook_new_hiber_DriverEntry_3; break;
			default:
				KeBugCheck(STATUS_INTERNAL_ERROR);
		}
		DbgMsg("hibernation driver loaded, i=%d, BaseDllName=%wZ, FullDllName=%wZ\n", i, &ldr_entry->BaseDllName, &ldr_entry->FullDllName);
	}
}

NTSTATUS dump_hook_init(PDRIVER_OBJECT DriverObject)
{
#if _M_IX86
	PHYSICAL_ADDRESS      allocation_high = { 0xFFFFFFFF, 0 };
#else
	PHYSICAL_ADDRESS      allocation_high = { 0xFFFFFFFF, 0x7FF };
#endif
	PLDR_DATA_TABLE_ENTRY ldr_entry;
	NTSTATUS              status;

	DbgMsg("dump_hook_init\n");

	// find PsLoadedModuleListHead in ntoskrnl
	if ( (DriverObject == NULL || DriverObject->DriverSection == NULL) ||
		 (ldr_entry = *((PLDR_DATA_TABLE_ENTRY*)DriverObject->DriverSection)) == NULL )
	{
		DbgMsg("first LDR_DATA_TABLE_ENTRY is not found\n");
		status = STATUS_PROCEDURE_NOT_FOUND;
		goto cleanup;
	}
	while ( ldr_entry != DriverObject->DriverSection )
	{
		if ( ldr_entry->BaseDllName.Length == 0x18 && *((PULONG)ldr_entry->BaseDllName.Buffer) == 0x0074006E )
		{
			p_PsLoadedModuleListHead = ldr_entry->InLoadOrderLinks.Blink;
			break;
		}
		ldr_entry = (PLDR_DATA_TABLE_ENTRY)ldr_entry->InLoadOrderLinks.Flink;
	}
	
	if (p_PsLoadedModuleListHead == NULL) {
		DbgMsg("PsLoadedModuleListHead is not found\n");
		status = STATUS_VARIABLE_NOT_FOUND;
		goto cleanup;
	}
	
	if ( (dump_hook_mem = (PUCHAR) MmAllocateContiguousMemory(DUMP_MEM_SIZE, allocation_high)) == NULL ||
		 (dump_hook_mdl = IoAllocateMdl(dump_hook_mem, DUMP_MEM_SIZE, FALSE, FALSE, NULL)) == NULL )
	{
		DbgMsg("insufficient resources for dump_hook, mem=%p, mdl=%p\n", dump_hook_mem, dump_hook_mdl);
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto cleanup;
	}
	MmBuildMdlForNonPagedPool(dump_hook_mdl);
	memset(dump_hook_mem, 0, DUMP_MEM_SIZE);

	if ( NT_SUCCESS(status = PsSetLoadImageNotifyRoutine(dump_hook_notify_image)) == FALSE ) {
		DbgMsg("PsSetLoadImageNotifyRoutine fails with status=%0.8x\n", status);
		goto cleanup;
	}
	DbgMsg("dump_hook initialized OK\n");
	status = STATUS_SUCCESS;

cleanup:
	if (NT_SUCCESS(status) == FALSE) {
		if (dump_hook_mdl != NULL) IoFreeMdl(dump_hook_mdl);
		if (dump_hook_mem != NULL) MmFreeContiguousMemory(dump_hook_mem);
		dump_hook_mdl = NULL, dump_hook_mem = NULL;
	}
	return status;
}
