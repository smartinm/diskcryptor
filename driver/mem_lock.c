/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2007-2010
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
#include "driver.h"
#include "mem_lock.h"
#include "misc_mem.h"

typedef struct _lock_mem {
	LIST_ENTRY entry;
	void      *key;
	PMDL       mdl;
	u32        km_size;
	void      *km_data;
	void      *um_data;

} lock_mem;

static LIST_ENTRY lock_mem_head;
static FAST_MUTEX lock_mem_mutex;

int mm_lock_user_memory(void *mem, u32 size, void *key)
{
	lock_mem *s_mem;
	void     *k_map;
	PMDL      mdl;
	int       locked;

	s_mem = NULL; mdl = NULL; 
	k_map = NULL; locked = 0;
	do
	{
		if ( (s_mem = mm_alloc(sizeof(lock_mem), MEM_SUCCESS)) == NULL ) break;
		if ( (mdl = IoAllocateMdl(mem, size, FALSE, FALSE, NULL)) == NULL ) break;

		__try {
			MmProbeAndLockPages(mdl, UserMode, IoModifyAccess);
			k_map  = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, HighPagePriority);
			locked = 1;
		} 
		__except(EXCEPTION_EXECUTE_HANDLER) {
			k_map = NULL;
		}
		if (k_map != NULL)
		{
			/* insert mapping descriptor to global list */
			s_mem->key = key;
			s_mem->mdl = mdl;
			s_mem->km_size = size;
			s_mem->km_data = k_map;
			s_mem->um_data = mem;

			ExAcquireFastMutex(&lock_mem_mutex);
			InsertTailList(&lock_mem_head, &s_mem->entry);
			ExReleaseFastMutex(&lock_mem_mutex);
		}
	} while (0);

	if (k_map == NULL)
	{
		if (mdl != NULL) {
			if (locked != 0) MmUnlockPages(mdl);
			IoFreeMdl(mdl);
		}
		if (s_mem != NULL) mm_free(s_mem);
		return ST_NOMEM;
	}
	return ST_OK;
}

static void mm_do_unlock(lock_mem *pmem)
{
	/* remove memory descriptor from list */
	RemoveEntryList(&pmem->entry);
	/* prevent leaks */
	burn(pmem->km_data, pmem->km_size);
	/* return if IRQL not allow free resources */
	if (KeGetCurrentIrql() > DISPATCH_LEVEL) return;
	/* unmap memory within kernel space */
	MmUnmapLockedPages(pmem->km_data, pmem->mdl);
	/* unlock pages */
	MmUnlockPages(pmem->mdl);
	/* free MDL */
	IoFreeMdl(pmem->mdl);
	/* free descriptor */
	mm_free(pmem);
}

void mm_unlock_user_memory(void *mem, void *key)
{
	PLIST_ENTRY item;
	lock_mem   *pmem;

	if (KeGetCurrentIrql() < DISPATCH_LEVEL) {
		ExAcquireFastMutex(&lock_mem_mutex);
	}
	/* find memory descriptor blocks */
	for (item = lock_mem_head.Flink; item != &lock_mem_head;)
	{
		pmem = CONTAINING_RECORD(item, lock_mem, entry);
		item = item->Flink;

		if ( (mem == NULL || mem == pmem->um_data) && (key == NULL || key == pmem->key) ) {
			mm_do_unlock(pmem);
		}
	}
	if (KeGetCurrentIrql() < DISPATCH_LEVEL) {
		ExReleaseFastMutex(&lock_mem_mutex);
	}
}

void mm_init_mem_lock()
{
	InitializeListHead(&lock_mem_head);	
	ExInitializeFastMutex(&lock_mem_mutex);
}