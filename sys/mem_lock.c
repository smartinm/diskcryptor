#include <ntifs.h>
#include "defines.h"
#include "driver.h"
#include "mem_lock.h"

typedef struct _lock_mem {
	LIST_ENTRY entry;
	PEPROCESS  process;
	void      *f_obj;
	PMDL       mdl;
	u32        km_size;
	u8        *km_data;
	u8        *um_data;

} lock_mem;

static LIST_ENTRY lock_mem_head;
static FAST_MUTEX lock_mem_mutex;

int dc_lock_mem(void *mem, u32 size, void *f_obj)
{
	lock_mem *s_mem;
	void     *k_map;
	PMDL      mdl;
	int       locked;

	s_mem = NULL; mdl = NULL; 
	k_map = NULL; locked = 0;
	do
	{
		if ( (s_mem = mem_alloc(sizeof(lock_mem))) == NULL ) {
			break;
		}

		mdl = IoAllocateMdl(mem, size, FALSE, FALSE, NULL);

		if (mdl == NULL) {
			break;
		}
		
		__try 
		{
			MmProbeAndLockPages(mdl, UserMode, IoModifyAccess);
			locked = 1;
			k_map  = MmMapLockedPages(mdl, KernelMode);			
		} 
		__except(EXCEPTION_EXECUTE_HANDLER) {
			k_map = NULL;
		}

		if (k_map != NULL)
		{
			/* insert mapping descriptor to global list */
			s_mem->process = IoGetCurrentProcess();
			s_mem->f_obj   = f_obj;
			s_mem->mdl     = mdl;
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
		if (mdl != NULL) 
		{
			if (locked != 0) {
				MmUnlockPages(mdl);
			}

			IoFreeMdl(mdl);
		}

		if (s_mem != NULL) {
			mem_free(s_mem);
		}

		return ST_NOMEM;
	} else {
		return ST_OK;
	}
}

int dc_unlock_mem(void *mem, void *f_obj)
{
	PLIST_ENTRY item;
	lock_mem   *find;
	lock_mem   *s_mem;
	PEPROCESS   process;

	ExAcquireFastMutex(&lock_mem_mutex);

	/* find memory descriptor block */
	item    = lock_mem_head.Flink;
	process = IoGetCurrentProcess();
	s_mem   = NULL;

	while (item != &lock_mem_head)
	{
		find = CONTAINING_RECORD(item, lock_mem, entry);
		item = item->Flink;

		if ( (find->process == process) && 
			 (find->f_obj == f_obj) && (find->um_data == mem) )
		{
			RemoveEntryList(&find->entry);
			s_mem = find; break;
		}
	}

	ExReleaseFastMutex(&lock_mem_mutex);

	if (s_mem != NULL)
	{
		/* prevent leaks */
		zeromem(s_mem->km_data, s_mem->km_size);
		/* unmap memory within kernel space */
		MmUnmapLockedPages(s_mem->km_data, s_mem->mdl);
		/* unlock pages */
		MmUnlockPages(s_mem->mdl);
		/* free MDL */
		IoFreeMdl(s_mem->mdl);
		/* free descriptor */
		mem_free(s_mem);
		
		return ST_OK;
	} else {
		return ST_ERROR;
	}
}

void dc_clean_locked_mem(void *f_obj)
{
	PLIST_ENTRY item;
	lock_mem   *s_mem;
	int         loirql;

	if (loirql = (KeGetCurrentIrql() == PASSIVE_LEVEL)) {
		ExAcquireFastMutex(&lock_mem_mutex);
	}

	item = lock_mem_head.Flink;

	while (item != &lock_mem_head)
	{
		s_mem = CONTAINING_RECORD(item, lock_mem, entry);
		item  = item->Flink;

		if ( (f_obj == NULL) || (s_mem->f_obj == f_obj) )
		{
			/* remove memory descriptor from list */
			RemoveEntryList(&s_mem->entry);
			/* prevent leaks */
			zeromem(s_mem->km_data, s_mem->km_size);
			
			if (loirql != 0)
			{
				/* unmap memory within kernel space */
				MmUnmapLockedPages(s_mem->km_data, s_mem->mdl);
				/* unlock pages */
				MmUnlockPages(s_mem->mdl);
				/* free MDL */
				IoFreeMdl(s_mem->mdl);
				/* free descriptor */
				mem_free(s_mem);
			}
		}
	}

	if (loirql != 0) {
		ExReleaseFastMutex(&lock_mem_mutex);
	}
}

void mem_lock_init()
{
	InitializeListHead(&lock_mem_head);
	
	ExInitializeFastMutex(&lock_mem_mutex);
}