/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2009-2011
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
#include "misc_mem.h"
#include "misc.h"

typedef struct _alloc_block {
	size_t     size;
	int        flags;
	int        index;
	align16 u8 data[];

} alloc_block;

#define MEM_PADDED  0x1000 /* internal, don't use */

#define ALLOC_SIZE(_x)    ( (_x) + sizeof(alloc_block) + 8)
#define APOOL_TYPE(_flags)( (_flags) & MEM_PAGED ? PagedPool : NonPagedPool )

#define NUM_MEM_LISTS 12  /* number of lookaside lists */
static NPAGED_LOOKASIDE_LIST mem_lists[NUM_MEM_LISTS];

void *mm_map_mdl_success(PMDL mdl)
{
	void *mem;
	int   timeout;

	for (timeout = DC_MEM_RETRY_TIMEOUT; timeout > 0; timeout -= DC_MEM_RETRY_TIME)
	{
		if (mem = MmGetSystemAddressForMdlSafe(mdl, HighPagePriority)) break;
		if (KeGetCurrentIrql() >= DISPATCH_LEVEL) break;
		dc_delay(DC_MEM_RETRY_TIME);
	}
	return mem;
}

PMDL mm_allocate_mdl_success(void *data, u32 size)
{
	PMDL mdl;
	int  timeout;

	for (timeout = DC_MEM_RETRY_TIMEOUT; timeout > 0; timeout -= DC_MEM_RETRY_TIME)
	{
		if (mdl = IoAllocateMdl(data, size, FALSE, FALSE, NULL)) break;
		if (KeGetCurrentIrql() >= DISPATCH_LEVEL) break;
		dc_delay(DC_MEM_RETRY_TIME);
	}
	return mdl;
}

PIRP mm_allocate_irp_success(CCHAR StackSize)
{
	PIRP irp;
	int  timeout;

	for (timeout = DC_MEM_RETRY_TIMEOUT; timeout > 0; timeout -= DC_MEM_RETRY_TIME)
	{
		if (irp = IoAllocateIrp(StackSize, FALSE)) break;
		if (KeGetCurrentIrql() >= DISPATCH_LEVEL) break;
		dc_delay(DC_MEM_RETRY_TIME);
	}
	return irp;
}

void *mm_alloc_success(POOL_TYPE pool, SIZE_T bytes, u32 tag)
{
	void *mem;
	int   timeout;

	for (timeout = DC_MEM_RETRY_TIMEOUT; timeout > 0; timeout -= DC_MEM_RETRY_TIME)
	{
		if (mem = ExAllocatePoolWithTag(pool, bytes, tag)) break;
		if (KeGetCurrentIrql() >= DISPATCH_LEVEL) break;
		dc_delay(DC_MEM_RETRY_TIME);
	}
	return mem;
}

void *mm_alloc(size_t size, int flags)
{
	alloc_block *block;
	char        *p_mem = NULL;
	int          i;
	
	if (flags & MEM_FAST)
	{
		for (i = 0; i < NUM_MEM_LISTS; i++) {
			if ((512u << i) < size) continue;
			p_mem = ExAllocateFromNPagedLookasideList(&mem_lists[i]); 
			break;
		}
	}
	if (p_mem == NULL) /* if memory not allocated, allocate from pool */
	{
		if (flags & MEM_SUCCESS)
			p_mem = mm_alloc_success(APOOL_TYPE(flags), ALLOC_SIZE(size), '1_cd'); else
			p_mem = ExAllocatePoolWithTag(APOOL_TYPE(flags), ALLOC_SIZE(size), '1_cd');
		
		if (p_mem == NULL) return NULL;
		flags &= ~MEM_FAST;
	}
	/* memory block must be 16byte aligned */
	if (dSZ(p_mem) & (16-1)) p_mem += 8, flags |= MEM_PADDED;
	/* initialize alloc_block struct */
	block = pv(p_mem);
	block->size  = size;
	block->flags = flags;
	block->index = i;
	/* zero memory if needed */
	if (flags & MEM_ZEROED) memset(block->data, 0, size);
	return &block->data;
}

void mm_free(void *mem)
{
	alloc_block *block = CONTAINING_RECORD(mem, alloc_block, data);               /* get the alloc_block struct */
	char        *p_mem = (block->flags & MEM_PADDED) ? p8(block) - 8 : p8(block); /* get the original memory pointer */

	/* zero block to prevent leaks if needed */
	if (block->flags & MEM_SECURE) burn(block->data, block->size);
	/* free memory */
	if (block->flags & MEM_FAST) {
		ExFreeToNPagedLookasideList(&mem_lists[block->index], p_mem);
	} else {
		ExFreePoolWithTag(p_mem, '1_cd');
	}
}

void mm_init()
{
	int i;

	for (i = 0; i < NUM_MEM_LISTS; i++) {
		ExInitializeNPagedLookasideList(&mem_lists[i], NULL, NULL, 0, ALLOC_SIZE(512u << i), '2_cd', 0);
	}
}

void mm_uninit()
{
	int i;

	for (i = 0; i < NUM_MEM_LISTS; i++) {
		ExDeleteNPagedLookasideList(&mem_lists[i]);
	}
}