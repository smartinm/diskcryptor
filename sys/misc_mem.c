/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2009-2010
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

#define NUM_MEM_LISTS 12  /* number of lookaside lists */
#define MEM_ADD       128 /* additional memory size on block */

#define ALLOC_SIZE(_x) ( (_x) + sizeof(alloc_block) + 8)

static NPAGED_LOOKASIDE_LIST mem_lists[NUM_MEM_LISTS];
static size_t                mem_sizes[NUM_MEM_LISTS];

void *mm_map_mdl_success(PMDL mdl)
{
	void *mem;
	u32   timeout;

	timeout = DC_MEM_RETRY_TIMEOUT;
	do
	{
		if (mem = MmGetSystemAddressForMdlSafe(mdl, HighPagePriority)) {
			break;
		}
		if (KeGetCurrentIrql() >= DISPATCH_LEVEL) {
			break;
		}
		dc_delay(DC_MEM_RETRY_TIME); timeout -= DC_MEM_RETRY_TIME;
	} while (timeout != 0);

	return mem;
}

PMDL mm_allocate_mdl_success(void *data, u32 size)
{
	PMDL mdl;
	u32  timeout;

	timeout = DC_MEM_RETRY_TIMEOUT;
	do
	{
		if (mdl = IoAllocateMdl(data, size, FALSE, FALSE, NULL)) {
			break;
		}
		if (KeGetCurrentIrql() >= DISPATCH_LEVEL) {
			break;
		}
		dc_delay(DC_MEM_RETRY_TIME); timeout -= DC_MEM_RETRY_TIME;
	} while (timeout != 0);

	return mdl;
}

void *mm_alloc_success(POOL_TYPE pool, SIZE_T bytes, u32 tag)
{
	void *mem;
	u32   timeout;

	timeout = DC_MEM_RETRY_TIMEOUT;
	do
	{
		if (mem = ExAllocatePoolWithTag(pool, bytes, tag)) {
			break;
		}
		if (KeGetCurrentIrql() >= DISPATCH_LEVEL) {
			break;
		}
		dc_delay(DC_MEM_RETRY_TIME); timeout -= DC_MEM_RETRY_TIME;
	} while (timeout != 0);

	return mem;
}

void *mm_alloc(size_t size, int flags)
{
	alloc_block *block = NULL;
	char        *p_mem;
	int          i;
	
	if (flags & MEM_FAST)
	{
		for (i = 0; i < NUM_MEM_LISTS; i++)
		{
			if (mem_sizes[i] >= size) {
				block = ExAllocateFromNPagedLookasideList(&mem_lists[i]);
				break;
			}
		}
	}
	if (block == NULL)
	{
		if (flags & MEM_SUCCESS) {
			p_mem = mm_alloc_success(NonPagedPool, ALLOC_SIZE(size), '1_cd');
		} else {
			p_mem = ExAllocatePoolWithTag(NonPagedPool, ALLOC_SIZE(size), '1_cd');
		}
		if (p_mem == NULL) {
			return NULL;
		}
		if (dSZ(p_mem) & 15) {
			block = pv(p_mem + 8); flags |= MEM_PADDED;
		} else {
			block = pv(p_mem);
		}
		flags &= ~MEM_FAST;
	} else {
		block->index = i;
	}
	block->size  = size;
	block->flags = flags;

	if (flags & MEM_ZEROED) {
		zeromem(block->data, size);
	}
	return &block->data;
}

void mm_free(void *mem)
{
	alloc_block *block = CONTAINING_RECORD(mem, alloc_block, data);

	if (block->flags & MEM_SECURE) {
		zeromem(block->data, block->size);
	}
	if (block->flags & MEM_FAST) {
		ExFreeToNPagedLookasideList(&mem_lists[block->index], block);
	} else 
	{
		if (block->flags & MEM_PADDED) {
			ExFreePool(p8(block) - 8);
		} else {
			ExFreePool(block);
		}
	}
}

void mm_init()
{
	int i;

	for (i = 0; i < NUM_MEM_LISTS; i++)
	{
		mem_sizes[i] = _align(
			((512 << i) + sizeof(alloc_block) + MEM_ADD), 512) - sizeof(alloc_block);

		ExInitializeNPagedLookasideList(
			&mem_lists[i], NULL, NULL, 0, mem_sizes[i] + sizeof(alloc_block), '2_cd', 0);
	}
}

void mm_uninit()
{
	int i;

	for (i = 0; i < NUM_MEM_LISTS; i++) {
		ExDeleteNPagedLookasideList(&mem_lists[i]);
	}
}