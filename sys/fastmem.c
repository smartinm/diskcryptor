/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2007-2009
    * ntldr <ntldr@diskcryptor.net> PGP key ID - 0xC48251EB4F8E4E6E
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
#include "fastmem.h"
#include "driver.h"
#include "misc.h"
#include "misc_mem.h"

typedef aligned struct _mem_block {
	u32        n_list;
	u32        in_list;
	aligned u8 data[];

} mem_block;

#define MAX_MEM_SIZE  1024*1024  /* maximum fast allocate           */
#define NUM_MEM_LISTS 10         /* number of lookaside lists       */
#define MEM_INC       512        /* block length increment          */
#define MEM_ADD       128        /* additional memory size on block */
#define MB_SIZE(_x) ( (_x) + sizeof(mem_block) + MEM_ADD )

static NPAGED_LOOKASIDE_LIST mem_lists[NUM_MEM_LISTS];

void *fast_alloc(size_t size)
{
	mem_block *block = NULL;
	size_t     len = MEM_INC;
	void      *mem = NULL;
	u32        num;	
	
	for (num = 0; num < NUM_MEM_LISTS; num++, len <<= 1) 
	{
		if (size <= len + MEM_ADD)
		{
			if (block = ExAllocateFromNPagedLookasideList(&mem_lists[num])) {
				block->n_list = num, block->in_list = 1, mem = &block->data;
			}
			break;
		}
	}
	if (block == NULL)
	{
		if (block = mem_alloc_success(MB_SIZE(size))) {
			block->in_list = 0; mem = &block->data;
		}			
	}
	return mem; 
}

void fast_free(void *mem)
{
	mem_block *block = CONTAINING_RECORD(mem, mem_block, data);

	if (block->in_list != 0) {
		ExFreeToNPagedLookasideList(&mem_lists[block->n_list], block);
	} else {
		mem_free(block);
	} 
}

void fastmem_init()
{
	u32    num;
	size_t len = MEM_INC;

	for (num = 0; num < NUM_MEM_LISTS; num++, len <<= 1) 
	{
		ExInitializeNPagedLookasideList(
			&mem_lists[num], mm_alloc_success, NULL, 0, MB_SIZE(len), '2_cd', 0);
	}
}

void fastmem_free()
{
	u32 num;

	for (num = 0; num < NUM_MEM_LISTS; num++) {
		ExDeleteNPagedLookasideList(&mem_lists[num]);
	}
}