/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2007 
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
#include "fastmem.h"
#include "driver.h"

typedef aligned struct _mem_block
{
	u32 n_list;
	u32 list;
	u8  data[];

} mem_block;

static NPAGED_LOOKASIDE_LIST mem_lists[NUM_MEM_LISTS];

void *fast_alloc(size_t size)
{
	mem_block    *block = NULL;
	void         *mem   = NULL;
	u32           num;
	size_t        len = MEM_INC;
	LARGE_INTEGER time;
	u32           timeout;
	
	
	for (num = 0; num < NUM_MEM_LISTS; num++, len <<= 1) 
	{
		if (size <= len + MEM_ADD)
		{
			if (block = ExAllocateFromNPagedLookasideList(&mem_lists[num])) {
				block->n_list = num;
				block->list   = 1;
				mem = &block->data;
			}
			break;
		}
	}

	if (block == NULL)
	{
		time.QuadPart = DC_MEM_RETRY_TIME * -10000;
		timeout       = DC_MEM_RETRY_TIMEOUT;

		do
		{
			if (block = mem_alloc(size + sizeof(mem_block) + MEM_ADD))
			{
				block->list = 0; mem = &block->data;
				break;
			}

			KeDelayExecutionThread(KernelMode, FALSE, &time);

			timeout -= DC_MEM_RETRY_TIME;
		} while (timeout != 0);
	}

	return mem; 
}

void fast_free(void *mem)
{
	mem_block *block = CONTAINING_RECORD(mem, mem_block, data);

	if (block->list != 0) {
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
			&mem_lists[num], NULL, NULL, 0, len + sizeof(mem_block) + MEM_ADD, '2_cd', 0);
	}
}

void fastmem_free()
{
	u32 num;

	for (num = 0; num < NUM_MEM_LISTS; num++) {
		ExDeleteNPagedLookasideList(&mem_lists[num]);
	}
}