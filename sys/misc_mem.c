/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2009
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
#include "misc_mem.h"
#include "misc.h"

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

