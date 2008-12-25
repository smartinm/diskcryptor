/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2008 
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
#include "driver.h"
#include "defines.h"
#include "..\boot\boot.h"
#include "boot_pass.h"
#include "mount.h"
#include "debug.h"


static void *find_8b(u8 *data, int size, u32 s1, u32 s2)
{
	void *find = NULL;
	int   i;

	for (i = 0; i < size - 8; i++) {
		if ( (p32(data + i)[0] == s1) && (p32(data + i)[1] == s2) ) {
			find = data + i;
			break;
		}
	}

	return find;
}

static void dc_zero_boot(u32 bd_base, u32 bd_size)
{
	PHYSICAL_ADDRESS addr;
	void            *mem;
	
	/* map bootloader body */
	addr.HighPart = 0;
	addr.LowPart  = bd_base;

	if (mem = MmMapIoSpace(addr, bd_size, MmCached)) 
	{
		/* zero bootloader body */
		zeromem(mem, bd_size);
		MmUnmapIoSpace(mem, bd_size);
	}
}

static void dc_restore_ints(bd_data *bdb)
{
	PHYSICAL_ADDRESS addr;
	void            *mem;

	DbgMsg("dc_restore_ints\n");

	/* map realmode interrupts table */
	addr.HighPart = 0;
	addr.LowPart  = 0;

	if (mem = MmMapIoSpace(addr, 0x1000, MmCached)) 
	{
		if (bdb->old_int13 != 0) {
			p32(mem)[0x13] = bdb->old_int13;
			p32(mem)[0x15] = bdb->old_int15;
		}	
		
		MmUnmapIoSpace(mem, 0x1000);
	}
}

void dc_get_boot_pass()
{
	PHYSICAL_ADDRESS addr;
	u8              *bmem;
	bd_data         *bdb;

	/* scan memory in range 500-640k */
	addr.QuadPart = 500 * 1024; bdb = NULL;
	do
	{
		if (bmem = MmMapIoSpace(addr, PAGE_SIZE, MmCached))
		{
			/* find boot data block */
			bdb = find_8b(
				bmem, PAGE_SIZE - sizeof(bd_data), 0x01F53F55, 0x9E4361E4);

			if (bdb != NULL) 
			{
				/* restore realmode interrupts */
				dc_restore_ints(bdb);
				/* add password to cache */
				dc_add_password(&bdb->password);				
				/* zero bootloader body */
				dc_zero_boot(bdb->bd_base, bdb->bd_size);
			}

			MmUnmapIoSpace(bmem, PAGE_SIZE);
		}
		addr.LowPart += PAGE_SIZE;
	} while ( (addr.LowPart < (640 * 1024)) && (bdb == NULL) );
}
