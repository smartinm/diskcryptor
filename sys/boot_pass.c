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

#define BMEM_SIZE (640 * 1024) /* base memory size is 640 kbytes */

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

static void dc_zero_boot(u32 pm_base, u32 pm_size)
{
	PHYSICAL_ADDRESS addr;
	void            *emem;
	ldr_config      *conf;
	
	/* map bootloader body */
	addr.HighPart = 0;
	addr.LowPart  = pm_base;

	if (emem = MmMapIoSpace(addr, pm_size, MmCached))
	{
		/* find configuration area */
		if (conf = find_8b(emem, pm_size, 0x1434A669, 0x7269DA46))
		{
			/* add legacy bootloader password to cache */
			dc_add_password(conf->pass_buf);

			/* zero bootloader body */
			zeromem(emem, pm_size);
		}

		MmUnmapIoSpace(emem, pm_size);
	}
}

static void dc_scan_page(u8 *base)
{
	rb_data   *rbd;
	rb_legacy *rbd_l;
	u32        rbm, rbs;	
	u32        pm_base, pm_size;

	rbm = 0; rbs = PAGE_SIZE;
	do
	{
		/* find real mode block */
		if (rbd = find_8b(base + rbm, rbs, 0x01F53F55, 0x9E4361E4))
		{
			if (rbd->sign3 == 0x13B3F73D) 
			{
				/* add password to cache */
				dc_add_password(rbd->info.password);

				/* update pointers */
				rbm    += min(rbd->rb_size, PAGE_SIZE);
				pm_base = rbd->pm_base;
				pm_size = rbd->pm_size;

				/* zero real mode block */
				zeroauto(rbd, sizeof(rb_data));
			} else 
			{
				rbd_l = pv(rbd);
				/* update pointers */
				rbm    += min(rbd_l->rb_size, PAGE_SIZE);
				pm_base = rbd_l->pm_base;
				pm_size = rbd_l->pm_size;
			}
			rbs = PAGE_SIZE - rbm;

			/* zero bootloader body */
			if (pm_base != 0) {
				dc_zero_boot(pm_base, pm_size);
			}
		}
	} while ( (rbd != NULL) && (rbs > sizeof(rb_data)) );
}

void dc_get_boot_pass()
{
	PHYSICAL_ADDRESS addr;
	u8              *bmem;
	int              kbs;

	kbs = 640; addr.QuadPart = 0;
	
	do
	{
		if (bmem = MmMapIoSpace(addr, PAGE_SIZE, MmCached))
		{
			dc_scan_page(bmem);

			MmUnmapIoSpace(bmem, PAGE_SIZE);
		}

		addr.LowPart += PAGE_SIZE, kbs -= 4;
	} while (kbs != 0);	
}