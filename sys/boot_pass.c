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

static void dc_load_boot_pass(rb_data *rbd)
{
	PHYSICAL_ADDRESS addr;
	u32              pm_base;
	u32              pm_size;
	void            *emem;
	ldr_config      *conf;	
	
	emem = NULL;
	do
	{
		/* get bootloader body offset and size */
		pm_base = rbd->pm_base;
		pm_size = rbd->pm_size;			

		/* map bootloader body */
		addr.HighPart = 0;
		addr.LowPart  = pm_base;
		if ( (emem = MmMapIoSpace(addr, pm_size, MmCached)) == NULL ) {
			break;
		}

		/* find configuration area */
		if ( (conf = find_8b(emem, pm_size, 0x1434A669, 0x7269DA46)) == NULL ) {
			break;
		}

		/* add password to cache */
		if (conf->pass_buf[0] != 0) {
			dc_add_password(conf->pass_buf);				
		}

		/* zero bootloader body */
		zeromem(emem, pm_size);
	} while (0);

	if (emem != NULL) {
		MmUnmapIoSpace(emem, pm_size);
	}
}

void dc_get_boot_pass()
{
	PHYSICAL_ADDRESS addr;
	u8              *bmem;
	u32              rbm;
	int              rbs;
	rb_data         *rbd;
	
	bmem = NULL;
	do
	{
		/* map base memory */
		addr.QuadPart = 0;
		
		if ( (bmem = MmMapIoSpace(addr, BMEM_SIZE, MmCached)) == NULL ) {
			break;
		}

		rbm = 0; rbs = BMEM_SIZE;
		do
		{
			/* find real mode block */
			if (rbd = find_8b(bmem + rbm, rbs, 0x01F53F55, 0x9E4361E4))
			{
				rbm = rbd->rb_base + rbd->rb_size;
				rbs = BMEM_SIZE - rbm;

				dc_load_boot_pass(rbd);
			}
		} while ( (rbd != NULL) && (rbs > sizeof(rb_data)) );
	} while (0);

	if (bmem != NULL) {
		MmUnmapIoSpace(bmem, BMEM_SIZE);
	}
}