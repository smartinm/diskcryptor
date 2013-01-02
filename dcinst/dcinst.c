/*  *
    * DiskCryptor - open source partition encryption tool
	* Copyright (c) 2009 
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
#include <windows.h>
#include "defines.h"
#include "drv_ioctl.h"
#include "drvinst.h"
#include "mbrinst.h"

/*
    -setup  - install or update driver (update bootloader when needed)
	-unins  - uninstall driver
	-unldr  - uninstall bootloader
	-isenc  - check for boot device encryption
	-isboot - check for bootloader on boot device
*/

int WINAPI wWinMain(
		HINSTANCE hinst,
		HINSTANCE hprev,
		LPWSTR    cmd_line,
		int       cmd_show
		)
{
	int d_st;
	int resl;

	if (dc_is_old_runned() != 0) {
		return ST_INCOMPATIBLE;
	}

	/* open DC driver device */
	dc_open_device();
	/* get DC sriver status */
	d_st = dc_driver_status();
	resl = ST_ERROR;

	do
	{
		if (wcscmp(cmd_line, L"-setup") == 0)
		{
			if (d_st == ST_ERROR) {
				resl = dc_install_driver(NULL);
			} else
			{
				resl = dc_update_boot(-1);

				if ( (resl != ST_OK) && (resl != ST_BLDR_NOTINST) ) {
					break;
				}
				resl = dc_update_driver();
			}
			break;
		}

		if (wcscmp(cmd_line, L"-unins") == 0)
		{
			if (d_st == ST_ERROR) {
				resl = ST_ERROR; break;
			}
			resl = dc_remove_driver(); 
			break;
		}

		if (wcscmp(cmd_line, L"-unldr") == 0) {
			resl = dc_unset_mbr(-1);
			break;
		}

		if (wcscmp(cmd_line, L"-isboot") == 0) {
			ldr_config conf;
			resl = dc_get_mbr_config(-1, NULL, &conf);
			break;
		}		

		if (wcscmp(cmd_line, L"-isenc") == 0)
		{
			vol_inf info;
			u32     flags;
			wchar_t boot_dev[MAX_PATH];
			int     is_enc = 0;

			if (dc_open_device() != ST_OK) {
				resl = ST_ERROR; break;
			}

			if (dc_get_boot_device(boot_dev) != ST_OK) {
				boot_dev[0] = 0;
			}
	
			if (dc_first_volume(&info) == ST_OK)
			{
				do
				{
					flags = info.status.flags;

					if ( ((flags & F_SYSTEM) || 
						  (wcscmp(info.device, boot_dev) == 0)) && (flags & F_ENABLED) )
					{
						is_enc = 1;
					}
				} while (dc_next_volume(&info) == ST_OK);
			}

			dc_close_device();
			resl = is_enc != 0 ? ST_ENCRYPTED : ST_OK; break;
		}
	} while (0);

	return resl;
}