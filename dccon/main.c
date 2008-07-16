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
#include <windows.h>
#include <stdio.h>
#include <conio.h>
#include "defines.h"
#include "..\sys\driver.h"
#include "misc.h"
#include "mbrinst.h"
#include "drv_ioctl.h"
#include "drvinst.h"
#include "shrink.h"
#include "rand.h"
#include "boot_menu.h"
#include "..\boot\boot.h"
#include "main.h"
#include "version.h"



       vol_inf volumes[MAX_VOLUMES];
       u32     vol_cnt;
static int     rng_inited;

static void print_usage()
{
	wprintf(
		L"dccon [-key] [params]\n\n"
		L"  key:\n"
		L"   -version                      display DiskCryptor version\n"
		L"   -install                      install DiskCryptor driver\n"
		L"   -remove                       uninstall DiskCryptor driver\n"
		L"   -update                       update DiskCryptor driver\n"
		L"   -enum                         enum all volume devices in system\n"
		L"   -mount   [device]             mount encrypted device\n"		
		L"   -mountall                     mount all encrypted devices\n"
		L"   -unmount [device] [-f]        unmount encrypted device\n"
		L"      -f       force unmount with close all opened files\n"
		L"   -unmountall                   force unmount all devices\n"
		L"   -clean                        wipe cached passwords in memory\n"
		L"   -encrypt [device] [wipe mode] encrypt volume device\n"
		L"      -dod_e   US DoD 5220.22-M (8-306. / E)          (3 passes)\n"
		L"      -dod     US DoD 5220.22-M (8-306. / E, C and E) (7 passes)\n"
		L"      -gutmann Gutmann mode                           (35 passes)\n"
		L"   -decrypt [device]             decrypt volume device\n"
		L"   -chpass  [device]             change volume password\n"
		L"   -updvol  [device]             update volume to last volume format\n"
		L"   -speedtest                    test encryption speed\n"
		L"   -config                       change program configuration\n"
		L"   -bsod                         erase all keys in memory and generate BSOD\n"
		L"   -boot [action]\n"
		L"      -enum                      enumerate all HDDs\n"
		L"      -setmbr   [hdd]            setup bootloader to HDD master boot record\n"
		L"      -delmbr   [hdd]            delete bootloader from HDD master boot record\n"
		L"      -updmbr   [hdd]            update bootloader on HDD master boot record\n"
		L"      -setpar   [partition root] setup bootloader to bootable partition (Floppy, USB-Stick, etc)\n"
	    L"      -makeiso  [file]           make .iso bootloader image\n"
		L"      -makepxe  [file]           make bootloader image for PXE network booting\n"
		L"      -config   [hdd/file]       change bootloader configuration\n"
		);
}

void cls_console() 
{
	CONSOLE_SCREEN_BUFFER_INFO csbi;
	COORD                      pos;
	u32                        bytes;
	HANDLE                     console = GetStdHandle(STD_OUTPUT_HANDLE);

	GetConsoleScreenBufferInfo(console, &csbi);

	pos.X = 0; pos.Y = 0;
	FillConsoleOutputCharacter(
		console, ' ', csbi.dwSize.X * csbi.dwSize.Y, pos, &bytes
		);
	SetConsoleCursorPosition(console, pos); 
}

char getchr(char min, char max) 
{
	char ch;

	do
	{
		ch = _getch();
	} while ( (ch < min) || (ch > max) );

	return ch;
}



static void print_devices()
{
	wchar_t boot_dev[MAX_PATH];
	wchar_t stat[MAX_PATH];
	wchar_t size[MAX_PATH];
	u32     i, flags;

	if (dc_get_boot_device(boot_dev) != ST_OK) {
		boot_dev[0] = 0;
	}

	wprintf(
		L"------------------------------------------------------------------\n"
		L"volume |     mount point      |   size  |       status\n"
		L"-------+----------------------+---------+-------------------------\n"
		);

	for (i = 0; i < vol_cnt; i++)
	{
		flags = volumes[i].status.flags;
	
		dc_format_byte_size(
			size, sizeof_w(size), volumes[i].status.dsk_size
			);

		wcscpy(stat, L"unmounted");

		if (flags & F_ENABLED) {
			wcscpy(stat, L"mounted");
		}

		if (flags & F_UNSUPRT) {
			wcscpy(stat, L"unsupported");
		}

		if (wcscmp(volumes[i].device, boot_dev) == 0) {
			wcscat(stat, L", boot");
		}

		if (flags & F_SYSTEM) {
			wcscat(stat, L", system");
		}
		
		wprintf(
			L"pt%d    | %-20s | %-7s | %-23s\n"   ,     
			i, volumes[i].status.mnt_point, size, stat
			);
	}
}

static void enum_devices()
{
	vol_inf info;
	
	if (dc_first_volume(&info) == ST_OK)
	{
		do
		{
			volumes[vol_cnt++] = info;
		} while (dc_next_volume(&info) == ST_OK);
	}
}

static vol_inf *find_device(wchar_t *name)
{
	wchar_t w_name[MAX_PATH];
	u32     idx;

	wcscpy(w_name, name); _wcslwr(w_name);

	if ( (w_name[0] == L'p') && (w_name[1] == L't') && (isdigit(name[2]) != 0) )
	{
		if ( (idx = _wtoi(name+2)) < vol_cnt ) {
			return &volumes[idx];
		}
	} else 
	{
		if (w_name[1] == L':') {
			w_name[2] = 0;
		}

		for (idx = 0; idx < vol_cnt; idx++) 
		{
			if (_wcsicmp(w_name, volumes[idx].status.mnt_point) == 0) {
				return &volumes[idx];
			}
		}
	}

	return NULL;
}

static char* dc_getpass_loop()
{
	u8 *pass, ch;
	u32 pos;

	if ( (pass = secure_alloc(MAX_PASSWORD)) == NULL ) {
		return NULL;
	}

	for (pos = 0;;)
	{
		ch = _getch();

		if (ch == '\r') {
			break;
		}

		/* reseed RNG */
		if (rng_inited != 0) {
			rnd_reseed_now();
		}

		if (ch == 8)
		{
			if (pos > 0) {
				_putch(8);
				pos--;
			}
			_putch(' '); _putch(8);
			continue;
		}

		if ( (ch == 0) || (ch == 0xE0) ) {
			_getch();
		}

		if ( (ch < ' ') || (ch > '~') || (pos == MAX_PASSWORD) ) {
			continue;
		}

		pass[pos++] = ch; _putch('*');
	}

	if (pos != 0) {
		pass[pos] = 0;
	} else {
		secure_free(pass); pass = NULL;
	}

	_putch('\n');

	return pass;
}

char* dc_get_password(int confirm)
{
	char *pass1;
	char *pass2;

	if (pass1 = dc_getpass_loop())
	{
		if (confirm != 0) 
		{
			wprintf(L"Confirm password: ");

			pass2 = dc_getpass_loop();

			if ( (pass2 == NULL) || (strcmp(pass1, pass2) != 0) ) 
			{
				wprintf(L"The password was not correctly confirmed.\n");
				secure_free(pass1); pass1 = NULL;
			}

			if (pass2 != NULL) {
				secure_free(pass2);
			}
		}
	}

	return pass1;
}

static int dc_encrypt_loop(vol_inf *inf, int wp_mode)
{
	dc_status status;
	int       i = 0;
	wchar_t  *wp_str;
	char      ch;
	int       resl;

bgn_loop:;
	cls_console();

	switch (wp_mode)
	{
		case WP_NONE: wp_str = L"None"; break;
		case WP_DOD_E: wp_str = L"US DoD 5220.22-M (8-306. / E) (3 passes)"; break;
		case WP_DOD: wp_str = L"US DoD 5220.22-M (8-306. / E, C and E) (7 passes)"; break;
		case WP_GUTMANN: wp_str = L"Gutmann (35 passes)"; break;
	}
	
	wprintf(
		L"Encrypting progress...\n"
		L"Old data wipe mode: %s\n\n"
		L"Press ESC to cancel encrypting or press \"W\" to change wipe mode\n", wp_str
		);

	do
	{
		if (_kbhit() != 0)
		{
			if ( (ch = _getch()) == 0x1B )
			{
				wprintf(L"\nEncryption cancelled\n");
				dc_sync_enc_state(inf->device);
				break;
			}

			if (tolower(ch) == 'w')
			{
				wprintf(L"\n"
					L"1 - None (fastest)\n"
					L"2 - US DoD 5220.22-M (8-306. / E) (3 passes)\n"
					L"3 - US DoD 5220.22-M (8-306. / E, C and E) (7 passes)\n"
					L"4 - Gutmann (35 passes)\n"
					);

				switch (getchr('1', '4'))
				{
					case '1': wp_mode = WP_NONE; break;
					case '2': wp_mode = WP_DOD_E; break;
					case '3': wp_mode = WP_DOD; break;
					case '4': wp_mode = WP_GUTMANN; break;
				}

				goto bgn_loop;
			}
		}

		if (i-- == 0) {
			dc_sync_enc_state(inf->device); i = 20;
		}

		dc_get_device_status(
			inf->device, &status
			);

		wprintf(
			L"\r%-.3f %%", 
			(double)(status.tmp_size) / (double)(status.dsk_size) * 100
			);

		resl = dc_enc_step(inf->device, wp_mode);

		if (resl == ST_FINISHED) {
			wprintf(L"\nEncryption finished\n");
			break;
		}

		if ( (resl != ST_OK) && (resl != ST_RW_ERR) ) {
			wprintf(L"\nEncryption error %d\n", resl);
			break;
		}
	} while (1);

	return ST_OK;
}

static int dc_decrypt_loop(vol_inf *inf)
{
	dc_status status;
	int       i = 0;
	int       resl;

	cls_console();
	
	wprintf(
		L"Decrypting progress...\n"
		L"Press ESC to cancel decrypting\n"
		);

	do
	{
		if ( (_kbhit() != 0) && (_getch() == 0x1B) ) {
			wprintf(L"\nDecryption cancelled\n");
			dc_sync_enc_state(inf->device);
			break;
		}

		if (i-- == 0) {
			dc_sync_enc_state(inf->device); i = 20;					
		}

		dc_get_device_status(
			inf->device, &status
			);

		wprintf(
			L"\r%-.3f %%", 
			100 - ((double)(status.tmp_size) / (double)(status.dsk_size) * 100)
			);

		resl = dc_dec_step(inf->device);

		if (resl == ST_FINISHED) {
			wprintf(L"\nDecryption finished\n");
			break;
		}

		if ( (resl != ST_OK) && (resl != ST_RW_ERR) ) {
			wprintf(L"\nDecryption error %d\n", resl);
			break;
		}
	} while (1);

	return ST_OK;
}


int dc_set_boot_interactive(int d_num)
{
	ldr_config conf;
	int        resl;

	if ( (resl = dc_set_mbr(d_num, 0)) == ST_NF_SPACE )
	{
		wprintf(
			L"Not enough space after partitions to install bootloader.\n"
			L"Install bootloader to first HDD track (incompatible with third-party bootmanagers, like GRUB) Y/N?\n"
			);

		if (tolower(_getch()) == 'y') 
		{
			if ( ((resl = dc_set_mbr(d_num, 1)) == ST_OK) && 
				 (dc_get_mbr_config(d_num, NULL, &conf) == ST_OK) )
			{
				conf.boot_type = BT_ACTIVE;
						
				if ( (resl = dc_set_mbr_config(d_num, NULL, &conf)) != ST_OK ) {
					dc_unset_mbr(d_num);
				}
			}
		} 
	}

	return resl;
}

static 
int dc_shrink_callback(
	  int stage, vol_inf *inf, wchar_t *file, int status
	  )
{
	if (stage == SHRINK_BEGIN) 
	{
		wprintf(
			L"Last two sectors on volume %s are used\n"
			L"Shrinking volume... (press ESC to cancel)\n",
			(inf->status.mnt_point[0] == 0) ? inf->device : inf->status.mnt_point
			);
	}

	if (stage == SHRINK_STEP)
	{
		if ( (_kbhit() != 0) && (_getch() == 0x1B) ) {
			return ST_ERROR;
		}
	}

	if (stage == SHRINK_END)
	{
		if (status == ST_OK) {
			wprintf(L"Volume shrinked successfully\n");
		} else {
			wprintf(L"Volume not shrinked, error %d\n", status);
		}
	}

	return ST_OK;
}

int wmain(int argc, wchar_t *argv[])
{
	vol_inf *inf;
	int      resl;
	int      status;
	int      vers;
	int      d_inited;

	do
	{
#ifdef _M_IX86 
		if (is_wow64() != 0) {
			wprintf(L"Please use x64 version of DiskCryptor\n");
			resl = ST_ERROR; break;
		}
#endif
		if (is_admin() != ST_OK) {
			wprintf(L"Administrator privilegies required\n");
			resl = ST_NO_ADMIN; break;
		}

		if (argc < 2) {
			print_usage();
			resl = ST_OK; break;
		}

		/* get driver load status */
		status   = dc_driver_status();
		d_inited = 0;

		if ( (status == ST_OK) && (dc_open_device() == ST_OK) )
		{
			if ((vers = dc_get_version()) == DC_DRIVER_VER) {
				/* get information of all volumes in system */
				enum_devices(); d_inited = 1;
			}
		}

		if ( (argc == 2) && (wcscmp(argv[1], L"-version") == 0) ) 
		{
			wprintf(L"DiskCryptor %s console\n", DC_FILE_VER);
			resl = ST_OK; break;
		}		

		if ( (argc == 2) && (wcscmp(argv[1], L"-install") == 0) ) 
		{
			if (status != ST_ERROR) 
			{
				wprintf(L"DiskCryptor driver already installed\n");

				if (status != ST_OK) {
					wprintf(L"Please reboot you system\n");
				}
				resl = ST_OK; break;
			}

			if ( (resl = dc_install_driver(NULL)) == ST_OK ) {
				wprintf(L"DiskCryptor driver installed, please reboot you system\n");
			}
			break;
		}

		if ( (argc == 2) && (wcscmp(argv[1], L"-remove") == 0) ) 
		{
			if (status == ST_ERROR) {
				wprintf(L"DiskCryptor driver not installed\n");
				resl = ST_OK; break;
			}

			if ( (resl = dc_remove_driver(NULL)) == ST_OK ) {
				wprintf(L"DiskCryptor driver uninstalled, please reboot you system\n");				
			}
			break;
		}

		if ( (argc == 2) && (wcscmp(argv[1], L"-update") == 0) ) 
		{
			if (status == ST_ERROR) {
				wprintf(L"DiskCryptor driver not installed\n");
				resl = ST_ERROR; break;
			}

			if ( (resl = dc_update_boot(-1)) == ST_OK ) {
				wprintf(L"DiskCryptor bootloader updated\n");
			} else if (resl != ST_BLDR_NOTINST) {
				wprintf(L"Bootloader update error, please update it manually\n");
				break;
			}

			if ( (resl = dc_update_driver()) == ST_OK ) {
				wprintf(L"DiskCryptor driver updated, please reboot you system\n");				
			}
			break;			
		}

		if ( (argc >= 3) && (wcscmp(argv[1], L"-boot") == 0) ) 
		{
			resl = boot_menu(argc, argv);
			break;
		}	

		if (status != ST_OK) 
		{
			wprintf(
				L"DiskCryptor driver not installed.\n"
				L"please run \"dccon -install\" and reboot you system\n"
				);
			resl = ST_OK; break;
		}

		if (d_inited == 0)
		{
			if (vers > DC_DRIVER_VER) 
			{
				wprintf(
					L"DiskCryptor driver ver %d detected\n"
					L"Please use last program version\n", vers
					);
				resl = ST_OK; break;
			}

			if (vers < DC_DRIVER_VER)
			{
				wprintf(
					L"Old DiskCryptor driver detected\n"
					L"please run \"dccon -update\" and reboot you system\n"
					);
				resl = ST_OK; break;
			}

			resl = ST_ERROR; break;
		}

		/* initialize user mode RNG part */
		if ( (resl = rnd_init()) != ST_OK ) {
			break;
		}
		rng_inited = 1;

		if ( (argc == 2) && (wcscmp(argv[1], L"-enum") == 0) ) {
			print_devices();
			resl = ST_OK; break;
		}

		if ( (argc == 3) && (wcscmp(argv[1], L"-mount") == 0) ) 
		{
			char *pass;

			if ( (inf = find_device(argv[2])) == NULL ) {
				resl = ST_NF_DEVICE; break;
			}

			if (inf->status.flags & F_ENABLED) {
				wprintf(L"This device is already mounted\n");
				resl = ST_OK; break;
			}

			wprintf(L"Enter password: ");

			if ( (pass = dc_get_password(0)) == NULL ) {
				resl = ST_OK; break;
			}

			if ( (resl = dc_mount_volume(inf->device, pass)) == ST_OK ) {
				wprintf(L"device %s mounted\n", argv[2]);
			}

			secure_free(pass);
			break;
		}

		if ( (argc == 2) && (wcscmp(argv[1], L"-mountall") == 0) ) 
		{
			char *pass;
			int   n_mount;

			wprintf(L"Enter password: ");

			resl = dc_mount_all(
				pass = dc_get_password(0), &n_mount
				);

			if (resl == ST_OK) {
				wprintf(L"%d devices mounted\n", n_mount);
			}

			if (pass != NULL) {
				secure_free(pass);
			}
			break;
		}

		if ( (argc >= 3) && (wcscmp(argv[1], L"-unmount") == 0) )
		{
			int flags = 0;

			if ( (inf = find_device(argv[2])) == NULL ) {
				resl = ST_NF_DEVICE; break;
			}

			if ( (argc == 4) && (tolower(argv[3][1]) == 'f') ) {
				flags = UM_FORCE;
			}

			if ( !(inf->status.flags & F_ENABLED) ) {
				wprintf(L"This device is not mounted\n");
				resl = ST_OK; break;
			}

			resl = dc_unmount_volume(inf->device, flags);

			if (resl == ST_LOCK_ERR)
			{
				wprintf(
					L"This volume contain opened files.\n"
					L"Would you like to force a unmount on this volume? (Y/N)\n"
					);

				if (tolower(_getch()) == 'y') {
					resl = dc_unmount_volume(inf->device, UM_FORCE);
				}
			}

			if (resl == ST_OK) {
				wprintf(L"device %s unmounted\n", argv[2]);
			}
			break;
		}

		if ( (argc == 2) && (wcscmp(argv[1], L"-unmountall") == 0) ) 
		{
			resl = dc_unmount_all();

			if (resl == ST_OK) {
				wprintf(L"all devices unmounted\n");
			}
			break;
		}

		if ( (argc == 2) && (wcscmp(argv[1], L"-clean") == 0) ) 
		{
			resl = dc_clean_pass_cache();

			if (resl == ST_OK) {
				wprintf(L"passwords has been erased in memory\n");
			}
			break;
		}

		if ( (argc >= 3) && (wcscmp(argv[1], L"-encrypt") == 0) )
		{
			wchar_t   boot_dev[MAX_PATH];
			char     *pass;
			int       wp_mode;
			dc_status status;
			sh_data   shd;

			if ( (inf = find_device(argv[2])) == NULL ) {
				resl = ST_NF_DEVICE; break;
			}

			if ( (argc == 4) && (wcscmp(argv[3], L"-dod_e") == 0) ) {
				wp_mode = WP_DOD_E;
			} else if ( (argc == 4) && (wcscmp(argv[3], L"-dod") == 0) ) {
				wp_mode = WP_DOD;
			} else if ( (argc == 4) && (wcscmp(argv[3], L"-gutmann") == 0) ) {
				wp_mode = WP_GUTMANN;
			} else {
				wp_mode = WP_NONE;
			}

			if (inf->status.flags & F_SYNC) 
			{
				if (wp_mode == WP_NONE) 
				{
					dc_get_device_status(
						inf->device, &status
						);

					wp_mode = status.wp_mode;
				}

				resl = dc_encrypt_loop(inf, wp_mode);
				break;
			}

			if (inf->status.flags & F_ENABLED) {
				wprintf(L"This device is already encrypted\n");
				resl = ST_OK; break;
			}

			if (dc_get_boot_device(boot_dev) != ST_OK) {
				boot_dev[0] = 0;
			}

			if ( (inf->status.flags & F_SYSTEM) || (wcscmp(inf->device, boot_dev) == 0) )
			{
				ldr_config conf;
				int        b_dsk;
				
				if (dc_get_boot_disk(&b_dsk) != ST_OK)
				{
					wprintf(
						L"This partition needed for system booting and bootable HDD not found\n"
						L"You must be use external bootloader\n"
						L"Continue operation (Y/N)?\n\n"
						);

					if (tolower(_getch()) != 'y') {
						resl = ST_OK; break;
					}
				} else if (dc_get_mbr_config(b_dsk, NULL, &conf) != ST_OK)
				{
					wprintf(
						L"This partition needed for system booting\n"
						L"You must install bootloader to HDD, or use external bootloader\n\n"
						L"1 - Install to HDD\n"
						L"2 - I already have external bootloader\n"
						);

					if (getchr('1', '2') == '1') 
					{
						if ( (resl = dc_set_boot_interactive(b_dsk)) != ST_OK ) {
							break;
						}
					}
				}				
			}

			wprintf(L"Enter password: ");

			if ( (pass = dc_get_password(1)) == NULL ) {
				resl = ST_OK; break;
			}

			shd.sh_pend = (inf->status.flags & F_SYSTEM) != 0;
			shd.offset  = 0;
			shd.value   = 0;

			resl = dc_shrink_volume(
				inf->w32_device, HEADER_SIZE + DC_RESERVED_SIZE, dc_shrink_callback, inf, &shd
				);

			if (resl == ST_OK) 
			{
				resl = dc_start_encrypt(
					inf->device, pass, wp_mode
					);
			}

			secure_free(pass);

			if (resl == ST_OK ) 
			{
				if (shd.sh_pend != 0) {
					dc_set_shrink_pending(inf->device, &shd);
				}

				resl = dc_encrypt_loop(inf, wp_mode);
			}
			break;
		}

		if ( (argc == 3) && (wcscmp(argv[1], L"-decrypt") == 0) ) 
		{
			char *pass;

			if ( (inf = find_device(argv[2])) == NULL ) {
				resl = ST_NF_DEVICE; break;
			}

			if (inf->status.flags & F_SYNC) {
				resl = dc_decrypt_loop(inf);
				break;
			}

			if ( !(inf->status.flags & F_ENABLED) ) {
				wprintf(L"This device is not mounted\n");
				resl = ST_OK; break;
			}

			wprintf(L"Enter password: ");

			if ( (pass = dc_get_password(0)) == NULL ) {
				resl = ST_OK; break;
			}

			resl = dc_start_decrypt(inf->device, pass);

			secure_free(pass);

			if (resl == ST_OK ) {
				resl = dc_decrypt_loop(inf);
			}
			break;
		}

		if ( (argc == 3) && (wcscmp(argv[1], L"-chpass") == 0) ) 
		{
			char *old_p, *new_p;
			
			if ( (inf = find_device(argv[2])) == NULL ) {
				resl = ST_NF_DEVICE; break;
			}

			if ( !(inf->status.flags & F_ENABLED) ) {
				wprintf(L"This device is not mounted\n");
				resl = ST_OK; break;
			}

			old_p = NULL; new_p = NULL;
			do
			{
				wprintf(L"Enter old password: ");

				if ( (old_p = dc_get_password(0)) == NULL ) {
					resl = ST_OK; break;
				}

				wprintf(L"Enter new password: ");

				if ( (new_p = dc_get_password(1)) == NULL ) {
					resl = ST_OK; break;
				}

				resl = dc_change_password(
					inf->device, old_p, new_p
					);

				if (resl == ST_OK) {
					wprintf(L"The password successfully changed\n");
				}
			} while (0);

			if (old_p != NULL) {
				secure_free(old_p);
			}

			if (new_p != NULL) {
				secure_free(new_p);
			}
			break;
		}

		if ( (argc == 3) && (wcscmp(argv[1], L"-updvol") == 0) ) 
		{
			sh_data  shd;
			char    *pass;			

			if ( (inf = find_device(argv[2])) == NULL ) {
				resl = ST_NF_DEVICE; break;
			}

			if ( !(inf->status.flags & F_ENABLED) ) {
				wprintf(L"This device is not mounted\n");
				resl = ST_OK; break;
			}

			if (inf->status.vf_version >= TC_VOLUME_HEADER_VERSION) {
				wprintf(L"This partition has already updated\n");
				resl = ST_OK; break;
			}

			if (inf->status.flags & F_SYNC) {
				wprintf(L"Partial encrypted volume can not be updated\n");
				resl = ST_OK; break;
			}

			wprintf(L"Enter password: ");

			if ( (pass = dc_get_password(0)) == NULL ) {
				resl = ST_OK; break;
			}

			shd.sh_pend = (inf->status.flags & F_SYSTEM) != 0;
			shd.offset  = 0;
			shd.value   = 0;

			resl = dc_shrink_volume(
				inf->w32_device, HEADER_SIZE + DC_RESERVED_SIZE, dc_shrink_callback, inf, &shd
				);

			if (resl == ST_OK) {
				resl = dc_update_volume(inf->device, pass, &shd);
			}

			secure_free(pass);

			if (resl == ST_OK ) {
				wprintf(L"device %s updated\n", argv[2]);
			}
		}

		if ( (argc == 2) && (wcscmp(argv[1], L"-speedtest") == 0) ) 
		{
			speed_test test;
			double     enc, dec;

			if ( (resl = dc_speed_test(&test)) != ST_OK ) {
				break;
			}

			enc = test.data_size / ( (double)test.enc_time / (double)test.cpu_freq) / 1024 / 1024;
			dec = test.data_size / ( (double)test.dec_time / (double)test.cpu_freq) / 1024 / 1024;

			wprintf(
				L"Encryption speed - %f mb/s\n"
				L"Decryption speed - %f mb/s\n", enc, dec
				);
			break;
		}

		if ( (argc == 2) && (wcscmp(argv[1], L"-config") == 0) ) 
		{
			dc_conf_data dc_conf;

			if ( (resl = dc_load_conf(&dc_conf)) != ST_OK ) {
				break;
			}

			do
			{
				int  onoff;
				char ch;

				cls_console();

				wprintf(
					L"1 - On/Off passwords caching (%s)\n"
					L"2 - On/Off advanced io queue (%s)\n"
					L"3 - Save changes and exit\n\n",
					on_off(dc_conf.conf_flags & CONF_CACHE_PASSWORD),
					on_off(dc_conf.conf_flags & CONF_QUEUE_IO)
					);

				if ( (ch = getchr('1', '3')) == '3' ) {
					break;
				}

				wprintf(L"0 - OFF\n1 - ON\n");
				onoff = (getchr('0', '1') == '1');

				if (ch == '1') {
					set_flag(dc_conf.conf_flags, CONF_CACHE_PASSWORD, onoff);
				} else {
					set_flag(dc_conf.conf_flags, CONF_QUEUE_IO, onoff);
				}
			} while (1);

			if ( (resl = dc_save_conf(&dc_conf)) == ST_OK ) {
				wprintf(L"Configuration successfully saved\n");
			}
		}	

		if ( (argc == 2) && (wcscmp(argv[1], L"-bsod") == 0) ) 
		{
			dc_get_bsod(); resl = ST_OK;
			break;
		}
	} while (0);

	if (resl != ST_OK) {
		wprintf(L"Error: %d\n", resl);
	}

	return resl;
}
