/*
    *
    * DiskCryptor - open source partition encryption tool
	* Copyright (c) 2007-2008
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
#include <stdio.h>
#include "drvinst.h"
#include "defines.h"
#include "dcres.h"
#include "misc.h"
#include "drv_ioctl.h"
#include "dcapi.h"

static wchar_t drv_dc[ ]  = L"dcrypt";
static wchar_t drv_fsf[ ] = L"dc_fsf";
static wchar_t vol_key[ ] = L"SYSTEM\\CurrentControlSet\\Control\\Class\\{71A27CDD-812A-11D0-BEC7-08002BE2092F}";
static wchar_t cdr_key[ ] = L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E965-E325-11CE-BFC1-08002BE10318}";

static wchar_t reg_srv[ ] = L"SYSTEM\\CurrentControlSet\\Services\\dcrypt\\config";
static wchar_t lwf_str[ ] = L"LowerFilters";
static wchar_t upf_str[ ] = L"UpperFilters";

int dc_load_conf(dc_conf_data *conf)
{
	dc_conf d_conf;
	HKEY    h_key = NULL;
	int     resl;
	u32     cb;

	do
	{
		if (RegOpenKey(HKEY_LOCAL_MACHINE, reg_srv, &h_key) != 0) {			
			resl = ST_REG_ERROR; break;
		}

		cb = sizeof(conf->conf_flags);

		if (RegQueryValueEx(h_key, L"Flags", NULL, NULL, pv(&conf->conf_flags), &cb) != 0) {			
			conf->conf_flags = 0;
		}

		cb = sizeof(conf->build);

		if (RegQueryValueEx(h_key, L"sysBuild", NULL, NULL, pv(&conf->build), &cb) != 0) {			
			conf->build = 0;
		}

		cb = sizeof(conf->hotkeys);

		if (RegQueryValueEx(h_key, L"Hotkeys", NULL, NULL, pv(&conf->hotkeys), &cb) != 0) {
			memset(&conf->hotkeys, 0, sizeof(conf->hotkeys));
		}

		if (dc_get_conf_flags(&d_conf) == ST_OK) {
			conf->load_flags = d_conf.load_flags;
		} else {
			conf->load_flags = 0;
		}

		resl = ST_OK;
	} while (0);

	if (h_key != NULL) {
		RegCloseKey(h_key);
	}

	return resl;
}

int dc_save_conf(dc_conf_data *conf)
{
	dc_conf d_conf;
	HKEY    h_key = NULL;
	u32     build = DC_DRIVER_VER;
	int     resl;

	do
	{
		if (RegCreateKey(HKEY_LOCAL_MACHINE, reg_srv, &h_key) != 0) {
			resl = ST_REG_ERROR; break;
		}

		if (RegSetValueEx(h_key, L"Flags", 0, REG_DWORD, pv(&conf->conf_flags), sizeof(conf->conf_flags)) != 0) {
			resl = ST_REG_ERROR; break;
		}

		if (RegSetValueEx(h_key, L"Hotkeys", 0, REG_BINARY, pv(&conf->hotkeys), sizeof(conf->hotkeys)) != 0) {
			resl = ST_REG_ERROR; break;
		}
		
		if (RegSetValueEx(h_key, L"sysBuild", 0, REG_DWORD, pv(&build), sizeof(build)) != 0) {
			resl = ST_REG_ERROR; break;
		}

		RegFlushKey(h_key);

		d_conf.conf_flags = conf->conf_flags;
		d_conf.load_flags = conf->load_flags;

		dc_set_conf_flags(&d_conf);

		resl = ST_OK;
	} while (0);

	if (h_key != NULL) {
		RegCloseKey(h_key);
	}

	return resl;
}



static int rmv_from_val(HKEY h_key, wchar_t *v_name, wchar_t *name)
{
	wchar_t  buf1[MAX_PATH];
	wchar_t *p;
	u32      cb, len;
	int      succs = 0;

	do
	{
		cb = sizeof(buf1); p = buf1;

		if (RegQueryValueEx(h_key, v_name, NULL, NULL, p8(buf1), &cb) != 0)  {
			break;
		}

		while (*p != 0)
		{
			len = (u32)(wcslen(p) * sizeof(wchar_t));

			if (wcscmp(p, name) == 0) 
			{
				memmove(p, p8(p) + len + sizeof(wchar_t), cb - (p - buf1) - len);
				cb -= len + sizeof(wchar_t);

				if ( (cb == 0) || (buf1[0] == 0) ) {
					cb = 0; break;
				}				
			} else {
				p = addof(p, len + sizeof(wchar_t));
			}
		}
		if (cb != 0) {
			succs = RegSetValueEx(h_key, v_name, 0, REG_MULTI_SZ, p8(buf1), cb) == 0;
		} else {
			succs = RegDeleteValue(h_key, v_name) == 0;
		}
	} while (0);

	return succs;
}

static int set_to_val(HKEY h_key, wchar_t *v_name, wchar_t *name)
{
	wchar_t  buf[MAX_PATH];
	u32      len, cb;
	wchar_t *p;
	
	len = (u32)((wcslen(name) + 1) * sizeof(wchar_t));
	cb  = sizeof(buf); p = buf;

	if (RegQueryValueEx(h_key, v_name, NULL, NULL, p8(buf), &cb) != 0) {
		buf[0] = 0; cb = sizeof(wchar_t);
	}

	while (*p != 0) 
	{
		if (wcscmp(p, name) == 0) {
			p = NULL; break;
		} else {
			p = addof(p, (wcslen(p) * sizeof(wchar_t)) + sizeof(wchar_t));
		}
	}
	if (p == NULL) { return 1; }

	memmove(p8(buf) + len, buf, cb);
	mincpy(buf, name, len);
	cb += len;

	return RegSetValueEx(h_key, v_name, 0, REG_MULTI_SZ, p8(buf), cb) == 0;
}

static void dc_get_driver_path(wchar_t *path, wchar_t *d_name)
{
	wchar_t tmpb[MAX_PATH];

	GetSystemDirectory(tmpb, countof(tmpb));

	_snwprintf(
		path, MAX_PATH, L"%s\\drivers\\%s.sys", tmpb, d_name);
}



static int dc_save_drv_file(wchar_t *d_name)
{
	wchar_t dest[MAX_PATH];
	wchar_t path[MAX_PATH];
	wchar_t srcf[MAX_PATH];
	int     resl;

	do
	{
		dc_get_driver_path(dest, d_name);

		if (dc_get_prog_path(path, countof(path) - 10) == 0) {
			resl = ST_ERROR; break;
		}

		_snwprintf(
			srcf, MAX_PATH, L"%s\\%s.sys", path, d_name);

		if (CopyFile(srcf, dest, FALSE) != 0) {
			resl = ST_OK;
		} else {
			resl = ST_ACCESS_DENIED;
		}
	} while (0);

	return resl;
}

static int dc_remove_service(wchar_t *name)
{
	SC_HANDLE h_scm = NULL;
	SC_HANDLE h_svc = NULL;
	int       resl;

	do
	{
		if ( (h_scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS)) == NULL ) {
			resl = ST_SCM_ERROR; break;
		}

		if (h_svc = OpenService(h_scm, name, SERVICE_ALL_ACCESS)) {			
			DeleteService(h_svc);
			CloseServiceHandle(h_svc);
		}
		resl = ST_OK;
	} while (0);

	if (h_scm != NULL) {
		CloseServiceHandle(h_scm);
	}
	return resl;
}

static int dc_remove_filter(wchar_t *key, wchar_t *name)
{
	HKEY h_key;
	int  resl;

	if (RegOpenKey(HKEY_LOCAL_MACHINE, key, &h_key) == 0) 
	{
		if ( (rmv_from_val(h_key, lwf_str, name) == 0) && 
			 (rmv_from_val(h_key, upf_str, name) == 0) ) 
		{
			resl = ST_ERROR;
		} else { resl = ST_OK; }		
		RegCloseKey(h_key);
	} else { resl = ST_REG_ERROR; }

	return resl;
}

static int dc_add_filter(wchar_t *key, wchar_t *name, int upper)
{
	HKEY h_key;
	int  resl;
	int  succs;

	if (RegOpenKey(HKEY_LOCAL_MACHINE, key, &h_key) == 0)
	{
		if (upper != 0) {
			succs = set_to_val(h_key, upf_str, name);
		} else {
			succs = set_to_val(h_key, lwf_str, name);
		}
		resl = (succs != 0) ? ST_OK : ST_REG_ERROR;
		RegCloseKey(h_key);
	} else { resl = ST_REG_ERROR; }

	return resl;
}

int dc_remove_driver()
{
	wchar_t buf[MAX_PATH];
	int     succs = 1;

	do 
	{
		/* remove Volume class filter */
		succs &= (dc_remove_filter(vol_key, drv_dc) == ST_OK);
		/* remove CDROM class filter */
		dc_remove_filter(cdr_key, drv_dc);

		/* delete drivers file */
		dc_get_driver_path(buf, drv_dc);
		DeleteFile(buf);

		/* remove service */
		succs &= (dc_remove_service(drv_dc) == ST_OK);		
	} while(0);

	return (succs != 0) ? ST_OK : ST_ERROR;
}

static int dc_add_service(wchar_t *name, u32 type)
{
	wchar_t   buf[MAX_PATH];
	SC_HANDLE h_scm = NULL;
	SC_HANDLE h_svc = NULL;
	int       resl;

	do
	{
		if ( (h_scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS)) == NULL ) {
			resl = ST_SCM_ERROR; break;
		}

		dc_get_driver_path(buf, name);

		h_svc = CreateService(
			h_scm, name, NULL, SERVICE_ALL_ACCESS, type, SERVICE_BOOT_START, 
			SERVICE_ERROR_CRITICAL, buf, L"Filter", NULL, L"FltMgr", NULL, NULL);

		if (h_svc == NULL) {
			resl = ST_SCM_ERROR;
		} else {
			resl = ST_OK;
		}
	} while (0);

	if (h_svc != NULL) {
		CloseServiceHandle(h_svc);
	}

	if (h_scm != NULL) {
		CloseServiceHandle(h_scm);
	}
	return resl;
}

static int dc_add_altitude()
{
	HKEY hkey1 = NULL;
	HKEY hkey2 = NULL;
	int  succs = 0;
	u32  flags = 0;

	if (RegCreateKey(
		HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\dcrypt\\Instances", &hkey1) != 0) 
	{
		goto exit;
	}
	if (RegSetValueEx(hkey1, L"DefaultInstance", 0, REG_SZ, pv(L"dcrypt"), sizeof(L"dcrypt")) != 0) {
		goto exit;
	}
	if (RegCreateKey(hkey1, L"dcrypt", &hkey2) != 0) {
		goto exit;
	}
	if (RegSetValueEx(hkey2, L"Altitude", 0, REG_SZ, pv(L"87150"), sizeof(L"87150")) != 0) {
		goto exit;
	}
	succs = RegSetValueEx(hkey2, L"Flags", 0, REG_DWORD, pv(&flags), sizeof(flags)) == 0;

	if (hkey2 != NULL) RegCloseKey(hkey2);
	if (hkey1 != NULL) RegCloseKey(hkey1);
exit:
	return succs != 0 ? ST_OK : ST_REG_ERROR;
}

int dc_install_driver()
{
	dc_conf_data conf;
	int          resl;
	
	do 
	{
		if ( (resl = dc_save_drv_file(drv_dc)) != ST_OK ) {
			break;
		}
		if ( (resl = dc_add_service(drv_dc, SERVICE_KERNEL_DRIVER)) != ST_OK ) {
			break;
		}
		/* add Volume class filter */
		if ( (resl = dc_add_filter(vol_key, drv_dc, 0)) != ST_OK ) {
			break;
		}
		/* add Altitude */
		if ( (resl = dc_add_altitude()) != ST_OK ) {
			break;
		}
		/* add CDROM class filter */
		dc_add_filter(cdr_key, drv_dc, 1);
		/* setup default config */
		memset(&conf, 0, sizeof(conf));
		conf.conf_flags = CONF_HW_CRYPTO | CONF_AUTOMOUNT_BOOT | CONF_ENABLE_SSD_OPT;
		
		resl = dc_save_conf(&conf);
	} while (0);

	if (resl != ST_OK) {
		dc_remove_driver();
	}

	return resl;
}

int dc_driver_status()
{
	wchar_t path[MAX_PATH];
	HANDLE  h_device;

	dc_get_driver_path(path, drv_dc);
	
	if (GetFileAttributes(path) != INVALID_FILE_ATTRIBUTES) 
	{
		h_device = CreateFile(
			DC_WIN32_NAME, 0, 0, NULL, OPEN_EXISTING, 0, NULL);

		if (h_device != INVALID_HANDLE_VALUE) {
			CloseHandle(h_device);
			return ST_OK;
		} else {
			return ST_INSTALLED;
		}
	} else {
		return ST_ERROR;
	}	
}

int dc_update_driver()
{
	wchar_t      buff[MAX_PATH];
	dc_conf_data conf;
	int          resl;

	do
	{
		if ( (resl = dc_save_drv_file(drv_dc)) != ST_OK ) {
			break;
		}
		if ( (resl = dc_load_conf(&conf)) != ST_OK ) {
			break;
		}
		if (conf.build < 692) 
		{
			/* remove old file system filter driver */
			if (dc_remove_service(drv_fsf) == ST_OK)
			{
				dc_get_driver_path(buff, drv_fsf);
				DeleteFile(buff);
			}
			/* add Altitude */
			if ( (resl = dc_add_altitude()) != ST_OK ) {
				break;
			}
		}
		if (conf.build < 366)
		{
			/* add CDROM class filter */
			dc_add_filter(cdr_key, drv_dc, 1);
			/* set new default flags */
			conf.conf_flags |= CONF_HW_CRYPTO | CONF_AUTOMOUNT_BOOT;
		}
		if (conf.build < 642) {
			conf.conf_flags |= CONF_ENABLE_SSD_OPT;
		}
		resl = dc_save_conf(&conf);
	} while (0);

	if (resl == ST_OK) 
	{
		_snwprintf(
			buff, countof(buff), L"DC_UPD_%d", dc_get_version());

		GlobalAddAtom(buff);			
	}
	return resl;
}
