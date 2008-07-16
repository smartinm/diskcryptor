/*
    *
    * DiskCryptor - open source partition encryption tool
	* Copyright (c) 2007-2008
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
#include "drvinst.h"
#include "defines.h"
#include "dcres.h"
#include "misc.h"
#include "drv_ioctl.h"
#include "dcapi.h"

static wchar_t drv_name[] = L"dcrypt";
static wchar_t reg_key[] = L"SYSTEM\\CurrentControlSet\\Control\\Class\\{71A27CDD-812A-11D0-BEC7-08002BE2092F}";
static wchar_t reg_srv[] = L"SYSTEM\\CurrentControlSet\\Services";
static wchar_t cnf_key[] = L"{9571C5B6-340C-4554-8FD9-2DA33629038D}";
static wchar_t upf_str[] = L"UpperFilters";
static wchar_t lwf_str[] = L"LowerFilters";

static int dc_get_old_drv_name(wchar_t *name, int n_max)
{
	HKEY    svc_key = NULL;	
	wchar_t path[MAX_PATH];
	int     resl, idx = 0;
	HKEY    h_key;

	do
	{
		if (RegOpenKey(HKEY_LOCAL_MACHINE, reg_srv, &svc_key) != 0) {
			resl = ST_REG_ERROR; break;
		}

		resl = ST_NF_REG_KEY;

		while (RegEnumKey(svc_key, idx++, name, n_max) == 0)
		{
			_snwprintf(
				path, sizeof_w(path), L"%s\\%s", name, cnf_key
				);

			if (RegOpenKey(svc_key, path, &h_key) == 0) {
				RegCloseKey(h_key);
				resl = ST_OK; break;
			}
		}
	} while (0);

	if (svc_key != NULL) {
		RegCloseKey(svc_key);
	}

	return resl;
}

int dc_load_conf(dc_conf_data *conf)
{
	wchar_t name[MAX_PATH];
	wchar_t path[MAX_PATH];
	dc_conf d_conf;
	HKEY    h_key = NULL;
	int     resl;
	u32     cb;

	/* get config registry key */
	if (dc_get_old_drv_name(name, sizeof_w(name)) == ST_OK) 
	{
		_snwprintf(
			path, sizeof_w(path), L"%s\\%s\\%s", reg_srv, name, cnf_key
			);
	} else 
	{
		_snwprintf(
			path, sizeof_w(path), L"%s\\%s", reg_srv, drv_name
			);
	}

	do
	{
		if (RegOpenKey(HKEY_LOCAL_MACHINE, path, &h_key) != 0) {			
			resl = ST_REG_ERROR; break;
		}

		cb = sizeof(conf->conf_flags);

		if (RegQueryValueEx(h_key, L"Flags", NULL, NULL, pv(&conf->conf_flags), &cb) != 0) {			
			conf->conf_flags = 0;
		}

		cb = sizeof(conf->hotkeys);

		if (RegQueryValueEx(h_key, L"Hotkeys", NULL, NULL, pv(&conf->hotkeys), &cb) != 0) {
			zeromem(&conf->hotkeys, sizeof(conf->hotkeys));
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
	wchar_t path[MAX_PATH];
	dc_conf d_conf;
	HKEY    h_key = NULL;
	int     resl;

	do
	{
		_snwprintf(
			path, sizeof(path), L"%s\\%s", reg_srv, drv_name
			);

		if (RegOpenKey(HKEY_LOCAL_MACHINE, path, &h_key) != 0) {
			resl = ST_REG_ERROR; break;
		}

		if (RegSetValueEx(h_key, L"Flags", 0, REG_DWORD, pv(&conf->conf_flags), sizeof(conf->conf_flags)) != 0) {
			resl = ST_REG_ERROR; break;
		}

		if (RegSetValueEx(h_key, L"Hotkeys", 0, REG_BINARY, pv(&conf->hotkeys), sizeof(conf->hotkeys)) != 0) {
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

		for (; *p; p = addof(p, len + sizeof(wchar_t)))
		{
			len = (u32)(wcslen(p) * sizeof(wchar_t));

			if (wcscmp(p, name) == 0) 
			{
				memmove(p, p8(p) + len + sizeof(wchar_t), cb - (p - buf1) - len);
				cb -= len + sizeof(wchar_t);

				/* delete key if it clear */
				if ( (cb == 0) || (buf1[0] == 0) ) {
					succs = RegDeleteValue(h_key, v_name) == 0;
				} else 
				{
					succs = RegSetValueEx(
						h_key, v_name, 0, REG_MULTI_SZ, p8(buf1), cb
						) == 0;
				}
				break;
			}
		}
	} while (0);

	return succs;
}

static int set_to_val(HKEY h_key, wchar_t *v_name, wchar_t *name)
{
	wchar_t buf[MAX_PATH];
	u32     len, cb;
	
	len = (u32)((wcslen(name) + 1) * sizeof(wchar_t));
	cb = sizeof(buf);

	if (RegQueryValueEx(h_key, v_name, NULL, NULL, p8(buf), &cb) != 0) {
		buf[0] = 0; cb = sizeof(wchar_t);
	}

	memmove(p8(buf) + len, buf, cb);
	memcpy(buf, name, len);
	cb += len;

	return RegSetValueEx(h_key, v_name, 0, REG_MULTI_SZ, p8(buf), cb) == 0;
}

static void dc_get_driver_path(wchar_t *name, wchar_t *path)
{
	wchar_t tmpb[MAX_PATH];

	GetSystemDirectory(
		tmpb, sizeof_w(tmpb)
		);

	_snwprintf(
		path, MAX_PATH, L"%s\\drivers\\%s.sys", tmpb, name
		);
}


static int dc_save_drv_file(wchar_t *name)
{
	wchar_t dest[MAX_PATH];
	wchar_t path[MAX_PATH];
	int     resl;

	do
	{
		dc_get_driver_path(name, dest);

		if (dc_get_prog_path(path, sizeof_w(path) - 10) == 0) {
			resl = ST_ERROR; break;
		}

		wcscat(path, L"\\dcrypt.sys");

		if (CopyFile(path, dest, FALSE) != 0) {
			resl = ST_OK;
		} else {
			resl = ST_ACCESS_DENIED;
		}
	} while (0);

	return resl;
}

int dc_remove_driver(wchar_t *name)
{
	SC_HANDLE h_scm = NULL;
	wchar_t   buf[MAX_PATH];
	wchar_t   dnm[MAX_PATH];
	HKEY      h_key = NULL;
	int       resl;
	SC_HANDLE h_svc;	

	if (name == NULL) 
	{
		if (dc_get_old_drv_name(dnm, sizeof_w(dnm)) == ST_OK) {
			name = dnm;
		} else {
			name = drv_name;
		}
	}
	
	dc_get_driver_path(name, buf);

	do 
	{
		DeleteFile(buf);

		if ( (h_scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS)) == NULL ) {
			resl = ST_SCM_ERROR; break;
		}

		if (h_svc = OpenService(h_scm, name, SERVICE_ALL_ACCESS)) {			
			DeleteService(h_svc);
			CloseServiceHandle(h_svc);
		}		

		if (RegOpenKey(HKEY_LOCAL_MACHINE, reg_key, &h_key) != 0) {
			resl = ST_REG_ERROR;
			break;
		}

		if ( (rmv_from_val(h_key, upf_str, name) == 0) && (rmv_from_val(h_key, lwf_str, name) == 0) ) {
			resl = ST_ERROR;
		} else {
			resl = ST_OK;
		}		
	} while(0);

	if (h_key != NULL) {
		RegCloseKey(h_key);
	}

	if (h_scm != NULL) {
		CloseServiceHandle(h_scm);
	}

	return resl;
}

int dc_install_driver(wchar_t *name)
{
	dc_conf_data conf;
	wchar_t      buf[MAX_PATH];
	SC_HANDLE    h_scm = NULL;
	SC_HANDLE    h_svc = NULL;
	HKEY         h_key = NULL;
	int          resl;
	
	if (name == NULL) {
		name = drv_name;
	}

	dc_get_driver_path(name, buf);

	do 
	{
		if ( (resl = dc_save_drv_file(name)) != ST_OK ) {
			break;
		}	
	
		if ( (h_scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS)) == NULL ) {
			resl = ST_SCM_ERROR; break;
		}

		h_svc = CreateService(
			h_scm, name, NULL, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
			SERVICE_BOOT_START, SERVICE_ERROR_CRITICAL, buf, 
			L"PnP Filter", NULL, NULL, NULL, NULL
			);

		if (h_svc == NULL) {
			resl = ST_SCM_ERROR; break;
		}

		CloseServiceHandle(h_svc);

		if (RegOpenKey(HKEY_LOCAL_MACHINE, reg_key, &h_key) != 0) {
			resl = ST_REG_ERROR; break;
		}

		if (set_to_val(h_key, lwf_str, name) == 0) {
			resl = ST_REG_ERROR; break;
		}
		
		/* setup default config */
		zeromem(&conf, sizeof(conf));
		conf.conf_flags = CONF_QUEUE_IO;
		resl = dc_save_conf(&conf);
	} while (0);

	if (h_key != NULL) {
		RegCloseKey(h_key);
	}

	if (h_scm != NULL) {
		CloseServiceHandle(h_scm);
	}

	if (resl != ST_OK) {
		dc_remove_driver(name);
	}

	return resl;
}

int dc_driver_status()
{
	wchar_t  name[MAX_PATH];
	wchar_t  path[MAX_PATH];
	HANDLE   h_device;
	wchar_t *dnm;

	/* check old driver */
	if (dc_get_old_drv_name(name, sizeof_w(name)) == ST_OK) {
		dnm = name;
	} else {
		dnm = drv_name;
	}

	/* check new driver */
	dc_get_driver_path(dnm, path);
	
	if (GetFileAttributes(path) != INVALID_FILE_ATTRIBUTES) 
	{
		h_device = CreateFile(
			DC_WIN32_NAME, 0, 0, NULL, OPEN_EXISTING, 0, NULL
			);

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
	wchar_t      path[MAX_PATH];
	wchar_t      name[MAX_PATH];	
	int          resl;
	HKEY         key = NULL;
	dc_conf_data conf;
	
	do
	{
		if (dc_get_old_drv_name(name, sizeof_w(name)) == ST_OK) 
		{
			/* 0.2-0.2.6 driver detected */
			if (wcscmp(name, drv_name) == 0)
			{   /* if driver name not changed, correct registry keys */
				
				/* change filter from UpperFilters to LowerFilters */
				if (RegOpenKey(HKEY_LOCAL_MACHINE, reg_key, &key) != 0) {
					resl = ST_REG_ERROR; break;
				}

				rmv_from_val(key, upf_str, name);
				rmv_from_val(key, lwf_str, name);
				
				if (set_to_val(key, lwf_str, name) == 0) {
					resl = ST_REG_ERROR; break;
				}

				/* move settings to root key */
				if ( (resl = dc_load_conf(&conf)) != ST_OK ) {
					break;
				}
				if ( (resl = dc_save_conf(&conf)) != ST_OK ) {
					break;
				}

				/* delete old config key */
				_snwprintf(
					path, sizeof_w(path), L"%s\\%s\\%s", reg_srv, name, cnf_key
					);	

				RegDeleteKey(HKEY_LOCAL_MACHINE, path);

				/* update driver file */
				resl = dc_save_drv_file(name);
			} else 
			{
				/* if driver name changed, full reinstall needed */

				/* get program settings */
				if ( (resl = dc_load_conf(&conf)) != ST_OK ) {
					break;
				}

				if ( (resl = dc_remove_driver(name)) != ST_OK ) {
					break;
				}

				if ( (resl = dc_install_driver(NULL)) != ST_OK ) {
					break;
				}

				/* save config */
				resl = dc_save_conf(&conf);
			}
		} else {
			/* if new driver detected, update driver file only */
			resl = dc_save_drv_file(drv_name);
		}		
	} while (0);

	if (key != NULL) {
		RegCloseKey(key);
	}

	return resl;
}
