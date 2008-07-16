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
#include <windows.h>
#include <stdio.h>
#include <richedit.h>
#include <shellapi.h>
#include <shlwapi.h>
#include <psapi.h>
#include <mbstring.h>
#include <prsht.h>
#include <strsafe.h>
#include <ntddscsi.h>
#include <shlwapi.h>

#include "misc.h"
#include "resource.h"
#include "linklist.h"
#include "prccode.h"
#include "..\sys\driver.h"
#include "defines.h"
#include "mbrinst.h"
#include "..\boot\boot.h"
#include "drv_ioctl.h"
#include "main.h"
#include "winreg.h"
#include "autorun.h"
#include "hotkeys.h"
#include "rand.h"
#include "subs.h"

#pragma warning(disable : 4995)

int _tmr_elapse[ ] = { 
	1000,  // MAIN_TIMER
	100,   // PROC_TIMER
	3000,  // RAND_TIMER
	500,   // HIDE_TIMER
	500    // SHRN_TIMER

};

////////////////
char __hide_on_load = FALSE;
int __status;

dc_conf_data __config;

list_entry __volumes;
list_entry __action;
list_entry __drives;

CRITICAL_SECTION crit_sect;

///////////
void _set_device_item(
		HWND hlist,
		int lvcount,
		int num,
		wchar_t *mnt_point,
		_dnode *root,
		BOOL fixed,
		BOOL installed,
		BOOL boot
	)
{
	LVITEM lvitem;

	int lvsub = 0;
	__int64 size;	

	wchar_t s_size[MAX_PATH];
	wchar_t s_hdd[MAX_PATH];

	lvitem.mask = LVIF_TEXT | LVIF_PARAM;
	lvitem.iItem = lvcount;
	lvitem.iSubItem = 0;			
			
	lvitem.lParam = (LPARAM)root;
	lvitem.pszText = L"";
	ListView_InsertItem(hlist, &lvitem);
			
	size = dc_dsk_get_size(num, 0);
	dc_format_byte_size(s_size, sizeof_w(s_size), size);

	_snwprintf(s_hdd, sizeof_w(s_hdd), L"HardDisk %d", num);		

	ListView_SetItemText(hlist, lvcount, lvsub++, fixed ? s_hdd : mnt_point);
	ListView_SetItemText(hlist, lvcount, lvsub++, _wcslwr(s_size));

	ListView_SetItemText(hlist, lvcount, lvsub++, installed ? L"installed" : L"none");
	ListView_SetItemText(hlist, lvcount, lvsub++, boot ? L"boot" : L"");

}


void _list_devices(
		HWND hlist,
		BOOL fixed,
		int sel
	)
{
	list_entry *node, *sub;

	int k = 0;
	int col = 0;

	int lvcount = 0;
	int boot_disk = -1;

	ldr_config conf;
	_dnode *root = malloc(sizeof(_dnode));

	memset(root, '\0', sizeof(_dnode));
	root->is_root = TRUE;

	_init_list_headers(hlist, _boot_headers);
	ListView_DeleteAllItems(hlist);

	dc_get_boot_disk(&boot_disk);
	if (!fixed) {

		for ( ; k < 2; k++ ) {
			wchar_t name[MAX_PATH];

			_snwprintf(name, sizeof_w(name), L"%c:", 'A'+k);
			if (GetDriveType(name) == DRIVE_REMOVABLE) {

				_list_insert_item(hlist, lvcount, 0, name, 0);
				_list_set_item(hlist, lvcount, 1, L"--");
				_list_set_item(hlist, lvcount++, 2, L"--");

			}
		}

		for ( node = __drives.flink;
					node != &__drives;
					node = node->flink ) {	
					
			_dnode *drv = contain_record(node, _dnode, list);

			for ( sub = drv->root.vols.flink;
						sub != &drv->root.vols;
						sub = sub->flink ) {

				dc_status *st = 
				&contain_record(sub, _dnode, list)->mnt.info.status;

				if (_is_removable_media(drv->root.dsk_num)) {

					_set_device_item(
						hlist,
						lvcount++,
						drv->root.dsk_num, 
						st->mnt_point,
						drv->root.dsk_num == sel ? root : NULL,
						FALSE,
						dc_get_mbr_config(drv->root.dsk_num, NULL, &conf) == ST_OK,
						drv->root.dsk_num == boot_disk			

					);
				}
			}
		}
	} else {
		for ( ; k < 100; k++ ) {

			if (dc_dsk_get_size(k, 0)) {
				if (!_is_removable_media(k)) {

					_set_device_item(
						hlist,
						lvcount++,
						k, 
						NULL,
						k == sel ? root : NULL,
						TRUE,
						dc_get_mbr_config(k, NULL, &conf) == ST_OK,
						k == boot_disk			

					);
				}
			}
		}
	}
	ListView_SetBkColor(hlist, GetSysColor(COLOR_BTNFACE));
	ListView_SetTextBkColor(hlist, GetSysColor(COLOR_BTNFACE));
	ListView_SetExtendedListViewStyle(hlist, LVS_EX_FLATSB | LVS_EX_FULLROWSELECT);

}


BOOL _list_part_by_disk_id(
		HWND hwnd,
		int disk_id
	)
{
	list_entry *node;
	list_entry *sub;

	wchar_t s_id[MAX_PATH];
	wchar_t s_size[MAX_PATH];

	int count = 0;
	int item = 0;

	_init_list_headers(hwnd, _part_by_id_headers);
	ListView_DeleteAllItems(hwnd);

	for ( node = __drives.flink;
				node != &__drives;
				node = node->flink ) {

		list_entry *vols = 
		&contain_record(node, _dnode, list)->root.vols;

		for ( sub = vols->flink;
					sub != vols;
					sub = sub->flink ) {

			dc_status *status = &contain_record(sub, _dnode, list)->mnt.info.status;
			if ((status->flags & F_ENABLED) && (status->disk_id)) {
							
				dc_format_byte_size(
					s_size, sizeof_w(s_size), status->dsk_size
				);
				_snwprintf(s_id, sizeof_w(s_id), L"%.08X", status->disk_id);

				_list_insert_item(hwnd, count, 0, 
					status->mnt_point, status->disk_id == disk_id ? LVIS_SELECTED : FALSE);

				_list_set_item(hwnd, count, 1, s_size);
				_list_set_item(hwnd, count, 2, s_id);

				if (status->disk_id == disk_id) item = count;
				count++;				

			}
		}
	}
	if (!count) {
		_list_insert_item(hwnd, count, 0, 
			L"Partitions not found", 0);

	}
	ListView_SetBkColor(hwnd, GetSysColor(COLOR_BTNFACE));
	ListView_SetTextBkColor(hwnd, GetSysColor(COLOR_BTNFACE));

	ListView_SetExtendedListViewStyle(hwnd, LVS_EX_FLATSB | LVS_EX_FULLROWSELECT);
	ListView_SetSelectionMark(hwnd, item);

	return count;

}


static void _add_drive_node(
		_dnode *exist_node,
		drive_inf *new_drv,
		vol_inf *vol, 
		int index
	)
{
	wchar_t drvname[MAX_PATH];

	wchar_t fs[MAX_PATH] = { 0 };
	wchar_t label[MAX_PATH] = { 0 };

	wchar_t path[MAX_PATH];

	list_entry *node;
	BOOL root_exists = FALSE;

	_dnode *root;
	_dnode *mnt;

	mnt = exist_node ?
		exist_node : malloc(sizeof(_dnode));

	mnt->exists = TRUE;
	memcpy(&mnt->mnt.info, vol, sizeof(vol_inf));

	_snwprintf(path, sizeof_w(path), L"%s\\", vol->status.mnt_point);
	GetVolumeInformation(path, label, sizeof_w(label), 0, 0, 0, fs, sizeof_w(fs));

	wcscpy(mnt->mnt.label, label);
	wcscpy(mnt->mnt.fs, fs);

	if (!exist_node) 
	{
		dc_get_hdd_name(
			new_drv->disks[index].number, drvname, sizeof_w(drvname));

		if (drvname[0] == '\0') 
			_snwprintf(drvname, sizeof_w(drvname), L"HardDisk %d", new_drv->disks[index].number);

		for ( node = __drives.flink;
					node != &__drives;
					node = node->flink ) {

			root = contain_record(node, _dnode, list);
			if (root->root.dsk_num == new_drv->disks[index].number) {

				root_exists = TRUE;
				break;

			}
		}

		mnt->is_root = FALSE;
		memcpy(&mnt->root.info, new_drv, sizeof(drive_inf));

		if (!root_exists) {

			root = malloc(sizeof(_dnode));	
			root->is_root = TRUE;

			memcpy(&root->mnt.info, vol, sizeof(vol_inf));
			memcpy(&root->root.info, new_drv, sizeof(drive_inf));

			wcscpy(root->root.dsk_name, drvname);
			root->root.dsk_num = new_drv->disks[index].number;	

			_init_list_head(&root->root.vols);
			_insert_tail_list(&__drives, &root->list);

		} 
		_insert_tail_list(&root->root.vols, &mnt->list);

	} 		
	if (vol->status.flags & F_SYNC && _create_act_thread(mnt, -1, -1) == NULL) {
		_create_act_thread(mnt, ACT_ENCRYPT, ACT_PAUSED);

	}
}


_dnode *_scan_vols_tree(
		vol_inf *vol,
		int *count
	)
{
	list_entry *del;
	list_entry *node;
	list_entry *sub;	

	for ( node = __drives.flink;
				node != &__drives
				;
		) 
	{
		_dnode *root = contain_record(node, _dnode, list);
		if (count) *count += 1;

		for ( sub = root->root.vols.flink;
					sub != &root->root.vols
					; 
			) 
		{
			_dnode *mnt = contain_record(sub, _dnode, list);
			if (count) *count += 1;
				
			if (!vol) {
				if (!mnt->exists) {

					del = sub;
					sub = sub->flink;

					_remove_entry_list(del);
					free(del);

					continue;
				}
			} else {
				if (!wcscmp(mnt->mnt.info.device, vol->device) && !mnt->exists) 
					return mnt;

			}
			sub = sub->flink;
		}

		if (_is_list_empty(sub)) {
			del = node;
			node = node->flink;

			_remove_entry_list(del);
			free(del);

			continue;
		}
		node = node->flink;

	}
	return NULL;

}


int _list_volumes(
		list_entry *volumes
	)
{
	u32 k = 2;
	u32 drives = 0;

	int count = 0;

	vol_inf volinfo;
	drive_inf drvinfo;

	if (dc_first_volume(&volinfo) == ST_OK) {
		do {
			_dnode *mnt = _scan_vols_tree(&volinfo, NULL);

			if (!mnt) {
				if (ST_OK != dc_get_drive_info(volinfo.w32_device, &drvinfo)) continue;
			
				for ( k = 0; k < drvinfo.dsk_num; k++ ) {
					_add_drive_node(NULL, &drvinfo, &volinfo, k);

				}
			} else {
				do {
					_add_drive_node(mnt, NULL, &volinfo, -1);
				} while ((mnt = _scan_vols_tree(&volinfo, NULL)) != NULL);
			}

		} while (dc_next_volume(&volinfo) == ST_OK);
	}
	_scan_vols_tree(NULL, &count);
	return count;

}


BOOL _is_active_item(
		LPARAM lparam
	)
{
	_dnode *info = pv(lparam);

	if (info &&
			!info->is_root && 
		   info->mnt.info.status.flags & F_UNSUPRT)
			 
			 return FALSE;
	return TRUE;

}


BOOL _is_root_item(
		LPARAM lparam
	)
{
	_dnode *info = pv(lparam);
	return info ? info->is_root : FALSE;

}


BOOL _is_enabled_item(
		LPARAM lparam
	)
{
	_dnode *info = pv(lparam);

	return info ? info->mnt.info.status.flags & 
		F_ENABLED : FALSE;

}

BOOL _is_marked_item(
		LPARAM lparam
	)
{
	_dnode *info = pv(lparam);

	return info ? info->is_root && 
		(info->root.dsk_name[0] == '\0') : FALSE;

}


BOOL _is_splited_item(
		LPARAM lparam
	)
{
	_dnode *info = pv(lparam);
	return info ? info->root.info.dsk_num>1 : FALSE;

}


BOOL _is_curr_in_group(
		HWND hwnd
	)
{
	_tab_data *tab;

	tab = wnd_get_long(GetParent(hwnd), GWL_USERDATA);
	return tab && (tab->curr == hwnd);

}


BOOL _is_simple_list(
		HWND hwnd
	)
{
	WINDOWINFO winfo = { sizeof(winfo) };

	GetWindowInfo(hwnd, &winfo);
	return winfo.dwStyle & LVS_NOCOLUMNHEADER;

}


BOOL _is_boot_device(
		vol_inf *vol
	)
{
	wchar_t boot_dev[MAX_PATH];
	dc_get_boot_device(boot_dev);

	return (vol->status.flags & F_SYSTEM) || 
		(!wcscmp(vol->device, boot_dev));

}


BOOL _is_removable_media(int dsk_num)
{
	DISK_GEOMETRY dg;
	HANDLE hdisk;

	int rlt;
	DWORD bytes;

	if ((hdisk = dc_disk_open(dsk_num))) 
	{
		if (DeviceIoControl(hdisk, 
			IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &dg, sizeof(dg), &bytes, NULL))
		{
			return dg.MediaType == RemovableMedia;

		} else rlt = ST_IO_ERROR;
	} else rlt = ST_ACCESS_DENIED;
		
	_error_s(__dlg, L"Error get volume information", rlt);
	return FALSE;

}


void _load_diskdrives(
		HWND hwnd,
		list_entry *volumes,
		char vcount
	)
{ 
	LVITEM lvitem;

	list_entry *node;
	list_entry *sub;

	BOOL boot_enc = TRUE;
	int count;
	wchar_t display[MAX_PATH] = { 0 };
	wchar_t boot_dev[MAX_PATH];

	DWORD col = 0, item = 0, subitem = 1;
	int k = 0;
		
	HWND hlist = GetDlgItem(hwnd, IDC_DISKDRIVES);

	SendMessage(hlist, WM_SETREDRAW, FALSE, 0);
	count = ListView_GetItemCount(hlist);

	_init_list_headers(hlist, _main_headers);
	if (count != vcount) {

		ListView_DeleteAllItems(hlist);
		count = 0;

	}

	lvitem.mask = LVIF_TEXT | LVIF_IMAGE | LVIF_STATE | LVIF_PARAM; 
	lvitem.state = 0; 
	lvitem.stateMask = 0;

	for ( node = __drives.flink;
				node != &__drives;
				node = node->flink, subitem = 1 ) {

			_dnode *root = contain_record(node, _dnode, list);

			lvitem.iItem = item;
			lvitem.iSubItem = 0;
			lvitem.lParam = (LPARAM)root;

			if (!count) {
					lvitem.iImage = 0;
					lvitem.pszText = root->root.dsk_name;
					ListView_InsertItem(hlist, &lvitem);

			} else {
					lvitem.mask = LVIF_PARAM; 
					ListView_SetItem(hlist, &lvitem);

			}

			for ( sub = root->root.vols.flink, item++;
						sub != &root->root.vols;
						sub = sub->flink, item++, subitem = 1 ) {

					_dnode *mnt = contain_record(sub, _dnode, list);
					mnt->exists = FALSE;

					lvitem.iItem = item;
					lvitem.lParam = (LPARAM)mnt;
					lvitem.iSubItem = 0;

					if (!wcsstr(mnt->mnt.info.status.mnt_point, L"\\\\?\\")) {
						_snwprintf(
							display, sizeof_w(display), L"&%s", mnt->mnt.info.status.mnt_point);

					} else {
						_snwprintf(
							display, sizeof_w(display), L"&%s", wcsrchr(mnt->mnt.info.device, 'V'));

					}

					if (!count) {
						lvitem.iImage = 1; 
						lvitem.pszText = display;
						ListView_InsertItem(hlist, &lvitem);

					} else {
						lvitem.mask = LVIF_PARAM;
						ListView_SetItem(hlist, &lvitem); 

					}
					_list_set_item_text(hlist, item, 0, display);

					dc_format_byte_size(display, sizeof_w(display), mnt->mnt.info.status.dsk_size);					
					_list_set_item_text(hlist, item, subitem++, _wcslwr(display));

					_list_set_item_text(hlist, item, subitem++, mnt->mnt.label);
					_list_set_item_text(hlist, item, subitem++, mnt->mnt.fs);

					_get_status_text(mnt, display, sizeof_w(display));
					_list_set_item_text(hlist, item, subitem++, display);

					if (dc_get_boot_device(boot_dev) == ST_OK) {
						wchar_t s_boot[MAX_PATH] = { 0 };

						if (wcscmp(mnt->mnt.info.device, boot_dev) == 0) wcscat(s_boot, L"boot");
						if (mnt->mnt.info.status.flags & F_SYSTEM) {

							if (wcslen(s_boot)) wcscat(s_boot, L", ");
							wcscat(s_boot, L"sys");

						}			
						if (wcslen(s_boot) && mnt->mnt.info.status.flags & F_ENABLED) boot_enc = FALSE; 
						_list_set_item_text(hlist, item, subitem++, s_boot);

					}
			}
	}	
	EnableMenuItem(GetMenu(__dlg), ID_TOOLS_DRIVER, _menu_onoff(boot_enc));
	SendMessage(hlist, WM_SETREDRAW, TRUE, 0);

} 


void _set_timer(
		int index,
		BOOL set,
		BOOL refresh
	)
{
	if (refresh) _refresh(TRUE);

	if (set) {
		SetTimer(__dlg, IDC_TIMER + index, 
			_tmr_elapse[index], (TIMERPROC)_timer_handle);

	} else {
		KillTimer(__dlg, IDC_TIMER + index);

	}
}


void _refresh(
		char main
	)
{
	_timer_handle(__dlg, WM_TIMER, 
		IDC_TIMER + (main ? MAIN_TIMER : PROC_TIMER), IDC_TIMER);

}


void _state_menu(
		HMENU menu,
		UINT state
	)
{
	int count = GetMenuItemCount(menu);
	char k = 0;

	for ( ;k < count; k++ ) {
		EnableMenuItem(menu, GetMenuItemID(menu, k), state);

	}
}


void _refresh_menu( )
{
	HMENU menu = GetMenu(__dlg);
	HWND hlist = GetDlgItem(__dlg, IDC_DISKDRIVES);

	_dnode *node = pv(_get_sel_item(hlist));
	_dact *act = _create_act_thread(node, -1, -1);

	BOOL unmount = FALSE;
	BOOL mount = FALSE;

	BOOL decrypt = FALSE;
	BOOL encrypt = FALSE;
	BOOL chpass = FALSE;

	if (node &&	ListView_GetSelectedCount(hlist) && 
		!_is_root_item((LPARAM)node) &&
	 	 _is_active_item((LPARAM)node)) 
	{
		int flags = node->mnt.info.status.flags;
		if (flags & F_ENABLED) {

			if (IS_UNMOUNTABLE(&node->mnt.info.status)) unmount = TRUE;
			chpass = TRUE;

			if (!(act && act->status == ACT_RUNNING)) {

				decrypt = TRUE;
				if (flags & F_SYNC)	encrypt = TRUE;

			}
		} else {
			if (*node->mnt.fs == '\0') mount = TRUE;							
			else encrypt = TRUE;
		}
	}

	SetWindowText(GetDlgItem(__dlg, IDC_BTN_MOUNT_), unmount ? IDS_UNMOUNT : IDS_MOUNT);
	EnableWindow(GetDlgItem(__dlg, IDC_BTN_MOUNT_), unmount || mount);

	EnableWindow(GetDlgItem(__dlg, IDC_BTN_ENCRYPT_), encrypt);
	EnableWindow(GetDlgItem(__dlg, IDC_BTN_DECRYPT_), decrypt);

	EnableMenuItem(menu, ID_VOLUMES_MOUNT, _menu_onoff(mount));
	EnableMenuItem(menu, ID_VOLUMES_ENCRYPT, _menu_onoff(encrypt));

	EnableMenuItem(menu, ID_VOLUMES_DISMOUNT, _menu_onoff(unmount));
	EnableMenuItem(menu, ID_VOLUMES_DECRYPT, _menu_onoff(decrypt));

	EnableMenuItem(menu, ID_VOLUMES_CHANGEPASS, _menu_onoff(chpass));

}


int _menu_set_loader_vol(
		HWND hwnd,
		wchar_t *vol,
		int dsk_num
	)
{
	ldr_config conf;
	int rlt = ST_ERROR;

	if (dsk_num == -1) {

		if ((rlt = dc_set_boot(vol, FALSE)) == ST_FORMAT_NEEDED) {
			if (_msg_q(
						hwnd,
						L"Removable media not correctly formatted\n"
						L"Format media?\n")) 
			{
				rlt = dc_set_boot(vol, TRUE);
			}
		}

		if (rlt == ST_OK) {
			if ((rlt = dc_mbr_config_by_partition(vol, FALSE, &conf)) == ST_OK ) {
				
				conf.options = OP_EXTERNAL;
				conf.boot_type = BT_AP_PASSWORD;

				rlt = dc_mbr_config_by_partition(vol, TRUE, &conf);

			}
		}
	} else {							
		rlt = _set_boot_loader(hwnd, dsk_num);
	}

	if (ST_OK == rlt) {
		_msg_i(hwnd, L"Bootloader successfully installed to [%s]", vol);							
	} else {
		_error_s(hwnd, L"Error install bootloader", rlt);
	}
	return rlt;

}


int _menu_set_loader_file(
		HWND hwnd,
		wchar_t *path,
		BOOL iso
	)
{
	ldr_config conf;

	BOOL create = TRUE;
	int rlt = ST_ERROR;

	if (PathFileExists(path)) {

		create = _msg_q(
			hwnd,
			L"File \"%s\" is exists\n\n"
			L"Press [Yes] for create new bootloader\n"
			L"Press [No] for change config",
			path
		);
	}
	if (create) {

		rlt = iso ? 
			dc_make_iso(path) : dc_make_pxe(path);

		if (rlt == ST_OK) {
			if ((rlt = dc_get_mbr_config(0, path, &conf)) == ST_OK) {

				conf.options = OP_EXTERNAL;
				conf.boot_type = BT_MBR_FIRST;

				rlt = dc_set_mbr_config(0, path, &conf);

			}			
		}
		if (rlt != ST_OK) {
			_error_s(hwnd, L"Error create bootloader %s image", 
				rlt, iso ? L".iso" : L"PXE");
		}
	} else rlt = ST_OK;
	return rlt;

}


void _menu_decrypt(
		_dnode *node
	)
{
	dlgpass dlg_info = { NULL, NULL, QR_MOUNT, node };

	int rlt;
	if (!_create_act_thread(node, -1, -1)) {

		rlt = _dlg_get_pass(__dlg, &dlg_info);
		if (rlt == ST_OK) {

			rlt = dc_start_decrypt(node->mnt.info.device, dlg_info.pass);
			secure_free(dlg_info.pass);

			if (rlt != ST_OK) {

				_error_s(
					__dlg, L"Error start decrypt volume [%s]", rlt, node->mnt.info.status.mnt_point
				);

			}
		}
	} else rlt = ST_OK;
	if (rlt == ST_OK) {

		_create_act_thread(node, ACT_DECRYPT, ACT_RUNNING);
		SendMessage(GetDlgItem(__dlg, IDB_MAIN_ACTION), WM_LBUTTONDOWN, 0, 0);

	}
}


int _set_boot_loader(
		HWND hwnd,
		int dsk_num
	)
{
	int boot_disk = dsk_num;
	ldr_config conf;

	int rlt;
	if (-1 == boot_disk) {

		rlt = dc_get_boot_disk(&boot_disk);
		if (ST_OK != rlt) return rlt;

	}
	if (ST_NF_SPACE == (rlt = dc_set_mbr(boot_disk, 0))) {

		if (__msg_w(
					L"Not enough space after partitions to install bootloader.\n\n"
					L"Install bootloader to first HDD track?\n"
					L"(incompatible with third-party bootmanagers, like GRUB)", 
				hwnd)										
				) {

			if ((ST_OK == (rlt = dc_set_mbr(boot_disk, 1))) && 
					(ST_OK == dc_get_mbr_config(boot_disk, NULL, &conf))) {

				conf.boot_type = BT_ACTIVE;						
				if (ST_OK != (rlt = dc_set_mbr_config(boot_disk, NULL, &conf))) {

					dc_unset_mbr(boot_disk);
										
				}
			}
		}
	}
	return rlt;

}


DWORD 
WINAPI 
_thread_enc_dec_proc(
		LPVOID lparam
	)
{
	BOOL encrypting;
	int i = 0;
	int rlt, wp_mode;

	wchar_t device[MAX_PATH];
	_dnode *node;
	_dact *act;

	dc_open_device( );
	EnterCriticalSection(&crit_sect);

	node = pv(lparam);
	act = _create_act_thread(node, -1, -1);
	if (!node || !act) return 0L;

	wcscpy(device, act->device);

	do {
		if (act->status != ACT_RUNNING) break;
		if (i-- == 0) {

			dc_sync_enc_state(device); 
			i = 20;

		}
		encrypting = act->act == ACT_ENCRYPT;
		wp_mode = act->wp_mode;

		LeaveCriticalSection(&crit_sect);

		rlt = encrypting ?

			dc_enc_step(device, wp_mode) :
			dc_dec_step(device);

		EnterCriticalSection(&crit_sect);
		if (rlt == ST_FINISHED) {

			act->status = ACT_STOPPED;
			break;

		}
		if ((rlt != ST_OK) && (rlt != ST_RW_ERR))
		{
			dc_status st;
			dc_get_device_status(device, &st);

			_error_s(
					HWND_DESKTOP,
					L"%s error on volume [%s]", 
					rlt,
					act->act == ACT_ENCRYPT ? L"Encryption" : L"Decryption", 
					st.mnt_point
				);
			
			act->status = ACT_STOPPED;
			break;
		}
	} while (1);

	dc_sync_enc_state(device);
	LeaveCriticalSection(&crit_sect);

	dc_close_device( );
	return 1L;

}

void _clear_act_list( )
{
	list_entry *node = __action.flink;
	list_entry *del = NULL;

	list_entry *head = &__action;

	for ( ;
		node != &__action;		
	) {
		_dact *act = contain_record(node, _dact, list);

		if (ACT_STOPPED == act->status) {
			if (WaitForSingleObject(act->thread, 0) == WAIT_OBJECT_0) {

				del = node;
				node = node->flink;

				_remove_entry_list(del); 

				CloseHandle(act->thread);
				free(del);
			
				continue;
			}
		}
		node = node->flink;
	}
}


_dact *_create_act_thread(
		_dnode *node,
		int act_type,   // -1 - search
		int act_status  //
	)
{
	list_entry *item;
	_dact *act;

	DWORD resume;	
	BOOL exist = FALSE;

	FILETIME time;

	if (!node) return NULL;
	_clear_act_list( );

	for ( 
		item = __action.flink;
		item != &__action; 
		item = item->flink 
	) {

		act = contain_record(item, _dact, list);
		if (!wcscmp(act->device, node->mnt.info.device)) {

			exist = TRUE;

			if (act_type == -1) 
				return act; else break;

		}
	}
	if (act_type != -1) {
		if (!exist) {
			
			act = malloc(sizeof(_dact));

			act->wp_mode = node->mnt.info.status.wp_mode;
			act->last_size = node->mnt.info.status.tmp_size;
			wcsncpy(act->device, node->mnt.info.device, MAX_PATH);

		}
		GetSystemTimeAsFileTime(&time);

		act->begin.HighPart = time.dwHighDateTime;
		act->begin.LowPart = time.dwLowDateTime;

		act->status = act_status;					
		act->act = act_type;

		act->thread = NULL;

		if (ACT_RUNNING == act_status) 
		{

			act->thread = CreateThread(NULL, 0, 
				_thread_enc_dec_proc, pv(node), CREATE_SUSPENDED, NULL);

			SetThreadPriority(act->thread, THREAD_PRIORITY_LOWEST);
			resume = ResumeThread(act->thread);

			if (!act->thread || resume == (DWORD)-1) {

				free(act);
				
				_error_s(__dlg, L"Error create thread", -1);
				return NULL;

			}
		}
		if (!exist) _insert_tail_list(&__action, &act->list);
		return act;			
	}
 	return NULL;

}


void _menu_encrypt(_dnode *node)
{
	int resl;

	if (_create_act_thread(node, -1, -1) == 0)
	{
		resl = (int)DialogBoxParam(
			__hinst, MAKEINTRESOURCE(IDD_WIZARD_ENCRYPT), __dlg, pv(_wizard_encrypt_dlg_proc), (LPARAM)node
			);
	} else {
		resl = ST_OK;
	}
	
	if (resl == ST_CANCEL) {
		return;
	}

	if (resl != ST_OK) {
		_error_s(__dlg, L"Error start encrypt volume [%s]", resl, node->mnt.info.status.mnt_point);
	} else 
	{
		_create_act_thread(node, ACT_ENCRYPT, ACT_RUNNING);
		SendMessage(GetDlgItem(__dlg, IDB_MAIN_ACTION), WM_LBUTTONDOWN, 0, 0);
	}
}


void _menu_unmount(_dnode *node)
{
	int resl  = ST_ERROR;
	int flags = __config.conf_flags & CONF_FORCE_DISMOUNT ? UM_FORCE : 0;

	if (_msg_q(__dlg, L"Unmount volume [%s]?", node->mnt.info.status.mnt_point)) 
	{
		resl = dc_unmount_volume(node->mnt.info.device, flags);

		if (resl == ST_LOCK_ERR) 
		{
			if (__msg_w(L"This volume contain opened files.\n"
				        L"Would you like to force a unmount on this volume?", __dlg)) 
			{
				resl = dc_unmount_volume(node->mnt.info.device, UM_FORCE);
			}
		}

		if (resl != ST_OK) {
			_error_s(__dlg, L"Error unmount volume [%s]", resl, node->mnt.info.status.mnt_point);
		} else 
		{
			_dact *act;

			EnterCriticalSection(&crit_sect);

			if (act = _create_act_thread(node, -1, -1)) {
				act->status = ACT_STOPPED;
			}

			LeaveCriticalSection(&crit_sect);
		}
	}
}


void _menu_mount(_dnode *node)
{
	dlgpass dlg_info = { NULL, NULL, QR_MOUNT, node };
	int     resl;

	resl = dc_mount_volume(node->mnt.info.device, "");

	if (resl != ST_OK) 
	{
		if (_dlg_get_pass(__dlg, &dlg_info) == ST_OK) 
		{
			resl = dc_mount_volume(node->mnt.info.device, dlg_info.pass);
			secure_free(dlg_info.pass);

			if (resl != ST_OK) {
				_error_s(__dlg, L"Error mount volume [%s]", resl, node->mnt.info.status.mnt_point);
			}
		}
	}

	if ( (resl == ST_OK) && (__config.conf_flags & CONF_EXPLORER_MOUNT) ) {
		__execute(node->mnt.info.status.mnt_point);
	}
}


void _menu_mountall()
{
	dlgpass dlg_info  = { NULL, NULL, QR_MOUNT, NULL };
	int     mount_cnt = 0;	

	dc_mount_all(NULL, &mount_cnt);

	if (mount_cnt == 0) 
	{
		if (_dlg_get_pass(__dlg, &dlg_info) == ST_OK) 
		{
			dc_mount_all(dlg_info.pass, &mount_cnt);
			secure_free(dlg_info.pass);
			_msg_i(__dlg, L"Mounted devices: %d", mount_cnt);
		}
	}
}


void _menu_unmountall()
{
	list_entry *node = __action.flink;

	if (_msg_q(__dlg, L"Unmount all volumes?")) 
	{
		dc_unmount_all();

		for ( ;node != &__action; node = node->flink ) {
			((_dact *)node)->status = ACT_STOPPED;
		}
	}
}


void _menu_change_pass(_dnode *node)
{
	dlgpass dlg_info = { NULL, NULL, QR_CHANGE_PASS, node };
	int     resl     = ST_ERROR;

	if (_dlg_get_pass(__dlg, &dlg_info) == ST_OK) 
	{
		resl = dc_change_password(
			node->mnt.info.device, dlg_info.pass, dlg_info.new_pass
			);

		secure_free(dlg_info.pass);
		secure_free(dlg_info.new_pass);

		if (resl != ST_OK) {
			_error_s(__dlg, L"Error change password", resl);
		} else {
			_msg_i(__dlg, L"Password successfully changed for [%s]", node->mnt.info.status.mnt_point);
		}
	}
}


void _menu_clear_cache( )
{
	if (_msg_q(__dlg, L"Wipe All Passwords?")) {
		dc_clean_pass_cache();
	}
}


void _menu_update_volume(_dnode *node)
{
	dlgpass dlg_info = { NULL, NULL, QR_MOUNT, node };
	sh_data shd;
	int     resl;
	
	if (_dlg_get_pass(__dlg, &dlg_info) == ST_OK) 
	{
		resl = _shrink_volume(__dlg, &node->mnt.info, &shd);

		if (resl == ST_OK) {
			resl = dc_update_volume(node->mnt.info.device, dlg_info.pass, &shd);
		}

		secure_free(dlg_info.pass);

		if (resl != ST_OK) {
			_error_s(__dlg, L"Error update volume [%s]", resl, node->mnt.info.status.mnt_point);
		} else {
			_msg_i(__dlg, L"Volume [%s] successfully updated\n", node->mnt.info.status.mnt_point);
		}
	}
}


static int _dc_upd_bootloader( )
{
	ldr_config conf;
	
	if (dc_get_mbr_config(-1, NULL, &conf) != ST_OK) {
		return ST_OK; 
	} else {
		return dc_update_boot(-1);
	}
}


int _drv_action(
		int action, 
		int version
	)
{
	int stat = dc_driver_status( );
	int resl = stat;
	static wchar_t restart_confirm[ ] = 
						L"You must restart your computer before the new settings will take effect.\n\n"
						L"Do you want to restart your computer now?";

	switch (action) 
	{
		case DA_INSTAL: 
			{
				if (stat == ST_INSTALLED) 
				{
					if (_msg_q(HWND_DESKTOP, restart_confirm))
						_reboot( );

					resl = ST_OK;
				}

				if (stat == ST_ERROR) 
				{
					if (_msg_q(HWND_DESKTOP, L"Install DiskCryptor driver?")) 
					{
						if ( (resl = dc_install_driver(NULL)) == ST_OK )
						{
							if (_msg_q(HWND_DESKTOP, restart_confirm)) 
								_reboot( );					
							
						}
					} else {
						resl = ST_OK;
					}
				}
			}
		break;
		case DA_REMOVE: 
			{
				if (stat != ST_ERROR) 
				{
					if ((resl = dc_remove_driver(NULL)) == ST_OK)
					{
						if (_msg_q(HWND_DESKTOP, restart_confirm)) 
							_reboot( );

					}
				}
			}
		break;
		case DA_UPDATE: 
			{
				wchar_t up_atom[MAX_PATH];

				_snwprintf(
					up_atom, sizeof_w(up_atom), L"DC_UPD_%d", version
					);

				if (GlobalFindAtom(up_atom) != 0) 
				{
					if (_msg_q(HWND_DESKTOP, restart_confirm)) _reboot( );
					resl = ST_OK; break;
				}

				if (stat == ST_ERROR) break;
				if (_msg_q(HWND_DESKTOP, L"Update DiskCryptor?"))
				{
					if (((resl = dc_update_driver()) == ST_OK) &&
						  ((resl = _dc_upd_bootloader()) == ST_OK))
					{
						GlobalAddAtom(up_atom);

						if (_msg_q(HWND_DESKTOP, restart_confirm)) 
							_reboot( );					
						
					}
				}
			}
		break;
	}
	return resl;
}

int WINAPI wWinMain(
		HINSTANCE hinst,
		HINSTANCE hprev,
		LPWSTR    cmd_line,
		int       cmd_show
	)
{
	int rlt, ver;
	int app_start = on_app_start(cmd_line);

	if (app_start == ST_NEED_EXIT) {
		return 0;
	}

	if (!_ui_init(hinst)) {
		_error_s(HWND_DESKTOP, L"Error GUI initialization", ST_OK);
		return 0;

	}
	if (is_admin( ) != ST_OK) {
		_error_s(HWND_DESKTOP, L"Admin Privileges Required", ST_OK);
		return 0;

	}
#ifdef _M_IX86 
	if (is_wow64( ) != 0) {
		_error_s(HWND_DESKTOP, L"Please use x64 version of DiskCryptor", ST_OK);
		return 0;
	}
#endif

	if (dc_driver_status() != ST_OK) 
	{
		if ((rlt = _drv_action(DA_INSTAL, 0)) != ST_OK) {
			_error_s(HWND_DESKTOP, NULL, rlt);
		}
		return 0;
	}

	if ((rlt = dc_open_device()) != ST_OK) {
		_error_s(HWND_DESKTOP, L"Can not open DC device", rlt);
		return 0; 
	}

	ver = dc_get_version();
	
	if (ver < DC_DRIVER_VER) 
	{
		if ((rlt = _drv_action(DA_UPDATE, ver)) != ST_OK) {
			_error_s(HWND_DESKTOP, NULL, rlt);
		}
		return 0;
	}

	if (ver > DC_DRIVER_VER) 
	{
		_msg_i(
			HWND_DESKTOP,
			L"DiskCryptor driver v%d detected\n"
			L"Please use last program version", ver
			);

		return 0;
	}

	if ((rlt = rnd_init()) != ST_OK) {
		_error_s(HWND_DESKTOP, L"Can not initialize RNG", rlt);
		return 0;
	}

	if ((rlt = dc_load_conf(&__config)) != ST_OK) {
		_error_s(HWND_DESKTOP, L"Error get config", rlt);
		return 0;		
	}
	InitializeCriticalSection(&crit_sect);

	_init_list_head(&__drives);
	_init_list_head(&__action);

	return 
		(int)DialogBoxParam(
				GetModuleHandleA(NULL), 
				MAKEINTRESOURCE(IDD_MAIN_DLG), 
				HWND_DESKTOP, 
				pv(_main_dialog_proc), 
				app_start == ST_AUTORUNNED
	);

}

