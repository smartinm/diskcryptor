#include <windows.h>
#include <stdio.h>
#include <richedit.h>
#include <ntddscsi.h>
#include <shlwapi.h>
#include <commctrl.h>

#include "defines.h"
#include "resource.h"
#include "prccode.h"
#include "hotkeys.h"
#include "uicode.h"
#include "main.h"
#include "misc.h"
#include "rand.h"
#include "drvinst.h"
#include "drv_ioctl.h"
#include "autorun.h"
#include "linklist.h"
#include "subs.h"
#include "shrink.h"
#include "pass_check.h"
#include "shrink.h"
#include "winternl.h"
#include "dcapi.h"
#include "..\sys\driver.h"
#include "..\boot\boot.h"

dlgpass dlg_emb_pass;

int _ext_disk_num(
		HWND hwnd
	)
{
	wchar_t vol[MAX_PATH];
	wchar_t *num_offset;
	
	_get_item_text(hwnd, 
		ListView_GetSelectionMark(hwnd), 0, vol, sizeof_w(vol));

	num_offset = wcschr(vol, ' ');

	return num_offset ? 
		_wtoi(num_offset) : -1;

}

INT_PTR
CALLBACK
_tab_proc(
		HWND hwnd,
		UINT message,
		WPARAM wparam,
		LPARAM lparam
	)
{
	WORD code = HIWORD(wparam);
	WORD id = LOWORD(wparam);
	HDC dc;

	wchar_t tmpb[500];
	int k;

	switch (message) {
		case WM_NOTIFY: {

			if (IDC_WZD_BOOT_DEVS == wparam) {

				NM_LISTVIEW *msg_info = pv(lparam);
				HWND hlist = msg_info->hdr.hwndFrom;

				if (LVN_ITEMACTIVATE == msg_info->hdr.code) {

					EnableWindow(GetDlgItem(GetParent(GetParent(hwnd)), IDOK), TRUE);
					SendMessage(GetParent(GetParent(hwnd)), WM_COMMAND, MAKELONG(IDOK, WM_APP + WM_APP_CHANGE_CONFIG), 0);					

				}

				if (NM_CLICK == msg_info->hdr.code || NM_RCLICK == msg_info->hdr.code) {
				if (IsWindowEnabled(hlist)) {

					BOOL lock = ((NM_LISTVIEW *)lparam)->iItem == -1;
					//EnableWindow(GetDlgItem(GetParent(GetParent(hwnd)), IDOK), !lock);

				}
				/*
				if (((NMHDR *)lparam)->code == NM_CUSTOMDRAW)
				{
					SetTextColor(((LPNMCUSTOMDRAW)lparam)->hdc, CL_BLUE);
					
					SelectObject(((LPNMCUSTOMDRAW)lparam)->hdc, __font_bold);
					return CDRF_NEWFONT;
				
				}
					//((NMLVCUSTOMDRAW *)lparam)->nmcd.dwDrawStage = CDDS_ITEMPREPAINT;
					//	return CDRF_SKIPDEFAULT;
					*/
				}

				if (NM_RCLICK == msg_info->hdr.code) 
				{
					HMENU popup = CreatePopupMenu( );
					BOOL item_update = FALSE;

					int type = (int)SendMessage(GetDlgItem(hwnd, IDC_COMBO_LOADER_TYPE), CB_GETCURSEL, 0, 0);
					ldr_config conf;

					int dsk_num = -1;
					int item, rlt;					

					wchar_t vol[MAX_PATH];					

					_get_item_text(hlist, msg_info->iItem, 0, vol, sizeof_w(vol));
					dsk_num = _ext_disk_num(hlist);

					if (ListView_GetSelectedCount(hlist))
					{
						_get_item_text(hlist, msg_info->iItem, 2, tmpb, sizeof_w(tmpb));
						if (!wcscmp(tmpb, L"installed")) {

							AppendMenu(popup, MF_STRING, ID_BOOT_REMOVE, IDS_BOOTREMOVE);

							if (!type) {
								item_update = dc_get_mbr_config(dsk_num, NULL, &conf) == 
									ST_OK && conf.ldr_ver < DC_BOOT_VER;
								
								if (item_update) AppendMenu(popup, MF_STRING, ID_BOOT_UPDATE, IDS_BOOTUPDATE);
								AppendMenu(popup, MF_SEPARATOR, 0, NULL);	
							}
							AppendMenu(popup, MF_STRING, ID_BOOT_CHANGE_CONFIG, IDS_BOOTCHANGECGF);
						} else {
							AppendMenu(popup, MF_STRING, ID_BOOT_INSTALL, IDS_BOOTINSTALL);

						}
					}
					item = TrackPopupMenu(
							popup,
							TPM_RETURNCMD | TPM_LEFTBUTTON,
							LOWORD(GetMessagePos( )),
							HIWORD(GetMessagePos( )),
							0,
							hwnd,
							NULL
					);

					DestroyMenu(popup);
					switch (item) {

					case ID_BOOT_INSTALL: 
					{
						if (type) {
							_menu_set_loader_vol(hwnd, vol, -1);
						} else {							
							_menu_set_loader_vol(hwnd, NULL, dsk_num);
						}
					}
					break;
					case ID_BOOT_REMOVE:
					{
						if (type) {

							wchar_t dev[MAX_PATH];
							drive_inf inf;

							_snwprintf(dev, sizeof_w(dev), L"\\\\.\\%s", vol);
							rlt = dc_get_drive_info(dev, &inf);

							if (rlt == ST_OK) {

								if (inf.dsk_num == 1) {
									dsk_num = inf.disks[0].number;

								} else {
									__msg_w(L"One volume on two disks\nIt's very strange..", hwnd);
									break;
								}								
							}
						}
						rlt = dc_unset_mbr(dsk_num);

						if ((rlt) == ST_OK) {
							_msg_i(hwnd, L"Bootloader successfully removed from [%s]\n", vol);
						} else {
							_error_s(hwnd, L"Error remove bootloader\n", rlt);
						}
					}
					break;
					case ID_BOOT_UPDATE: 
					{
						if ((rlt = dc_update_boot(dsk_num)) == ST_OK) {
							_msg_i(hwnd, L"Bootloader on [%s] successfully updated\n", vol);
							
							/*if (__get_check(hwnd, IDC_CHECK_CONFIG)) {
								SendMessage(GetParent(GetParent(hwnd)), WM_COMMAND, MAKELONG(IDOK, 0), 0);

							}*/
						} else {
							_error_s(hwnd, L"Error updated bootloader\n", rlt);
						}
					}
					break;
					case ID_BOOT_CHANGE_CONFIG: {
						EnableWindow(GetDlgItem(GetParent(GetParent(hwnd)), IDOK), TRUE);
						SendMessage(GetParent(GetParent(hwnd)), WM_COMMAND, MAKELONG(IDOK, WM_APP + WM_APP_CHANGE_CONFIG), 0);

					}
					break;
					}
					if (item) _list_devices(GetDlgItem(hwnd, IDC_WZD_BOOT_DEVS),
						!SendMessage(GetDlgItem(hwnd, IDC_COMBO_LOADER_TYPE), CB_GETCURSEL, 0, 0), -1);

				}
			}
		}
		break;

		case WM_USER_CLICK: {
			HWND ctl_wnd = (HWND)wparam;

			if (ctl_wnd == GetDlgItem(hwnd, IDC_AUTO_START)) {
				BOOL enable = __get_check(hwnd, IDC_AUTO_START);

				EnableWindow(GetDlgItem(hwnd, IDC_WIPE_LOGOFF), enable);
				EnableWindow(GetDlgItem(hwnd, IDC_UNMOUNT_LOGOFF), enable);

				InvalidateRect(GetDlgItem(hwnd, IDC_WIPE_LOGOFF), NULL, TRUE);
				InvalidateRect(GetDlgItem(hwnd, IDC_UNMOUNT_LOGOFF), NULL, TRUE);

				if (!enable) {
					__set_check(hwnd, IDC_WIPE_LOGOFF, enable);
					__set_check(hwnd, IDC_UNMOUNT_LOGOFF, enable);
				}
				return 1L;
			}

			if (ctl_wnd == GetDlgItem(hwnd, IDC_BT_ENTER_PASS_MSG)) {
				EnableWindow(GetDlgItem(hwnd, IDE_RICH_BOOTMSG), __get_check(hwnd, IDC_BT_ENTER_PASS_MSG));
				return 1L;
			}

			if (ctl_wnd == GetDlgItem(hwnd, IDC_BT_BAD_PASS_MSG)) {
				EnableWindow(GetDlgItem(hwnd, IDE_RICH_ERRPASS_MSG), __get_check(hwnd, IDC_BT_BAD_PASS_MSG));
				return 1L;
			}
	
			if (ctl_wnd == GetDlgItem(hwnd, IDC_CHECK_SHOW)) 
			{
				int mask = __get_check(hwnd, IDC_CHECK_SHOW) ? 0 : '*';

				SendMessage(GetDlgItem(hwnd, IDE_PASS),
					EM_SETPASSWORDCHAR,	mask, 0
				);				

				SendMessage(GetDlgItem(hwnd, IDE_CONFIRM),
					EM_SETPASSWORDCHAR,	mask, 0
				);

				InvalidateRect(GetDlgItem(hwnd, IDE_PASS), NULL, TRUE);
				InvalidateRect(GetDlgItem(hwnd, IDE_CONFIRM), NULL, TRUE);
				return 1L;
			}

			{
				_wnd_data *data = wnd_get_long(ctl_wnd, GWL_USERDATA);

				k = 0;
				while (hotks_chk[k].id != -1) {
					if(ctl_wnd == GetDlgItem(hwnd, hotks_chk[k].id)) {

						EnableWindow(GetDlgItem(hwnd, hotks_edit[k].id), data->state);
						EnableWindow(GetDlgItem(hwnd, hotks_static[k].id), data->state);
						return 1L;
												
					}
					k++;
				}
			}
		}
		break;

		case WM_COMMAND: {

			HWND hlist = GetDlgItem(__dlg, IDC_DISKDRIVES);	

			_dnode *node = pv(_get_sel_item(hlist));			
			_dact *act = _create_act_thread(node, -1, -1);

			switch (id) {
				case IDB_BOOT_PREF: _dlg_config_loader(hwnd, TRUE);
					break;

				case IDB_BT_CONF_EMB_PASS: 
					{
						if (dlg_emb_pass.new_pass) secure_free(dlg_emb_pass.new_pass);
						if (dlg_emb_pass.pass) secure_free(dlg_emb_pass.pass);

						dlg_emb_pass.new_pass = NULL;
						dlg_emb_pass.pass = NULL;

						dlg_emb_pass.node = NULL;
						dlg_emb_pass.query = QR_MOUNT;						

						_dlg_get_pass(hwnd, &dlg_emb_pass);

					}
					break;
				case IDB_ACT_PAUSE:
					{
						if (node) {
		
							if (act->status == ACT_RUNNING) {

								act->status = ACT_PAUSED;	
								act->act = ACT_ENCRYPT;

							}
						}
						_refresh(TRUE);
					}
					break;
				case IDB_BOOT_PATH:
					{

						OPENFILENAME ofn = { sizeof(ofn), hwnd };
						wchar_t file[MAX_PATH] = { L"loader" };

						ofn.lpstrFile = file;
						ofn.nMaxFile = sizeof_w(file);

						ofn.lpstrTitle = L"Save Bootloader File As";

						ofn.Flags = OFN_FORCESHOWHIDDEN | OFN_HIDEREADONLY;
						ofn.FlagsEx = OFN_EX_NOPLACESBAR;

						if (GetSaveFileName(&ofn)) {
							SetWindowText(GetDlgItem(hwnd, IDE_BOOT_PATH), file);

						}
					}
					break;

			}
			switch (code) {
			case CBN_SELCHANGE: {

				switch (id) {
					case IDC_COMBO_AUTH_TYPE:
						{
							BOOL enable = LT_GET_PASS == _get_combo_val((HWND)lparam, auth_type);

							_enb_but_this(hwnd, IDC_COMBO_AUTH_TYPE, enable);

							EnableWindow(GetDlgItem(hwnd, IDC_STATIC_AUTH_TYPE), TRUE);
							EnableWindow(GetDlgItem(hwnd, IDC_CNT_BOOTMSG), FALSE);

							EnableWindow(GetDlgItem(hwnd, IDB_BT_CONF_EMB_PASS), !enable);
							//
							if (enable) {
								EnableWindow(GetDlgItem(hwnd, IDE_RICH_BOOTMSG), __get_check(hwnd, IDC_BT_ENTER_PASS_MSG));

								EnableWindow(GetDlgItem(hwnd, IDC_BT_CANCEL_TMOUT), 
									(BOOL)SendMessage(GetDlgItem(hwnd, IDC_COMBO_AUTH_TMOUT), CB_GETCURSEL, 0, 0));

							}
						}
						break;
					case IDC_COMBO_AUTH_TMOUT:
						{						
							EnableWindow(GetDlgItem(hwnd, IDC_BT_CANCEL_TMOUT), 
								(BOOL)SendMessage((HWND)lparam, CB_GETCURSEL, 0, 0));
							InvalidateRect(GetDlgItem(hwnd, IDC_BT_CANCEL_TMOUT), NULL, TRUE);

						}
						break;
					case IDC_COMBO_METHOD:
						{
							wchar_t text[MAX_PATH];

							HWND hlist = GetDlgItem(hwnd, IDC_PART_LIST_BY_ID);
							BOOL enable;

							_get_item_text(hlist, 0, 0, text, sizeof_w(text));

							enable = _get_combo_val((HWND)lparam, boot_type_ext) == 
								BT_DISK_ID && !wcsstr(text, L"not found");

							EnableWindow(GetDlgItem(hwnd, IDC_STATIC_SELECT_PART), enable);
							EnableWindow(hlist, enable);

						}
						break;

					case IDC_COMBO_LOADER_TYPE: {

						int k = 0;
						int ctl_enb[5] = {
							IDC_HEAD_BOOT_DEV, IDC_WZD_BOOT_DEVS,
							IDC_HEAD_BOOT_FILE, IDE_BOOT_PATH, IDB_BOOT_PATH
						};

						int type = (int)SendMessage(GetDlgItem(hwnd, IDC_COMBO_LOADER_TYPE), CB_GETCURSEL, 0, 0);

						for ( ; k < 5; EnableWindow(GetDlgItem(
							hwnd, ctl_enb[k]), (type < 2 && k < 2) || (type > 1 && k > 1)), k++ );

						if (type < 2) _list_devices(GetDlgItem(hwnd, IDC_WZD_BOOT_DEVS), !type, -1);

						//EnableWindow(GetDlgItem(GetParent(GetParent(hwnd)), IDOK), type > 1);
						SetFocus(GetDlgItem(hwnd, IDE_BOOT_PATH));

					}
					break;
					case IDC_COMBO_BOOT_INST: {

						EnableWindow(GetDlgItem(hwnd, IDB_BOOT_PREF), 
							SendMessage((HWND)lparam, CB_GETCURSEL, 0, 0) == 0);					

					}
					break;
					case IDC_COMBO_KBLAYOUT: {

						SendMessage(hwnd, WM_COMMAND, 
							MAKELONG(IDE_PASS, EN_CHANGE), lparam);

					}
					break;
					case IDC_COMBO_PASSES: {

						_dact *act = _create_act_thread(node, -1, -1);
						if (act) {

							act->wp_mode =
								(int)(SendMessage((HWND)lparam, CB_GETCURSEL, 0, 0));

						}
					}
					break;
				}
			}
			break;
			case EN_CHANGE: {

				if (id == IDE_RICH_BOOTMSG) {


				}

				if (id == IDE_RICH_ERRPASS_MSG) {


				}

				if (id == IDE_BOOT_PATH) {

					wchar_t text[MAX_PATH];
					GetWindowText((HWND)lparam, text, sizeof_w(text));

					EnableWindow(GetDlgItem(GetParent(GetParent(hwnd)), IDOK), text[0] != 0);

				}

				if (id == IDE_PASS || id == IDE_CONFIRM) {

					int kb_layout = -1;
					int entropy;

					wchar_t err[MAX_PATH] = { 0 };
					char *pass;

					if ((pass = secure_alloc(MAX_PASSWORD + 1)) == NULL) break;

					if (IsWindowEnabled(GetDlgItem(hwnd, IDC_COMBO_KBLAYOUT))) {
						kb_layout = _get_combo_val(GetDlgItem(hwnd, IDC_COMBO_KBLAYOUT), kb_layouts);

					}
			
					GetWindowTextA(GetDlgItem(hwnd, IDE_PASS), pass, MAX_PASSWORD + 1);

					_draw_pass_rating(hwnd, pass, kb_layout, err, &entropy);
					secure_free(pass);

					SendMessage(
							GetDlgItem(hwnd, IDP_BREAKABLE),
							PBM_SETPOS,
							(WPARAM)entropy, 0
					);						

					if (IsWindowVisible(GetDlgItem(hwnd, IDE_PASS))) {
						EnableWindow(GetDlgItem(GetParent(GetParent(hwnd)), IDOK), 

							_input_verify(
									GetDlgItem(hwnd, IDE_PASS),
									GetDlgItem(hwnd, IDE_CONFIRM),
									kb_layout,
									err,
									sizeof_w(err)
								)
						);

					}
					SetWindowText(GetDlgItem(hwnd, IDC_ERR), err);
					return 1L;	
				}

			}
			break;
			
			}
		}
		break;

		case WM_CTLCOLOREDIT:
		case WM_CTLCOLORSTATIC:
		case WM_CTLCOLORLISTBOX: {

			COLORREF bgcolor, fn = 0;
		
			dc = (HDC)wparam;
			SetBkMode(dc, TRANSPARENT);

			if (WM_CTLCOLORSTATIC == message) {
				k = 0;
				while (pass_gr_ctls[k].id != -1) {

					if (pass_gr_ctls[k].hwnd == (HWND)lparam)
						fn = pass_gr_ctls[k].color;

					if (pass_pe_ctls[k].hwnd == (HWND)lparam)
						fn = pass_pe_ctls[k].color;

					k++;

				}
				SetTextColor(dc, fn);
				bgcolor = GetSysColor(COLOR_BTNFACE);

			} else bgcolor = _cl(COLOR_BTNFACE, LGHT_CLR);

			SetDCBrushColor(dc, bgcolor);
			return (INT_PTR)GetStockObject(DC_BRUSH);
		
		}
		break;
		case WM_MEASUREITEM: {
			MEASUREITEMSTRUCT *item = pv(lparam);

			if (item->CtlType != ODT_LISTVIEW)
				item->itemHeight -= 3;
 
		}
		break; 
		/*case WM_KEYDOWN: {

			if (wparam == VK_TAB) {
				HWND edit = GetDlgItem(hwnd, IDE_PASS);

				if (edit && (GetFocus( ) == edit))
					SetFocus(GetDlgItem(hwnd, IDE_NEW_PASS));

			}
		}
		break;*/
		case WM_DRAWITEM: {
			_draw_static((LPDRAWITEMSTRUCT)lparam);
			return 1L;

		}
	}
	return 0L;

}


INT_PTR CALLBACK
_shrink_dlg_proc(
		HWND hwnd,
		UINT message,
		WPARAM wparam,
		LPARAM lparam
	)
{
	wchar_t display[MAX_PATH] = { 0 };
	static vol_inf *vol;

	switch (message) {
		case WM_SYSCOMMAND: {
			
			if (wparam == SC_CLOSE) {
				EnableWindow(GetDlgItem(hwnd, IDB_SHRINK_CANCEL), FALSE);

			}
		}
		break;
		case WM_CLOSE: {

			EndDialog(hwnd, 0);
			return 0L;

		}
		break;
		case WM_COMMAND: {

			if (LOWORD(wparam) == IDB_SHRINK_CANCEL) {
				EnableWindow(GetDlgItem(hwnd, IDB_SHRINK_CANCEL), FALSE);

			}
		}
		break;
		case WM_APP + WM_APP_FILE: {

			wchar_t *path = (wchar_t *)wparam;
			wchar_t *file = wcsstr(path+sizeof(wchar_t), L"\\\\");

			_snwprintf(display, sizeof_w(display), L"Scanned files: %d", lparam);
			
			SetWindowText(GetDlgItem(hwnd, IDC_STATIC_FILE), file ? file : path);
			SetWindowText(GetDlgItem(hwnd, IDC_INFO_SCANNED), display);

			return 0L;

		}
		break;
		case WM_INITDIALOG : {

			SendMessage(GetDlgItem(hwnd, IDC_INFO_LABEL), WM_SETFONT, (WPARAM)__font_bold, 0);
			SetForegroundWindow(hwnd);

			return 1L;

		}
		break;
		case WM_DRAWITEM: {

			_draw_static((LPDRAWITEMSTRUCT)lparam);
			return 1L;

		}
	}
	return 0L;

}


static 
int _dc_shrink_callback(
		int stage, 
		vol_inf *inf, 
		wchar_t *file, 
		int status
	)
{
	static int cnt = 0;
	static int total = 0;

	static HWND dlg;
	static HANDLE thread;

	BOOL cancel = FALSE;

	if (stage == SHRINK_BEGIN) {
		ShowWindow(__dlg_shrink, TRUE);

	}
	if (stage == SHRINK_STEP) {		

		if (cnt++ > 120) {
			if (!IsWindowEnabled(GetDlgItem(__dlg_shrink, IDB_SHRINK_CANCEL))) {
				return ST_ERROR;

			}
			total += cnt;	cnt = 0;
			SendMessage(__dlg_shrink, WM_APP + WM_APP_FILE, (WPARAM)file, total);

		}
	}
	if (stage == SHRINK_END) {
		SendMessage(__dlg_shrink, WM_CLOSE, 0, 0);

	}
	return ST_OK;

}

static 
u32 WINAPI _shrink_thread(shrink_thread_info *info)
{
	info->rlt = dc_shrink_volume(
		info->vol->w32_device, HEADER_SIZE + DC_RESERVED_SIZE, _dc_shrink_callback, NULL, info->shd
		);

	return 0;
}


int _shrink_volume(
	   HWND parent, vol_inf *vol, sh_data *shd
	   )
{
	shrink_thread_info info = { vol, -1, shd };
	HANDLE             thread;
	MSG                msg;

	__dlg_shrink = CreateDialog(
		__hinst, MAKEINTRESOURCE(IDD_DIALOG_SHRINK),  parent, _shrink_dlg_proc
		);

	ShowWindow(__dlg_shrink, SW_HIDE);

	shd->sh_pend = (vol->status.flags & F_SYSTEM) != 0;
	shd->offset  = 0;
	shd->value   = 0;
	
	if (thread = CreateThread(NULL, 0, _shrink_thread, &info, 0, NULL))
	{
		SetThreadPriority(thread, THREAD_PRIORITY_BELOW_NORMAL);
		CloseHandle(thread);

		while (GetMessage(&msg, NULL, 0, 0))
		{
			if (info.rlt != -1) {
				break;
			}

			TranslateMessage(&msg); 
			DispatchMessage(&msg); 
		}
	} else {
		info.rlt = ST_ERROR;
	}
	
	return info.rlt;

}


INT_PTR CALLBACK
_link_proc(
		HWND hwnd,
		UINT message,
		WPARAM wparam,
		LPARAM lparam
	)
{
	WNDPROC old_proc = pv(GetWindowLongPtr(hwnd, GWL_USERDATA));
	static BOOL over = FALSE;

	switch (message) {
		case WM_SETCURSOR: {
		
			if (!over) {
				TRACKMOUSEEVENT	track = { sizeof(track) };

				track.dwFlags = TME_LEAVE;
				track.hwndTrack = hwnd;
	
				over = TrackMouseEvent(&track);
				//SetCursor(__cur_hand);
	
			}
			return 0L;
		}
		case WM_MOUSELEAVE: {
		
			over = FALSE;
			//SetCursor(__cur_arrow);
			return 0L;
		}
	}
	return CallWindowProc(old_proc, hwnd, message, wparam, lparam);

}


INT_PTR CALLBACK
_about_dlg_proc(
		HWND hwnd,
		UINT message,
		WPARAM wparam,
		LPARAM lparam
	)
{
	_ctl_init ctl_links[ ] = {
		{ DC_HOMEPAGE, IDC_ABOUT3, 0 },
		{ DC_FORUMPAGE, IDC_ABOUT4, 0 },
		{ L"", -1, -1 }
	};

	static HICON hicon;
	switch (message) {

		case WM_DESTROY: DestroyIcon(hicon);
			return 0L;

		case WM_CLOSE: EndDialog(hwnd, 0);
			return 0L;

		case WM_COMMAND: {
			int id = LOWORD(wparam);
			int k = 0;

			if (id == IDCANCEL || id == IDOK) EndDialog(hwnd, 0);

			while (ctl_links[k].id != -1) {
				if (id == ctl_links[k].id) __execute(ctl_links[k].display);				
				k++;
			}
		}
		break;
		case WM_INITDIALOG : {
			wchar_t display[MAX_PATH];

			BYTE *res;
			int size, id_icon, k=0;

			res = _extract_rsrc(IDI_ICON_TRAY, RT_GROUP_ICON, &size);

			id_icon = LookupIconIdFromDirectoryEx(res, TRUE, 48, 48, 0); 
			res = _extract_rsrc(id_icon, RT_ICON, &size);
 
			hicon = CreateIconFromResourceEx(res, size, TRUE, 0x00030000, 48, 48, 0);
			SendMessage(GetDlgItem(hwnd, IDC_ICON_MAIN), STM_SETICON, (WPARAM)hicon, 0);			
			{
				HWND htitle = GetDlgItem(hwnd, IDC_ABOUT1);

				_snwprintf(display, sizeof_w(display), L"%s %d.%d.%d.%d",
					DC_NAME, DC_MAJOR_VER, DC_MINOR_VER, DC_DRIVER_VER, DC_BOOT_VER);

				SetWindowText(htitle, display);
				SetWindowText(GetDlgItem(hwnd, IDC_EDIT_NOTICE),
					L"This program is free software: you can redistribute "
					L"it and/or modify it under the terms of the GNU General "
					L"Public License as published by the Free Software "
					L"Foundation, either version 3 of the License, "
					L"or any later version.\r\n\r\n"
					L"Portions of this software:\r\n"
					L"Copyright \xa9 1998, 2001, 2002 Brian Palmer\r\n"
					L"Copyright \xa9 2003, Dr Brian Gladman, Worcester, UK.\r\n"
					L"Copyright \xa9 2006, Rik Snel <rsnel@cube.dyndns.org>\r\n"
					L"Copyright \xa9 Vincent Rijmen <vincent.rijmen@esat.kuleuven.ac.be>\r\n"
					L"Copyright \xa9 Antoon Bosselaers <antoon.bosselaers@esat.kuleuven.ac.be>\r\n"
					L"Copyright \xa9 Paulo Barreto <paulo.barreto@terra.com.br>\r\n"
					L"Copyright \xa9 Tom St Denis <tomstdenis@gmail.com>"
				);

				SendMessage(htitle, WM_SETFONT, (WPARAM)__font_bold, 0);
				//SendMessage(GetDlgItem(hwnd, IDC_EDIT_NOTICE), WM_SETFONT, (WPARAM)__font_small, 0);

				while (ctl_links[k].id != -1) {

					HWND ctl = GetDlgItem(hwnd, ctl_links[k].id);

					SetWindowLongPtr(ctl, GWL_USERDATA, (LONG_PTR)GetWindowLongPtr(ctl, GWL_WNDPROC));
					SetWindowLongPtr(ctl, GWL_WNDPROC, (LONG_PTR)_link_proc);

					SetWindowText(ctl, ctl_links[k].display);
					SendMessage(ctl, WM_SETFONT, (WPARAM)__font_link, 0);
					k++;
				}
				{
					speed_test test;
					double enc, dec;

					int rlt;
					if ((rlt = dc_speed_test(&test)) == ST_OK) {
					
						enc = test.data_size / ((double)test.enc_time / (double)test.cpu_freq) / 1024 / 1024;
						dec = test.data_size / ((double)test.dec_time / (double)test.cpu_freq) / 1024 / 1024;

						_snwprintf(display, sizeof_w(display), 
							L" Encryption speed: %f mb/s\n"
							L" Decryption speed: %f mb/s", 
							enc, dec
						);
						SetWindowText(GetDlgItem(hwnd, IDC_SPEED), display);

					}				
				}
			}
			SendMessage(GetDlgItem(hwnd, IDC_EDIT_NOTICE), EM_SCROLLCARET, 0, 0);
			SetForegroundWindow(hwnd);			
			return 1L;
		}
		break;
		case WM_DRAWITEM: {

			_draw_static((LPDRAWITEMSTRUCT)lparam);
			return 1L;
		}
	}
	return 0L;

}


void _dlg_about(
		HWND hwnd
	)
{
	DialogBoxParam(
			NULL,
			MAKEINTRESOURCE(IDD_DIALOG_ABOUT),
			hwnd,
			pv(_about_dlg_proc),
			0
	);		
}


INT_PTR 
CALLBACK
_options_dlg_proc(
		HWND hwnd,
		UINT message,
		WPARAM wparam,
		LPARAM lparam
	)
{
	_ctl_init ctl_chk[ ] = {
		{ L"", IDC_EXPLORER_ON_MOUNT, CONF_EXPLORER_MOUNT },
		{ L"", IDC_UNMOUNT_LOGOFF, CONF_DISMOUNT_LOGOFF },
		{ L"", IDC_CACHE_PASSWORDS, CONF_CACHE_PASSWORD },
		{ L"", IDC_FORCE_UNMOUNT, CONF_FORCE_DISMOUNT },
		{ L"", IDC_WIPE_LOGOFF, CONF_WIPEPAS_LOGOFF },
		{ L"", IDC_ADV_IO_QUEUE, CONF_QUEUE_IO },
		{ L"", IDC_AUTO_START, CONF_AUTO_START },
		{ L"", -1, -1 }
	};

	_ctl_init static_head[ ] = {
		{ L" Mount Settings", IDC_HEAD1, 0 },
		{ L" Password Caching", IDC_HEAD2, 0 },
		{ L" Other Options", IDC_HEAD3, 0 },
		{ L"", -1, -1 }
	};

	WORD code = LOWORD(wparam);
	WORD id = LOWORD(wparam);

	DWORD _flags = 0;
	DWORD _hotkeys[HOTKEYS] = { 0 };

	_wnd_data *wnd;

	int check = 0; int k = 0;
	switch (message) {

		case WM_INITDIALOG: {

			_tab_data *tab = malloc(sizeof(_tab_data));
			wnd_set_long(hwnd, GWL_USERDATA, tab); 

			wnd = __sub_class(GetDlgItem(hwnd, IDB_PREF_GENERAL), 
				CreateDialog(__hinst, MAKEINTRESOURCE(DLG_CONF_GENERAL), GetDlgItem(hwnd, IDC_TAB), _tab_proc), FALSE);

			{
				while (ctl_chk[k].id != -1) {

					__sub_class(GetDlgItem(wnd->dlg, ctl_chk[k].id), FALSE, FALSE);
					__set_check(wnd->dlg, ctl_chk[k].id, __config.conf_flags & ctl_chk[k].val);
					k++;
				}
				k = 0;
				while (static_head[k].id != -1) {

					SetWindowText(GetDlgItem(wnd->dlg, static_head[k].id), static_head[k].display);
					SendMessage(GetDlgItem(wnd->dlg, static_head[k].id), (UINT)WM_SETFONT, (WPARAM)__font_bold, 0);
					k++;
				}	

				SendMessage(wnd->dlg, WM_USER_CLICK, 
					(WPARAM)GetDlgItem(wnd->dlg, IDC_AUTO_START), 0);

			}

			wnd = __sub_class(GetDlgItem(hwnd, IDB_PREF_HOTKEYS), 
				CreateDialog(__hinst, MAKEINTRESOURCE(DLG_CONF_HOTKEYS), GetDlgItem(hwnd, IDC_TAB), _tab_proc), FALSE);

			{
				__sub_class(GetDlgItem(wnd->dlg, IDC_KEY_USEEXT), FALSE, FALSE);

				k = 0;
				while (hotks_edit[k].id != -1) {
					wchar_t key[200] = { 0 };

					__sub_class(GetDlgItem(wnd->dlg, hotks_edit[k].id), FALSE, TRUE);
					__sub_class(GetDlgItem(wnd->dlg, hotks_chk[k].id), FALSE, FALSE);

					__set_check(wnd->dlg, hotks_chk[k].id, __config.hotkeys[k]);
					SendMessage(wnd->dlg, WM_USER_CLICK, (WPARAM)GetDlgItem(wnd->dlg, hotks_chk[k].id), 0);

					_key_name(HIWORD(__config.hotkeys[k]), LOWORD(__config.hotkeys[k]), key);
					SetWindowText(GetDlgItem(wnd->dlg, hotks_edit[k].id), key);

					((_wnd_data *)wnd_get_long(GetDlgItem(
						wnd->dlg, hotks_edit[k].id), GWL_USERDATA))->vk = __config.hotkeys[k];

					k++;
				}
			}
			SendMessage(GetDlgItem(hwnd, IDB_PREF_GENERAL), WM_LBUTTONDOWN, 0, 0);
			SetForegroundWindow(hwnd);

			return 1L;
		}
		break;

		case WM_COMMAND: {
			if ((id == IDOK) || (id == IDCANCEL)) {

				wnd = wnd_get_long(GetDlgItem(hwnd, IDB_PREF_GENERAL), GWL_USERDATA);
				if (wnd) {

					k = 0;
					while (ctl_chk[k].id != -1) {	
						_flags |= __get_check(wnd->dlg, ctl_chk[k].id) ? ctl_chk[k].val : FALSE;
						k++;
					}
				}
				wnd = wnd_get_long(GetDlgItem(hwnd, IDB_PREF_HOTKEYS), GWL_USERDATA);
				if (wnd) {

					k = 0;
					while (hotks_edit[k].id != -1) {
					
						if (__get_check(wnd->dlg, hotks_chk[k].id))
							_hotkeys[k] = ((_wnd_data *)wnd_get_long(GetDlgItem(wnd->dlg, hotks_edit[k].id), GWL_USERDATA))->vk;
						k++;
					}
				}
				
				if (id == IDCANCEL) check = TRUE;
				if (id == IDOK) {

					_unset_hotkeys(__config.hotkeys);	
					check = _check_hotkeys(wnd->dlg, _hotkeys);					

					if (check) {
						if (_hotkeys[3] && !__config.hotkeys[3]) {
							if (!__msg_w(L"Set Hotkey for call BSOD?", hwnd)) _hotkeys[3] = 0;

						}
						if ((_flags & CONF_AUTO_START) != (__config.conf_flags & CONF_AUTO_START)) {
							autorun_set(_flags & CONF_AUTO_START);
						}

						__config.conf_flags = _flags;
						memcpy(&__config.hotkeys, &_hotkeys, sizeof(DWORD)*HOTKEYS);

						dc_save_conf(&__config);						

					}
					_set_hotkeys(hwnd, __config.hotkeys, FALSE);

				}
				if (check) EndDialog (hwnd, id);
				return 1L;
			}
		}
		break;
		case WM_DRAWITEM: {

			_draw_static((LPDRAWITEMSTRUCT)lparam);
      return 1L;

		}
		break;

		case WM_DESTROY: {
			wnd = wnd_get_long(GetDlgItem(hwnd, IDB_PREF_GENERAL), GWL_USERDATA);
			if (wnd) {

				k = 0;
				while (ctl_chk[k].id != -1) {
					__unsub_class(GetDlgItem(wnd->dlg, ctl_chk[k].id));
					k++;
				}
			}
			wnd = wnd_get_long(GetDlgItem(hwnd, IDB_PREF_HOTKEYS), GWL_USERDATA);
			if (wnd) {

				__unsub_class(GetDlgItem(wnd->dlg, IDC_KEY_USEEXT));

				k = 0;
				while (hotks_edit[k].id != -1) {

					__unsub_class(GetDlgItem(wnd->dlg, hotks_edit[k].id));
					__unsub_class(GetDlgItem(wnd->dlg, hotks_chk[k].id));
					k++;

				}
			}
			__unsub_class(GetDlgItem(hwnd, IDB_PREF_GENERAL));
			__unsub_class(GetDlgItem(hwnd, IDB_PREF_HOTKEYS));
			__unsub_class(GetDlgItem(hwnd, IDB_PREF_BOOT));

		}
	}
	return 0L;

}


INT_PTR CALLBACK
_password_dlg_proc(
		HWND hwnd,
		UINT message,
		WPARAM wparam,
		LPARAM lparam
	)
{
	WORD code = HIWORD(wparam);
	WORD id = LOWORD(wparam);

	int k;

	wchar_t display[MAX_PATH] = { 0 };
	static dlgpass *info;

	static BOOL mount;

	switch (message) {
		case WM_DRAWITEM : {

			DRAWITEMSTRUCT *draw = pv(lparam);

			static RECT left;
			static RECT right;

			if (mount)
			switch (draw->CtlID) {

				case IDC_FRAME_LEFT: {

					int offset = 4;
					if (!left.bottom) {

						left.bottom = draw->rcItem.bottom - 160 + offset;
						left.top = --offset; left.left = offset;
						left.right = draw->rcItem.right + --offset;

					}
					InvalidateRect(GetDlgItem(hwnd, IDC_FRAME_RIGHT), 0, TRUE);
					MoveWindow(draw->hwndItem, 
						left.left, left.top, left.right, left.bottom, TRUE);

				}
				break;
				case IDC_FRAME_RIGHT: {

					if (!left.bottom) break;
					if (!right.bottom) {

						right.top = left.top; right.left = left.right + 6;
						right.right = draw->rcItem.right+2;
						right.bottom = left.bottom;

					}
					MoveWindow(draw->hwndItem,
						right.left, right.top, right.right, right.bottom, TRUE);

				}
				break;

			}

			_draw_static(draw);
			return 1L;		

		}
		break;
		case WM_CTLCOLOREDIT : {
			return _ctl_color(wparam, _cl(COLOR_BTNFACE, LGHT_CLR));

		}
		break;
		case WM_CTLCOLORSTATIC: {

			HDC dc = (HDC)wparam;
			COLORREF bgcolor, fn = 0;

			int k = 0;			
			SetBkMode(dc, TRANSPARENT);

			while (pass_gr_ctls[k].id != -1) {

				if (pass_gr_ctls[k].hwnd == (HWND)lparam)
					fn = pass_gr_ctls[k].color;

				if (pass_pe_ctls[k].hwnd == (HWND)lparam)
					fn = pass_pe_ctls[k].color;

				k++;

			}
			SetTextColor(dc, fn);

			bgcolor = GetSysColor(COLOR_BTNFACE);
			SetDCBrushColor(dc, bgcolor);
			
			return (INT_PTR)GetStockObject(DC_BRUSH);
		
		}
		break;
		case WM_INITDIALOG : {

			int ctl_show[4] = {
				IDC_NEW_PASS, IDC_NEW_CONFIRM,
				IDE_NEW_PASS, IDE_NEW_CONFIRM

			};
			int ctl_resize[2] = {
				IDC_FRAME_LEFT, IDC_FRAME_RIGHT

			};

			info = (dlgpass *)lparam;
			mount = info->query == QR_MOUNT ? TRUE : FALSE;

			SendMessage(GetDlgItem(hwnd, IDE_PASS), EM_LIMITTEXT, MAX_PASSWORD, 0);
			SendMessage(GetDlgItem(hwnd, IDE_NEW_PASS), EM_LIMITTEXT, MAX_PASSWORD, 0);
			SendMessage(GetDlgItem(hwnd, IDE_NEW_CONFIRM), EM_LIMITTEXT, MAX_PASSWORD, 0);

			SendMessage(hwnd, WM_COMMAND, 
				MAKELONG(IDE_NEW_PASS, EN_CHANGE), (LPARAM)GetDlgItem(hwnd, IDE_NEW_PASS));

			if (info->node) {
				_snwprintf(display, sizeof_w(display), L"[%s] - %s", 
					info->node->mnt.info.status.mnt_point, info->node->mnt.info.device);

			} else {
				wcscpy(display, L"Enter password");
			}
			SetWindowText(hwnd, display);
			
			SendMessage(
				GetDlgItem(hwnd, IDP_BREAKABLE),
				PBM_SETBARCOLOR, 0, _cl(COLOR_BTNSHADOW, DARK_CLR-20)

			);	
			SendMessage(
				GetDlgItem(hwnd, IDP_BREAKABLE),
				PBM_SETRANGE, 0,
				MAKELPARAM(0, 193)
			);

			SetWindowText(GetDlgItem(hwnd, IDC_HEAD_CURRENT), L" Current Password");
			SendMessage(GetDlgItem(hwnd, IDC_HEAD_CURRENT), WM_SETFONT, (WPARAM)__font_bold, 0);

			SetWindowText(GetDlgItem(hwnd, IDC_HEAD_RATING), L" Password Rating");
			SendMessage(GetDlgItem(hwnd, IDC_HEAD_RATING), WM_SETFONT, (WPARAM)__font_bold, 0);

			if (mount)
			{
				RECT rc,prc;
				
				GetWindowRect(GetDlgItem(hwnd, IDC_CHECK_SHOW), &rc);
				GetWindowRect(hwnd, &prc);

				rc.top -= prc.top+60;
				rc.left -= prc.left;

				rc.bottom = prc.bottom - rc.bottom;
				rc.right = prc.right - rc.right;				
				
				prc.bottom -= 160;

				MoveWindow(GetDlgItem(hwnd, IDC_CHECK_SHOW), 
					rc.left, rc.top, rc.right-rc.left+40, rc.bottom-rc.top, TRUE);		

				SetWindowPos(hwnd, 
					HWND_TOP, prc.left, prc.top, prc.right-prc.left, prc.bottom-prc.top, 0);		

				for ( k=0; k<4; ShowWindow(
					GetDlgItem(hwnd, ctl_show[k]), FALSE), k++ );

			
			}
			SetForegroundWindow(hwnd);

			__sub_class(GetDlgItem(hwnd, IDC_CHECK_SHOW), FALSE, FALSE);
			__set_check(hwnd, IDC_CHECK_SHOW, FALSE);

			return 1L;

		}
		break;
		case WM_USER_CLICK : {
			if ((HWND)wparam == GetDlgItem(hwnd, IDC_CHECK_SHOW)) {

				int mask = __get_check(hwnd, IDC_CHECK_SHOW) ? 0 : '*';

				SendMessage(GetDlgItem(hwnd, IDE_PASS),
					EM_SETPASSWORDCHAR,	mask, 0
				);
				SendMessage(GetDlgItem(hwnd, IDE_NEW_PASS),
					EM_SETPASSWORDCHAR,	mask, 0
				);
				SendMessage(GetDlgItem(hwnd, IDE_NEW_CONFIRM),
					EM_SETPASSWORDCHAR,	mask, 0
				);

				InvalidateRect(GetDlgItem(hwnd, IDE_PASS), NULL, TRUE);
				InvalidateRect(GetDlgItem(hwnd, IDE_NEW_PASS), NULL, TRUE);
				InvalidateRect(GetDlgItem(hwnd, IDE_NEW_CONFIRM), NULL, TRUE);

				return 1L;

			}
		}
		break;
		case WM_COMMAND :
			if (code == EN_CHANGE) {

				BOOL correct = FALSE;
				wchar_t err[MAX_PATH] = { 0 };

				ldr_config conf;
				int kb_layout = -1;

				if (info->node && _is_boot_device(&info->node->mnt.info)) {

					if (dc_get_mbr_config(-1, NULL, &conf) == ST_OK) {
						kb_layout = conf.kbd_layout;

					}
				}
				if (id == IDE_NEW_PASS && info->query != QR_MOUNT) {

					int entropy;
					char *pass;

					if ((pass = secure_alloc(MAX_PASSWORD + 1)) == NULL) break;
					GetWindowTextA(GetDlgItem(hwnd, IDE_NEW_PASS), pass, MAX_PASSWORD + 1);

					_draw_pass_rating(hwnd, pass, kb_layout, err, &entropy);
					secure_free(pass);

					SendMessage(
							GetDlgItem(hwnd, IDP_BREAKABLE),
							PBM_SETPOS,
							(WPARAM)entropy, 0
					);			
				}

				correct = 
					_input_verify(
							GetDlgItem(hwnd, IDE_PASS),
							(HWND)-1, -1,
							err,
							sizeof_w(err)
						);

				EnableWindow(
					GetDlgItem(hwnd, IDOK), correct);

				if (info->query == QR_CHANGE_PASS) {
					if (correct) {

						EnableWindow(GetDlgItem(hwnd, IDOK),

							_input_verify(
									GetDlgItem(hwnd, IDE_NEW_PASS),
									GetDlgItem(hwnd, IDE_NEW_CONFIRM),
									kb_layout,
									err,
									sizeof_w(err)
								)

						);
					}
				}
				return 1L;
		
			}
			if ((id == IDCANCEL) || (id == IDOK)) 
			{
				wchar_t wipe[MAX_PASSWORD + 1];
				wipe[MAX_PASSWORD] = 0;

				if (id == IDOK) 
				{
					info->pass     = secure_alloc(MAX_PASSWORD + 1);
					info->new_pass = secure_alloc(MAX_PASSWORD + 1);

					if (info->pass && info->new_pass) {

						GetWindowTextA(GetDlgItem(hwnd, IDE_PASS), info->pass, MAX_PASSWORD + 1);
						GetWindowTextA(GetDlgItem(hwnd, IDE_NEW_PASS), info->new_pass, MAX_PASSWORD + 1);

					}
				}
				memset(wipe, '#', MAX_PASSWORD*sizeof(wchar_t));

				SetWindowText(GetDlgItem(hwnd, IDE_PASS), wipe);
				SetWindowText(GetDlgItem(hwnd, IDE_NEW_PASS), wipe);
				SetWindowText(GetDlgItem(hwnd, IDE_NEW_CONFIRM), wipe);

				EndDialog (hwnd, id);
				return 1L;
	
			}
	}
	return 0L;

}


INT_PTR 
CALLBACK
_wizard_encrypt_dlg_proc(
		HWND hwnd,
		UINT message,
		WPARAM wparam,
		LPARAM lparam
	)
{
	WORD code = LOWORD(wparam);
	WORD id = LOWORD(wparam);

	static HWND sheets[BOOT_SHEETS];
	static vol_inf *vol;
	static _dnode *node;

	static skip_boot;
	static index;	

	int cr = 0;
	int check = 0; int k = 0;

	switch (message) {
		case WM_INITDIALOG: {

			drive_inf drv;

			_ctl_init static_head[3] = {
				{L" Encryption Settings", IDC_PAGE1, 0 },
				{L" Boot Settings", IDC_PAGE2, 0 },
				{L" Volume Password", IDC_PAGE3, 0 }
			};
			int combo_sel[4] = {
				IDC_COMBO_ALGORT, IDC_COMBO_HASH,
				IDC_COMBO_MODE, IDC_COMBO_PASSES
			};
			int dlg_pages[BOOT_SHEETS] = {
				DLG_WIZ_CONF, DLG_WIZ_LOADER,
				DLG_WIZ_PASS
			};

			vol = &((_dnode *)lparam)->mnt.info;
			node = (_dnode *)lparam;

			skip_boot = TRUE;
			index = 0;

			for ( k = 0 ;k < BOOT_SHEETS; sheets[k] = CreateDialog(__hinst,
				MAKEINTRESOURCE(dlg_pages[k]), GetDlgItem(hwnd, IDC_TAB), _tab_proc), k++ );

			SetWindowText(hwnd, vol->device);
			//////////////////////////////////////////////////////////////////////////////////////////////
			hwnd = sheets[cr++];
			{

				SendMessage(GetDlgItem(hwnd, IDC_COMBO_ALGORT), (UINT)CB_ADDSTRING, 0, (LPARAM)L"AES");
				SendMessage(GetDlgItem(hwnd, IDC_COMBO_HASH), (UINT)CB_ADDSTRING, 0, (LPARAM)L"SHA1");
				SendMessage(GetDlgItem(hwnd, IDC_COMBO_MODE), (UINT)CB_ADDSTRING, 0, (LPARAM)L"LRW");

				_init_combo(GetDlgItem(hwnd, IDC_COMBO_PASSES), wipe_modes, WP_NONE, FALSE);

				for ( k = 0 ;k < 4; SendMessage(GetDlgItem(hwnd, 
					combo_sel[k]), CB_SETCURSEL, 0, 0), k++ );
				 
			}
			//////////////////////////////////////////////////////////////////////////////////////////////
			hwnd = sheets[cr++]; 
			{

				int dsk_num = -1;
				int rlt;
				{				
					ldr_config conf;
					int boot_disk;

					if (_is_boot_device(vol)) skip_boot = FALSE;

					rlt = dc_get_drive_info(vol->w32_device, &drv);
					if (ST_OK == rlt) dsk_num = drv.disks[0].number;

					rlt = dc_get_boot_disk(&boot_disk);
					if (ST_OK == rlt) {
	
						if (ST_OK == dc_get_mbr_config(boot_disk, NULL, &conf))
							skip_boot = TRUE;

					}
				}
				_list_devices(GetDlgItem(hwnd, IDC_BOOT_DEVS), TRUE, dsk_num);
				SendMessage(GetDlgItem(hwnd, IDC_COMBO_BOOT_INST), (UINT)CB_ADDSTRING, 0, (LPARAM)L"Use external bootloader"); 

				if (ST_OK != rlt) {
					SetWindowText(GetDlgItem(hwnd, IDC_WARNING), L"Bootable HDD not found!");
					SendMessage(GetDlgItem(hwnd, IDC_COMBO_BOOT_INST), CB_SETCURSEL, 0, 0);

					SendMessage(GetDlgItem(hwnd, IDC_WARNING), (UINT)WM_SETFONT, (WPARAM)__font_bold, 0);
					EnableWindow(GetDlgItem(hwnd, IDB_BOOT_PREF), TRUE);				

				} else {		
					SendMessage(GetDlgItem(hwnd, IDC_COMBO_BOOT_INST), (UINT)CB_ADDSTRING, 0, (LPARAM)L"Install to HDD"); 					
					SendMessage(GetDlgItem(hwnd, IDC_COMBO_BOOT_INST), CB_SETCURSEL, 1, 0);

				}

			}
			//////////////////////////////////////////////////////////////////////////////////////////////
			hwnd = sheets[cr++]; 
			{
				BOOL kb_active = _is_boot_device(vol);

				__sub_class(GetDlgItem(hwnd, IDC_CHECK_SHOW), FALSE, FALSE);
				__set_check(hwnd, IDC_CHECK_SHOW, FALSE);

				_init_combo(GetDlgItem(hwnd, IDC_COMBO_KBLAYOUT), kb_layouts, KB_QWERTY, FALSE);

				SendMessage(
					GetDlgItem(hwnd, IDP_BREAKABLE),
					PBM_SETBARCOLOR, 0, _cl(COLOR_BTNSHADOW, DARK_CLR-20)

				);	
				SendMessage(
					GetDlgItem(hwnd, IDP_BREAKABLE),
					PBM_SETRANGE, 0,
					MAKELPARAM(0, 193)
				);

				SetWindowText(GetDlgItem(hwnd, IDC_PAGE4), L" Password Rating");
				SendMessage(GetDlgItem(hwnd, IDC_PAGE4), (UINT)WM_SETFONT, (WPARAM)__font_bold, 0);
				SendMessage(GetDlgItem(hwnd, IDC_ERR), (UINT)WM_SETFONT, (WPARAM)__font_bold, 0);

				EnableWindow(GetDlgItem(hwnd, IDC_LAUOUTS_LIST), kb_active);
				EnableWindow(GetDlgItem(hwnd, IDC_COMBO_KBLAYOUT), kb_active);

				SendMessage(GetDlgItem(hwnd, IDC_COMBO_KBLAYOUT), CB_SETCURSEL, 0, 0);				

				SendMessage(GetDlgItem(hwnd, IDE_PASS), EM_LIMITTEXT, MAX_PASSWORD, 0);
				SendMessage(GetDlgItem(hwnd, IDE_CONFIRM), EM_LIMITTEXT, MAX_PASSWORD, 0);
		
			}
			/////////////////////////////////////////////////////////////////////////////////////////////////////////////////		

			for ( k = 0; k < BOOT_SHEETS; k++ ) {
				EnumChildWindows(sheets[k], __sub_enum, (LPARAM)NULL);

				SetWindowText(GetDlgItem(sheets[k], static_head[k].id), static_head[k].display);
				SendMessage(GetDlgItem(sheets[k], static_head[k].id), (UINT)WM_SETFONT, (WPARAM)__font_bold, 0);

			}
			ShowWindow(sheets[0], SW_SHOW);
			SetForegroundWindow(hwnd);
			sheets[BOOT_SHEETS] = (HWND)lparam;
			return 1L;

		}
		break;
		case WM_COMMAND: {
			
			EnableWindow(GetDlgItem(hwnd, IDC_BACK), TRUE);		
			ShowWindow(sheets[index], SW_HIDE);

			if (id == IDOK) {
				if (index >= BOOT_SHEETS-1) {

					int rlt = ST_OK;
					ShowWindow(hwnd, FALSE);

					{
						BOOL set_loader = (BOOL)
							SendMessage(GetDlgItem(sheets[1], IDC_COMBO_BOOT_INST), CB_GETCURSEL, 0, 0);

						int wp_mode = (int)
							SendMessage(GetDlgItem(sheets[0], IDC_COMBO_PASSES), CB_GETCURSEL, 0, 0);

						int kb_layout = _get_combo_val(GetDlgItem(sheets[2], IDC_COMBO_KBLAYOUT), kb_layouts);
						ldr_config conf;

						node->mnt.info.status.wp_mode = wp_mode;
						if (!skip_boot) {

							if (set_loader) rlt = _set_boot_loader(hwnd, -1);

							if ((rlt == ST_OK) &&
									(rlt = dc_get_mbr_config(-1, NULL, &conf)) == ST_OK) {

								conf.kbd_layout = kb_layout;								
								rlt = dc_set_mbr_config(-1, NULL, &conf);

							}
						}
						if (ST_OK == rlt) 
						{
							sh_data shd;
							char   *pass;

							if ( (rlt = _shrink_volume(hwnd, vol, &shd)) == ST_OK )
							{
								if (pass = secure_alloc(MAX_PASSWORD + 1))
								{
									wchar_t wipe[MAX_PASSWORD + 1];

									wipe[MAX_PASSWORD] = 0;
									memset(wipe, '#', MAX_PASSWORD*sizeof(wchar_t));

									GetWindowTextA(GetDlgItem(sheets[2], IDE_PASS), pass, MAX_PASSWORD + 1);
									rlt = dc_start_encrypt(vol->device, pass, wp_mode);

									if ( (rlt == ST_OK) && (shd.sh_pend != 0) ) {
										rlt = dc_set_shrink_pending(vol->device, &shd);
									}
									
									SetWindowText(GetDlgItem(sheets[2], IDE_PASS), wipe);
									SetWindowText(GetDlgItem(sheets[2], IDE_CONFIRM), wipe);
									secure_free(pass);
								}
							}
						}
					}
					EndDialog(hwnd, rlt);
					
				}					
				if (skip_boot) index++; 
				index++;

			}
			if (id == IDC_BACK) {

				if (skip_boot) index--;
				index--;

			}
			EnableWindow(GetDlgItem(hwnd, IDC_BACK), index);
			if (index >= BOOT_SHEETS-1) {
				
				SetWindowText(GetDlgItem(hwnd, IDOK), L"OK");
				EnableWindow(GetDlgItem(hwnd, IDOK), FALSE);

			} else {
				SetWindowText(GetDlgItem(hwnd, IDOK), L"&Next");
				EnableWindow(GetDlgItem(hwnd, IDOK), TRUE);

			}
			ShowWindow(sheets[index], SW_SHOW);

			SetFocus(GetDlgItem(sheets[index], IDE_PASS));
			SendMessage(sheets[index], WM_COMMAND, MAKELONG(IDE_PASS, EN_CHANGE), (LPARAM)GetDlgItem(sheets[index], IDE_PASS));

			if (id == IDCANCEL) {
				EndDialog(hwnd, ST_CANCEL);
				return 0L;

			}
		}
		break;
		case WM_DRAWITEM: {

			_draw_static((LPDRAWITEMSTRUCT)lparam);
      return 1L;

		}
		break;

	}
	return 0L;

}


int _dlg_options(
		HWND hwnd
	)
{
	int result =
		(int)DialogBoxParam(
				NULL,
				MAKEINTRESOURCE(IDD_DIALOG_OPTIONS),
				hwnd,
				pv(_options_dlg_proc),
				(LPARAM)NULL
		);

	return result == IDOK ? ST_OK : ST_CANCEL;

}


int _dlg_config_loader(
		HWND hwnd,
		BOOL external
	)
{
	int result =
		(int)DialogBoxParam(
				NULL, 
				MAKEINTRESOURCE(IDD_WIZARD_BOOT),
				hwnd,
				pv(_wizard_boot_dlg_proc),
				(LPARAM)external
		);

	return result == IDOK ? ST_OK : ST_CANCEL;

}


int _dlg_get_pass(
		HWND hwnd,
		dlgpass *pass
	)
{
	int result =
		(int)DialogBoxParam(
				NULL, 
				MAKEINTRESOURCE(IDD_DIALOG_PASS),
				hwnd,
				pv(_password_dlg_proc),
				(LPARAM)pass
		);

	return result == IDOK ? ST_OK : ST_CANCEL;

}


void _init_main_dlg(
		HWND hwnd
	)
{
	MENUITEMINFO mnitem = { sizeof(mnitem) };

	HWND henum = hwnd;
	EnumWindows(_enum_proc, (LPARAM)&henum);

	if (henum != hwnd) {
			
		ShowWindow(henum, SW_SHOW);
		SetForegroundWindow(henum);
				
		ExitProcess(0);
	} else {

		__dlg = hwnd;

		SendMessage(hwnd, WM_SYSCOLORCHANGE, 0, 0);		
		_set_hotkeys(hwnd, __config.hotkeys, TRUE);

		_tray_icon(TRUE);

		mnitem.fMask =  MIIM_FTYPE;
		mnitem.fType = MFT_RIGHTJUSTIFY;
		SetMenuItemInfo(GetMenu(hwnd), ID_HOMEPAGE, FALSE, &mnitem);

		SendMessage(GetDlgItem(hwnd, IDC_DRIVES_HEAD), WM_SETFONT, (WPARAM)__font_bold, 0);		

	}
}


void _get_time_period(
		__int64 begin,
		wchar_t *display
	)
{
	LARGE_INTEGER curr;
	SYSTEMTIME st;
	FILETIME ft;

	int j = 0;

	GetSystemTimeAsFileTime(&ft);
	curr.HighPart = ft.dwHighDateTime;
	curr.LowPart = ft.dwLowDateTime;
			
	curr.QuadPart -= begin;

	ft.dwHighDateTime = curr.HighPart;
	ft.dwLowDateTime = curr.LowPart;

	FileTimeToSystemTime(&ft, &st);

	if (st.wHour)   j += _snwprintf(display+j, 4, L"%dh ",   st.wHour);
	if (st.wMinute) j += _snwprintf(display+j, 4, L"%dm:",   st.wMinute);
	if (st.wSecond) j += _snwprintf(display+j, 4, L"%02ds ", st.wSecond);
	
	display[j] = '\0';


}


void _update_info_table( )
{
	HWND hlist = GetDlgItem(__dlg, IDC_DISKDRIVES);

	HWND idb_inf = GetDlgItem(__dlg, IDB_MAIN_INFO);
	HWND idb_act = GetDlgItem(__dlg, IDB_MAIN_ACTION);

	_dnode *node = pv(_get_sel_item(hlist));
	_dact *act = _create_act_thread(node, -1, -1);

	_wnd_data *wnd_inf = wnd_get_long(idb_inf, GWL_USERDATA);
	_wnd_data *wnd_act = wnd_get_long(idb_act, GWL_USERDATA);

	HWND htable_inf = GetDlgItem(wnd_inf->dlg, IDC_INF_TABLE); 
	HWND htable_act = GetDlgItem(wnd_act->dlg, IDC_ACT_TABLE); 

	BOOL idb_inf_enb = FALSE;
	BOOL idb_act_enb = FALSE;

	int k = 0;

	if (SendMessage(GetDlgItem(wnd_act->dlg, 
		IDC_COMBO_PASSES), CB_GETDROPPEDSTATE, 0, 0)) return;

	for ( ; k<2; k++ ) {

		_list_set_item_text(htable_act, k, 1, L"--");
		_list_set_item_text(htable_act, k, 3, L"--");

	}	
	if (ListView_GetSelectedCount(hlist) && node) {
		if (!node->is_root) {

			_list_set_item_text(htable_inf, 0, 1, node->mnt.info.device);
			_list_set_item_text(htable_inf, 1, 1, L"");

			idb_inf_enb = TRUE;

			if (act) {

				EnableWindow(GetDlgItem(wnd_act->dlg, IDC_COMBO_PASSES), 
					ACT_ENCRYPT == act->act);

				EnableWindow(GetDlgItem(wnd_act->dlg, IDC_STATIC_PASSES_LIST), 
					ACT_ENCRYPT == act->act);				

				EnableWindow(GetDlgItem(wnd_act->dlg, IDB_ACT_PAUSE), 
					ACT_RUNNING == act->status);

				EnableWindow(GetDlgItem(wnd_act->dlg, IDC_STATIC_SECTOR), 
					ACT_RUNNING == act->status);

				EnableWindow(GetDlgItem(wnd_act->dlg, IDC_ACT_TABLE), 
					ACT_RUNNING == act->status);

				{
					HWND hsector = GetDlgItem(wnd_act->dlg, IDC_STATIC_SECTOR);

					wchar_t s_time_period[MAX_PATH];
					wchar_t s_sectors[MAX_PATH];
					wchar_t s_old[MAX_PATH];

					wchar_t s_speed[MAX_PATH];
					wchar_t s_done[MAX_PATH];

					u64 done;
					u64 sectors;

					int odd;
					int new_pos;
					int j = 0;

					dc_status *status = &node->mnt.info.status;
					dc_get_device_status(node->mnt.info.device, status);					

					_get_time_period(act->begin.QuadPart, s_time_period);

					new_pos = (int)(status->tmp_size/(status->dsk_size/PRG_STEP));
					sectors = status->tmp_size / 512;

					if (act->act == ACT_DECRYPT) {

						new_pos = PRG_STEP - new_pos;
						odd = (int)(act->last_size - status->tmp_size);

						done = status->dsk_size - status->tmp_size;
						sectors = status->dsk_size / 512 - sectors;

					} else {

						odd = (int)(status->tmp_size - act->last_size);
						done = status->tmp_size;

					}						

					_snwprintf(s_speed, sizeof_w(s_speed), L"%.2f mb/s ", 
						(double)(odd * (1000 / _tmr_elapse[PROC_TIMER])) / 1024 / 1024);

					dc_format_byte_size(s_done, sizeof_w(s_done), done);

					j = _snwprintf(s_sectors, sizeof_w(s_sectors), L"Sector: %d\t\t", sectors);
					j = _snwprintf(s_sectors+j, sizeof_w(s_sectors)-j, L"Total Sectors: %d", status->dsk_size / 512);		

					_list_set_item_text(htable_act, 0, 1, _wcslwr(s_done));
					_list_set_item_text(htable_act, 1, 1, ACT_RUNNING == act->status ? s_speed : L"--");

					if (ACT_RUNNING == act->status) {

						_list_set_item_text(htable_act, 0, 3, s_time_period);
						_list_set_item_text(htable_act, 1, 3, L"");

					}
					GetWindowText(hsector, s_old, sizeof_w(s_old));
					if (wcscmp(s_old, s_sectors)) SetWindowText(hsector, s_sectors);

					SendMessage(GetDlgItem(wnd_act->dlg, IDC_COMBO_PASSES), CB_SETCURSEL, act->wp_mode, 0);

					SendMessage(
						GetDlgItem(wnd_act->dlg, IDC_PROGRESS),
						PBM_SETPOS,
						(WPARAM)new_pos, 0
					);

					act->last_size = status->tmp_size;	
				}
				idb_act_enb = TRUE;
					
			}
		}
	}

	if (!idb_act_enb && !_is_curr_in_group(idb_inf)) 			
			SendMessage(idb_inf, WM_LBUTTONDOWN, 0, 0);

	if (!idb_inf_enb) {

		_list_set_item_text(htable_inf, 0, 1, L"");
		_list_set_item_text(htable_inf, 1, 1, L"");

	}
	if (!idb_act_enb) {

		SendMessage(GetDlgItem(wnd_act->dlg, IDC_COMBO_PASSES), CB_SETCURSEL, 0, 0);
		SendMessage(GetDlgItem(wnd_act->dlg, IDC_PROGRESS), PBM_SETPOS, 0, 0);

		SetWindowText(GetDlgItem(wnd_act->dlg, IDC_STATIC_SECTOR), NULL);

	}	
	EnableWindow(idb_inf, idb_inf_enb);
	EnableWindow(idb_act, idb_act_enb);
	

}


INT_PTR 
CALLBACK
_wizard_boot_dlg_proc(
		HWND hwnd,
		UINT message,
		WPARAM wparam,
		LPARAM lparam
	)
{
	WORD code = HIWORD(wparam);
	WORD id = LOWORD(wparam);

	DWORD _flags = 0;
	DWORD _hotkeys[HOTKEYS] = { 0 };

	static HWND sheets[BOOT_WZR_SHEETS];
	static ldr_config *ldr;

	int check = 0; int k = 0;
	switch (message) {

		case WM_INITDIALOG: {

			wchar_t *loader_type[4] = {
				L"HDD master boot record",
				L"Bootable partition (Floppy, USB-Stick, etc)",
				L"ISO bootloader image",
				L"Bootloader image for PXE network booting"

			};

			int dlgs_pages[2] = {
				DLG_BOOT_SET, DLG_BOOT_CONF
			};

			for ( k = 0 ;k < 2; sheets[k] = CreateDialog(__hinst,
				MAKEINTRESOURCE(dlgs_pages[k]), GetDlgItem(hwnd, IDC_TAB), _tab_proc), k++ );

			hwnd = sheets[0];
			{
				for ( k = 0 ;k < 4; SendMessage(GetDlgItem(hwnd,
					IDC_COMBO_LOADER_TYPE), (UINT)CB_ADDSTRING, 0, (LPARAM)loader_type[k]), k++ );

				SendMessage(GetDlgItem(hwnd, IDC_COMBO_LOADER_TYPE), CB_SETCURSEL, lparam ? 2 : 0, 0);
				SendMessage(hwnd, WM_COMMAND, MAKELONG(IDC_COMBO_LOADER_TYPE, CBN_SELCHANGE), 0);

				_list_devices(GetDlgItem(hwnd, IDC_WZD_BOOT_DEVS), TRUE, -1);

				__sub_class(GetDlgItem(hwnd, IDC_CHECK_CONFIG), FALSE, FALSE);
				__set_check(hwnd, IDC_CHECK_CONFIG, FALSE);							

			}
			ShowWindow(sheets[0], SW_SHOW);

		}
		break;
		case WM_COMMAND: {
			if (IDOK == id) 
			{
				HWND hlist = GetDlgItem(sheets[0], IDC_WZD_BOOT_DEVS);

				static int type;
				int rlt = ST_OK;

				static int dsk_num = -1;
				static ldr_config conf;

				_wnd_data *wnd;			

				static wchar_t path[MAX_PATH] = { 0 };
				static wchar_t vol[MAX_PATH] = { 0 };
				
				wchar_t text[MAX_PATH];

				hwnd = sheets[1];
				if (!IsWindowVisible(hwnd)) 
				{
					type = (int)SendMessage(GetDlgItem(sheets[0], IDC_COMBO_LOADER_TYPE), CB_GETCURSEL, 0, 0);
					if (!type) dsk_num = _ext_disk_num(hlist);

					_get_item_text(hlist, ListView_GetSelectionMark(hlist), 0, vol, sizeof_w(vol));
					_get_item_text(hlist, ListView_GetSelectionMark(hlist), 2, text, sizeof_w(text));

					GetWindowText(GetDlgItem(sheets[0], IDE_BOOT_PATH), path, sizeof_w(path));

					switch (type) {
						case 0: 
						case 1: 
							if (wcscmp(text, L"installed")) {
								rlt = _menu_set_loader_vol(hwnd, vol, dsk_num); 
							}
							break;
						case 2:
						case 3: 
								rlt = _menu_set_loader_file(hwnd, path, type == 2);
							break;
					}
					if (rlt != ST_OK) break;
			///////////////////////////////////////////////////////////////////////////////////////////////////////////
					memset(&conf, '\0', sizeof(conf));

					switch (type) {
						case 0: rlt = dc_get_mbr_config(dsk_num, NULL, &conf); break;
						case 1: rlt = dc_mbr_config_by_partition(vol, FALSE, &conf); break;
						case 2:
						case 3: rlt = dc_get_mbr_config(0, path, &conf); break;
					}

					if (rlt != ST_OK) {
						_error_s(hwnd, L"Error get bootloader configuration", rlt);
					} else {

						_tab_data *tab = malloc(sizeof(_tab_data));
						
						wnd_set_long(hwnd, GWL_USERDATA, tab);

						wnd = __sub_class(GetDlgItem(hwnd, IDB_BOOT_MAIN),
							CreateDialog(__hinst, MAKEINTRESOURCE(DLG_BOOT_CONF_MAIN), GetDlgItem(hwnd, IDC_BOOT_TAB), _tab_proc), FALSE);
						{
							_init_combo(GetDlgItem(wnd->dlg, IDC_COMBO_KBLAYOUT), kb_layouts, conf.kbd_layout, FALSE);

							_init_combo(GetDlgItem(wnd->dlg, IDC_COMBO_METHOD), 
								conf.options & OP_EXTERNAL ? boot_type_ext : boot_type_all, conf.boot_type, FALSE);

							_list_part_by_disk_id(GetDlgItem(wnd->dlg, IDC_PART_LIST_BY_ID), conf.disk_id);

							SendMessage(wnd->dlg, WM_COMMAND, MAKELONG(IDC_COMBO_METHOD, CBN_SELCHANGE), 
								(LPARAM)GetDlgItem(wnd->dlg, IDC_COMBO_METHOD));


						}
			///////////////////////////////////////////////////////////////////////////////////////////////////////////
						wnd = __sub_class(GetDlgItem(hwnd, IDB_BOOT_LOGON),
							CreateDialog(__hinst, MAKEINTRESOURCE(DLG_BOOT_CONF_LOGON), GetDlgItem(hwnd, IDC_BOOT_TAB), _tab_proc), FALSE);
						{
							HWND auth_combo = GetDlgItem(wnd->dlg, IDC_COMBO_AUTH_TYPE);
							HWND hmsg = GetDlgItem(wnd->dlg, IDE_RICH_BOOTMSG);

							SendMessage(auth_combo, (UINT)CB_ADDSTRING, 0, (LPARAM)auth_type[0].display);
							SendMessage(auth_combo, (UINT)CB_ADDSTRING, 0, (LPARAM)auth_type[1].display);
							SendMessage(auth_combo, CB_SETCURSEL, conf.pass_buf[0] == 0 ? 0 : 1, 0);

							__sub_class(GetDlgItem(wnd->dlg, IDC_BT_ENTER_PASS_MSG), FALSE, FALSE);
							__set_check(wnd->dlg, IDC_BT_ENTER_PASS_MSG, conf.logon_type & LT_MESSAGE);
							EnableWindow(hmsg, conf.logon_type & LT_MESSAGE);

							_init_combo(GetDlgItem(wnd->dlg, IDC_COMBO_SHOW_PASS), show_pass, conf.logon_type, TRUE);

							SetWindowTextA(hmsg, conf.eps_msg);									
							SendMessage(hmsg, EM_SETBKGNDCOLOR,	0, _cl(COLOR_BTNFACE, LGHT_CLR));
							SendMessage(hmsg, EM_EXLIMITTEXT,	0, sizeof(conf.eps_msg)-1);

							_init_combo(GetDlgItem(wnd->dlg, IDC_COMBO_AUTH_TMOUT), auth_tmount, conf.timeout, FALSE);

							__sub_class(GetDlgItem(wnd->dlg, IDC_BT_CANCEL_TMOUT), FALSE, FALSE);
							__set_check(wnd->dlg, IDC_BT_CANCEL_TMOUT, conf.options & OP_TMO_STOP);

							EnableWindow(GetDlgItem(wnd->dlg, IDC_BT_CANCEL_TMOUT), conf.timeout);
							SendMessage(wnd->dlg, WM_COMMAND, MAKELONG(IDC_COMBO_AUTH_TYPE, CBN_SELCHANGE), (LPARAM)auth_combo);

						}
			///////////////////////////////////////////////////////////////////////////////////////////////////////////
						wnd = __sub_class(GetDlgItem(hwnd, IDB_BOOT_BADPASS),
							CreateDialog(__hinst, MAKEINTRESOURCE(DLG_BOOT_CONF_BADPASS), GetDlgItem(hwnd, IDC_BOOT_TAB), _tab_proc), FALSE);
						{
							HWND err_mes = GetDlgItem(wnd->dlg, IDE_RICH_ERRPASS_MSG);

							__sub_class(GetDlgItem(wnd->dlg, IDC_BT_BAD_PASS_MSG), FALSE, FALSE);
							__set_check(wnd->dlg, IDC_BT_BAD_PASS_MSG, conf.error_type & ET_MESSAGE);

							EnableWindow(GetDlgItem(wnd->dlg, IDE_RICH_ERRPASS_MSG), conf.error_type & ET_MESSAGE);

							__sub_class(GetDlgItem(wnd->dlg, IDC_BT_ACTION_NOPASS), FALSE, FALSE);
							__set_check(wnd->dlg, IDC_BT_ACTION_NOPASS, conf.options & OP_NOPASS_ERROR);

							_init_combo(GetDlgItem(wnd->dlg, IDC_COMBO_BAD_PASS_ACT), bad_pass_act, conf.error_type, TRUE);

							SetWindowTextA(err_mes, conf.err_msg);
							SendMessage(err_mes, EM_EXLIMITTEXT, 0, sizeof(conf.err_msg)-1);

							SendMessage(GetDlgItem(wnd->dlg, IDE_RICH_ERRPASS_MSG), EM_SETBKGNDCOLOR,	0, _cl(COLOR_BTNFACE, LGHT_CLR));		

						}
						SendMessage(GetDlgItem(hwnd, IDB_BOOT_MAIN), WM_LBUTTONDOWN, 0, 0);			

						_snwprintf(text, sizeof_w(text), L"Bootloader config for [%s]", path[0] ? path : vol);
						SetWindowText(GetParent(GetParent(hwnd)), text);
						
						ShowWindow(sheets[0], SW_HIDE);
						ShowWindow(sheets[1], SW_SHOW);

					}
				} else {
			///////////////////////////////////////////////////////////////////////////////////////////////////////////
			///////////////////////////////////////////////////////////////////////////////////////////////////////////

					wnd = wnd_get_long(GetDlgItem(hwnd, IDB_BOOT_MAIN), GWL_USERDATA);
					if (wnd) {

						conf.kbd_layout = _get_combo_val(GetDlgItem(wnd->dlg, IDC_COMBO_KBLAYOUT), kb_layouts);
						conf.boot_type = _get_combo_val(GetDlgItem(wnd->dlg, IDC_COMBO_METHOD), boot_type_all);

						if (conf.boot_type == BT_DISK_ID) {

							wchar_t text[MAX_PATH];
							HWND hlist = GetDlgItem(wnd->dlg, IDC_PART_LIST_BY_ID);

							_get_item_text(hlist, ListView_GetSelectionMark(hlist), 2, text, sizeof_w(text));
							if (wcslen(text) && ListView_GetSelectedCount(hlist)) {

								conf.disk_id = wcstoul(text, L'\0', 16);
							} else {

								__msg_e(hwnd, L"You must select partition by id");
								break;

							}
						}
					}
			///////////////////////////////////////////////////////////////////////////////////////////////////////////
					wnd = wnd_get_long(GetDlgItem(hwnd, IDB_BOOT_LOGON), GWL_USERDATA);
					if (wnd) {

						HWND auth_combo = GetDlgItem(wnd->dlg, IDC_COMBO_AUTH_TYPE);
						HWND show_combo = GetDlgItem(wnd->dlg, IDC_COMBO_SHOW_PASS);

						BOOL dsp_pass, mask_pass;
						int timeout = _get_combo_val(GetDlgItem(wnd->dlg, IDC_COMBO_AUTH_TMOUT), auth_tmount);

						BOOL show_text = __get_check(wnd->dlg, IDC_BT_ENTER_PASS_MSG);
						BOOL get_pass = _get_combo_val(auth_combo, auth_type) == LT_GET_PASS;

						set_flag(conf.logon_type, LT_GET_PASS, get_pass);

						if (show_text) GetWindowTextA(GetDlgItem(wnd->dlg, IDE_RICH_BOOTMSG), conf.eps_msg, sizeof(conf.eps_msg));
						set_flag(conf.logon_type, LT_MESSAGE, show_text);

						dsp_pass = _get_combo_val(show_combo, show_pass) == LT_DSP_PASS;
						mask_pass = _get_combo_val(show_combo, show_pass) == LT_MASK_PASS;

						set_flag(conf.logon_type, LT_DSP_PASS, mask_pass ? TRUE : dsp_pass);
						set_flag(conf.logon_type, LT_MASK_PASS, mask_pass);

						conf.timeout = timeout;
						set_flag(conf.options, OP_EPS_TMO, timeout != 0);
						set_flag(conf.options, OP_TMO_STOP, __get_check(wnd->dlg, IDC_BT_CANCEL_TMOUT));

						if (!get_pass) {
							if (dlg_emb_pass.pass) {

								memset(conf.pass_buf, '\0', sizeof(conf.pass_buf));
								strcpy(conf.pass_buf, dlg_emb_pass.pass);

								secure_free(dlg_emb_pass.pass);
								secure_free(dlg_emb_pass.new_pass);

								dlg_emb_pass.pass = NULL;
								dlg_emb_pass.new_pass = NULL;

							} else {
								if (!strlen(conf.pass_buf)) {

									__msg_e(hwnd, L"You must enter embeded bootauth password");
									break;

								}
							}
						} else {
							memset(conf.pass_buf, '\0', sizeof(conf.pass_buf));

						}
					}
			///////////////////////////////////////////////////////////////////////////////////////////////////////////
					wnd = wnd_get_long(GetDlgItem(hwnd, IDB_BOOT_BADPASS), GWL_USERDATA);
					if (wnd) {

						BOOL show_err = __get_check(wnd->dlg, IDC_BT_BAD_PASS_MSG);
						BOOL act_no_pass = __get_check(wnd->dlg, IDC_BT_ACTION_NOPASS);

						conf.error_type = _get_combo_val(GetDlgItem(wnd->dlg, IDC_COMBO_BAD_PASS_ACT), bad_pass_act);

						set_flag(conf.error_type, ET_MESSAGE, show_err);
						set_flag(conf.options, OP_NOPASS_ERROR, act_no_pass);

						if (show_err) GetWindowTextA(GetDlgItem(
							wnd->dlg, IDE_RICH_ERRPASS_MSG), conf.err_msg, sizeof(conf.err_msg));						
						
					}
			///////////////////////////////////////////////////////////////////////////////////////////////////////////
					switch (type) {
						case 0: rlt = dc_set_mbr_config(dsk_num, NULL, &conf); break;
						case 1: rlt = dc_mbr_config_by_partition(vol, TRUE, &conf); break;
						case 2:
						case 3: rlt = dc_set_mbr_config(0, path, &conf); break;
					}
					if (rlt != ST_OK) {
						_error_s(hwnd, L"Error set bootloader configuration", rlt);
						break;
					}
					EndDialog(GetParent(GetParent(hwnd)), IDOK);

				}
			}
			if (IDCANCEL == id) {
				EndDialog(hwnd, IDCANCEL);

			}
		}
		break;
		case WM_DRAWITEM: {

			_draw_static((LPDRAWITEMSTRUCT)lparam);
      return 1L;

		}
		break;
	}
	return 0L;

}


INT_PTR CALLBACK
_main_dialog_proc(
		HWND hwnd,
		UINT message,
		WPARAM wparam,
		LPARAM lparam
	)
{
	WORD id = LOWORD(wparam);
	WORD code = HIWORD(wparam);

	_wnd_data *wnd;
	_dnode *sel;
	_dmnt *mnt;

	int k = 0;

	HWND hlist = GetDlgItem(hwnd, IDC_DISKDRIVES);

	switch (message) {
		case WM_INITDIALOG: {

			//wchar_t title[MAX_PATH];
			
			_init_main_dlg(hwnd);
			_load_diskdrives(hwnd, &__drives, _list_volumes(0));

			/*{
				TCITEM tab_item = { TCIF_TEXT };

				tab_item.pszText = L"Tab";
				TabCtrl_InsertItem(GetDlgItem(hwnd, IDT_INFO), 0, &tab_item);
				TabCtrl_InsertItem(GetDlgItem(hwnd, IDT_INFO), 0, &tab_item);
				TabCtrl_InsertItem(GetDlgItem(hwnd, IDT_INFO), 0, &tab_item);

			}*/

			{
				_tab_data *tab = malloc(sizeof(_tab_data));
				wnd_set_long(hwnd, GWL_USERDATA, tab);

				wnd = __sub_class(GetDlgItem(hwnd, IDB_MAIN_INFO), 
					CreateDialog(__hinst, MAKEINTRESOURCE(DLG_MAIN_INFO), GetDlgItem(hwnd, IDC_MAIN_TAB), _tab_proc), FALSE);

				{
					HWND hlist = GetDlgItem(wnd->dlg, IDC_INFO_TABLE);
					ListView_SetBkColor(hlist, GetSysColor(COLOR_BTNFACE));
		
					_list_insert_col(hlist, 380);
					_list_insert_col(hlist, 70);
					
					while (_list_insert_item(hlist, k, 0, _info_table_items[k], 0)) k++;

				}

				k = 0;
				wnd = __sub_class(GetDlgItem(hwnd, IDB_MAIN_ACTION), 
					CreateDialog(__hinst, MAKEINTRESOURCE(DLG_MAIN_ACTION), GetDlgItem(hwnd, IDC_MAIN_TAB), _tab_proc), FALSE);

				{
					HWND hlist = GetDlgItem(wnd->dlg, IDC_ACT_TABLE);
					__dlg_act_info = wnd->dlg;

					ListView_SetBkColor(hlist, GetSysColor(COLOR_BTNFACE));
		
					_list_insert_col(hlist, 90);
					_list_insert_col(hlist, 55);

					_list_insert_col(hlist, 75);
					_list_insert_col(hlist, 55);
						
					_list_insert_item(hlist, 0, 0, _act_table_items[0], 0);
					ListView_SetItemText(hlist, 0, 2, _act_table_items[2]);

					_list_insert_item(hlist, 1, 0, _act_table_items[1], 0);
					ListView_SetItemText(hlist, 1, 2, _act_table_items[3]);

					_init_combo(GetDlgItem(wnd->dlg, 
						IDC_COMBO_PASSES), wipe_modes, WP_NONE, FALSE);

					SendMessage(
						GetDlgItem(wnd->dlg, IDC_PROGRESS),
						PBM_SETBARCOLOR, 0, _cl(COLOR_BTNSHADOW, DARK_CLR-20)

					);
					SendMessage(
						GetDlgItem(wnd->dlg, IDC_PROGRESS),
						PBM_SETRANGE, 0,
						MAKELPARAM(0, PRG_STEP)
					);
				}
				SendMessage(GetDlgItem(hwnd, IDB_MAIN_INFO), WM_LBUTTONDOWN, 0, 0);

			}			
			_set_timer(MAIN_TIMER, TRUE, TRUE);
			_set_timer(RAND_TIMER, TRUE, FALSE);

			if (lparam) _set_timer(HIDE_TIMER, TRUE, FALSE);

			//_snwprintf(title, sizeof_w(title), L"%s %s", DC_NAME, DC_FILE_VER);
			SetWindowText(hwnd, DC_NAME);
			return 0L;			
		} 
		break;

		case WM_WINDOWPOSCHANGED: {
			int flags = ((WINDOWPOS *)lparam)->flags;

			if (flags & SWP_SHOWWINDOW || flags & SWP_HIDEWINDOW) {
				_set_timer(MAIN_TIMER, flags & SWP_SHOWWINDOW, TRUE);

			}
			return 0L;	
		}
		break;
		case WM_SYSCOMMAND: {

			if (wparam == SC_MINIMIZE || wparam == SC_RESTORE) {
				_set_timer(MAIN_TIMER, wparam == SC_RESTORE, TRUE);

			}
			return 0L;
		}
		break;

		case WM_APP + WM_APP_SHOW: {
			ShowWindow(hwnd, SW_HIDE);

		}
		break;

		case WM_NOTIFY: {
			if(IDC_DISKDRIVES == wparam) {

				sel = pv(_get_sel_item(hlist));
				mnt = &sel->mnt;

				//if (((NMHDR *)lparam)->code == NM_CUSTOMDRAW) 
				//	((NMLVCUSTOMDRAW *)lparam)->nmcd.dwDrawStage = CDDS_ITEMPREPAINT;
				//		return CDRF_SKIPDEFAULT;
				
				if (((NMHDR *)lparam)->code == LVN_ITEMCHANGED &&
					  (((NMLISTVIEW *)lparam)->uNewState & LVIS_FOCUSED )) {

					_update_info_table( );
					_refresh_menu( );

					return 1L;

				}
				if (((NMHDR *)lparam)->code == LVN_ITEMACTIVATE) {

					BOOL mount = !(sel->mnt.info.status.flags & F_ENABLED) 
						&& sel->mnt.fs[0] == '\0';
					
					if (!mount) {
						if (!sel->is_root) __execute(mnt->info.status.mnt_point);
					} else {
						_menu_mount(sel);
					}
				}

				switch(((NM_LISTVIEW *)lparam)->hdr.code) {
					case LVN_KEYDOWN : {

						WORD key = ((NMLVKEYDOWN *)lparam)->wVKey;
						int item = ListView_GetSelectionMark(hlist);

						switch (key) {
							case VK_UP: item -= 1; break;
							case VK_DOWN: item += 1; break;

						}
						if (_is_root_item(_get_item_index(hlist, item))) 
							ListView_SetItemState(hlist, item, LVIS_FOCUSED, TRUE);

					}
					break;
					case NM_RCLICK : {

						int item;
						HMENU popup = CreatePopupMenu( );

						_dact *act = _create_act_thread(sel, -1, -1);

						_update_info_table( );
						_set_timer(MAIN_TIMER, FALSE, FALSE);

						_refresh_menu( );
						
						if (ListView_GetSelectedCount(hlist) && 
								!_is_root_item((LPARAM)sel) && _is_active_item((LPARAM)sel))
						{
							if (mnt->info.status.flags & F_ENABLED) {

								if (IS_UNMOUNTABLE(&mnt->info.status)) {
									AppendMenu(popup, MF_STRING, ID_VOLUMES_UNMOUNT, IDS_UNMOUNT);

								}
								AppendMenu(popup, MF_STRING, ID_VOLUMES_CHANGEPASS, IDS_CHPASS);

								if (sel->mnt.info.status.vf_version < TC_VOLUME_HEADER_VERSION) {
									AppendMenu(popup, MF_STRING, ID_VOLUMES_UPDATE, IDS_UPD_VOL);
								}

								if (!(act && act->status == ACT_RUNNING)) {
									AppendMenu(popup, MF_SEPARATOR, 0, NULL);	
									AppendMenu(popup, MF_STRING, ID_VOLUMES_DECRYPT, IDS_DECRYPT);

									if (mnt->info.status.flags & F_SYNC)
										AppendMenu(popup, MF_STRING, ID_VOLUMES_ENCRYPT, IDS_ENCRYPT);

								}
							} else {
								if (*mnt->fs == '\0')
									AppendMenu(popup, MF_STRING, ID_VOLUMES_MOUNT, IDS_MOUNT); 
								else
									AppendMenu(popup, MF_STRING, ID_VOLUMES_ENCRYPT, IDS_ENCRYPT);

							}
						}
						//_state_menu(popup, sel && 
						//	sel->status.flags & F_LOCKED ? MF_GRAYED : MF_ENABLED);

						item = TrackPopupMenu(
							popup,
							TPM_RETURNCMD | TPM_LEFTBUTTON,
							LOWORD(GetMessagePos( )),
							HIWORD(GetMessagePos( )),
							0,
							hwnd,
							NULL
						);

						DestroyMenu(popup);
						switch (item) {

						case ID_VOLUMES_DECRYPT: _menu_decrypt(sel); break;
						case ID_VOLUMES_ENCRYPT: _menu_encrypt(sel); break;

						case ID_VOLUMES_UNMOUNT: _menu_unmount(sel); break;
						case ID_VOLUMES_MOUNT: _menu_mount(sel); break;

						case ID_VOLUMES_CHANGEPASS: _menu_change_pass(sel); break;
						case ID_VOLUMES_UPDATE: _menu_update_volume(sel); break;

						}
						if (item) _refresh(TRUE);
						_set_timer(MAIN_TIMER, TRUE, TRUE);

					}
					break;
					case NM_CLICK: {
						sel = pv(_get_item_index(
							hlist, ((NM_LISTVIEW *)lparam)->iItem));

						_update_info_table( );
						_refresh_menu( );
						
					}
					break;

				}
			}
			if (((NMHDR *)lparam)->code == HDN_ITEMCHANGED) {
				InvalidateRect(hlist, NULL, TRUE);

			}
		}
		break;

		case WM_COMMAND: {
			_dnode *node = pv(_get_sel_item(hlist));

			switch (id) {
			case ID_TOOLS_DRIVER: {

				if (_msg_q(__dlg, L"Remove DiskCryptor driver?")) {
					int rlt;

					if ((rlt = _drv_action(DA_REMOVE, 0)) != ST_OK) {
						_error_s(__dlg, L"Error remove DiskCryptor driver", rlt);
	
					} else {
						return 0L;

					}
				}
			}
			break;
			case ID_HOMEPAGE: 
				__execute(DC_HOMEPAGE);
				break;

			case ID_HELP_ABOUT: _dlg_about(__dlg); break;
			case ID_EXIT: SendMessage(hwnd, WM_CLOSE, 0, 1); break;

			case IDC_BTN_DECRYPT_:
			case ID_VOLUMES_DECRYPT: _menu_decrypt(node); break;

			case IDC_BTN_ENCRYPT_:
			case ID_VOLUMES_ENCRYPT: _menu_encrypt(node); break;

			case ID_VOLUMES_MOUNTALL: 
			case IDC_BTN_MOUNTALL_: _menu_mountall( ); break;

			case ID_VOLUMES_DISMOUNTALL: 
			case IDC_BTN_UNMOUNTALL_: _menu_unmountall( ); break;

			case ID_VOLUMES_DISMOUNT: _menu_unmount(node); break;
			case ID_VOLUMES_MOUNT: _menu_mount(node); break;

			case ID_TOOLS_SETTINGS: _dlg_options(__dlg); break;
			case ID_BOOT_OPTIONS: _dlg_config_loader(__dlg, FALSE); break;

			case ID_VOLUMES_CHANGEPASS: _menu_change_pass(node); break;
			case ID_TOOLS_CLEARCACHE: _menu_clear_cache( ); break;

			}
			switch (id) {
			case IDC_BTN_MOUNT_: {		

				node->mnt.info.status.flags & F_ENABLED ? 
					_menu_unmount(node) : _menu_mount(node);

			}
			break;	
			case ID_TOOLS_BSOD: {
				if (_msg_q(__dlg, L"Crash?")) dc_get_bsod( );

			}
			break;
			}

			if (IDCANCEL == id) {
				ShowWindow(hwnd, SW_HIDE);

			}
			_refresh(TRUE);

		}
		break;

		case WM_CLOSE: {
			if (lparam) {
				_tray_icon(FALSE);

				EndDialog(hwnd, 0);
				ExitProcess(0);

			} else ShowWindow(hwnd, SW_HIDE);
			return 0L;
		}
		break;

		case WM_DESTROY: {
			PostQuitMessage(0);
			return 0L;
		}
		break;

		case WM_DRAWITEM: {
			_draw_static((LPDRAWITEMSTRUCT)lparam);
      return 1L;
		}
		break;

		case WM_HOTKEY: {
			switch (wparam) {

				case 0: {
					int mount_cnt;
					dc_mount_all(NULL, &mount_cnt); 

				}
				break;
				case 1: dc_unmount_all( ); break;
				case 2: dc_clean_pass_cache( ); break;
				case 3: dc_get_bsod( ); break;

			}
			return 1L;
		}
		break;

		case WM_ENDSESSION: {
			if (lparam & ENDSESSION_LOGOFF) {

				if (__config.conf_flags & CONF_DISMOUNT_LOGOFF) dc_unmount_all( );
				if (__config.conf_flags & CONF_WIPEPAS_LOGOFF) dc_clean_pass_cache( );

			}
		}
		break;

		case WM_SYSCOLORCHANGE: {
			COLORREF bgcolor = _cl(COLOR_BTNFACE, LGHT_CLR);
			HWND hlist = GetDlgItem(hwnd, IDC_DISKDRIVES);

			TreeView_SetBkColor(GetDlgItem(hwnd, IDC_TREE), bgcolor);
			ListView_SetBkColor(hlist, bgcolor);

			ListView_SetTextBkColor(hlist, bgcolor);
			ListView_SetExtendedListViewStyle(hlist, LVS_EX_FLATSB | LVS_EX_FULLROWSELECT);

			ListView_SetImageList(hlist, __dsk_img, LVSIL_SMALL);

		}
		break;

		case WM_APP + WM_APP_TRAY: {
			switch (lparam) {

			case WM_LBUTTONDOWN: {
				BOOL show = !IsWindowVisible(hwnd);

				ShowWindow(hwnd, show ? SW_SHOW : SW_HIDE);
				if (show) SetForegroundWindow(hwnd);

			}
			break;
			case WM_RBUTTONDOWN: {

				POINT pt; int item;
				HMENU menu = CreatePopupMenu( );				

				AppendMenu(menu, MF_STRING, ID_VOLUMES_UNMOUNTALL, IDS_UNMOUNTALL);
				AppendMenu(menu, MF_STRING, ID_VOLUMES_MOUNTALL, IDS_MOUNTALL);
				AppendMenu(menu, MF_SEPARATOR, 0, NULL);

				AppendMenu(menu, MF_STRING, ID_TOOLS_SETTINGS, IDS_SETTINGS);
				AppendMenu(menu, MF_STRING, ID_HELP_ABOUT, IDS_ABOUT);
				AppendMenu(menu, MF_SEPARATOR, 0, NULL);
				AppendMenu(menu, MF_STRING, ID_EXIT, IDS_EXIT);

				GetCursorPos(&pt);
				SetForegroundWindow(hwnd);

				item = TrackPopupMenu (menu,
					TPM_RETURNCMD | TPM_LEFTALIGN | TPM_BOTTOMALIGN | TPM_RIGHTBUTTON,
					pt.x, pt.y, 0, hwnd,
					NULL
				);

				DestroyMenu(menu);
				switch (item) {

				case ID_VOLUMES_UNMOUNTALL: _menu_unmountall( ); break;
				case ID_VOLUMES_MOUNTALL: _menu_mountall( ); break;

				case ID_HELP_ABOUT: _dlg_about(HWND_DESKTOP); break;
				case ID_EXIT: SendMessage(hwnd, WM_CLOSE, 0, 1); break;

				case ID_TOOLS_SETTINGS:
					DialogBoxParam(
						NULL, 
						MAKEINTRESOURCE(IDD_DIALOG_OPTIONS),
						hwnd,
						pv(_options_dlg_proc),
						(LPARAM)NULL
					);
					break;
				}
			}
			break;
			}
		}
		break;

  	case WM_INITMENU: {
			;
		}
		break;

	}	
	return 0L; 

}


void __stdcall 
_timer_handle(
		HWND hwnd,
		UINT msg,
		UINT_PTR id,
		DWORD tickcount
	)
{
	int j = 0;
	HWND hlist = GetDlgItem(hwnd, IDC_DISKDRIVES);

	switch (id - IDC_TIMER) {

		case PROC_TIMER: {	
			_update_info_table( );

		}
		break;
		case MAIN_TIMER: {

			EnterCriticalSection(&crit_sect);

			_load_diskdrives(hwnd, &__drives, _list_volumes(0));
			_update_info_table( );

			_set_timer(PROC_TIMER, IsWindowVisible(__dlg_act_info), FALSE);
			_refresh_menu( );

			LeaveCriticalSection(&crit_sect);


		}
		break;

		case RAND_TIMER: rnd_reseed_now( ); break;
		case HIDE_TIMER: {

			ShowWindow(hwnd, SW_HIDE);
			_set_timer(HIDE_TIMER, FALSE, FALSE);

		}
		break;

	}
}



