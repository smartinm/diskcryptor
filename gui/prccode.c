#include <windows.h>
#include <stdio.h>
#include <richedit.h>
#include <ntddscsi.h>
#include <shlwapi.h>
#include <shlobj.h>
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
#include "pass.h"
#include "winternl.h"
#include "dcapi.h"
#include "..\sys\driver.h"
#include "..\boot\boot.h"
#include "crypto\crypto.h"
#include "crypto\pkcs5.h"
#include "ukeyfiles.h"

int radio_type[ ] = {
	IDC_RADIO_REENCRYPT,
	IDC_RADIO_ENCRYPT,
	IDC_RADIO_FORMAT,
	-1
};

int combo_sel[ ] = {
	IDC_COMBO_ALGORT, IDC_COMBO_HASH,
	IDC_COMBO_MODE, IDC_COMBO_PASSES,
	-1
};

wchar_t *fs_names[ ] = {
	L"RAW", L"FAT", L"FAT32", L"NTFS", L""
};

static int _dlg_height;
static int _dlg_width;

static int _dlg_right;
static int _dlg_left;
static int _dlg_bottom;

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


void _refresh_boot_buttons(
		HWND hwnd,
		HWND hlist,
		int  item
	)
{
	BOOL       remove  = FALSE;
	BOOL       update  = FALSE;
	BOOL       enable  = FALSE;

	HWND       hparent = GetParent(GetParent(hwnd));
	wchar_t    s_item[MAX_PATH];

	ldr_config conf;	

	if (ListView_GetSelectedCount(hlist))
	{
		enable = TRUE;

		_get_item_text(hlist, item, 2, s_item, sizeof_w(s_item));
		if (!wcscmp(s_item, L"installed"))
		{
			remove = TRUE;
			update = dc_get_mbr_config(_ext_disk_num(hlist), NULL, &conf) == ST_OK && conf.ldr_ver < DC_BOOT_VER;
		}
	}
	SetWindowText(GetDlgItem(hparent, IDC_BTN_INSTALL), remove ? IDS_BOOTREMOVE : IDS_BOOTINSTALL);
	EnableWindow(GetDlgItem(hparent, IDC_BTN_INSTALL), enable);

	EnableWindow(GetDlgItem(hparent, IDC_BTN_CHANGE_CONF), remove);
	EnableWindow(GetDlgItem(hparent, IDC_BTN_UPDATE), update);
	
}


INT_PTR
CALLBACK
_tab_proc(
		HWND   hwnd,
		UINT   message,
		WPARAM wparam,
		LPARAM lparam
	)
{
	WORD code = HIWORD(wparam);
	WORD id = LOWORD(wparam);
	HDC dc;

	wchar_t tmpb[MAX_PATH];
	int k;

	switch (message)
	{
		case WM_NOTIFY:
		{
			if (IDC_WZD_BOOT_DEVS == wparam) 
			{
				NM_LISTVIEW *msg_info = pv(lparam);
				NMHDR       *msg_hdr  = pv(lparam);
				HWND         hlist    = msg_info->hdr.hwndFrom;

				if (LVN_ITEMACTIVATE == msg_hdr->code) 
				{
					_get_item_text(hlist, msg_info->iItem, 2, tmpb, sizeof_w(tmpb));
					if (wcscmp(tmpb, L"installed") == 0)
					{
						SendMessage(GetParent(GetParent(hwnd)), WM_COMMAND, MAKELONG(IDC_BTN_CHANGE_CONF, 0), 0);
					} else {

						wchar_t vol[MAX_PATH];

						int dsk_num;
						int type = _get_combo_val(GetDlgItem(hwnd, IDC_COMBO_LOADER_TYPE), loader_type);

						_get_item_text(hlist, msg_info->iItem, 0, vol, sizeof_w(vol));
						dsk_num = _ext_disk_num(hlist);

						_menu_set_loader_vol(hwnd, vol, dsk_num, type);

						_list_devices(GetDlgItem(hwnd, IDC_WZD_BOOT_DEVS), type == CTL_LDR_MBR, -1);
						_refresh_boot_buttons(hwnd, msg_hdr->hwndFrom, msg_info->iItem);

					}
				}

				if (msg_hdr->code == LVN_ITEMCHANGED && msg_info->uNewState & LVIS_FOCUSED) 
				{
					_refresh_boot_buttons(hwnd, msg_hdr->hwndFrom, msg_info->iItem);
					return 1L;
				}

				if (NM_CLICK == msg_hdr->code) 
				{
					_refresh_boot_buttons(hwnd, msg_hdr->hwndFrom, msg_info->iItem);
					return 1L;
				}
					
				if (NM_RCLICK == msg_hdr->code) 
				{
					HMENU popup = CreatePopupMenu( );
					BOOL item_update = FALSE;

					int type = _get_combo_val(GetDlgItem(hwnd, IDC_COMBO_LOADER_TYPE), loader_type);
					ldr_config conf;

					int dsk_num = -1;
					int item;					

					wchar_t vol[MAX_PATH];					

					_get_item_text(hlist, msg_info->iItem, 0, vol, sizeof_w(vol));
					dsk_num = _ext_disk_num(hlist);

					if (ListView_GetSelectedCount(hlist))
					{
						_get_item_text(hlist, msg_info->iItem, 2, tmpb, sizeof_w(tmpb));
						if (!wcscmp(tmpb, L"installed")) 
						{
							AppendMenu(popup, MF_STRING, ID_BOOT_REMOVE, IDS_BOOTREMOVE);

							if (!type) 
							{
								item_update = dc_get_mbr_config(
									dsk_num, NULL, &conf) == ST_OK && conf.ldr_ver < DC_BOOT_VER;
								
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
					switch (item) 
					{
						case ID_BOOT_INSTALL: _menu_set_loader_vol(hwnd, vol, dsk_num, type); break;
						case ID_BOOT_REMOVE:  _menu_unset_loader_mbr(hwnd, vol, dsk_num, type); break;

						case ID_BOOT_UPDATE: _menu_update_loader(hwnd, vol, dsk_num); break;
						case ID_BOOT_CHANGE_CONFIG: 
						{
							SendMessage(GetParent(GetParent(hwnd)), WM_COMMAND, MAKELONG(IDC_BTN_CHANGE_CONF, 0), 0);
						}
						break;
					}
					if (item == ID_BOOT_INSTALL || item == ID_BOOT_REMOVE) 
					{
						_list_devices(GetDlgItem(hwnd, IDC_WZD_BOOT_DEVS), type == CTL_LDR_MBR, -1);
						_refresh_boot_buttons(hwnd, msg_hdr->hwndFrom, msg_info->iItem);
					}
				}
			}
		}
		break;
		case WM_USER_CLICK : 
		{
			HWND ctl_wnd = (HWND)wparam;

			if (ctl_wnd == GetDlgItem(hwnd, IDC_AUTO_START)) 
			{
				BOOL enable = _get_check(hwnd, IDC_AUTO_START);
				EnableWindow(GetDlgItem(hwnd, IDC_WIPE_LOGOFF), enable);
				EnableWindow(GetDlgItem(hwnd, IDC_UNMOUNT_LOGOFF), enable);

				InvalidateRect(GetDlgItem(hwnd, IDC_WIPE_LOGOFF), NULL, TRUE);
				InvalidateRect(GetDlgItem(hwnd, IDC_UNMOUNT_LOGOFF), NULL, TRUE);

				if (!enable) 
				{
					_set_check(hwnd, IDC_WIPE_LOGOFF, enable);
					_set_check(hwnd, IDC_UNMOUNT_LOGOFF, enable);
				}
				return 1L;
			}
			if (ctl_wnd == GetDlgItem(hwnd, IDC_BT_ENTER_PASS_MSG)) 
			{
				EnableWindow(GetDlgItem(hwnd, IDE_RICH_BOOTMSG), _get_check(hwnd, IDC_BT_ENTER_PASS_MSG));
				return 1L;
			}

			if (ctl_wnd == GetDlgItem(hwnd, IDC_BT_BAD_PASS_MSG)) 
			{
				EnableWindow(GetDlgItem(hwnd, IDE_RICH_ERRPASS_MSG), _get_check(hwnd, IDC_BT_BAD_PASS_MSG));
				return 1L;
			}

			if (ctl_wnd == GetDlgItem(hwnd, IDC_CHECK_SHOW)) 
			{
				int mask = _get_check(hwnd, IDC_CHECK_SHOW) ? 0 : '*';

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

			if (ctl_wnd == GetDlgItem(hwnd, IDC_USE_KEYFILES)) 
			{
				SendMessage(hwnd, WM_COMMAND, 
					MAKELONG(IDE_PASS, EN_CHANGE), (LPARAM)GetDlgItem(hwnd, IDE_PASS));

				EnableWindow(GetDlgItem(hwnd, IDB_USE_KEYFILES), _get_check(hwnd, IDC_USE_KEYFILES));

				return 1L;
			}

			{
				_wnd_data *data = wnd_get_long(ctl_wnd, GWL_USERDATA);

				k = 0;
				while (hotks_chk[k].id != -1) 
				{
					if(ctl_wnd == GetDlgItem(hwnd, hotks_chk[k].id)) 
					{
						EnableWindow(GetDlgItem(hwnd, hotks_edit[k].id), data->state);
						EnableWindow(GetDlgItem(hwnd, hotks_static[k].id), data->state);
						return 1L;												
					}
					k++;
				}
			}
		}
		break;

		case WM_COMMAND : 
		{
			HWND hlist = GetDlgItem(__dlg, IDC_DISKDRIVES);	

			_dnode *node = pv(_get_sel_item(hlist));			
			_dact *act = _create_act_thread(node, -1, -1);

			switch (id) 
			{
				case IDB_USE_KEYFILES :
				{
					wchar_t text[MAX_PATH];
					int keylist;

					GetWindowText(GetDlgItem(hwnd, IDC_USE_KEYFILES), text, sizeof_w(text));
					keylist = wcscmp(text, IDS_USE_KEYFILE) == 0 ? KEYLIST_EMBEDDED : KEYLIST_CURRENT;

					_dlg_keyfiles(hwnd, keylist);

					SendMessage(hwnd, WM_COMMAND, 
						MAKELONG(IDE_PASS, EN_CHANGE), (LPARAM)GetDlgItem(hwnd, IDE_PASS));

				}
				break;
				case IDB_BOOT_PREF :
				{
					_dlg_config_loader(hwnd, TRUE);
				}
				break;
				case IDB_BT_CONF_EMB_KEY : 
				{
					_dlg_keyfiles(hwnd, KEYLIST_EMBEDDED);
				}
				break;
				case IDB_ACT_PAUSE :
				{
					if (node)
					{	
						if (act->status == ACT_RUNNING) 
						{
							act->status = act->act != ACT_FORMAT ? ACT_PAUSED : ACT_STOPPED;
							act->act = ACT_ENCRYPT;
						}
					}
					_refresh(TRUE);
				}
				break;
				case IDB_BOOT_PATH :
				{
					OPENFILENAME ofn = { sizeof(ofn), hwnd };
					wchar_t file[MAX_PATH] = { L"loader" };

					ofn.lpstrFile = file;
					ofn.nMaxFile = sizeof_w(file);

					ofn.lpstrTitle = L"Save Bootloader File As";

					ofn.Flags = OFN_FORCESHOWHIDDEN | OFN_HIDEREADONLY;
					ofn.FlagsEx = OFN_EX_NOPLACESBAR;

					if (GetSaveFileName(&ofn)) 
					{
						SetWindowText(GetDlgItem(hwnd, IDE_BOOT_PATH), file);
					}
				}
				break;
			}

			switch (code) 
			{
				case CBN_SELCHANGE :
				{
					switch (id) 
					{
						case IDC_COMBO_AUTH_TYPE :
						{
							BOOL b_pass   = _get_combo_val((HWND)lparam, auth_type) & LT_GET_PASS;
							BOOL b_keyfie = _get_combo_val((HWND)lparam, auth_type) & LT_EMBED_KEY;

							_enb_but_this(hwnd, IDC_COMBO_AUTH_TYPE, b_pass);

							EnableWindow(GetDlgItem(hwnd, IDC_STATIC_AUTH_TYPE), TRUE);
							EnableWindow(GetDlgItem(hwnd, IDC_CNT_BOOTMSG), FALSE);

							EnableWindow(GetDlgItem(hwnd, IDB_BT_CONF_EMB_PASS), b_keyfie);

							if (b_pass) 
							{
								EnableWindow(GetDlgItem(hwnd, IDE_RICH_BOOTMSG), _get_check(hwnd, IDC_BT_ENTER_PASS_MSG));

								EnableWindow(
									GetDlgItem(hwnd, IDC_BT_CANCEL_TMOUT), (BOOL)SendMessage(GetDlgItem(hwnd, IDC_COMBO_AUTH_TMOUT), CB_GETCURSEL, 0, 0)
									);
							}
						}
						break;
						case IDC_COMBO_AUTH_TMOUT :
						{						
							EnableWindow(
								GetDlgItem(hwnd, IDC_BT_CANCEL_TMOUT), (BOOL)SendMessage((HWND)lparam, CB_GETCURSEL, 0, 0)
								);

							InvalidateRect(GetDlgItem(hwnd, IDC_BT_CANCEL_TMOUT), NULL, TRUE);

						}
						break;
						case IDC_COMBO_METHOD :
						{
							wchar_t text[MAX_PATH];

							HWND hlist = GetDlgItem(hwnd, IDC_PART_LIST_BY_ID);
							BOOL enable;

							_get_item_text(hlist, 0, 0, text, sizeof_w(text));
							enable = _get_combo_val((HWND)lparam, boot_type_ext) == BT_DISK_ID && !wcsstr(text, L"not found");

							EnableWindow(GetDlgItem(hwnd, IDC_STATIC_SELECT_PART), enable);
							EnableWindow(hlist, enable);

						}
						break;
						case IDC_COMBO_LOADER_TYPE: 
						{
							int k = 0;
							int ctl_enb[ ] =
							{
								IDC_HEAD_BOOT_DEV, IDC_WZD_BOOT_DEVS,
								IDC_HEAD_BOOT_FILE, IDE_BOOT_PATH, IDB_BOOT_PATH,
								-1
							};

							int type = (int)SendMessage(GetDlgItem(hwnd, IDC_COMBO_LOADER_TYPE), CB_GETCURSEL, 0, 0);
							while (ctl_enb[k] != -1)
							{
								EnableWindow(
									GetDlgItem(hwnd, ctl_enb[k]), (type < 2 && k < 2) || (type > 1 && k > 1)
									);

								k++;
							}
							if (type < 2) _list_devices(GetDlgItem(hwnd, IDC_WZD_BOOT_DEVS), !type, -1);

							SetWindowText(
								GetDlgItem(GetParent(GetParent(hwnd)), IDC_BTN_INSTALL), type > 1 ? IDS_BOOTCREATE : IDS_BOOTINSTALL
								);

							EnableWindow(GetDlgItem(GetParent(GetParent(hwnd)), IDC_BTN_INSTALL), FALSE);

							SetWindowText(GetDlgItem(hwnd, IDE_BOOT_PATH), L"");
							SetFocus(GetDlgItem(hwnd, IDE_BOOT_PATH));

						}
						break;
						case IDC_COMBO_BOOT_INST :
						{
							EnableWindow(
								GetDlgItem(hwnd, IDB_BOOT_PREF), SendMessage((HWND)lparam, CB_GETCURSEL, 0, 0) == 0
								);
						}
						break;
						case IDC_COMBO_KBLAYOUT :
						{
							SendMessage(hwnd, WM_COMMAND, MAKELONG(IDE_PASS, EN_CHANGE), lparam);
						}
						break;
						case IDC_COMBO_PASSES : 
						{
							_dact *act = _create_act_thread(node, -1, -1);
							if (act) 
							{
								act->wp_mode = (int)(SendMessage((HWND)lparam, CB_GETCURSEL, 0, 0));
							}
						}
						break;
					}
				}
				break;
				case EN_CHANGE : 
				{
					if (id == IDE_RICH_BOOTMSG) //#
					{	
						char s_msg[MAX_PATH];
						char s_count[MAX_PATH];

						GetWindowTextA((HWND)lparam, s_msg, sizeof(s_msg));

						_snprintf(s_count, sizeof(s_count), "%d / %d", strlen(s_msg), 0);
						SetWindowTextA(GetDlgItem(hwnd, IDC_CNT_BOOTMSG), s_count);
					
					}
					if (id == IDE_RICH_ERRPASS_MSG) {	}

					if (id == IDE_BOOT_PATH) 
					{
						wchar_t s_path[MAX_PATH];
						GetWindowText((HWND)lparam, s_path, sizeof_w(s_path));

						EnableWindow(GetDlgItem(GetParent(GetParent(hwnd)), IDC_BTN_INSTALL), s_path[0] != 0);
						EnableWindow(GetDlgItem(GetParent(GetParent(hwnd)), IDC_BTN_CHANGE_CONF), PathFileExists(s_path));

					}

					if (id == IDE_PASS || id == IDE_CONFIRM)
					{
						BOOL correct;

						int kb_layout = -1;
						int idx_status;
						int entropy;

						dc_pass *pass;

						if (IsWindowEnabled(GetDlgItem(hwnd, IDC_COMBO_KBLAYOUT))) 
						{
							kb_layout = _get_combo_val(GetDlgItem(hwnd, IDC_COMBO_KBLAYOUT), kb_layouts);
						}			
						pass = _get_pass(hwnd, IDE_PASS);

						_draw_pass_rating(hwnd, pass, kb_layout, &entropy);
						secure_free(pass);

						SendMessage(
								GetDlgItem(hwnd, IDP_BREAKABLE),
								PBM_SETPOS,
								(WPARAM)entropy, 0
							);						

						if (IsWindowVisible(GetDlgItem(hwnd, IDE_PASS))) 
						{
							dc_pass *pass   = _get_pass(hwnd, IDE_PASS);
							dc_pass *verify = _get_pass(hwnd, IDE_CONFIRM);

							int keylist = _get_check(hwnd, IDC_USE_KEYFILES) ? KEYLIST_CURRENT : KEYLIST_NONE;

							correct = 
								_input_verify(pass, verify, keylist, kb_layout, &idx_status
							);
						
							secure_free(pass);
							secure_free(verify);

							SetWindowText(GetDlgItem(hwnd, IDC_PASS_STATUS), _get_text_name(idx_status, pass_status));
							EnableWindow(GetDlgItem(GetParent(GetParent(hwnd)), IDOK), correct);
						}
						return 1L;	
					}
				}
				break;
			}
		}
		break;

		case WM_CTLCOLOREDIT :
		case WM_CTLCOLORSTATIC :
		case WM_CTLCOLORLISTBOX : 
		{
			COLORREF bgcolor, fn = 0;
		
			dc = (HDC)wparam;
			SetBkMode(dc, TRANSPARENT);

			if (WM_CTLCOLORSTATIC == message) 
			{
				k = 0;
				while (pass_gr_ctls[k].id != -1) 
				{
					if (pass_gr_ctls[k].hwnd == (HWND)lparam) {
						fn = pass_gr_ctls[k].color;
					}
					if (pass_pe_ctls[k].hwnd == (HWND)lparam) {
						fn = pass_pe_ctls[k].color;
					}
					k++;
				}
				SetTextColor(dc, fn);
				bgcolor = GetSysColor(COLOR_BTNFACE);

			} else bgcolor = _cl(COLOR_BTNFACE, LGHT_CLR);

			SetDCBrushColor(dc, bgcolor);
			return (INT_PTR)GetStockObject(DC_BRUSH);
		
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

		default:
		{
			int rlt = _draw_proc(message, lparam);
			if (rlt != -1) return rlt;
		}
	}
	return 0L;

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

	switch (message)
	{
		case WM_SETCURSOR : 
		{
			if (!over) 
			{
				TRACKMOUSEEVENT	track = { sizeof(track) };

				track.dwFlags = TME_LEAVE;
				track.hwndTrack = hwnd;
	
				over = TrackMouseEvent(&track);
				SetCursor(__cur_hand);
	
			}
			return 0L;
		}
		case WM_MOUSELEAVE : 
		{
			over = FALSE;
			SetCursor(__cur_arrow);

			return 0L;
		}
	}
	return CallWindowProc(old_proc, hwnd, message, wparam, lparam);

}


INT_PTR CALLBACK
_benchmark_dlg_proc(
		HWND hwnd,
		UINT message,
		WPARAM wparam,
		LPARAM lparam
	)
{
	switch (message) 
	{
		case WM_CLOSE: EndDialog(hwnd, 0);
			return 0L;

		case WM_COMMAND: 
		{
			int code = HIWORD(wparam);			
			int id = LOWORD(wparam);

			if (id == IDOK || id == IDCANCEL) {
				EndDialog(hwnd, 0);
			}

			if (id == IDB_REFRESH_TEST)
			{
				HWND hbutton = GetDlgItem(hwnd, IDB_REFRESH_TEST);

				SetCursor(__cur_wait);
				EnableWindow(hbutton, FALSE);
				{
					HWND hlist = GetDlgItem(hwnd, IDC_LIST_BENCHMARK);
					
					bench_item bench[CF_CIPHERS_NUM];

					wchar_t s_speed[50];
					int cnt;

					int lvcount = 0;
					int k = 0;

					cnt  = _benchmark(pv(&bench));
					ListView_DeleteAllItems(hlist);
						
					for (k = 0; k < cnt; k++) 
					{
						_list_insert_item(hlist, lvcount, 0, bench[k].alg, 0);
						_list_set_item(hlist, lvcount, 1, L"--");

						_snwprintf(s_speed, sizeof_w(s_speed), L"%-.2f mb/s", bench[k].speed);
						_list_set_item(hlist, lvcount++, 2, s_speed);
					}
				}
				EnableWindow(hbutton, TRUE);
				SetCursor(__cur_arrow);
			}
		}
		break;
		case WM_INITDIALOG : 
		{
			HWND hlist = GetDlgItem(hwnd, IDC_LIST_BENCHMARK);
			_init_list_headers(hlist, _benchmark_headers);

			ListView_SetBkColor(hlist, GetSysColor(COLOR_BTNFACE));
			ListView_SetTextBkColor(hlist, GetSysColor(COLOR_BTNFACE));
			ListView_SetExtendedListViewStyle(hlist, LVS_EX_FLATSB | LVS_EX_FULLROWSELECT);			

			SetForegroundWindow(hwnd);
			return 1L;
		}
		break;
		case WM_CTLCOLOREDIT :
		{
			return _ctl_color(wparam, _cl(COLOR_BTNFACE, LGHT_CLR));
		}
		break;
		default:
		{
			int rlt = _draw_proc(message, lparam);
			if (rlt != -1) return rlt;
		}
	}
	return 0L;

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
		{ DC_HOMEPAGE,  IDC_ABOUT_URL1, 0 },
		{ DC_FORUMPAGE, IDC_ABOUT_URL2, 0 },
		{ L"", -1, -1 }
	};

	static HICON hicon;
	switch (message) 
	{
		case WM_DESTROY: DestroyIcon(hicon);
			return 0L;

		case WM_CLOSE: EndDialog(hwnd, 0);
			return 0L;

		case WM_COMMAND: 
		{
			int id = LOWORD(wparam);
			int k = 0;

			if (id == IDCANCEL || id == IDOK) EndDialog(hwnd, 0);

			while (ctl_links[k].id != -1) {
				if (id == ctl_links[k].id) __execute(ctl_links[k].display);				
				k++;
			}
		}
		break;
		case WM_INITDIALOG : 
		{
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

				_snwprintf(display, 
					sizeof_w(display), L"%s %d.%d.%d.%d", DC_NAME, DC_MAJOR_VER, DC_MINOR_VER, DC_DRIVER_VER, DC_BOOT_VER
					);

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
				while (ctl_links[k].id != -1)
				{
					HWND ctl = GetDlgItem(hwnd, ctl_links[k].id);

					SetWindowLongPtr(ctl, GWL_USERDATA, (LONG_PTR)GetWindowLongPtr(ctl, GWL_WNDPROC));
					SetWindowLongPtr(ctl, GWL_WNDPROC, (LONG_PTR)_link_proc);

					SetWindowText(ctl, ctl_links[k].display);
					SendMessage(ctl, WM_SETFONT, (WPARAM)__font_link, 0);
					{
						WINDOWINFO pwi;
						SIZE       size;
						HDC        hdc = GetDC(ctl);

						SelectObject(hdc, __font_link);
						GetTextExtentPoint32(hdc, ctl_links[k].display, d32(wcslen(ctl_links[k].display)), &size);						

						GetWindowInfo(ctl, &pwi);
						ScreenToClient(hwnd, pv(&pwi.rcClient));

						MoveWindow(ctl, pwi.rcClient.left, pwi.rcClient.top, size.cx, size.cy, TRUE);
						ReleaseDC(ctl, hdc);
					}
					k++;
				}
			}
			SendMessage(GetDlgItem(hwnd, IDC_EDIT_NOTICE), EM_SCROLLCARET, 0, 0);
			SetForegroundWindow(hwnd);			
			return 1L;
		}
		break;		
		default:
		{
			int rlt = _draw_proc(message, lparam);
			if (rlt != -1) return rlt;
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


void _dlg_benchmark(
		HWND hwnd
	)
{
	DialogBoxParam(
			NULL,
			MAKEINTRESOURCE(IDD_DIALOG_BENCHMARK),
			hwnd,
			pv(_benchmark_dlg_proc),
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
		{ L"", IDC_AUTO_START, CONF_AUTO_START },
		{ L"", -1, -1 }
	};

	_ctl_init static_head[ ] = {
		{ L"# Mount Settings", IDC_HEAD1, 0 },
		{ L"# Password Caching", IDC_HEAD2, 0 },
		{ L"# Other Options", IDC_HEAD3, 0 },
		{ L"", -1, -1 }
	};

	WORD code = LOWORD(wparam);
	WORD id = LOWORD(wparam);

	DWORD _flags = 0;
	DWORD _hotkeys[HOTKEYS] = { 0 };

	_wnd_data *wnd;

	int check = 0; int k = 0;
	switch (message) 
	{
		case WM_INITDIALOG: 
		{
			_tab_data *tab = malloc(sizeof(_tab_data));
			wnd_set_long(hwnd, GWL_USERDATA, tab); 

			wnd = _sub_class(GetDlgItem(hwnd, IDB_PREF_GENERAL), 
				CreateDialog(__hinst, MAKEINTRESOURCE(DLG_CONF_GENERAL), GetDlgItem(hwnd, IDC_TAB), _tab_proc), FALSE);

			{
				while (ctl_chk[k].id != -1) {

					_sub_class(GetDlgItem(wnd->dlg, ctl_chk[k].id), FALSE, FALSE);
					_set_check(wnd->dlg, ctl_chk[k].id, __config.conf_flags & ctl_chk[k].val);
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

			wnd = _sub_class(GetDlgItem(hwnd, IDB_PREF_HOTKEYS), 
				CreateDialog(__hinst, MAKEINTRESOURCE(DLG_CONF_HOTKEYS), GetDlgItem(hwnd, IDC_TAB), _tab_proc), FALSE);

			{
				_sub_class(GetDlgItem(wnd->dlg, IDC_KEY_USEEXT), FALSE, FALSE);

				k = 0;
				while (hotks_edit[k].id != -1) {
					wchar_t key[200] = { 0 };

					_sub_class(GetDlgItem(wnd->dlg, hotks_edit[k].id), FALSE, TRUE);
					_sub_class(GetDlgItem(wnd->dlg, hotks_chk[k].id), FALSE, FALSE);

					_set_check(wnd->dlg, hotks_chk[k].id, __config.hotkeys[k]);
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
		case WM_COMMAND: 
		{
			if ((id == IDOK) || (id == IDCANCEL)) 
			{
				wnd = wnd_get_long(GetDlgItem(hwnd, IDB_PREF_GENERAL), GWL_USERDATA);
				if (wnd) 
				{
					k = 0;
					while (ctl_chk[k].id != -1) {	
						_flags |= _get_check(wnd->dlg, ctl_chk[k].id) ? ctl_chk[k].val : FALSE;
						k++;
					}
				}
				wnd = wnd_get_long(GetDlgItem(hwnd, IDB_PREF_HOTKEYS), GWL_USERDATA);
				if (wnd) 
				{
					k = 0;
					while (hotks_edit[k].id != -1) 
					{					
						if (_get_check(wnd->dlg, hotks_chk[k].id))
							_hotkeys[k] = ((_wnd_data *)wnd_get_long(GetDlgItem(wnd->dlg, hotks_edit[k].id), GWL_USERDATA))->vk;
						k++;
					}
				}
				
				if (id == IDCANCEL) check = TRUE;
				if (id == IDOK) 
				{
					_unset_hotkeys(__config.hotkeys);	
					check = _check_hotkeys(wnd->dlg, _hotkeys);					

					if (check) 
					{
						if (_hotkeys[3] && !__config.hotkeys[3]) {
							if (!__msg_w(L"Set Hotkey for call BSOD?", hwnd)) _hotkeys[3] = 0;

						}
						if ((_flags & CONF_AUTO_START) != (__config.conf_flags & CONF_AUTO_START)) {
							autorun_set(_flags & CONF_AUTO_START);
						}

						__config.conf_flags = _flags;
						autocpy(&__config.hotkeys, &_hotkeys, sizeof(DWORD)*HOTKEYS);

						dc_save_conf(&__config);						

					}
					_set_hotkeys(hwnd, __config.hotkeys, FALSE);

				}
				if (check) EndDialog (hwnd, id);
				return 1L;
			}
		}
		break;
		case WM_DESTROY: 
		{
			wnd = wnd_get_long(GetDlgItem(hwnd, IDB_PREF_GENERAL), GWL_USERDATA);
			if (wnd) 
			{
				k = 0;
				while (ctl_chk[k].id != -1) {
					__unsub_class(GetDlgItem(wnd->dlg, ctl_chk[k].id));
					k++;
				}
			}
			wnd = wnd_get_long(GetDlgItem(hwnd, IDB_PREF_HOTKEYS), GWL_USERDATA);
			if (wnd) 
			{
				__unsub_class(GetDlgItem(wnd->dlg, IDC_KEY_USEEXT));

				k = 0;
				while (hotks_edit[k].id != -1) 
				{
					__unsub_class(GetDlgItem(wnd->dlg, hotks_edit[k].id));
					__unsub_class(GetDlgItem(wnd->dlg, hotks_chk[k].id));
					k++;
				}
			}
			__unsub_class(GetDlgItem(hwnd, IDB_PREF_GENERAL));
			__unsub_class(GetDlgItem(hwnd, IDB_PREF_HOTKEYS));
			__unsub_class(GetDlgItem(hwnd, IDB_PREF_BOOT));

		}
		default:
		{
			int rlt = _draw_proc(message, lparam);
			if (rlt != -1) return rlt;
		}
	}
	return 0L;

}

INT_PTR CALLBACK
_password_change_dlg_proc(
		HWND hwnd,
		UINT message,
		WPARAM wparam,
		LPARAM lparam
	)
{
	WORD code = HIWORD(wparam);
	WORD id   = LOWORD(wparam);

	wchar_t display[MAX_PATH] = { 0 };
	static  dlgpass *info;
	int     k;

	int check_init[ ] = {
		IDC_CHECK_SHOW_CURRENT, IDC_USE_KEYFILES_CURRENT,
		IDC_CHECK_SHOW_NEW, IDC_USE_KEYFILES_NEW,
		-1
	};

	_ctl_init static_head[ ] = {
		{ L"# Current Password", IDC_HEAD_PASS_CURRENT, 0 },
		{ L"# New Password",     IDC_HEAD_PASS_NEW,     0 },
		{ L"# Password Rating",  IDC_HEAD_RATING,       0 },
		{ L"", -1, -1 }
	};

	switch (message) 
	{
		case WM_CTLCOLOREDIT : return _ctl_color(wparam, _cl(COLOR_BTNFACE, LGHT_CLR));
			break;

		case WM_CTLCOLORSTATIC : 
		{
			HDC dc = (HDC)wparam;
			COLORREF bgcolor, fn = 0;

			SetBkMode(dc, TRANSPARENT);

			k = 0;
			while (pass_gr_ctls[k].id != -1) 
			{
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
		case WM_INITDIALOG : 
		{
			info = (dlgpass *)lparam;

			SendMessage(GetDlgItem(hwnd, IDE_PASS_NEW_CONFIRM), EM_LIMITTEXT, MAX_PASSWORD, 0);
			SendMessage(GetDlgItem(hwnd, IDE_PASS_CURRENT),     EM_LIMITTEXT, MAX_PASSWORD, 0);
			SendMessage(GetDlgItem(hwnd, IDE_PASS_NEW),         EM_LIMITTEXT, MAX_PASSWORD, 0);			

			SendMessage(hwnd, WM_COMMAND, 
				MAKELONG(IDE_PASS_NEW, EN_CHANGE), (LPARAM)GetDlgItem(hwnd, IDE_PASS_NEW));

			if (info->node) {
				_snwprintf(display, sizeof_w(display), L"[%s] - %s", 
					info->node->mnt.info.status.mnt_point, info->node->mnt.info.device);

			} else {
				wcscpy(display, L"Change password");

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

			k = 0;
			while (static_head[k].id != -1) {

				SetWindowText(GetDlgItem(hwnd, static_head[k].id), static_head[k].display);
				SendMessage(GetDlgItem(hwnd, static_head[k].id), (UINT)WM_SETFONT, (WPARAM)__font_bold, 0);
				k++;
			}

			k = 0;
			while (check_init[k] != -1) {

				_sub_class(GetDlgItem(hwnd, check_init[k]), FALSE, FALSE);
				_set_check(hwnd, check_init[k], FALSE);
				k++;
			}	
			SetForegroundWindow(hwnd);
			return 1L;

		}
		break;
		case WM_USER_CLICK : 
		{
			if ((HWND)wparam == GetDlgItem(hwnd, IDC_CHECK_SHOW_CURRENT))
			{
				SendMessage(GetDlgItem(hwnd, IDE_PASS_CURRENT), 
					EM_SETPASSWORDCHAR, _get_check(hwnd, IDC_CHECK_SHOW_CURRENT) ? 0 : '*', 0);

				InvalidateRect(GetDlgItem(hwnd, IDE_PASS_CURRENT), NULL, TRUE);
				return 1L;

			}
			if ((HWND)wparam == GetDlgItem(hwnd, IDC_CHECK_SHOW_NEW))
			{
				int mask = _get_check(hwnd, IDC_CHECK_SHOW_NEW) ? 0 : '*';

				SendMessage(GetDlgItem(hwnd, IDE_PASS_NEW), EM_SETPASSWORDCHAR,	mask, 0);
				SendMessage(GetDlgItem(hwnd, IDE_PASS_NEW_CONFIRM), EM_SETPASSWORDCHAR,	mask, 0);

				InvalidateRect(GetDlgItem(hwnd, IDE_PASS_NEW), NULL, TRUE);
				InvalidateRect(GetDlgItem(hwnd, IDE_PASS_NEW_CONFIRM), NULL, TRUE);
				return 1L;

			}
			if ((HWND)wparam == GetDlgItem(hwnd, IDC_USE_KEYFILES_CURRENT)) 
			{
				SendMessage(hwnd, WM_COMMAND, 
					MAKELONG(IDE_PASS_CURRENT, EN_CHANGE), (LPARAM)GetDlgItem(hwnd, IDE_PASS_CURRENT));

				EnableWindow(GetDlgItem(hwnd, IDB_USE_KEYFILES_CURRENT), _get_check(hwnd, IDC_USE_KEYFILES_CURRENT));

				return 1L;
			}
			if ((HWND)wparam == GetDlgItem(hwnd, IDC_USE_KEYFILES_NEW)) 
			{
				SendMessage(hwnd, WM_COMMAND, 
					MAKELONG(IDE_PASS_NEW, EN_CHANGE), (LPARAM)GetDlgItem(hwnd, IDE_PASS_NEW));

				EnableWindow(GetDlgItem(hwnd, IDB_USE_KEYFILES_NEW), _get_check(hwnd, IDC_USE_KEYFILES_NEW));

				return 1L;
			}
		}
		break;
		case WM_COMMAND :

			if (id == IDB_USE_KEYFILES_CURRENT) 
			{
				_dlg_keyfiles(hwnd, KEYLIST_CURRENT);

				SendMessage(hwnd, WM_COMMAND, 
					MAKELONG(IDE_PASS_CURRENT, EN_CHANGE), (LPARAM)GetDlgItem(hwnd, IDE_PASS_CURRENT));

			}
			if (id == IDB_USE_KEYFILES_NEW) 
			{
				_dlg_keyfiles(hwnd, KEYLIST_CHANGE_PASS);

				SendMessage(hwnd, WM_COMMAND, 
					MAKELONG(IDE_PASS_NEW, EN_CHANGE), (LPARAM)GetDlgItem(hwnd, IDE_PASS_NEW));

			}

			if (code == EN_CHANGE) 
			{
				BOOL correct_current, correct_new;
				int  id_stat_current, id_stat_new;

				dc_pass *pass;
				dc_pass *verify;

				ldr_config conf;

				int kb_layout = -1;
				int keylist;

				if (info->node && _is_boot_device(&info->node->mnt.info)) {

					if (dc_get_mbr_config(-1, NULL, &conf) == ST_OK) {
						kb_layout = conf.kbd_layout;

					}
				}
				if (id == IDE_PASS_NEW)
				{
					int entropy;
					dc_pass *pass;

					pass = _get_pass(hwnd, IDE_PASS_NEW);

					_draw_pass_rating(hwnd, pass, kb_layout, &entropy);
					secure_free(pass);

					SendMessage(
							GetDlgItem(hwnd, IDP_BREAKABLE),
							PBM_SETPOS,
							(WPARAM)entropy, 0
					);			
				}
				
				pass    = _get_pass(hwnd, IDE_PASS_CURRENT);
				keylist = _get_check(hwnd, IDC_USE_KEYFILES_CURRENT) ? KEYLIST_CURRENT : KEYLIST_NONE;

				correct_current = 
					_input_verify(pass, NULL, keylist, -1, &id_stat_current
				);

				secure_free(pass);

				pass    = _get_pass(hwnd, IDE_PASS_NEW);
				verify  = _get_pass(hwnd, IDE_PASS_NEW_CONFIRM);
				keylist = _get_check(hwnd, IDC_USE_KEYFILES_NEW) ? KEYLIST_CHANGE_PASS : KEYLIST_NONE;

				correct_new =
					_input_verify(pass, verify, keylist, kb_layout, &id_stat_new
				);

				secure_free(pass);
				secure_free(verify);				

				SetWindowText(GetDlgItem(hwnd, IDC_PASS_STATUS_CURRENT), _get_text_name(id_stat_current, pass_status));
				SetWindowText(GetDlgItem(hwnd, IDC_PASS_STATUS_NEW), _get_text_name(id_stat_new, pass_status));

				EnableWindow(GetDlgItem(hwnd, IDOK), correct_current && correct_new);

				return 1L;
		
			}
			if ((id == IDCANCEL) || (id == IDOK)) 
			{
				if (id == IDOK)
				{
					info->pass     = _get_pass_keyfiles(hwnd, IDE_PASS_CURRENT, IDC_USE_KEYFILES_CURRENT, KEYLIST_CURRENT);
					info->new_pass = _get_pass_keyfiles(hwnd, IDE_PASS_NEW,     IDC_USE_KEYFILES_NEW,     KEYLIST_CHANGE_PASS);

					if (IsWindowEnabled(GetDlgItem(hwnd, IDC_COMBO_MNPOINT)) && 
							info->mnt_point) 
					{
						GetWindowText(
								GetDlgItem(hwnd, IDC_COMBO_MNPOINT), 
								(wchar_t *)info->mnt_point, 
								MAX_PATH
						);
					}
				}
				EndDialog (hwnd, id);
				return 1L;
	
			}
		break;
		case WM_DESTROY: 
		{
			_wipe_pass_control(hwnd, IDE_PASS_NEW_CONFIRM);
			_wipe_pass_control(hwnd, IDE_PASS_CURRENT);
			_wipe_pass_control(hwnd, IDE_PASS_NEW);		

			_keyfiles_wipe(KEYLIST_CURRENT);
			_keyfiles_wipe(KEYLIST_CHANGE_PASS);

			return 0L;
		}
		break;
		default:
		{
			int rlt = _draw_proc(message, lparam);
			if (rlt != -1) return rlt;
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

	wchar_t display[MAX_PATH] = { 0 };
	static dlgpass *info;

	static RECT rc_left  = { 0, 0, 0, 0 };
	static RECT rc_right = { 0, 0, 0, 0 };

	static cut;

	switch (message) {
		case WM_DRAWITEM : {

			DRAWITEMSTRUCT *draw = pv(lparam);

			static RECT left;
			static RECT right;

			switch (draw->CtlID) {

				case IDC_FRAME_LEFT: 
				{
					if (!rc_left.right)
					{
						_relative_rect(draw->hwndItem, &rc_left);
						rc_left.bottom -= cut;
					}
					MoveWindow(draw->hwndItem, 
						rc_left.left, rc_left.top, rc_left.right, rc_left.bottom, TRUE
					);
				}
				break;
				case IDC_FRAME_RIGHT:
				{					
					if (!rc_right.right)
					{
						_relative_rect(draw->hwndItem, &rc_right);
						rc_right.bottom -= cut;
					}
					MoveWindow(draw->hwndItem, 
						rc_right.left, rc_right.top, rc_right.right, rc_right.bottom, TRUE
					);
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
		case WM_INITDIALOG : 
		{
			int ctl_resize[ ] = {
				IDC_FRAME_LEFT,
				IDC_FRAME_RIGHT,
				-1
			};

			info = (dlgpass *)lparam;			
			_init_mount_points(GetDlgItem(hwnd, IDC_COMBO_MNPOINT));

			SendMessage(GetDlgItem(hwnd, IDC_COMBO_MNPOINT), CB_SETCURSEL, 1, 0);
			SendMessage(GetDlgItem(hwnd, IDE_PASS), EM_LIMITTEXT, MAX_PASSWORD, 0);

			if (info->node) {
				_snwprintf(display, sizeof_w(display), L"[%s] - %s", 
					info->node->mnt.info.status.mnt_point, info->node->mnt.info.device);

			} else {
				wcscpy(display, L"Enter password");

			}
			SetWindowText(hwnd, display);

			SetWindowText(GetDlgItem(hwnd, IDC_HEAD_PASS), L"# Current Password");
			SendMessage(GetDlgItem(hwnd, IDC_HEAD_PASS), WM_SETFONT, (WPARAM)__font_bold, 0);

			SetWindowText(GetDlgItem(hwnd, IDC_HEAD_MOUNT_OPTIONS), L"# Mount Options");
			SendMessage(GetDlgItem(hwnd, IDC_HEAD_MOUNT_OPTIONS), WM_SETFONT, (WPARAM)__font_bold, 0);			

			_sub_class(GetDlgItem(hwnd, IDC_CHECK_SHOW), FALSE, FALSE);
			_set_check(hwnd, IDC_CHECK_SHOW, FALSE);

			_sub_class(GetDlgItem(hwnd, IDC_USE_KEYFILES), FALSE, FALSE);
			_set_check(hwnd, IDC_USE_KEYFILES, FALSE);

			{
				HWND mnt_combo = GetDlgItem(hwnd, IDC_COMBO_MNPOINT);
				HWND mnt_check = GetDlgItem(hwnd, IDC_CHECK_MNT_SET);
				HWND mnt_label = GetDlgItem(hwnd, IDC_MNT_POINT);

				BOOL enable;
				RECT rc_main;

				GetWindowRect(hwnd, &rc_main);
				enable = info->node && wcsstr(info->node->mnt.info.status.mnt_point, L"\\\\?\\") != NULL;

				EnableWindow(mnt_combo, enable);
				EnableWindow(mnt_check, enable);
				EnableWindow(mnt_label, enable);

				_sub_class(GetDlgItem(hwnd, IDC_CHECK_MNT_SET), FALSE, FALSE);
				_set_check(hwnd, IDC_CHECK_MNT_SET, enable);
				/*
				cut = info->mnt_point ? 0 : 45;

				ShowWindow(mnt_label, !cut);
				ShowWindow(mnt_combo, !cut);

				SetWindowPos(hwnd, HWND_TOP, rc_main.left, rc_main.top, 
					rc_main.right - rc_main.left, rc_main.bottom - rc_main.top - cut, 0);	
				*/
			}
			SendMessage(hwnd, WM_COMMAND, 
				MAKELONG(IDE_PASS, EN_CHANGE), (LPARAM)GetDlgItem(hwnd, IDE_PASS));

			SetForegroundWindow(hwnd);
			return 1L;

		}
		break;
		case WM_USER_CLICK : 
		{
			if ((HWND)wparam == GetDlgItem(hwnd, IDC_CHECK_MNT_SET))
			{
				EnableWindow(
					GetDlgItem(hwnd, IDC_COMBO_MNPOINT), _get_check(hwnd, IDC_CHECK_MNT_SET)
				);
				EnableWindow(
					GetDlgItem(hwnd, IDC_MNT_POINT), _get_check(hwnd, IDC_CHECK_MNT_SET)
				);
				return 1L;
			}

			if ((HWND)wparam == GetDlgItem(hwnd, IDC_CHECK_SHOW))
			{
				int mask = _get_check(hwnd, IDC_CHECK_SHOW) ? 0 : '*';

				SendMessage(GetDlgItem(hwnd, IDE_PASS),
					EM_SETPASSWORDCHAR,	mask, 0
				);

				InvalidateRect(GetDlgItem(hwnd, IDE_PASS), NULL, TRUE);
				return 1L;

			}

			if ((HWND)wparam == GetDlgItem(hwnd, IDC_USE_KEYFILES)) 
			{
				SendMessage(hwnd, WM_COMMAND, 
					MAKELONG(IDE_PASS, EN_CHANGE), (LPARAM)GetDlgItem(hwnd, IDE_PASS));

				EnableWindow(GetDlgItem(hwnd, IDB_USE_KEYFILES), _get_check(hwnd, IDC_USE_KEYFILES));

				return 1L;
			}
		}
		break;
		case WM_COMMAND :

			if (id == IDB_USE_KEYFILES)
			{
				_dlg_keyfiles(hwnd, KEYLIST_CURRENT);

				SendMessage(hwnd, WM_COMMAND, 
					MAKELONG(IDE_PASS, EN_CHANGE), (LPARAM)GetDlgItem(hwnd, IDE_PASS));
			}

			if (code == CBN_SELCHANGE && id == IDC_COMBO_MNPOINT) 
			{
				if (SendMessage((HWND)lparam, CB_GETCURSEL, 0, 0) == 0)
				{
					HWND h_combo = GetDlgItem(hwnd, IDC_COMBO_MNPOINT);

					int sel_item = 1;
					wchar_t path[MAX_PATH];

					if (_folder_choice(hwnd, path, L"Choice folder for mount point"))
					{
						sel_item = (int)SendMessage(h_combo, CB_GETCOUNT, 0, 0);
						SendMessage(h_combo, CB_ADDSTRING, 0, (LPARAM)path);						
					}
					SendMessage(h_combo, CB_SETCURSEL, sel_item, 0);

				}
			}
			if (code == EN_CHANGE)
			{
				BOOL correct;
				int idx_status;

				dc_pass *pass = _get_pass(hwnd, IDE_PASS);
				int keylist = _get_check(hwnd, IDC_USE_KEYFILES) ? KEYLIST_CURRENT : KEYLIST_NONE;

				correct = 
					_input_verify(pass, NULL, keylist, -1, &idx_status
				);

				secure_free(pass);

				SetWindowText(GetDlgItem(hwnd, IDC_PASS_STATUS), _get_text_name(idx_status, pass_status));
				EnableWindow(GetDlgItem(hwnd, IDOK), correct);

				return 1L;
		
			}
			if ((id == IDCANCEL) || (id == IDOK)) 
			{
				if (id == IDOK)
				{
					info->pass = _get_pass_keyfiles(hwnd, IDE_PASS, IDC_USE_KEYFILES, KEYLIST_CURRENT);

					if (IsWindowEnabled(GetDlgItem(hwnd, IDC_COMBO_MNPOINT)) && 
							info->mnt_point) 
					{
						GetWindowText(
								GetDlgItem(hwnd, IDC_COMBO_MNPOINT), 
								(wchar_t *)info->mnt_point, 
								MAX_PATH
						);
					}
				}
				EndDialog (hwnd, id);
				return 1L;
	
			}
		break;
		case WM_DESTROY: 
		{
			_wipe_pass_control(hwnd, IDE_PASS);
			_keyfiles_wipe(KEYLIST_CURRENT);

			zeroauto(&rc_right, sizeof(rc_right));
			zeroauto(&rc_left, sizeof(rc_left));

			cut = 0;
			return 0L;

		}
		break;
		case WM_MEASUREITEM: 
		{
			MEASUREITEMSTRUCT *item = pv(lparam);

			if (item->CtlType != ODT_LISTVIEW)
				item->itemHeight -= 3;
 
		}
		break; 
	}
	return 0L;

}


int _get_info_install_boot_page(
		vol_inf *vol,
		_wz_sheets *sheets,
		int *dsk_num	
	)
{				
	ldr_config conf;
	drive_inf drv;

	int boot_disk;
	int rlt = ST_ERROR;

	sheets[WPAGE_ENC_BOOT].show = FALSE;
	if (_is_boot_device(vol)) sheets[WPAGE_ENC_BOOT].show = TRUE;

	rlt = dc_get_drive_info(vol->w32_device, &drv);
	if (ST_OK == rlt && dsk_num) *dsk_num = drv.disks[0].number;

	rlt = dc_get_boot_disk(&boot_disk);
	if (ST_OK == rlt) {
	
		if (ST_OK == dc_get_mbr_config(boot_disk, NULL, &conf))
			sheets[WPAGE_ENC_BOOT].show = FALSE;

	}
	return rlt;

}


BOOL _wizard_step(
		_dnode *node,
		_wz_sheets *sheets,
		int *index,
		int id_back,
		int id_next,
		int id
	)
{
	HWND parent = GetParent(GetParent(sheets[WPAGE_ENC_TYPE].hwnd));
	BOOL enb_back = FALSE;

	int next = 0;
	int back = 0;
	int k = 0;

	ShowWindow(sheets[*index].hwnd, SW_HIDE);

	if (id == id_next) 
	{
		while (!sheets[++*index].show);
	} else {
		while (!sheets[--*index].show);
	}

	next = *index;
	while (!sheets[++next].show);

	back = *index - 1;
	while (back > 0 && !sheets[back].show) back--;

	EnableWindow(GetDlgItem(parent, id_back), !(back == 0 && node->dlg.act_type != -1));

	if (sheets[*index].id == -1 || sheets[next].id == -1) 
	{
		SetWindowText(GetDlgItem(parent, id_next), L"OK");
		EnableWindow(GetDlgItem(parent, id_next), FALSE);
	} else {
		SetWindowText(GetDlgItem(parent, id_next), L"&Next");
		EnableWindow(GetDlgItem(parent, id_next), TRUE);

	}
	ShowWindow(sheets[*index].hwnd, SW_SHOW);
	if (!*index) 
	{
		while (sheets[k].id != -1) sheets[k++].show = TRUE;
		_get_info_install_boot_page(&node->mnt.info, sheets, NULL);
	}
	return sheets[*index].id == -1; 

}


int _update_layout(
		_dnode *node,
		int new_layout,  /*-1 - init*/
		int *old_layout

	)
{
	BOOL _boot_dev = _is_boot_device(&node->mnt.info);
	ldr_config conf;

	int kbd_layout = KB_QWERTY;
	int rlt = ST_OK;

	if (new_layout != -1) {
		if (_boot_dev) {

			if ((rlt = dc_get_mbr_config(-1, NULL, &conf)) != ST_OK) 
				return rlt;

			conf.kbd_layout = new_layout;

			if ((rlt = dc_set_mbr_config(-1, NULL, &conf)) != ST_OK) 
				return rlt;

		}
		return rlt;
	} else {
		BOOL result = dc_get_mbr_config(-1, NULL, &conf) == ST_OK;

		if (old_layout) {
			*old_layout = result ? conf.kbd_layout : KB_QWERTY;
		}

		return result;

	}
}


int _init_wizard_encrypt_pages(
		HWND        parent,
		_wz_sheets *sheets,
		_dnode     *node
	)
{
	wchar_t *static_head[ ] = {
		L"# Action Type",
		L"# Format Options",
		L"# Encryption Settings",
		L"# Boot Settings",
		L"# Volume Password",
		L""
	};

	HWND hwnd;
	int k = 0;

	int count = 0;
	while (sheets[count].id != -1) {				

		sheets[count].hwnd = CreateDialog(__hinst,
			MAKEINTRESOURCE(sheets[count].id), GetDlgItem(parent, IDC_TAB), _tab_proc
			);
		count++;

	}
	while (wcslen(static_head[k]) != 0) {

		EnumChildWindows(sheets[k].hwnd, __sub_enum, (LPARAM)NULL);
		SetWindowText(GetDlgItem(sheets[k].hwnd, IDC_HEAD), static_head[k]);

		SendMessage(GetDlgItem(sheets[k++].hwnd, IDC_HEAD), (UINT)WM_SETFONT, (WPARAM)__font_bold, 0);

	}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
	hwnd = sheets[WPAGE_ENC_TYPE].hwnd;
/////////////////////////////////////
	{
		if (node->dlg.act_type == -1) {
			_set_check(hwnd, IDC_RADIO_ENCRYPT, TRUE);
		} else 
		{
			_set_check(hwnd, IDC_RADIO_REENCRYPT, node->dlg.act_type == ACT_REENCRYPT);
			_set_check(hwnd, IDC_RADIO_ENCRYPT, node->dlg.act_type == ACT_ENCRYPT);
			_set_check(hwnd, IDC_RADIO_FORMAT, node->dlg.act_type == ACT_FORMAT);

		}
		k = 0;
		while (radio_type[k] != -1) SendMessage(
			GetDlgItem(hwnd, radio_type[k++]), (UINT)WM_SETFONT, (WPARAM)__font_bold, 0);		

	}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
	hwnd = sheets[WPAGE_ENC_FRMT].hwnd;
/////////////////////////////////////
	{
		HWND h_fs = GetDlgItem(hwnd, IDC_COMBO_FS_LIST);

		_sub_class(GetDlgItem(hwnd, IDC_CHECK_QUICK_FORMAT), FALSE, FALSE);
		_set_check(hwnd, IDC_CHECK_QUICK_FORMAT, FALSE);

		k = 0;
		while (wcslen(fs_names[k])) SendMessage(
			h_fs, (UINT)CB_ADDSTRING, 0, (LPARAM)fs_names[k++]);

		SendMessage(h_fs, CB_SETCURSEL, 2, 0);
			
	}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
	hwnd = sheets[WPAGE_ENC_CONF].hwnd;
/////////////////////////////////////
	{
		_init_combo(
			GetDlgItem(hwnd, IDC_COMBO_ALGORT), cipher_names, CF_AES, FALSE, -1
			);

		_init_combo(
			GetDlgItem(hwnd, IDC_COMBO_PASSES), wipe_modes, WP_NONE, FALSE, -1
			);

		k = 0;
		while (combo_sel[k] != -1) SendMessage(
			GetDlgItem(hwnd, combo_sel[k++]), CB_SETCURSEL, 0, 0);
		
	}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
	hwnd = sheets[WPAGE_ENC_BOOT].hwnd;
/////////////////////////////////////
	{
		int dsk_num = -1;
		int rlt = _get_info_install_boot_page(&node->mnt.info, sheets, &dsk_num);;

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
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
	hwnd = sheets[WPAGE_ENC_PASS].hwnd;
/////////////////////////////////////
	{
		int kbd_layout;
		_update_layout(node, -1, &kbd_layout);

		_init_combo(
			GetDlgItem(hwnd, IDC_COMBO_KBLAYOUT), kb_layouts, kbd_layout, FALSE, -1
			);

		SetWindowText(GetDlgItem(
			hwnd, IDC_USE_KEYFILES), _is_boot_device(&node->mnt.info) ? IDS_USE_KEYFILE : IDS_USE_KEYFILES
			);

		_sub_class(GetDlgItem(hwnd, IDC_CHECK_SHOW), FALSE, FALSE);
		_set_check(hwnd, IDC_CHECK_SHOW, FALSE);

		_sub_class(GetDlgItem(hwnd, IDC_USE_KEYFILES), FALSE, FALSE);
		_set_check(hwnd, IDC_USE_KEYFILES, FALSE);

		SendMessage(
			GetDlgItem(hwnd, IDP_BREAKABLE),
			PBM_SETBARCOLOR, 0, _cl(COLOR_BTNSHADOW, DARK_CLR-20)

		);	
		SendMessage(
			GetDlgItem(hwnd, IDP_BREAKABLE),
			PBM_SETRANGE, 0,
			MAKELPARAM(0, 193)
		);

		SetWindowText(GetDlgItem(hwnd, IDC_HEAD2), L"# Password Rating");
		SendMessage(GetDlgItem(hwnd, IDC_HEAD2), (UINT)WM_SETFONT, (WPARAM)__font_bold, 0);

		SendMessage(GetDlgItem(hwnd, IDE_PASS), EM_LIMITTEXT, MAX_PASSWORD, 0);
		SendMessage(GetDlgItem(hwnd, IDE_CONFIRM), EM_LIMITTEXT, MAX_PASSWORD, 0);
		
	}
/////////////////////////////////////
	return count;

}


void _run_wizard_action(
		HWND hwnd,
		_wz_sheets *sheets,
		_dnode *node
												
	)
{
	BOOL set_loader = (BOOL)
		SendMessage(GetDlgItem(sheets[WPAGE_ENC_BOOT].hwnd, IDC_COMBO_BOOT_INST), CB_GETCURSEL, 0, 0);

	wchar_t *fs_name = fs_names[SendMessage(
		GetDlgItem(sheets[WPAGE_ENC_FRMT].hwnd, IDC_COMBO_FS_LIST), CB_GETCURSEL, 0, 0)];

	int kb_layout = _get_combo_val(GetDlgItem(sheets[WPAGE_ENC_PASS].hwnd, IDC_COMBO_KBLAYOUT), kb_layouts);
	BOOL q_format = _get_check(sheets[WPAGE_ENC_FRMT].hwnd, IDC_CHECK_QUICK_FORMAT);

	crypt_info crypt;

	int rlt = ST_OK;
	int act_type;

	dc_pass *pass = NULL;

	crypt.cipher_id  = _get_combo_val(GetDlgItem(sheets[WPAGE_ENC_CONF].hwnd, IDC_COMBO_ALGORT), cipher_names);
	crypt.wp_mode    = _get_combo_val(GetDlgItem(sheets[WPAGE_ENC_CONF].hwnd, IDC_COMBO_PASSES), wipe_modes);
		
	if (_get_check(sheets[WPAGE_ENC_TYPE].hwnd, IDC_RADIO_REENCRYPT)) act_type = ACT_REENCRYPT;
	if (_get_check(sheets[WPAGE_ENC_TYPE].hwnd, IDC_RADIO_ENCRYPT))   act_type = ACT_ENCRYPT;
	if (_get_check(sheets[WPAGE_ENC_TYPE].hwnd, IDC_RADIO_FORMAT))    act_type = ACT_FORMAT;

/////////////////////////////////////////////////////////////////////////////////////////////////////////////
	if (act_type == ACT_ENCRYPT || act_type == ACT_FORMAT) 
/////////////////////////////////////
	{
		node->mnt.info.status.crypt.wp_mode = crypt.wp_mode;
		rlt = ST_OK;

		if (sheets[WPAGE_ENC_BOOT].show) {
	 		if (set_loader) rlt = _set_boot_loader(hwnd, -1);

		}
		if (rlt == ST_OK && 
			IsWindowEnabled(GetDlgItem(sheets[WPAGE_ENC_PASS].hwnd, IDC_LAYOUTS_LIST))) 
		{
			rlt = _update_layout(node, kb_layout, NULL);
		}
		if (rlt == ST_OK)
		{
		/////////////////////////////////////////////////////////////////////////////////////////////////////////////
			if (act_type == ACT_ENCRYPT)
		/////////////////////////////////////
		{
			ShowWindow(hwnd, FALSE);

			pass = _get_pass_keyfiles(sheets[WPAGE_ENC_PASS].hwnd, IDE_PASS, IDC_USE_KEYFILES, KEYLIST_CURRENT);

			if (pass != NULL) 
			{
				rlt = dc_start_encrypt(node->mnt.info.device, pass, &crypt);
				secure_free(pass);

			}
		}
		/////////////////////////////////////////////////////////////////////////////////////////////////////////////
			if (act_type == ACT_FORMAT)
		/////////////////////////////////////
			{
				pass = _get_pass_keyfiles(sheets[WPAGE_ENC_PASS].hwnd, IDE_PASS, IDC_USE_KEYFILES, KEYLIST_CURRENT);
				if (pass) {

					rlt = dc_start_format(node->mnt.info.device, pass, &crypt);
					secure_free(pass);

				}
			}			
		}
	}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
	if (act_type == ACT_REENCRYPT)
/////////////////////////////////////
	{
		wchar_t mnt_point[MAX_PATH] = { 0 };
		wchar_t vol[MAX_PATH];

		dlgpass dlg_info = { node, NULL, NULL, mnt_point };

		ShowWindow(hwnd, FALSE);
		if (_dlg_get_pass(__dlg, &dlg_info) == ST_OK) 
		{
			node->mnt.info.status.crypt.wp_mode = crypt.wp_mode;
			rlt = dc_start_re_encrypt(node->mnt.info.device, dlg_info.pass, &crypt);

			secure_free(dlg_info.pass);
			if (mnt_point[0] != 0)
			{
				_snwprintf(vol, sizeof_w(vol), L"%s\\", node->mnt.info.w32_device);
				_set_trailing_slash(mnt_point);

				if (SetVolumeMountPoint(mnt_point, vol) == 0) {
					_error_s(__dlg, L"Error when adding mount point", rlt);

				}
			}
		} else 
		{
			rlt = ST_CANCEL;
		}
	}		
/////////////////////////////////////

	node->dlg.rlt = rlt;
	node->dlg.act_type = act_type;

	node->dlg.q_format = q_format;
	node->dlg.fs_name  = fs_name;

	EndDialog(hwnd, 0);

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
	WORD id   = LOWORD(wparam);

	static _wz_sheets sheets[ ] = 
	{
		{ DLG_WIZ_TYPE,   0, TRUE },
		{ DLG_WIZ_FORMAT, 0, TRUE },
		{ DLG_WIZ_CONF,   0, TRUE },
		{ DLG_WIZ_LOADER, 0, TRUE },
		{ DLG_WIZ_PASS,   0, TRUE },
		{ -1, 0, TRUE }
	};

	static vol_inf *vol;
	static _dnode  *node;

	static index = 0;	

	static count = 0;
	int cr = 0;

	int check = 0; int k = 0;

	switch (message) 
	{
		case WM_INITDIALOG: 
		{
			vol = &((_dnode *)lparam)->mnt.info;
			node = (_dnode *)lparam;

			SetWindowText(hwnd, vol->device);

			count = _init_wizard_encrypt_pages(hwnd, pv(&sheets), node);
			sheets[count].hwnd = (HWND)lparam;

			if (node->dlg.act_type != -1) 
			{				
				SendMessage(hwnd, WM_COMMAND, MAKELONG(IDOK, 0), (LPARAM)GetDlgItem(hwnd, IDOK));
			} else {
				ShowWindow(sheets[WPAGE_ENC_TYPE].hwnd, SW_SHOW);
			}

			SetForegroundWindow(hwnd);			
			return 1L;

		}
		break;
		case WM_COMMAND: 
		{
			if (id != IDCANCEL) 
			{
				BOOL set_loader = (BOOL) (
						( sheets[WPAGE_ENC_BOOT].show && SendMessage(GetDlgItem(sheets[WPAGE_ENC_BOOT].hwnd, IDC_COMBO_BOOT_INST), CB_GETCURSEL, 0, 0) ) ||
						( _is_boot_device(vol) && _update_layout(node, -1, NULL) )
					);

				sheets[WPAGE_ENC_FRMT].show = _get_check(sheets[WPAGE_ENC_TYPE].hwnd, IDC_RADIO_FORMAT);
				sheets[WPAGE_ENC_TYPE].show = node->dlg.act_type == -1;

				if (_get_check(sheets[WPAGE_ENC_TYPE].hwnd, IDC_RADIO_REENCRYPT)) 
				{
					sheets[WPAGE_ENC_BOOT].show = FALSE;
					sheets[WPAGE_ENC_PASS].show = FALSE;

					k = 0;
					while (combo_sel[k] != -1) SendMessage(
						GetDlgItem(hwnd, combo_sel[k++]), CB_RESETCONTENT, 0, 0);

					_init_combo(
						GetDlgItem(hwnd, IDC_COMBO_ALGORT), cipher_names, node->mnt.info.status.crypt.cipher_id, FALSE, -1
						);

					_init_combo(
						GetDlgItem(hwnd, IDC_COMBO_PASSES), wipe_modes, node->mnt.info.status.crypt.wp_mode, FALSE, -1
						);
				}

				EnableWindow(GetDlgItem(sheets[WPAGE_ENC_PASS].hwnd, IDC_LAYOUTS_LIST), set_loader);
				EnableWindow(GetDlgItem(sheets[WPAGE_ENC_PASS].hwnd, IDC_COMBO_KBLAYOUT), set_loader);

				if (_wizard_step(node, pv(&sheets), &index, IDC_BACK, IDOK, id)) 
				{
					_run_wizard_action(hwnd, pv(&sheets), node);					
				}
				if (_get_check(sheets[WPAGE_ENC_TYPE].hwnd, IDC_RADIO_REENCRYPT)) 
				{
					EnableWindow(GetDlgItem(hwnd, IDOK), TRUE);
				}
				SetFocus(GetDlgItem(sheets[index].hwnd, IDE_PASS));

				SendMessage(
					sheets[index].hwnd, WM_COMMAND, MAKELONG(IDE_PASS, EN_CHANGE), (LPARAM)GetDlgItem(sheets[index].hwnd, IDE_PASS)
					);

			} else 
			{
				node->dlg.rlt = ST_CANCEL;
				EndDialog(hwnd, 0);

				return 0L;
			}
		}
		break;
		case WM_DESTROY : 
		{
			node = NULL;			
			vol  = NULL;

			_wipe_pass_control(sheets[WPAGE_ENC_PASS].hwnd, IDE_PASS);
			_wipe_pass_control(sheets[WPAGE_ENC_PASS].hwnd, IDE_CONFIRM);

			_keyfiles_wipe(KEYLIST_CURRENT);

			count = 0;
			while (sheets[count].id != -1) 
			{
				sheets[count].show = TRUE;
				DestroyWindow(sheets[count++].hwnd);
			}
			count = index = 0;
			return 0L;
		}
		break;
		default:
		{
			int rlt = _draw_proc(message, lparam);
			if (rlt != -1) return rlt;
		}
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


int _dlg_change_pass(
		HWND hwnd,
		dlgpass *pass
	)
{
	int result =
		(int)DialogBoxParam(
				NULL, 
				MAKEINTRESOURCE(IDD_DIALOG_CHANGE_PASS),
				hwnd,
				pv(_password_change_dlg_proc),
				(LPARAM)pass
		);

	return result == IDOK ? ST_OK : ST_CANCEL;

}


void _init_main_dlg(
		HWND hwnd
	)
{
	MENUITEMINFO mnitem = { sizeof(mnitem) };
	wchar_t      display[MAX_PATH];

	_snwprintf(display,
		sizeof_w(display), L"%s %d.%d.%d.%d", DC_NAME, DC_MAJOR_VER, DC_MINOR_VER, DC_DRIVER_VER, DC_BOOT_VER
		);

	SetWindowText(hwnd, display);	

	__dlg = hwnd;

	SendMessage(hwnd, WM_SYSCOLORCHANGE, 0, 0);		
	_set_hotkeys(hwnd, __config.hotkeys, TRUE);

	_tray_icon(TRUE);

	mnitem.fMask =  MIIM_FTYPE;
	mnitem.fType = MFT_RIGHTJUSTIFY;
	SetMenuItemInfo(GetMenu(hwnd), ID_HOMEPAGE, FALSE, &mnitem);

	SendMessage(GetDlgItem(hwnd, IDC_DRIVES_HEAD), WM_SETFONT, (WPARAM)__font_bold, 0);		
	{
		RECT  rc, cr;
		void *res;
		int   size;

		GetClientRect(hwnd, &rc);
		GetWindowRect(hwnd, &cr);

		if ( (res = _extract_rsrc(IDD_MAIN_DLG, RT_DIALOG, &size)) != NULL )
		{
			_dlg_templateex *rs_template = pv(res);		
			RECT rect = { rs_template->x, rs_template->y, rs_template->cx, rs_template->cy };

			MapDialogRect(hwnd, &rect);

			_dlg_height = rect.bottom;
			_dlg_width  = rect.right;

			_dlg_right  = cr.right;
			_dlg_bottom = cr.bottom;

			if (_dlg_height != rc.bottom) 
			{
				SendMessage(hwnd, WM_SIZE, 0, MAKELONG(rc.right, rc.bottom));
			}
		}
	}
}


void _get_time_period(
		__int64  begin,
		wchar_t *display,
		BOOL     abs
	)
{
	LARGE_INTEGER curr;
	SYSTEMTIME st;
	FILETIME ft;

	int j = 0;

	if (!abs)
	{
		GetSystemTimeAsFileTime(&ft);		
		curr.HighPart = ft.dwHighDateTime;
		curr.LowPart = ft.dwLowDateTime;
			
		curr.QuadPart -= begin;
	} else {
		curr.QuadPart = begin * 10000000;
	}

	ft.dwHighDateTime = curr.HighPart;
	ft.dwLowDateTime = curr.LowPart;

	FileTimeToSystemTime(&ft, &st);

	if (st.wHour)    j += _snwprintf(display+j, 8, L"%d hr.%s", st.wHour, st.wMinute ? L", " : L"");
	if (st.wMinute)  j += _snwprintf(display+j, 8, L"%d min.",  st.wMinute);
	if (st.wSecond && !st.wHour) j += _snwprintf(display+j, 9, L"%s%d sec.", st.wMinute ? L", " : L"", st.wSecond);
	
	display[j] = '\0';

}


static
int _speed_stat(
		wchar_t *s_speed,
		size_t   chars,
		_dact   *act,
		__int64  tmp_size
	)
{
	BOOL init = FALSE;

	__int64 last_size = 0;
	int k;

	for ( k = 0; k < SPEED_STAT; k++ )
	{
		last_size += act->speed_stat[k];
		if (act->speed_stat[k] == -1)
		{
			last_size = 0;
			init = TRUE;

			break;
		}
	}
	if (!init && act->status == ACT_RUNNING)
	{
		last_size = _abs64(
				( last_size / SPEED_STAT ) * 
				( 1000 / _tmr_elapse[PROC_TIMER] )
			);

		_snwprintf(
			s_speed, chars, L"%.1f mb/sec.", (double) last_size / 1024 / 1024
			);
	} else {
		_snwprintf(
			s_speed, chars, L"" //L"??.? mb/sec."
		);

	}
	for ( k = 0; k < SPEED_STAT - 1; k++ )
	{
		act->speed_stat[k] = act->speed_stat[k + 1];
	}
	act->speed_stat[SPEED_STAT - 1] = tmp_size - act->tmp_size;
	act->tmp_size = tmp_size;

	return (int) last_size / 1024 / 1024;

}


void _activate_page( )
{
	HWND hlist   = GetDlgItem(__dlg, IDC_DISKDRIVES);
	HWND idb_act = GetDlgItem(__dlg, IDB_MAIN_ACTION);

	_dnode *node = pv(_get_sel_item(hlist));
	_dact  *act  = _create_act_thread(node, -1, -1);

	if (ListView_GetSelectedCount(hlist) && node && !node->is_root && act && !_is_curr_in_group(idb_act)) 
	{
		SendMessage(idb_act, WM_LBUTTONDOWN, 0, 0);
	}
}


void _update_info_table( )
{
	HWND hlist = GetDlgItem(__dlg, IDC_DISKDRIVES);

	HWND idb_inf = GetDlgItem(__dlg, IDB_MAIN_INFO);
	HWND idb_act = GetDlgItem(__dlg, IDB_MAIN_ACTION);

	_dnode *node = pv(_get_sel_item(hlist));
	_dact  *act  = _create_act_thread(node, -1, -1);

	_wnd_data *wnd_inf = wnd_get_long(idb_inf, GWL_USERDATA);
	_wnd_data *wnd_act = wnd_get_long(idb_act, GWL_USERDATA);

	HWND htable_inf = GetDlgItem(wnd_inf->dlg, IDC_INF_TABLE); 
	HWND htable_act = GetDlgItem(wnd_act->dlg, IDC_ACT_TABLE); 

	BOOL idb_inf_enb = FALSE;
	BOOL idb_act_enb = FALSE;

	BOOL crypt_info;
	int k = 0;

	if (SendMessage(
		GetDlgItem(wnd_act->dlg, IDC_COMBO_PASSES), CB_GETDROPPEDSTATE, 0, 0)
		) 
	{
		return;
	}
	for ( ; k<2; k++ ) 
	{
		_list_set_item_text(htable_act, k, 1, L"--");
		_list_set_item_text(htable_act, k, 3, L"--");
	}

	if (ListView_GetSelectedCount(hlist) && node) 
	{
		if (!node->is_root)
		{
			_list_set_item_text(htable_inf, 0, 1, node->mnt.info.w32_device);
			_list_set_item_text(htable_inf, 1, 1, node->mnt.info.device);
			_list_set_item_text(htable_inf, 2, 1, L"");

			crypt_info = node->mnt.info.status.flags & F_ENABLED;

			_list_set_item_text(htable_inf, 3, 1, 
				!crypt_info ? L"--" : _get_text_name(node->mnt.info.status.crypt.cipher_id, cipher_names));
	
			_list_set_item_text(htable_inf, 4, 1, !crypt_info ? L"--" : IDS_MODE_NAME);
			_list_set_item_text(htable_inf, 5, 1, !crypt_info ? L"--" : IDS_PRF_NAME);

			idb_inf_enb = TRUE;

			if (act) 
			{
				EnableWindow(GetDlgItem(
					wnd_act->dlg, IDC_STATIC_PASSES_LIST), ACT_DECRYPT != act->act
					);
				EnableWindow(GetDlgItem(
					wnd_act->dlg, IDC_STATIC_SECTOR), ACT_RUNNING == act->status
					);
				EnableWindow(GetDlgItem(
					wnd_act->dlg, IDC_COMBO_PASSES), ACT_DECRYPT != act->act
					);
				EnableWindow(GetDlgItem(
					wnd_act->dlg, IDB_ACT_PAUSE), ACT_RUNNING == act->status
					);
				EnableWindow(GetDlgItem(
					wnd_act->dlg, IDC_ACT_TABLE), ACT_RUNNING == act->status
					);
				SetWindowText(GetDlgItem(
					wnd_act->dlg, IDB_ACT_PAUSE), ACT_FORMAT == act->act ? L"Cancel" : L"Pause"
					);
				{
					HWND hsector = GetDlgItem(wnd_act->dlg, IDC_STATIC_SECTOR);

					wchar_t s_elapsed[MAX_PATH];
					wchar_t s_estimated[MAX_PATH] = { 0 };

					wchar_t s_sectors[MAX_PATH];
					wchar_t s_old[MAX_PATH];

					wchar_t s_speed[MAX_PATH];
					wchar_t s_done[MAX_PATH];

					__int64 done;
					__int64 sectors;

					int new_pos;
					int speed;
					int j = 0;

					dc_status *status = &node->mnt.info.status;
					dc_get_device_status(node->mnt.info.device, status);					

					new_pos = (int)( status->tmp_size / ( status->dsk_size/PRG_STEP ) );
					sectors = status->tmp_size / 512;

					if (act->act == ACT_DECRYPT) 
					{
						new_pos = PRG_STEP - new_pos;
						sectors = status->dsk_size / 512 - sectors;

						done = status->dsk_size - status->tmp_size;
					} else {
						done = status->tmp_size;
					}
					dc_format_byte_size(s_done, sizeof_w(s_done), done);
					
					_get_time_period(act->begin.QuadPart, s_elapsed, FALSE);
					speed = _speed_stat(s_speed, sizeof_w(s_speed), act, status->tmp_size);
					
					if (speed != 0)
					{
						_get_time_period(
							( ( status->dsk_size - done ) / 1024 / 1024 ) / speed, s_estimated, TRUE
							);					
					}

					j = _snwprintf(s_sectors, sizeof_w(s_sectors), L"Sector: %d\t\t", sectors);
					j = _snwprintf(s_sectors+j, sizeof_w(s_sectors)-j, L"Total Sectors: %d", status->dsk_size / 512);		

					_list_set_item_text(htable_act, 0, 1, _wcslwr(s_done));
					_list_set_item_text(htable_act, 1, 1, ACT_RUNNING == act->status ? s_speed : L"--");

					if (act->status == ACT_RUNNING) 
					{
						_list_set_item_text(htable_act, 0, 3, s_estimated);
						_list_set_item_text(htable_act, 1, 3, s_elapsed);
					}
					GetWindowText(hsector, s_old, sizeof_w(s_old));
					if (wcscmp(s_old, s_sectors)) SetWindowText(hsector, s_sectors);

					SendMessage(GetDlgItem(wnd_act->dlg, IDC_COMBO_PASSES), CB_SETCURSEL, act->wp_mode, 0);

					SendMessage(
						GetDlgItem(wnd_act->dlg, IDC_PROGRESS),
						PBM_SETPOS,
						(WPARAM)new_pos, 0
					);
					
				}
				idb_act_enb = TRUE;
					
			}
		}
	}
	if (!idb_act_enb && !_is_curr_in_group(idb_inf)) SendMessage(idb_inf, WM_LBUTTONDOWN, 0, 0);
	if (!idb_inf_enb)
	{
		for ( k=0; k<6; k++ ) 
		{
			_list_set_item_text(htable_inf, k, 1, L"");
		}
	}
	if (!idb_act_enb) 
	{
		SendMessage(GetDlgItem(wnd_act->dlg, IDC_COMBO_PASSES), CB_SETCURSEL, 0, 0);
		SendMessage(GetDlgItem(wnd_act->dlg, IDC_PROGRESS), PBM_SETPOS, 0, 0);
		SetWindowText(GetDlgItem(wnd_act->dlg, IDC_STATIC_SECTOR), NULL);
	}	

	EnableWindow(idb_inf, idb_inf_enb);
	EnableWindow(idb_act, idb_act_enb);	

}


int _ui_init_boot_config(
		HWND hwnd,
		int type,
		int dsk_num,
		wchar_t *vol,
		wchar_t *path,
		ldr_config *conf
	)
{
	HWND dlg;
	wchar_t s_title[MAX_PATH];

	_tab_data *tab = NULL;
	_wnd_data *wnd;

	int rlt;

	switch (type) {
		case CTL_LDR_MBR:   rlt = dc_get_mbr_config(dsk_num, NULL, conf); break;
		case CTL_LDR_STICK: rlt = dc_mbr_config_by_partition(vol, FALSE, conf); break;
		case CTL_LDR_ISO:
		case CTL_LDR_PXE:   rlt = dc_get_mbr_config(0, path, conf); break;
	}

	if (rlt != ST_OK) {
		_error_s(hwnd, L"Error getting bootloader configuration", rlt);
		return rlt;

	}

	tab = malloc(sizeof(_tab_data));
	wnd_set_long(hwnd, GWL_USERDATA, tab);

/////////////////////////////////////////////////////////////////////////////////////////////////////////////
	dlg = CreateDialog(
		__hinst, MAKEINTRESOURCE(DLG_BOOT_CONF_MAIN), GetDlgItem(hwnd, IDC_BOOT_TAB), _tab_proc);
	wnd = _sub_class(GetDlgItem(hwnd, IDB_BOOT_MAIN), dlg, FALSE);
/////////////////////////////////////

	{
		_init_combo(
			GetDlgItem(wnd->dlg, IDC_COMBO_KBLAYOUT), kb_layouts, conf->kbd_layout, FALSE, -1
			);

		_init_combo(
			GetDlgItem(wnd->dlg, IDC_COMBO_METHOD), conf->options & OP_EXTERNAL ? boot_type_ext : boot_type_all, conf->boot_type, FALSE, -1
			);

		_list_part_by_disk_id(GetDlgItem(wnd->dlg, IDC_PART_LIST_BY_ID), conf->disk_id);

		SendMessage(wnd->dlg, WM_COMMAND, MAKELONG(IDC_COMBO_METHOD, CBN_SELCHANGE), 
			(LPARAM)GetDlgItem(wnd->dlg, IDC_COMBO_METHOD));

	}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////
	dlg = CreateDialog(
		__hinst, MAKEINTRESOURCE(DLG_BOOT_CONF_LOGON), GetDlgItem(hwnd, IDC_BOOT_TAB), _tab_proc);
	wnd = _sub_class(GetDlgItem(hwnd, IDB_BOOT_LOGON), dlg, FALSE);
/////////////////////////////////////

	{
		HWND h_auth_combo = GetDlgItem(wnd->dlg, IDC_COMBO_AUTH_TYPE);
		HWND h_msg = GetDlgItem(wnd->dlg, IDE_RICH_BOOTMSG);

		int bits = 0;

		if (conf->logon_type & LT_GET_PASS)  bits++;
		if (conf->logon_type & LT_EMBED_KEY) bits++;

		_init_combo(
			h_auth_combo, auth_type, conf->logon_type, TRUE, bits
			);

		_sub_class(GetDlgItem(wnd->dlg, IDC_BT_ENTER_PASS_MSG), FALSE, FALSE);
		_set_check(wnd->dlg, IDC_BT_ENTER_PASS_MSG, conf->logon_type & LT_MESSAGE);
		EnableWindow(h_msg, conf->logon_type & LT_MESSAGE);

		_init_combo(
			GetDlgItem(wnd->dlg, IDC_COMBO_SHOW_PASS), show_pass, conf->logon_type, TRUE, -1
			);

		SetWindowTextA(h_msg, conf->eps_msg);									
		SendMessage(h_msg, EM_SETBKGNDCOLOR,	0, _cl(COLOR_BTNFACE, LGHT_CLR));
		SendMessage(h_msg, EM_EXLIMITTEXT,	0, sizeof(conf->eps_msg) - 1);

		_init_combo(
			GetDlgItem(wnd->dlg, IDC_COMBO_AUTH_TMOUT), auth_tmount, conf->timeout, FALSE, -1
			);

		_sub_class(GetDlgItem(wnd->dlg, IDC_BT_CANCEL_TMOUT), FALSE, FALSE);
		_set_check(wnd->dlg, IDC_BT_CANCEL_TMOUT, conf->options & OP_TMO_STOP);

		EnableWindow(GetDlgItem(wnd->dlg, IDC_BT_CANCEL_TMOUT), conf->timeout);
		SendMessage(wnd->dlg, WM_COMMAND, MAKELONG(IDC_COMBO_AUTH_TYPE, CBN_SELCHANGE), (LPARAM)h_auth_combo);

	}

////////////////////////////////////////////////////////////////////////////////////////////////////////////
	dlg = CreateDialog(
		__hinst, MAKEINTRESOURCE(DLG_BOOT_CONF_BADPASS), GetDlgItem(hwnd, IDC_BOOT_TAB), _tab_proc);
	wnd = _sub_class(GetDlgItem(hwnd, IDB_BOOT_BADPASS), dlg, FALSE);
////////////////////////////////////

	{
		HWND err_mes = GetDlgItem(wnd->dlg, IDE_RICH_ERRPASS_MSG);

		_sub_class(GetDlgItem(wnd->dlg, IDC_BT_BAD_PASS_MSG), FALSE, FALSE);
		_set_check(wnd->dlg, IDC_BT_BAD_PASS_MSG, conf->error_type & ET_MESSAGE);

		EnableWindow(GetDlgItem(wnd->dlg, IDE_RICH_ERRPASS_MSG), conf->error_type & ET_MESSAGE);

		_sub_class(GetDlgItem(wnd->dlg, IDC_BT_ACTION_NOPASS), FALSE, FALSE);
		_set_check(wnd->dlg, IDC_BT_ACTION_NOPASS, conf->options & OP_NOPASS_ERROR);

		_init_combo(
			GetDlgItem(wnd->dlg, IDC_COMBO_BAD_PASS_ACT), bad_pass_act, conf->error_type, TRUE, -1
			);

		SetWindowTextA(err_mes, conf->err_msg);
		SendMessage(err_mes, EM_EXLIMITTEXT, 0, sizeof(conf->err_msg)-1);

		SendMessage(GetDlgItem(wnd->dlg, IDE_RICH_ERRPASS_MSG), EM_SETBKGNDCOLOR,	0, _cl(COLOR_BTNFACE, LGHT_CLR));		

	}
////////////////////////////////////////////////////////////////////////////////////////////////////////////

	SendMessage(GetDlgItem(hwnd, IDB_BOOT_MAIN), WM_LBUTTONDOWN, 0, 0);			

	_snwprintf(s_title, sizeof_w(s_title), L"Bootloader config for [%s]", path[0] ? path : vol);
	SetWindowText(GetParent(GetParent(hwnd)), s_title);

	return rlt;
						
}


int _ui_save_config(
		HWND hwnd,
		int type,
		int dsk_num,
		wchar_t *vol,
		wchar_t *path,
		ldr_config *conf
	)
{
	_wnd_data *wnd;
	int rlt = ST_OK;

////////////////////////////////////////////////////////////////////////////////////////////////////////////
	wnd = wnd_get_long(GetDlgItem(hwnd, IDB_BOOT_MAIN), GWL_USERDATA);
////////////////////////////////////

	if (wnd) 
	{
		conf->kbd_layout = _get_combo_val(GetDlgItem(wnd->dlg, IDC_COMBO_KBLAYOUT), kb_layouts);
		conf->boot_type  = _get_combo_val(GetDlgItem(wnd->dlg, IDC_COMBO_METHOD), boot_type_all);

		if (conf->boot_type == BT_DISK_ID)
		{
			HWND hlist = GetDlgItem(wnd->dlg, IDC_PART_LIST_BY_ID);
			wchar_t text[MAX_PATH];

			_get_item_text(hlist, ListView_GetSelectionMark(hlist), 2, text, sizeof_w(text));
			if (wcslen(text) && ListView_GetSelectedCount(hlist)) 
			{
				conf->disk_id = wcstoul(text, L'\0', 16);
			} else {
				__msg_e(hwnd, L"You must select partition by id");
				return ST_ERROR;
			}
		}
	}

////////////////////////////////////////////////////////////////////////////////////////////////////////////
	wnd = wnd_get_long(GetDlgItem(hwnd, IDB_BOOT_LOGON), GWL_USERDATA);
////////////////////////////////////
					
	if (wnd) 
	{
		HWND auth_combo = GetDlgItem(wnd->dlg, IDC_COMBO_AUTH_TYPE);
		HWND show_combo = GetDlgItem(wnd->dlg, IDC_COMBO_SHOW_PASS);

		BOOL dsp_pass;
		int timeout = _get_combo_val(GetDlgItem(wnd->dlg, IDC_COMBO_AUTH_TMOUT), auth_tmount);

		BOOL show_text = _get_check(wnd->dlg, IDC_BT_ENTER_PASS_MSG);
		BOOL embed_key = _get_combo_val(auth_combo, auth_type) & LT_EMBED_KEY;

		conf->logon_type &= ~(LT_GET_PASS | LT_EMBED_KEY);
		conf->logon_type |= _get_combo_val(auth_combo, auth_type);

		if (show_text) GetWindowTextA(GetDlgItem(wnd->dlg, IDE_RICH_BOOTMSG), conf->eps_msg, sizeof(conf->eps_msg));
		set_flag(conf->logon_type, LT_MESSAGE, show_text);

		dsp_pass = _get_combo_val(show_combo, show_pass) == LT_DSP_PASS;
		set_flag(conf->logon_type, LT_DSP_PASS, dsp_pass);

		conf->timeout = timeout;
		set_flag(conf->options, OP_EPS_TMO, timeout != 0);
		set_flag(conf->options, OP_TMO_STOP, _get_check(wnd->dlg, IDC_BT_CANCEL_TMOUT));

		if (embed_key) 
		{
			if (_keyfiles_count(KEYLIST_EMBEDDED))
			{
				int   keysize;
				byte *keyfile;

				zeroauto(conf->emb_key, sizeof(conf->emb_key));
				set_flag(conf->logon_type, LT_EMBED_KEY, 0);

				if (load_file(_first_keyfile(KEYLIST_EMBEDDED)->path, &keyfile, &keysize) != ST_OK) 
				{
					__msg_e(hwnd, L"Keyfile not loaded\n");
					rlt = ST_ERROR;

				} else
				{
					autocpy(&conf->emb_key, keyfile, sizeof(conf->emb_key));
					set_flag(conf->logon_type, LT_EMBED_KEY, 1);				
				}				
				zeromem(keyfile, keysize);
				free(keyfile);
							
			}
		} else {
			zeroauto(conf->emb_key, sizeof(conf->emb_key));
		}
	}
////////////////////////////////////////////////////////////////////////////////////////////////////////////
	wnd = wnd_get_long(GetDlgItem(hwnd, IDB_BOOT_BADPASS), GWL_USERDATA);
////////////////////////////////////

	if (wnd) 
	{
		BOOL show_err    = _get_check(wnd->dlg, IDC_BT_BAD_PASS_MSG);
		BOOL act_no_pass = _get_check(wnd->dlg, IDC_BT_ACTION_NOPASS);

		conf->error_type = _get_combo_val(GetDlgItem(wnd->dlg, IDC_COMBO_BAD_PASS_ACT), bad_pass_act);

		set_flag(conf->error_type, ET_MESSAGE, show_err);
		set_flag(conf->options, OP_NOPASS_ERROR, act_no_pass);

		if (show_err) {
			GetWindowTextA(GetDlgItem(
			wnd->dlg, IDE_RICH_ERRPASS_MSG), conf->err_msg, sizeof(conf->err_msg));						

		}						
	}

////////////////////////////////////
	if (rlt != ST_OK) return rlt;

	switch (type) 
	{
		case CTL_LDR_MBR:   rlt = dc_set_mbr_config(dsk_num, NULL, conf); break;
		case CTL_LDR_STICK: rlt = dc_mbr_config_by_partition(vol, TRUE, conf); break;
		case CTL_LDR_ISO:
		case CTL_LDR_PXE:   rlt = dc_set_mbr_config(0, path, conf); break;
	}
	if (rlt != ST_OK) 
	{
		_error_s(hwnd, L"Error set bootloader configuration", rlt);
		return rlt;				
	}
	EndDialog(GetParent(GetParent(hwnd)), IDOK);
	return rlt;

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

	static HWND bt_sheets[BOOT_WZR_SHEETS];
	static ldr_config *ldr;

	int check = 0; int k = 0;
	switch (message) {

		case WM_CLOSE:
		case WM_DESTROY:

			_keyfiles_wipe(KEYLIST_EMBEDDED);
			break;

		case WM_INITDIALOG: {

			int dlgs_pages[2] = {
				DLG_BOOT_SET, DLG_BOOT_CONF
			};

			for ( k = 0 ;k < 2; bt_sheets[k] = CreateDialog(__hinst,
				MAKEINTRESOURCE(dlgs_pages[k]), GetDlgItem(hwnd, IDC_TAB), _tab_proc), k++ );

			hwnd = bt_sheets[0];
			{
				_init_combo(
					GetDlgItem(hwnd, IDC_COMBO_LOADER_TYPE), loader_type, lparam ? CTL_LDR_ISO : CTL_LDR_MBR, FALSE, -1
					);

				_list_devices(GetDlgItem(hwnd, IDC_WZD_BOOT_DEVS), TRUE, -1);
				SendMessage(hwnd, WM_COMMAND, MAKELONG(IDC_COMBO_LOADER_TYPE, CBN_SELCHANGE), 0);

				_sub_class(GetDlgItem(hwnd, IDC_CHECK_CONFIG), FALSE, FALSE);
				_set_check(hwnd, IDC_CHECK_CONFIG, FALSE);							

			}
			ShowWindow(bt_sheets[0], SW_SHOW);

		}
		break;
		case WM_COMMAND: 
		{
			HWND hlist = GetDlgItem(bt_sheets[0], IDC_WZD_BOOT_DEVS);

			int type    = _get_combo_val(GetDlgItem(bt_sheets[0], IDC_COMBO_LOADER_TYPE), loader_type);	
			int dsk_num = _ext_disk_num(hlist);			

			int rlt;

			wchar_t vol[MAX_PATH]  = { 0 };
			wchar_t path[MAX_PATH] = { 0 };

			static ldr_config conf = { 0 };

			_get_item_text(hlist, ListView_GetSelectionMark(hlist), 0, vol, sizeof_w(vol));		
			GetWindowText(GetDlgItem(bt_sheets[0], IDE_BOOT_PATH), path, sizeof_w(path));

			switch (id)
			{
				case IDC_BTN_INSTALL:
				{
					wchar_t btn_text[MAX_PATH];				
					GetWindowText((HWND)lparam, btn_text, sizeof_w(btn_text));				

					if (wcscmp(btn_text, IDS_BOOTINSTALL) == 0)	{
						_menu_set_loader_vol(hwnd, vol, dsk_num, type);					
					}
					if (wcscmp(btn_text, IDS_BOOTREMOVE) == 0) {
						_menu_unset_loader_mbr(hwnd, vol, dsk_num, type);
					}
					if (wcscmp(btn_text, IDS_BOOTCREATE) == 0) 
					{
						_menu_set_loader_file(hwnd, path, type == CTL_LDR_ISO);

						SendMessage(bt_sheets[0], WM_COMMAND, 
							MAKELONG(IDE_BOOT_PATH, EN_CHANGE), (LPARAM)GetDlgItem(bt_sheets[0], IDE_BOOT_PATH));

						return 0L;
					}
					if (wcscmp(btn_text, IDS_SAVECHANGES) == 0) 
					{
						_ui_save_config(bt_sheets[1], type, dsk_num, vol, path, &conf);
						return 0L;
					}
					_list_devices(hlist, type == CTL_LDR_MBR, -1);
					_refresh_boot_buttons(bt_sheets[0], hlist, -1);

				} 
				break;
				case IDC_BTN_UPDATE:
				{
					_menu_update_loader(hwnd, vol, dsk_num);
				}
				break;
				case IDC_BTN_CHANGE_CONF:
				{
					rlt = _ui_init_boot_config(bt_sheets[1], type, dsk_num, vol, path, &conf);
					if (rlt == ST_OK) 
					{
						SetWindowText(GetDlgItem(hwnd, IDC_BTN_INSTALL), IDS_SAVECHANGES);
						EnableWindow(GetDlgItem(hwnd, IDC_BTN_INSTALL), TRUE);

						ShowWindow(GetDlgItem(hwnd, IDC_BTN_CHANGE_CONF), FALSE);
						ShowWindow(GetDlgItem(hwnd, IDC_BTN_UPDATE), FALSE);

						ShowWindow(bt_sheets[0], SW_HIDE);
						ShowWindow(bt_sheets[1], SW_SHOW);
					}
				}
				break;

				case IDCANCEL: EndDialog(hwnd, IDCANCEL);
					break;				

			}
		}
		break;
		default:
		{
			int rlt = _draw_proc(message, lparam);
			if (rlt != -1) return rlt;
		}
	}
	return 0L;

}


void _is_breaking_action( )
{
	list_entry *node;
	list_entry *sub;

	int count = 0;
	int k, flag;

	BOOL resume;

	wchar_t s_vol[MAX_PATH] = { 0 };

	for ( k = 0; k < 4; k++ )
	{
		if (k % 2 == 0)
		{
			zeroauto(s_vol, sizeof_w(s_vol));
			count = 0;
			resume = FALSE;
		}

		for ( node = __drives.flink;
					node != &__drives;
					node = node->flink 
					)
		{
			_dnode *root = contain_record(node, _dnode, list);
			
			for ( sub = root->root.vols.flink;
						sub != &root->root.vols;
						sub = sub->flink 
					)
			{
				_dnode *mnt = contain_record(sub, _dnode, list);
				switch (k)
				{
					case 0:
					case 1:  flag = F_FORMATTING; break;
					case 2:
					case 3:  flag = F_SYNC; break;
					default: flag = -1; break;
				}
				if (mnt->mnt.info.status.flags & flag)
				{
					if (k % 2 == 0)
					{
						if (s_vol[0] != L'\0') wcscat(s_vol, L", ");
						wcscat(s_vol, mnt->mnt.info.status.mnt_point);

						count++;

					} else {
						if (resume)
						{
							if (k == 1) _menu_format(mnt);
							if (k == 3) _menu_encrypt(mnt);
						}
					}
				}
			}
		}
		if ((k % 2 == 0) && count > 0)
		{
			if (_msg_q(__dlg,
						L"%s was suspended for volume%s %s.\n\n"
						L"Continue %s?", 
						k != 0 ? L"Encrypting/decrypting" : L"Formatting",
						count > 1 ? L"s" : L"", 
						s_vol,
						k != 0 ? L"encrypting" : L"formatting")
						) 
			{
				resume = TRUE;
			}
		}
	}
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

	switch (message)
	{
		case WM_INITDIALOG :
		{
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
				zeroauto(tab, sizeof(_tab_data));
				wnd_set_long(hwnd, GWL_USERDATA, tab);

				wnd = _sub_class(
					GetDlgItem(hwnd, IDB_MAIN_INFO),
					CreateDialog(__hinst, MAKEINTRESOURCE(DLG_MAIN_INFO), GetDlgItem(hwnd, IDC_MAIN_TAB), _tab_proc), FALSE
					);
				{
					HWND hlist = GetDlgItem(wnd->dlg, IDC_INFO_TABLE);
					ListView_SetBkColor(hlist, GetSysColor(COLOR_BTNFACE));
		
					_list_insert_col(hlist, 380);
					_list_insert_col(hlist, 90);
					
					while (_list_insert_item(hlist, k, 0, _info_table_items[k], 0)) k++;

				}
				k = 0;
				wnd = _sub_class(
					GetDlgItem(hwnd, IDB_MAIN_ACTION), 
					CreateDialog(__hinst, MAKEINTRESOURCE(DLG_MAIN_ACTION), GetDlgItem(hwnd, IDC_MAIN_TAB), _tab_proc), FALSE
					);
				{
					HWND hlist = GetDlgItem(wnd->dlg, IDC_ACT_TABLE);
					__dlg_act_info = wnd->dlg;

					ListView_SetBkColor(hlist, GetSysColor(COLOR_BTNFACE));
		
					_list_insert_col(hlist, 90);
					_list_insert_col(hlist, 70);

					_list_insert_col(hlist, 85);
					_list_insert_col(hlist, 50);
						
					_list_insert_item(hlist, 0, 0, _act_table_items[0], 0);
					ListView_SetItemText(hlist, 0, 2, _act_table_items[2]);

					_list_insert_item(hlist, 1, 0, _act_table_items[1], 0);
					ListView_SetItemText(hlist, 1, 2, _act_table_items[3]);

					_init_combo(
						GetDlgItem(wnd->dlg, IDC_COMBO_PASSES), wipe_modes, WP_NONE, FALSE, -1
						);

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
			_set_timer(POST_TIMER, TRUE, FALSE);

			if (lparam) _set_timer(HIDE_TIMER, TRUE, FALSE);
			return 0L;			
		} 
		break;
		case WM_WINDOWPOSCHANGED :
		{
			WINDOWPOS *pos = (WINDOWPOS *)lparam;
			int flags = pos->flags;

			_dlg_right  = pos->cx + pos->x;
			_dlg_bottom = pos->cy + pos->y;
			_dlg_left   = pos->x;

			if (flags & SWP_SHOWWINDOW || flags & SWP_HIDEWINDOW)
			{
				//#
				_set_timer(MAIN_TIMER, flags & SWP_SHOWWINDOW, TRUE);
			}
			return 0L;
		}
		break;
		case WM_ENTERSIZEMOVE :
		{
			//_middle_ctl(
			//	GetDlgItem(hwnd, IDC_DISKDRIVES),
			//	GetDlgItem(hwnd, IDC_RESIZING),
			//	TRUE
			//	);

			//ShowWindow(GetDlgItem(hwnd, IDC_DISKDRIVES), SW_HIDE);
			return 0L;
		}
		break;
		case WM_EXITSIZEMOVE :
		{
			//ShowWindow(GetDlgItem(hwnd, IDC_DISKDRIVES), SW_SHOW);
			return 0L;
		}
		break;
		case WM_SIZING :
		{
			RECT *rect = ((RECT *)lparam);

			rect->right = _dlg_right;
			rect->left  = _dlg_left;

			if (rect->bottom - rect->top < MAIN_DLG_MIN_HEIGHT) 
			{
				rect->bottom = rect->top + MAIN_DLG_MIN_HEIGHT;
			}
			return 1L;
		}
		break;
		case WM_SIZE :
		{
			int height = HIWORD(lparam);
			int width  = LOWORD(lparam);
			int k;

			_size_move_ctls _resize[ ] = 
			{
				{ -1, IDC_DISKDRIVES,   FALSE, 0, 0 },
				{ -1, IDC_STATIC_LIST,  TRUE,  0, 0 },
				{ -1, IDC_STATIC_RIGHT, TRUE,  0, 0 },
				{ -1, -1, -1, 0, 0 }
			};

			_size_move_ctls _move[ ] =
			{
				{ IDC_STATIC_LIST, IDC_MAIN_TAB,    TRUE,  0, 3 },
				{ IDC_MAIN_TAB,    IDB_MAIN_INFO,   FALSE, 0, 1 },
				{ IDC_MAIN_TAB,    IDB_MAIN_ACTION, FALSE, 0, 1 },
				{ IDB_MAIN_INFO,   IDC_LINE_BOTTOM, TRUE,  0, 2 },
				{ -1, -1, FALSE, 0, 0 }
			};

			HWND hlist = GetDlgItem(hwnd, IDC_DISKDRIVES);
			{
				int c_size_hide = _main_headers[1].width;
				int c_size_show = c_size_hide - GetSystemMetrics(SM_CXVSCROLL);
				int c_size_curr = ListView_GetColumnWidth(hlist, 1);

				if ( GetWindowLong(hlist, GWL_STYLE) & WS_VSCROLL )
				{
					if (c_size_curr != c_size_show) ListView_SetColumnWidth(hlist, 1, c_size_show);
				} else {
					if (c_size_curr != c_size_hide) ListView_SetColumnWidth(hlist, 1, c_size_hide);
				}
			}

			if (height == 0 || width == 0) return 0L;

			k = 0;
			while (_resize[k].id != -1)
			{
				_resize_ctl(
						GetDlgItem(hwnd, _resize[k].id),
						height - _dlg_height,
						0, 
						_resize[k++].val
						);
			}
			_dlg_height = height;

			k = 0;
			while (_move[k].id != -1)
			{
				_relative_move(
					GetDlgItem(hwnd, _move[k].anchor),
					GetDlgItem(hwnd, _move[k].id),
					_move[k].dy,
					_move[k].dy,
					_move[k].val
					);

				InvalidateRect(GetDlgItem(hwnd, _move[k++].id), NULL, TRUE);

			}
			_middle_ctl(
				GetDlgItem(hwnd, IDC_DISKDRIVES),
				GetDlgItem(hwnd, IDC_RESIZING),
				TRUE
				);

			return 0L;
		}
		break;
		case WM_SYSCOMMAND :
		{
			if (wparam == SC_MINIMIZE || wparam == SC_RESTORE) 
			{
				_set_timer(MAIN_TIMER, wparam == SC_RESTORE, TRUE);
			}
			return 0L;
		}
		break;
		case WM_APP + WM_APP_SHOW :
		{
			ShowWindow(hwnd, SW_HIDE);
		}
		break;
		case WM_NOTIFY :
		{
			if(IDC_DISKDRIVES == wparam) 
			{
				sel = pv(_get_sel_item(hlist));
				mnt = &sel->mnt;

				//if (((NMHDR *)lparam)->code == NM_CUSTOMDRAW) 
				//	((NMLVCUSTOMDRAW *)lparam)->nmcd.dwDrawStage = CDDS_ITEMPREPAINT;
				//		return CDRF_SKIPDEFAULT;
				
				if (((NMHDR *)lparam)->code == LVN_ITEMCHANGED &&
					  (((NMLISTVIEW *)lparam)->uNewState & LVIS_FOCUSED )) 
				{
					_update_info_table( );
					_activate_page( );
					_refresh_menu( );					

					return 1L;
				}
				if (((NMHDR *)lparam)->code == LVN_ITEMACTIVATE)
				{
					BOOL mount = !(sel->mnt.info.status.flags & F_ENABLED) 
						&& sel->mnt.fs[0] == '\0';
					
					if (!mount) 
					{
						if (!sel->is_root) __execute(mnt->info.status.mnt_point);
					} else {
						_menu_mount(sel);
					}
				}
				switch(((NM_LISTVIEW *)lparam)->hdr.code) 
				{
					case LVN_KEYDOWN : 
					{
						WORD key = ((NMLVKEYDOWN *)lparam)->wVKey;
						int item = ListView_GetSelectionMark(hlist);

						switch (key) 
						{
							case VK_UP: item -= 1; break;
							case VK_DOWN: item += 1; break;
						}
						if (_is_root_item(_get_item_index(hlist, item))) 
						{
							ListView_SetItemState(hlist, item, LVIS_FOCUSED, TRUE);
						}
					}
					break;
					case NM_RCLICK :
					{
						int item;
						HMENU popup = CreatePopupMenu( );

						_dact *act = _create_act_thread(sel, -1, -1);

						_update_info_table( );
						_activate_page( );

						_set_timer(MAIN_TIMER, FALSE, FALSE);

						_refresh_menu( );
						
						if (ListView_GetSelectedCount(hlist) && 
								!_is_root_item((LPARAM)sel) && _is_active_item((LPARAM)sel))
						{
							if (mnt->info.status.flags & F_ENABLED) 
							{
								if (mnt->info.status.flags & F_FORMATTING)
								{
									AppendMenu(popup, MF_STRING, ID_VOLUMES_FORMAT, IDS_FORMAT);
								} else 
								{
									if (IS_UNMOUNTABLE(&mnt->info.status)) 
									{
										AppendMenu(popup, MF_STRING, ID_VOLUMES_UNMOUNT, IDS_UNMOUNT);										
									}
									if (!(mnt->info.status.flags & F_SYNC)) 
									{
										AppendMenu(popup, MF_SEPARATOR, 0, NULL);
										AppendMenu(popup, MF_STRING, ID_VOLUMES_CHANGEPASS, IDS_CHPASS);
									}
									if (!(act && act->status == ACT_RUNNING)) 
									{
										if (mnt->info.status.flags & F_SYNC) 
										{
											if (GetMenuItemCount(popup) > 0) AppendMenu(popup, MF_SEPARATOR, 0, NULL);
											AppendMenu(popup, MF_STRING, ID_VOLUMES_ENCRYPT, IDS_ENCRYPT);
										} else {
											if (GetMenuItemCount(popup) > 0) AppendMenu(popup, MF_SEPARATOR, 0, NULL);
											AppendMenu(popup, MF_STRING, ID_VOLUMES_REENCRYPT, IDS_REENCRYPT);
										}
										AppendMenu(popup, MF_STRING, ID_VOLUMES_DECRYPT, IDS_DECRYPT);
									}
								}								
							} else 
							{
								if (*mnt->fs == '\0') 
								{
									AppendMenu(popup, MF_STRING, ID_VOLUMES_MOUNT, IDS_MOUNT); 
								} else {
									AppendMenu(popup, MF_STRING, ID_VOLUMES_ENCRYPT, IDS_ENCRYPT);
								}
								if (IS_UNMOUNTABLE(&mnt->info.status)) 
								{
									AppendMenu(popup, MF_SEPARATOR, 0, NULL);
									AppendMenu(popup, MF_STRING, ID_VOLUMES_FORMAT, IDS_FORMAT);
								}
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
						switch (item) 
						{
							case ID_VOLUMES_DECRYPT : _menu_decrypt(sel); break;
							case ID_VOLUMES_ENCRYPT : _menu_encrypt(sel); break;

							case ID_VOLUMES_FORMAT : _menu_format(sel); break;
							case ID_VOLUMES_REENCRYPT : _menu_reencrypt(sel); break;

							case ID_VOLUMES_UNMOUNT : _menu_unmount(sel); break;
							case ID_VOLUMES_MOUNT : _menu_mount(sel); break;

							case ID_VOLUMES_CHANGEPASS : _menu_change_pass(sel); break;						
						}
						if (item) _refresh(TRUE);
						_set_timer(MAIN_TIMER, TRUE, TRUE);

					}
					break;
					case NM_CLICK :
					{
						sel = pv(
							_get_item_index(hlist, ((NM_LISTVIEW *)lparam)->iItem)
							);

						_update_info_table( );
						_activate_page( );
						_refresh_menu( );
						
					}
					break;

				}
			}
			if (((NMHDR *)lparam)->code == HDN_ITEMCHANGED) 
			{
				InvalidateRect(hlist, NULL, TRUE);
			}
			if (((NMHDR *)lparam)->code == HDN_ITEMCHANGING) 
			{
				return 0L;
			}
			if (((NMHDR *)lparam)->code == HDN_BEGINTRACK) 
			{
				return 1L;
			}
		}
		break;
		case WM_COMMAND: 
		{
			_dnode *node = pv(_get_sel_item(hlist));

			switch (id) 
			{
			case ID_TOOLS_DRIVER :
			{
				if (_msg_q(__dlg, L"Remove DiskCryptor driver?")) 
				{
					int rlt;
					if ((rlt = _drv_action(DA_REMOVE, 0)) != ST_OK) 
					{
						_error_s(__dlg, L"Error remove DiskCryptor driver", rlt);	
					} else {
						return 0L;
					}
				}
			}
			break;
			case ID_TOOLS_BENCHMARK : _dlg_benchmark(__dlg); break;
			case ID_HOMEPAGE :
			{
				__execute(DC_HOMEPAGE);
			}
			break;

			case ID_HELP_ABOUT : _dlg_about(__dlg); break;
			case ID_EXIT : SendMessage(hwnd, WM_CLOSE, 0, 1); break;

			case IDC_BTN_WIZARD : _menu_wizard(node); break;
			case ID_VOLUMES_DELETE_MNTPOINT :
			{
				wchar_t *mnt_point = node->mnt.info.status.mnt_point;				
				if (_msg_q(__dlg, L"Are you sure you want to delete mount point [%s]?", mnt_point)) 
				{
					_set_trailing_slash(mnt_point);
					DeleteVolumeMountPoint(mnt_point);
				}
			}
			break;

			case IDC_BTN_DECRYPT_ :
			case ID_VOLUMES_DECRYPT : _menu_decrypt(node); break;

			case IDC_BTN_ENCRYPT_ :
			case ID_VOLUMES_ENCRYPT : _menu_encrypt(node); break;

			case ID_VOLUMES_MOUNTALL : 
			case IDC_BTN_MOUNTALL_ : _menu_mountall( ); break;

			case ID_VOLUMES_DISMOUNTALL : 
			case IDC_BTN_UNMOUNTALL_ : _menu_unmountall( ); break;

			case ID_VOLUMES_DISMOUNT : _menu_unmount(node); break;
			case ID_VOLUMES_MOUNT : _menu_mount(node); break;

			case ID_VOLUMES_FORMAT : _menu_format(node); break;
			case ID_VOLUMES_REENCRYPT : _menu_reencrypt(node); break;

			case ID_TOOLS_SETTINGS : _dlg_options(__dlg); break;
			case ID_BOOT_OPTIONS : _dlg_config_loader(__dlg, FALSE); break;

			case ID_VOLUMES_CHANGEPASS : _menu_change_pass(node); break;
			case ID_TOOLS_CLEARCACHE : _menu_clear_cache( ); break;

			case ID_VOLUMES_BACKUPHEADER : _menu_backup_header(node); break;
			case ID_VOLUMES_RESTOREHEADER : _menu_restore_header(node); break;

			}
			switch (id) {
			case IDC_BTN_MOUNT_: 
			{		
				node->mnt.info.status.flags & F_ENABLED ? 
					_menu_unmount(node) : _menu_mount(node);
			}
			break;	
			case ID_TOOLS_BSOD : 
			{
				if (_msg_q(__dlg, L"Crash?")) dc_get_bsod( );
			}
			break;
			}
			if (IDCANCEL == id) 
			{
				ShowWindow(hwnd, SW_HIDE);
			}
			_refresh(TRUE);
		}
		break;

		case WM_CLOSE :
		{
			if (lparam) 
			{
				_tray_icon(FALSE);

				EndDialog(hwnd, 0);
				ExitProcess(0);
			} else {
				ShowWindow(hwnd, SW_HIDE);

			}
			return 0L;
		}
		break;
		case WM_DESTROY : 
		{
			PostQuitMessage(0);
			return 0L;
		}
		break;
		case WM_HOTKEY :
		{
			switch (wparam) 
			{
				case 0 : 
				{
					int mount_cnt;
					dc_mount_all(NULL, &mount_cnt); 
				}
				break;
				case 1 : dc_unmount_all( ); break;
				case 2 : dc_clean_pass_cache( ); break;
				case 3 : dc_get_bsod( ); break;
			}
			return 1L;
		}
		break;
		case WM_ENDSESSION : 
		{
			if (lparam & ENDSESSION_LOGOFF) 
			{
				if (__config.conf_flags & CONF_DISMOUNT_LOGOFF) dc_unmount_all( );
				if (__config.conf_flags & CONF_WIPEPAS_LOGOFF) dc_clean_pass_cache( );
			}
		}
		break;
		case WM_SYSCOLORCHANGE :
		{
			COLORREF bgcolor = _cl(COLOR_BTNFACE, LGHT_CLR);
			HWND hlist = GetDlgItem(hwnd, IDC_DISKDRIVES);

			TreeView_SetBkColor(GetDlgItem(hwnd, IDC_TREE), bgcolor);
			ListView_SetBkColor(hlist, bgcolor);

			ListView_SetTextBkColor(hlist, bgcolor);
			ListView_SetExtendedListViewStyle(hlist, LVS_EX_FULLROWSELECT);

			ListView_SetImageList(hlist, __dsk_img, LVSIL_SMALL);
		}
		break;
		case WM_APP + WM_APP_TRAY :
		{
			switch (lparam) 
			{
			case WM_LBUTTONDOWN : 
			{
				BOOL show = !IsWindowVisible(hwnd);				
				ShowWindow(hwnd, show ? SW_SHOW : SW_HIDE);

				if (show) SetForegroundWindow(hwnd);
			}
			break;
			case WM_RBUTTONDOWN : 
			{
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

				case ID_VOLUMES_UNMOUNTALL : _menu_unmountall( ); break;
				case ID_VOLUMES_MOUNTALL : _menu_mountall( ); break;

				case ID_HELP_ABOUT : _dlg_about(HWND_DESKTOP); break;
				case ID_EXIT : SendMessage(hwnd, WM_CLOSE, 0, 1); break;

				case ID_TOOLS_SETTINGS :
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
		default:
		{
			int rlt = _draw_proc(message, lparam);
			if (rlt != -1) return rlt;
		}
	}	
	return 0L; 

}


void __stdcall 
_timer_handle(
		HWND     hwnd,
		UINT     msg,
		UINT_PTR id,
		DWORD    tickcount
	)
{
	int j = 0;
	HWND hlist = GetDlgItem(hwnd, IDC_DISKDRIVES);

	switch (id - IDC_TIMER) 
	{
		case PROC_TIMER :
		
			_update_info_table( );
			break;

		case MAIN_TIMER :
		{
			EnterCriticalSection(&crit_sect);

			_load_diskdrives(hwnd, &__drives, _list_volumes(0));
			_update_info_table( );

			_set_timer(PROC_TIMER, IsWindowVisible(__dlg_act_info), FALSE);
			_refresh_menu( );

			LeaveCriticalSection(&crit_sect);
		}
		break;

		case RAND_TIMER : rnd_reseed_now( ); break;
		case HIDE_TIMER : 
		{
			ShowWindow(hwnd, SW_HIDE);
			_set_timer(HIDE_TIMER, FALSE, FALSE);
		}
		break;
		case POST_TIMER :
		{
			_set_timer(POST_TIMER, FALSE, FALSE);
			_is_breaking_action( );
		}
		break;

	}
}



