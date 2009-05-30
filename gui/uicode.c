/*
    *
    * DiskCryptor - open source partition encryption tool
	* Copyright (c) 2007 
	* ntldr <ntldr@diskcryptor.net> PGP key ID - 0xC48251EB4F8E4E6E
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
#include <ctype.h>
#include <shlwapi.h>
#include <shlobj.h>

#include "resource.h"
#include "hotkeys.h"
#include "uicode.h"
#include "defines.h"
#include "misc.h"
#include "subs.h"
#include "main.h"
#include "crypto\crypto.h"
#include "crypto\pkcs5.h"

_colinfo _main_headers[ ] = {
	{ STR_SPACE,	120,	LVCFMT_LEFT,	TRUE	},
	{ L"Size",		74,		LVCFMT_RIGHT,	FALSE	},
	{ L"Label",		94,		LVCFMT_RIGHT,	FALSE	},
	{ L"Type",		43,		LVCFMT_RIGHT,	FALSE	},
	{ L"Status",	88,		LVCFMT_RIGHT,	FALSE	},
	{ STR_SPACE,	65,		LVCFMT_RIGHT,	FALSE	},
	{ STR_NULL }
};

_colinfo _boot_headers[ ] = {
	{ L"Device ",		115,	LVCFMT_LEFT,	TRUE	},
	{ L"Size",			60,		LVCFMT_RIGHT,	FALSE	},
	{ L"Bootloader",	75,		LVCFMT_RIGHT,	FALSE	},
	{ STR_SPACE,		40,		LVCFMT_RIGHT,	FALSE	},
	{ STR_NULL }
};

_colinfo _part_by_id_headers[ ] = {
	{ L"Volume ",	115,	LVCFMT_LEFT,	TRUE	},
	{ L"Size",		60,		LVCFMT_RIGHT,	FALSE	},
	{ L"Disk ID",	90,		LVCFMT_RIGHT,	FALSE	},
	{ STR_SPACE,	110,	LVCFMT_RIGHT,	FALSE	},
	{ STR_NULL },
};

_colinfo _benchmark_headers[ ] = {
	{ L"Cipher",	160,	LVCFMT_LEFT,	FALSE	},
	{ L"Mode",		60,		LVCFMT_RIGHT,	FALSE	},
	{ L"Speed",		90,		LVCFMT_RIGHT,	FALSE	},
	{ STR_NULL },
};

wchar_t *_info_table_items[ ] = {
	L"Symbolic Link",
	L"Device",
	STR_SPACE,
	L"Cipher",
	L"Encryption mode",
	L"Pkcs5.2 prf",
	STR_NULL
};

wchar_t *_act_table_items[ ] = {
	L"Done:",
	L"Speed:",
	STR_SPACE,
	L"Estimated:",
	L"Elapsed:",
	STR_NULL
};

_static_view pass_gr_ctls[ ] = {
	{ IDC_GR_SMALL,	 0, 0 }, { IDC_GR_CAPS,	 0, 0 },
	{ IDC_GR_DIGITS, 0, 0 }, { IDC_GR_SPACE, 0, 0 },
	{ IDC_GR_SPEC,	 0, 0 }, { IDC_GR_ALL,	 0, 0 },
	{ -1, 0, 0 }
};

_static_view pass_pe_ctls[ ] = {
	{ IDC_PE_NONE,   0, 0 }, { IDC_PE_LOW,  0, 0 },
	{ IDC_PE_MEDIUM, 0, 0 }, { IDC_PE_HIGH, 0, 0 },
	{ IDC_PE_UNCRK,  0, 0 }, 
	{ -1, 0, 0 }
};

_init_list cipher_names[ ] = {
	{ CF_AES,					L"AES"					},
	{ CF_TWOFISH,				L"Twofish"				},
	{ CF_SERPENT,				L"Serpent"				},
	{ CF_AES_TWOFISH,			L"AES-Twofish"			},
	{ CF_TWOFISH_SERPENT,		L"Twofish-Serpent"		},
	{ CF_SERPENT_AES,			L"Serpent-AES"			},
	{ CF_AES_TWOFISH_SERPENT,	L"AES-Twofish-Serpent"	},
	{ 0, STR_NULL }
};

_init_list wipe_modes[ ] = {
	{ WP_NONE,		L"None"										},
	{ WP_DOD_E,		L"US DoD 5220.22-M (8-306. / E)"			},
	{ WP_DOD,		L"US DoD 5220.22-M (8-306. / E, C and E)"	},
	{ WP_GUTMANN,	L"Gutmann mode"								},
	{ 0, STR_NULL }
};

_init_list kb_layouts[ ] = {
	{ KB_QWERTY, L"QWERTY" },
	{ KB_QWERTZ, L"QWERTZ" },
	{ KB_AZERTY, L"AZERTY" },
	{ 0, STR_NULL }
};

_init_list auth_type[ ] = {
	{ LT_GET_PASS | LT_EMBED_KEY,	L"Password and bootauth keyfile"	},
	{ LT_GET_PASS,					L"Password request"					},
	{ LT_EMBED_KEY,					L"Embedded bootauth keyfile"		},
	{ 0, STR_NULL }
};

_init_list show_pass[ ] = {
	{ TRUE,			L"Hide entered password"				},
	{ LT_DSP_PASS,	L"Display entered password as \"*\""	},
	{ 0, STR_NULL }
};

_init_list auth_tmount[ ] = {
	{ 0,	L"Disabled"		},
	{ 3,	L"3 sec"		},
	{ 5,	L"5 sec"		},
	{ 7,	L"7 sec"		},
	{ 10,	L"10 sec"		},
	{ 20,	L"20 sec"		},
	{ 30,	L"30 sec"		},
	{ 50,	L"50 sec"		},
	{ 60,	L"2 minutes"	},
	{ 120,	L"5 minutes"	},
	{ 0,STR_NULL }
};

_init_list boot_type_ext[ ] = {
	{ BT_MBR_FIRST,		L"First disk MBR"								},
	{ BT_AP_PASSWORD,	L"First partition with appropriate password"	},
	{ BT_DISK_ID,		L"Specified partition"							},
	{ 0, STR_NULL }
};

_init_list boot_type_all[ ] = {
	{ BT_MBR_FIRST,		L"First disk MBR"								},
	{ BT_AP_PASSWORD,	L"First partition with appropriate password"	},
	{ BT_DISK_ID,		L"Specified partition"							},
	{ BT_MBR_BOOT,		L"Boot disk MBR"								},
	{ BT_ACTIVE,		L"Active partition"								},
	{ 0, STR_NULL }
};

_init_list bad_pass_act[ ] = {
	{ FALSE,			L"Halt system"					},
	{ ET_REBOOT,		L"Reboot system"				},
	{ ET_BOOT_ACTIVE,	L"Boot from active partition"	},
	{ ET_EXIT_TO_BIOS,	L"Exit to BIOS"					},
	{ ET_RETRY,			L"Retry authentication"			},
	{ ET_MBR_BOOT,		L"Load Boot Disk MBR"			},
	{ 0, STR_NULL }
};

_init_list loader_type[ ] = {
	{ CTL_LDR_MBR,		L"HDD master boot record"					},
	{ CTL_LDR_STICK,	L"Bootable partition (USB-Stick, etc)"		},
	{ CTL_LDR_ISO,		L"ISO bootloader image"						},
	{ CTL_LDR_PXE,		L"Bootloader image for PXE network booting"	},
	{ 0, STR_NULL }
};

_init_list pass_status[ ] = {
	{ ST_PASS_SPRS_SYMBOLS,		L" Used suppressed symbols on this layout"		},
	{ ST_PASS_EMPTY,			L" Pass is empty"								},
	{ ST_PASS_NOT_CONFIRMED,	L" The password was not correctly confirmed"	},
	{ ST_PASS_EMPTY_CONFIRM,	L" Confirm is empty"							},
	{ ST_PASS_EMPTY_KEYLIST,	L" Keyfiles list is empty"						},
	{ ST_PASS_CORRRECT,			L" Correct"										},
	{ 0, STR_NULL }
};

_ctl_init hotks_chk[ ] = {
	{ STR_NULL, IDC_KEY_MOUNTALL	},
	{ STR_NULL, IDC_KEY_UNMOUNTALL	},
	{ STR_NULL, IDC_KEY_WIPE		},
	{ STR_NULL, IDC_KEY_BSOD		},
	{ STR_NULL, -1, -1 }
};

_ctl_init hotks_edit[ ] = {
	{ STR_NULL, IDC_EDIT_KEY_MOUNTALL,		0 },
	{ STR_NULL, IDC_EDIT_KEY_UNMOUNTALL,	0 },
	{ STR_NULL, IDC_EDIT_KEY_WIPE,			0 },
	{ STR_NULL, IDC_EDIT_KEY_BSOD,			0 },
	{ STR_NULL, -1, -1 }
};

_ctl_init hotks_static[ ] = {
	{ STR_NULL, IDC_STATIC_KEY_MOUNTALL,	0 },
	{ STR_NULL, IDC_STATIC_KEY_UNMOUNTALL,	0 },
	{ STR_NULL, IDC_STATIC_KEY_WIPE,		0 },
	{ STR_NULL, IDC_STATIC_KEY_BSOD,		0 },
	{ STR_NULL, -1, -1 }
};

HINSTANCE __hinst;

HFONT __font_small;
HFONT __font_bold;
HFONT __font_link;

HCURSOR __cur_arrow;
HCURSOR __cur_hand;
HCURSOR __cur_wait;

HIMAGELIST __dsk_img;
HIMAGELIST __img;

HWND __dlg;
HWND __dlg_act_info;

void *wnd_get_long(
		HWND h_wnd, 
		int  index
	)
{
#pragma warning(disable:4312)
	return (void*)GetWindowLongPtr(h_wnd, index);
#pragma warning(default:4312)
}

void *wnd_set_long(
		HWND  h_wnd, 
		int   index, 
		void *ptr
	)
{
#pragma warning(disable:4312 4244)
	return (void*)SetWindowLongPtr(h_wnd, index, (LONG_PTR)ptr);
#pragma warning(default:4312 4244)
}


int _draw_proc(
		int    message,
		LPARAM lparam
	)
{
	switch (message) 
	{
		case WM_DRAWITEM : 
		{
			_draw_static((LPDRAWITEMSTRUCT)lparam);			
			return 1L;
		}
		break;
		case WM_MEASUREITEM:
		{
			MEASUREITEMSTRUCT *item = pv(lparam);
			if (item->CtlType != ODT_LISTVIEW)
			{
				item->itemHeight -= 3;
			}
		}
		break;
	}
	return -1;
}


BOOL _list_set_item(
		HWND     hlist,
		DWORD    item,
		DWORD    subitem,
		wchar_t *text
	)
{
	LVITEM lvitem = { LVIF_TEXT, 0, 0 };
	lvitem.pszText = text;
	
	lvitem.iItem = item; 
	lvitem.iSubItem = subitem;

	return ListView_SetItem(hlist, &lvitem);

}


void _list_set_item_text(
		HWND     hlist,
		DWORD    item,
		DWORD    subitem,
		wchar_t *text
	)
{
	wchar_t curr[MAX_PATH];

	LVITEM lvitem = { 
		LVIF_TEXT, item, subitem, 0, 0, curr, sizeof_w(curr) 
	};

	ListView_GetItem(hlist, &lvitem);
	if (wcscmp(curr, text))
	{
		ListView_SetItemText(hlist, item, subitem, text);
	}
}


BOOL _list_insert_item(
		HWND     hlist,
		DWORD    item,
		DWORD    subitem,
		wchar_t *text,
		int      state
	)
{
	LVITEM lvitem = { LVIF_TEXT | LVIF_STATE, 0, 0 };
	lvitem.pszText = text;

	lvitem.iItem = item; 
	lvitem.iSubItem = subitem;

	lvitem.state = state;

	if (wcslen(text) == 0) {
		return FALSE;
	}
	return ListView_InsertItem( hlist, &lvitem ) != -1;

}


int _list_insert_col(
		HWND hlist,
		int  cx
	)
{
	LVCOLUMN lvcol = { LVCF_WIDTH, 0 };			
	lvcol.cx = cx;

	if (ListView_InsertColumn( hlist, 0, &lvcol ))
	{
		return ST_OK;
	} else {
		return ST_ERROR;
	}
}


LPARAM _get_item_index(
		HWND h_list,
		int  item
	)
{
	LVITEM lvi;
	zeroauto( &lvi, sizeof(LVITEM) );

	lvi.mask  = LVIF_PARAM;
	lvi.iItem = item;

	if ( ListView_GetItem( h_list, &lvi ) ) 
	{
		return lvi.lParam;
	} else {
		return (LPARAM)NULL;
	}
}


void _get_item_text(
		HWND     hlist,
		int      item,
		int      subitem,
		wchar_t *text,
		int      chars
	)
{
	LVITEM lvitem = { 
		LVIF_TEXT, item, subitem, 0, 0, text, chars 
	};

	ListView_GetItem(hlist, &lvitem);
	if (item == -1) 
	{
		text[0] = 0;
	}

}


BOOL _is_duplicated_item(
		HWND     h_list,
		wchar_t *s_item
	)
{
	wchar_t item[MAX_PATH];
	int k = 0;

	for ( ; k < ListView_GetItemCount(h_list) ; k++ )
	{
		_get_item_text( h_list, k, 0, item, sizeof_w(item) );
		if ( wcscmp(item, s_item) == 0 )
		{
			return TRUE;
		}
	}
	return FALSE;

}

LPARAM _get_sel_item( HWND h_list )
{
	return _get_item_index(
		h_list, ListView_GetSelectionMark( h_list )
		);
}

BOOL _get_header_text(
		HWND     h_list,
		int      idx,
		wchar_t *s_header,
		int      size
	)
{
	HDITEM hd_item = { HDI_TEXT };

	hd_item.pszText    = s_header;
	hd_item.cchTextMax = size;

	return Header_GetItem(
		ListView_GetHeader( h_list ), idx, &hd_item
		);
}

BOOL _set_header_text(
		HWND     h_list,
		int      idx,
		wchar_t *s_header,
		int      size
	)
{
	HDITEM hd_item = { HDI_TEXT };

	hd_item.pszText    = s_header;
	hd_item.cchTextMax = size;

	return Header_SetItem(
		ListView_GetHeader( h_list ), idx, &hd_item
		);
}


DWORD _cl(
		int  index,
		char prc
	)
{
	DWORD color = GetSysColor(index);

	BYTE r = (BYTE)color;	
	BYTE g = (BYTE)(color >> 8);
	BYTE b = (BYTE)(color >> 16);

	r += ((255 - r) * prc) / 100;
	g += ((255 - g) * prc) / 100;
	b += ((255 - b) * prc) / 100;

	return (r | (g << 8) | (b << 16));

}


void _middle_ctl(
		HWND h_anchor,
		HWND h_child,
		BOOL border_correct
	)
{
	RECT ch_size, pr_rect, pr_size;

	GetClientRect(h_child, &ch_size);
	GetClientRect(h_anchor, &pr_size);

	GetWindowRect(h_anchor, &pr_rect);
	ScreenToClient(GetParent(h_anchor), pv(&pr_rect));

	MoveWindow(
		h_child, 
		pr_rect.left   + ( pr_size.right  / 2 ) - ( ch_size.right  / 2 ),
		pr_rect.top    + ( pr_size.bottom / 2 ) - ( ch_size.bottom / 2 ),
		ch_size.right  + ( border_correct ? GetSystemMetrics(SM_CXEDGE) : 0 ),
		ch_size.bottom + ( border_correct ? GetSystemMetrics(SM_CYEDGE) : 0 ),
		TRUE

	);
}


void _resize_ctl(
		HWND h_ctl,
		int  dy,
		int  dx,
		BOOL border_correct
	)
{	
	RECT rc_ctl, cr_ctl;

	GetWindowRect(h_ctl, &cr_ctl);
	GetClientRect(h_ctl, &rc_ctl);

	ScreenToClient(GetParent(h_ctl), pv(&cr_ctl.right));
	ScreenToClient(GetParent(h_ctl), pv(&cr_ctl.left));
	
	MoveWindow(
		h_ctl, 
		cr_ctl.left,
		cr_ctl.top,
		rc_ctl.right + dx + 
				( border_correct ? GetSystemMetrics(SM_CXEDGE) : 0 ) + 
				( GetWindowLong(h_ctl, GWL_STYLE) & WS_VSCROLL ? GetSystemMetrics(SM_CYVSCROLL) : 0 ),
		rc_ctl.bottom + dy + 
				( border_correct ? GetSystemMetrics(SM_CYEDGE) : 0 ) + 
				( GetWindowLong(h_ctl, GWL_STYLE) & WS_HSCROLL ? GetSystemMetrics(SM_CYHSCROLL) : 0 ),
		TRUE

	);
}


void _relative_move(
		HWND h_anchor,
		HWND h_child,
		int  dt,
		BOOL dy,
		BOOL border_correct
	)
{
	RECT rc_child, cr_child;
	RECT rc_anchor;

	HWND h_parent = GetParent(h_anchor);
	if (GetParent(h_anchor) != GetParent(h_child)) return;

	GetClientRect(h_child,  &rc_child);
	GetWindowRect(h_child,  &cr_child);

	ScreenToClient(h_parent, pv(&cr_child.left));
	GetWindowRect(h_anchor, &rc_anchor);

	ScreenToClient(h_parent, pv(&rc_anchor.right));
	ScreenToClient(h_parent, pv(&rc_anchor.left));

	MoveWindow(
		h_child, 
		( !dy ? rc_anchor.left   + dt : cr_child.left ),
		(  dy ? rc_anchor.bottom + dt : cr_child.top  ),
		rc_child.right   + ( border_correct ? GetSystemMetrics(SM_CXEDGE) : 0 ),
		rc_child.bottom  + ( border_correct ? GetSystemMetrics(SM_CYEDGE) : 0 ),
		TRUE

	);
}


void _relative_rect(
		HWND  hwnd,
		RECT *rc
	)
{
	RECT rc_parent;
	RECT rc_size;

	WINDOWINFO winfo;

	GetWindowInfo(GetParent(hwnd), &winfo);
	GetWindowRect(GetParent(hwnd), &rc_parent);

	GetWindowRect(hwnd, rc);
	GetClientRect(hwnd, &rc_size);

	rc->top  -= (rc_parent.top  + winfo.cyWindowBorders + GetSystemMetrics(SM_CYCAPTION));
	rc->left -= (rc_parent.left + winfo.cxWindowBorders);

	rc->right  = /*rc->left + */rc_size.right  + winfo.cxWindowBorders - 1;
	rc->bottom = /*rc->top  + */rc_size.bottom + winfo.cyWindowBorders - 1;

}


INT_PTR _ctl_color(
		WPARAM   wparam,
		COLORREF color
	)
{
	HDC dc = (HDC)wparam;
	SetDCBrushColor(dc, color);
	SetBkMode(dc, TRANSPARENT);

	return (INT_PTR)GetStockObject(DC_BRUSH);

}


BOOL _ui_init(
		HINSTANCE h_inst
	)
{
	HBITMAP undisk      = LoadBitmap( h_inst, MAKEINTRESOURCE( IDB_UNDISK ) );
	HBITMAP undisk_mask = LoadBitmap( h_inst, MAKEINTRESOURCE( IDB_UNDISK_MASK ) );

	HBITMAP disk        = LoadBitmap( h_inst, MAKEINTRESOURCE( IDB_DISK ) );
	HBITMAP disk_mask   = LoadBitmap( h_inst, MAKEINTRESOURCE( IDB_DISK_MASK ) );

	HBITMAP cdrom       = LoadBitmap( h_inst, MAKEINTRESOURCE( IDB_CDROM ) );
	HBITMAP cdrom_mask  = LoadBitmap( h_inst, MAKEINTRESOURCE( IDB_CDROM_MASK ) );

	HBITMAP disk_enb    = LoadBitmap( h_inst, MAKEINTRESOURCE( IDB_ENABLED ) );

	HBITMAP check       = LoadBitmap( h_inst, MAKEINTRESOURCE( IDB_CHECK ) );
	HBITMAP check_mask  = LoadBitmap( h_inst, MAKEINTRESOURCE( IDB_CHECK_MASK ) );

	NONCLIENTMETRICS metric = { sizeof(metric) };

	InitCommonControls( );
	if (! LoadLibrary(L"riched20.dll") ) return FALSE;

	__hinst = h_inst;
	__dlg = HWND_DESKTOP;

	metric.lfMessageFont.lfWeight = FW_BOLD;
	metric.lfMessageFont.lfHeight = -11;
	__font_bold = CreateFontIndirect( &metric.lfMessageFont );

	metric.lfMessageFont.lfWeight = FW_DONTCARE;
	metric.lfMessageFont.lfUnderline = TRUE;
	__font_link = CreateFontIndirect( &metric.lfMessageFont );

	metric.lfMessageFont.lfHeight = -9;
	metric.lfMessageFont.lfUnderline = FALSE;
	__font_small = CreateFontIndirect( &metric.lfMessageFont );

	__img = ImageList_Create( 9, 9, ILC_MASK, 2, 2 );
	__dsk_img = ImageList_Create( 15, 11, ILC_MASK | ILC_COLOR24, 5, 5 );
	
	ImageList_Add( __img, check, check_mask );

	ImageList_Add( __dsk_img, disk, disk_mask );
	ImageList_Add( __dsk_img, undisk, undisk_mask );
	ImageList_Add( __dsk_img, disk_enb, disk_mask );
	ImageList_Add( __dsk_img, cdrom, cdrom_mask );

	__cur_arrow = LoadCursor( NULL, IDC_ARROW );
	__cur_hand  = LoadCursor( NULL, IDC_HAND );
	__cur_wait  = LoadCursor( NULL, IDC_WAIT );

	return TRUE;

}


_wnd_data *_sub_class(
		HWND hwnd,
		int  proc_idx,
		HWND dlg,
		...
	)
{
	_wnd_data *data = NULL;
	void *proc = NULL;

	if ( hwnd ) 
	{
		data = malloc(sizeof(_wnd_data));
		zeroauto( data, sizeof(_wnd_data) );
	}
	if ( data ) 
	{
		if ( proc_idx != SUB_NONE )
		{
			if ( proc_idx == SUB_KEY_PROC )    proc = _key_proc; 
			if ( proc_idx == SUB_STATIC_PROC ) proc = _static_proc; 

			if ( proc != NULL )
			{
				data->old_proc = wnd_set_long( hwnd, GWL_WNDPROC, proc );
			}
		}
		{
			int     k   = 0;
			HWND    val = dlg;
			va_list va;

			va_start( va, dlg );
			while ( val != HWND_NULL )
			{
				data->dlg[k] = val;
				val = va_arg( va, HWND );				
				k++;
			}
			va_end(va);
		}
		wnd_set_long( hwnd, GWL_USERDATA, data );
		return data;

	} else return NULL;

}


void __unsub_class(
		HWND hwnd
	)
{
	_wnd_data *data = wnd_get_long(hwnd, GWL_USERDATA);		
	int k = 0;

	if (data)
	{		
		while (data->dlg[k] && data->dlg[k] != HWND_NULL) 
		{
			DestroyWindow(data->dlg[k]);
			k++;
		}
		free(data);
		SetWindowLongPtr(hwnd, GWL_USERDATA, 0);
	}
}


void _init_mount_points(
		HWND hwnd
	)
{
	wchar_t item[MAX_PATH];

	int drives = GetLogicalDrives( );
	int k = 2;

	SendMessage(hwnd, CB_ADDSTRING, 0, (LPARAM)L"Select Folder..");
	for ( ; k < 26; k++ ) 
	{
		if (!(drives & (1 << k)))
		{
			_snwprintf(item, sizeof_w(item), L"%c:", 'A'+k);
			SendMessage(hwnd, CB_ADDSTRING, 0, (LPARAM)item);
		}
	}
}


LRESULT 
CALLBACK 
_key_proc(
		HWND   hwnd,
		UINT   msg,
		WPARAM wparam,
		LPARAM lparam
	)
{
	char resolve;
	wchar_t text[500] = { 0 };

	int shift = 0;
	_wnd_data *data = wnd_get_long(hwnd, GWL_USERDATA);

	if (!data) return 1L;

	if (msg == WM_KEYDOWN || msg == WM_SYSKEYDOWN || msg == WM_KEYUP) {
		wchar_t key[100] = { 0 };

		do {
			if (GetKeyState(VK_CONTROL) < 0) shift |= MOD_CONTROL;
			if (GetKeyState(VK_SHIFT) < 0)   shift |= MOD_SHIFT;
			if (GetKeyState(VK_MENU) < 0)    shift |= MOD_ALT;

			resolve = _key_name(wparam, shift, key);
			if ((msg == WM_KEYUP) && (!resolve)) {			

				GetWindowText(hwnd, text, sizeof_w(text));
				if (text[wcslen(text)-2*sizeof(wchar_t)] != L'+') break;

			}
			SetWindowText(hwnd, key);

			if ((msg != WM_KEYUP) && resolve) 
			{
				data->vk = MAKELONG(shift, wparam);
			}			
		} while (0);
		return 0L;

	}
	CallWindowProc(data->old_proc, hwnd, msg, wparam, lparam);
	return 1L;	

}


void _change_page(
		HWND hwnd,
		int  wnd_idx
	)
{
	_wnd_data *data = wnd_get_long( hwnd, GWL_USERDATA );
	if (! data ) return;

	data->state = !data->state;
	if ( data->dlg[0] )
	{
		_tab_data *tab = wnd_get_long( GetParent(hwnd), GWL_USERDATA );
		if (! tab ) return;

		tab->h_curr   = hwnd;
		tab->curr_tab = wnd_idx;

		if ( data->dlg[wnd_idx] != HWND_NULL )
		{				
			ShowWindow( tab->active, SW_HIDE );
			tab->active = data->dlg[wnd_idx];

			ShowWindow( tab->active, SW_SHOW );
			SetWindowPos( tab->active, HWND_TOP, 0, 0, 0, 0, SWP_NOSIZE );
		}
		InvalidateRect( GetParent(hwnd), NULL, FALSE );
	} else InvalidateRect( hwnd, NULL, FALSE );

	SendMessage( GetParent(hwnd), WM_USER_CLICK, (WPARAM)hwnd, 0 );

}


LRESULT 
CALLBACK 
_static_proc(
		HWND   hwnd,
		UINT   msg,
		WPARAM wparam,
		LPARAM lparam
	)
{
	_wnd_data *data = wnd_get_long(hwnd, GWL_USERDATA);
	if (!data) return 1L;	

	switch (msg) 
	{
		/*case WM_GETDLGCODE: {
			return DLGC_STATIC;

		}
		break;*/
		/*case WM_NOTIFY:
		{
			if (wparam == IDT_INFO)
			{
				int code = ((NMHDR *)lparam)->code;
				__msg_i( hwnd, L"static_proc: %d", code );

			}
		}
		break;*/

		case BM_GETCHECK:
			return (data->state) ? BST_CHECKED : BST_UNCHECKED;

		case BM_SETCHECK:
			data->state = wparam ? BST_CHECKED : BST_UNCHECKED;
			return 0L;

		case WM_KEYUP:
			if (wparam != VK_SPACE) break;

		case WM_LBUTTONDBLCLK:
		case WM_LBUTTONDOWN:

			_change_page(hwnd, 0);
			return 0L;		

		break;

	}
	CallWindowProc( data->old_proc, hwnd, msg, wparam, lparam );
	return 1L;	

}

void _fill(
		HDC      dc,
		RECT    *rc,
		COLORREF cl
	)
{
	HGDIOBJ brsh;

	SetDCBrushColor(dc, cl); 
	SetBkMode(dc, TRANSPARENT);

	brsh = GetStockObject(DC_BRUSH);
	FillRect(dc, rc, brsh);
	return;

}


void _draw_listview(
		LPDRAWITEMSTRUCT itst
	)
{
	DRAWTEXTPARAMS dtp = { sizeof(dtp) };
	LVCOLUMN       lvc = { sizeof(lvc) };

	wchar_t s_text[200] = { 0 };
	int     cx, cy, k   = 0;
	int     offset      = 0;
	int     icon;
	BOOL    is_root;

	int col_cnt = Header_GetItemCount( ListView_GetHeader( itst->hwndItem ) );

	LVITEM   lvitem   = { LVIF_TEXT | LVIF_PARAM, itst->itemID, 0, 0, 0, s_text, sizeof_w(s_text) };
	COLORREF bgcolor = ListView_GetBkColor( itst->hwndItem );

	ListView_GetItem( itst->hwndItem, &lvitem );
	is_root = _is_root_item( lvitem.lParam );
	/*
	if (_is_warning_item(lvitem.lParam)) {
		bgcolor = CL_WARNING_BG;
	}
	*/
	if ( itst->itemState & ODS_SELECTED && IsWindowEnabled( itst->hwndItem ) ) {
		bgcolor = CL_WHITE; // == _cl(COLOR_BTNSHADOW, 88);
	}
	if ( is_root ) {
		bgcolor = _cl( COLOR_BTNSHADOW, 60 );
	}
	if ( _is_marked_item(lvitem.lParam) ) {
		bgcolor = _cl( COLOR_BTNSHADOW, 35 );
	}
	
	_fill( itst->hDC, &itst->rcItem, bgcolor );

	for ( ;k < col_cnt; k++ )
	{
		lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_IMAGE;
		ListView_GetColumn( itst->hwndItem, k, &lvc );

		itst->rcItem.left = k ? itst->rcItem.right : 0;
		itst->rcItem.right = itst->rcItem.left + lvc.cx;

		lvitem.iItem = itst->itemID; 
		lvitem.iSubItem = k;

		ListView_GetItem( itst->hwndItem, &lvitem );
		dtp.iLeftMargin = dtp.iRightMargin = 5;		

		if ( (!itst->rcItem.left) && _is_icon_show( itst->hwndItem, k ) )
		{
			ImageList_GetIconSize( __dsk_img, &cx, &cy );
			offset = lvitem.lParam && !is_root ? 25 : 3;

			itst->rcItem.left += offset + cy + ( lvitem.lParam && !is_root ? 8 : 4 );
			icon = 0;

			if (! is_root ) 
			{
				//icon = 0;
				if ( _is_splited_item(lvitem.lParam) ) icon = 1;
				if ( _is_cdrom_item(lvitem.lParam) ) icon = 2;
			}

			ImageList_Draw(
				__dsk_img, icon, itst->hDC, offset, itst->rcItem.top + 3, ILD_TRANSPARENT
				);

		} else offset = 0;
		if ( offset && is_root )
		{
			/*
			if (_is_marked_item(lvitem.lParam)) {
				SelectObject(itst->hDC, __font_bold);
			}
			*/					
			DrawState(
				itst->hDC, 0, NULL, (LPARAM)s_text, 0, 
				itst->rcItem.left+5, itst->rcItem.top, 0, 0, DST_PREFIXTEXT | DSS_MONO
				); // second param = GetStockObject(DC_PEN)
		} else {
			if ( wcslen(s_text) != 0) 
			{
				COLORREF text_color = GetSysColor( COLOR_WINDOWTEXT );
				/*
				if (_is_warning_item(lvitem.lParam)) 
				{
					text_color = CL_WARNING;
					SelectObject( itst->hDC, __font_bold );
				}
				*/
				if (!_is_active_item(lvitem.lParam)) {
					text_color = GetSysColor( COLOR_GRAYTEXT );
				}
				SetTextColor( itst->hDC, text_color );

				if (k >= 4) {
					SelectObject( itst->hDC, __font_bold );
				}
				if (!IsWindowEnabled( itst->hwndItem )) 
				{
					/*
					DrawState(
						itst->hDC, 0, NULL, (LPARAM)text, 0,
						itst->rcItem.left+5, itst->rcItem.top, 0, 0, DST_PREFIXTEXT | DSS_MONO | DSS_DISABLED
						);
					*/
					SetTextColor( itst->hDC, GetSysColor(COLOR_GRAYTEXT) );

					DrawTextEx(
						itst->hDC, s_text, -1, &itst->rcItem,
						DT_END_ELLIPSIS | ((lvc.fmt & LVCFMT_RIGHT) ? DT_RIGHT : FALSE), &dtp
						);
				} else {
					DrawTextEx(
						itst->hDC, s_text, -1, &itst->rcItem,
						DT_END_ELLIPSIS | ((lvc.fmt & LVCFMT_RIGHT) ? DT_RIGHT : FALSE), &dtp
						);
				}
			}
		}
	}							
}


void _draw_combobox(
		LPDRAWITEMSTRUCT itst
	)
{	
	TEXTMETRIC tm; 	

	wchar_t data[MAX_PATH];
	int x,y;

	DWORD txc = COLOR_WINDOWTEXT;
	DWORD bgc = _cl(COLOR_BTNFACE, LGHT_CLR);

	if (itst->itemState & ODS_SELECTED) {
		bgc = _cl(COLOR_BTNSHADOW, DARK_CLR-15);
		txc = COLOR_HIGHLIGHTTEXT;

	}
	if (itst->itemState & ODS_DISABLED) {
		bgc = _cl(COLOR_BTNFACE, FALSE);
		txc = COLOR_GRAYTEXT;

	}
		
	SetTextColor(itst->hDC, GetSysColor(txc));  
	SetBkColor(itst->hDC, bgc);

	GetTextMetrics(itst->hDC, &tm);

	y = (itst->rcItem.bottom + itst->rcItem.top - tm.tmHeight) / 2;
	x = LOWORD(GetDialogBaseUnits( )) / 4;
			
	SendMessage(itst->hwndItem, CB_GETLBTEXT, itst->itemID, (LPARAM)data);				
	ExtTextOut(itst->hDC, 3*x, y, ETO_CLIPPED | ETO_OPAQUE, &itst->rcItem, 
		data, (u32)(wcslen(data)), NULL);

}


void _draw_tabs(
		LPDRAWITEMSTRUCT itst
	)
{	
	DrawState(itst->hDC, NULL, NULL, 
		(LPARAM)NULL, 0, itst->rcItem.left, itst->rcItem.top, 0, 0, DST_PREFIXTEXT);

	DrawEdge(itst->hDC, &itst->rcItem, BDR_SUNKENOUTER, 0);


}


void _draw_static(
		LPDRAWITEMSTRUCT itst
	)
{
	UINT edge = BDR_RAISEDINNER;
	UINT state = DSS_NORMAL;
	UINT border = BF_RECT;

	DRAWTEXTPARAMS tp = { sizeof(tp) };
	WINDOWINFO wi;
	RECT rc;

	_wnd_data *gwl;
	_tab_data *tab;

	wchar_t data[MAX_PATH];
	int x = 6, y = 3;
	char curr;	

	if (!itst) return;
	switch (itst->CtlType) 
	{
		case ODT_LISTVIEW: _draw_listview(itst); break;
		case ODT_COMBOBOX: _draw_combobox(itst); break;
		case ODT_TAB:      _draw_tabs(itst);     break;

		case ODT_BUTTON:

        if (itst->itemState & ODS_DISABLED) state = DSS_DISABLED;
        if (itst->itemState & ODS_SELECTED)
				{
					edge = BDR_SUNKENOUTER;
					x++; y++;
        }
				itst->rcItem.top++;
				GetWindowText(itst->hwndItem, data, MAX_PATH);

				gwl = wnd_get_long(itst->hwndItem, GWL_USERDATA);
				tab = wnd_get_long(GetParent(itst->hwndItem), GWL_USERDATA);
				curr = tab && (tab->h_curr == itst->hwndItem);

				if (gwl) 
				{
					if (!gwl->dlg[0]) 
					{
						itst->rcItem.right = itst->rcItem.left + 13;
						itst->rcItem.bottom = itst->rcItem.top + 13;

						_fill(itst->hDC, &itst->rcItem, (itst->itemState & ODS_FOCUS) ?
							_cl(COLOR_BTNFACE, FALSE):
							_cl(COLOR_BTNFACE, LGHT_CLR));

						GetWindowText(itst->hwndItem, data, MAX_PATH);
						if (gwl->state)

							ImageList_DrawEx(__img, 0, itst->hDC, 
							itst->rcItem.right-11, 2, 0, 0, CLR_NONE, GetSysColor(COLOR_BTNSHADOW), ILD_BLEND);

						DrawEdge(itst->hDC, &itst->rcItem, BDR_SUNKENOUTER, border);
						DrawState(itst->hDC, NULL, NULL,
							(LPARAM)data, 0, itst->rcItem.right+4, -1, 0, 0, DST_PREFIXTEXT | state);

						return;
					} else 
					{ 
						if (curr) 
						{							
							edge = BDR_SUNKENOUTER;
							x++; y++;

						} else border = BF_FLAT;
					}
				}

				_fill(itst->hDC, &itst->rcItem,/*(itst->itemState & ODS_FOCUS) ?
					_cl(COLOR_BTNFACE, LGHT_CLR):*/
					_cl(COLOR_BTNFACE, FALSE));

				DrawState(itst->hDC, NULL, NULL, (LPARAM)data, 0, x, y, 0, 0, DST_PREFIXTEXT | state);

		case ODT_STATIC:

				GetWindowInfo(itst->hwndItem, &wi);
				GetWindowText(itst->hwndItem, data, MAX_PATH);

				if (data[0] == L'#')
				{
					GetWindowRect(GetParent(GetParent(itst->hwndItem)), &rc);

					itst->rcItem.right = rc.right - rc.left - 3;
					itst->rcItem.top = itst->rcItem.left = 1;

					_fill(itst->hDC, &itst->rcItem, _cl(COLOR_BTNSHADOW, DARK_CLR - 7));

					tp.iLeftMargin += 10;
					itst->rcItem.top += 1;
					DrawTextEx(itst->hDC, data + 1, -1, &itst->rcItem, DT_END_ELLIPSIS, &tp);					
				}
				else 
				{
					if ((wi.dwStyle & SS_SUNKEN) == 0) DrawEdge(itst->hDC, &itst->rcItem, edge, border);				
				}


	}
}


BOOL 
CALLBACK 
__sub_enum(
		HWND   hwnd,
		LPARAM lParam
	)
{
	wchar_t name[MAX_PATH];

	if (!GetClassName(hwnd, name, MAX_PATH)) return 1L;
	if ((wcscmp(name, L"SysListView32") == 0) || 
		  (wcscmp(name, L"ComboBox") == 0) ||
			(wcscmp(name, L"Button") == 0)) return 1L;

	if (GetWindowLong(hwnd, GWL_STYLE) & BS_OWNERDRAW)
		_sub_class(hwnd, SUB_STATIC_PROC, HWND_NULL);

	return 1L;

}


BOOL 
CALLBACK 
__enable_enum(
		HWND   hwnd,
		LPARAM lparam
	)
{
	EnableWindow(hwnd, (BOOL)(lparam));
	InvalidateRect(hwnd, NULL, TRUE);

	return 1L;

}

void _enb_but_this(
		HWND parent,
		int  skip_id,
		BOOL enable
	)
{
	EnumChildWindows(parent, __enable_enum, enable);
	EnableWindow(GetDlgItem(parent, skip_id), TRUE);

}


int _find_list_item(
		HWND     hlist,
		wchar_t *text,
		int      column
	)
{
	int item = 0;
	wchar_t tmpb[MAX_PATH];
	int count = ListView_GetItemCount(hlist);

	if (count) {
		for ( ;item < count; item++ ) {

			ListView_GetItemText(hlist, item, column, tmpb, MAX_PATH);
			if (!wcscmp(text, tmpb)) return item;

		}
	}
	return -1;

}


void _tray_icon(
		char install
	)
{
	if (install) {

		NOTIFYICONDATA ni = { sizeof(ni), 
			__dlg, IDI_ICON_TRAY, NIF_MESSAGE | NIF_ICON | NIF_TIP, WM_APP + WM_APP_TRAY,
			LoadIcon(__hinst, MAKEINTRESOURCE(IDI_ICON_TRAY)),
			DC_NAME
		};
		Shell_NotifyIcon(NIM_ADD, &ni);
	} else {

		NOTIFYICONDATA ni = { sizeof(ni), __dlg, IDI_ICON_TRAY };
		Shell_NotifyIcon(NIM_DELETE, &ni);	
	}

}


BOOL 
CALLBACK 
_enum_proc(
		HWND   hwnd,
		LPARAM lparam
	)
{
	wchar_t caption[200];
	void *data;

	if (*(HWND *)lparam == hwnd) return 1L;

	data = wnd_get_long(hwnd, GWL_USERDATA);
	if (data)
	{
		GetWindowText(hwnd, caption, sizeof_w(caption));
		if (wcscmp(caption, DC_NAME) == 0) *(HWND *)lparam = hwnd;
	}
	return 1L;

}


int _init_combo(
		HWND        hwnd, 
		_init_list *list,
		DWORD       val,
		BOOL        or,
		int         bits
	)
{
	int count = 0;
	int item = 0;

	while (wcslen(list[count].display))
	{
		SendMessage(hwnd, (UINT)CB_ADDSTRING, 0, (LPARAM)list[count].display);
		if (!or) 
		{
			if (list[count].val == val) item = count;			
		} else {
			if ( (bits != -1 ? _bitcount(list[count].val) == bits : TRUE) && 
				 (val & list[count].val) )
			{
				item = count;
			}
		}		
		count++;
	}
	SendMessage(hwnd, CB_SETCURSEL, item, 0);
	return item;

}


int _get_combo_val(
		HWND        hwnd, 
		_init_list *list
	)
{
	int count = 0;
	wchar_t text[MAX_PATH];

	GetWindowText(hwnd, text, sizeof_w(text));
	while (wcslen(list[count].display)) {

		if (!wcscmp(list[count].display, text)) 
			return list[count].val;

		count++;

	}
	return -1;

}


wchar_t *_get_text_name(
		int         val, 
		_init_list *list
	)
{
	int count = 0;
	while (wcslen(list[count].display)) 
	{
		if (list[count].val == val) 
			return list[count].display;

		count++;
	}
	return NULL;

}


int 
CALLBACK 
_browse_callback(
		HWND   hwnd,
		UINT   msg,
		LPARAM lparam,
		LPARAM data
	)
{
	WIN32_FIND_DATA file_data;
	HANDLE h_find;

	int count = -1;
	wchar_t path[MAX_PATH];

	if (msg == BFFM_SELCHANGED) 
	{
		if (SHGetPathFromIDList((PIDLIST_ABSOLUTE)lparam, path)) 
		{
			_set_trailing_slash(path);
			wcscat(path, L"*.*");

			h_find = FindFirstFile(path, &file_data);
			if (h_find != INVALID_HANDLE_VALUE) 
			{
				while (FindNextFile(h_find, &file_data) != 0) 
					count++;

				FindClose(h_find);
			}
		}
	}
	return 1L;
}


BOOL _folder_choice(
		HWND     hwnd, 
		wchar_t *path, 
		wchar_t *title
	)
{
	PIDLIST_ABSOLUTE pid;
	BROWSEINFO binfo = { hwnd };

	binfo.pszDisplayName = path;
	//binfo.lpfn           = _browse_callback; 
	binfo.ulFlags        = BIF_NEWDIALOGSTYLE;
	binfo.lpszTitle      = title;

	pid = SHBrowseForFolder(&binfo);
	if (pid) {
		if (SHGetPathFromIDList(pid, path)) return TRUE;

	}
	return FALSE;
}


void _init_list_headers(
		HWND      hwnd,
		_colinfo *cols
	)
{
	LVCOLUMN lvcol = { 0 };
	int col = 0;

	if (!ListView_GetItemCount(hwnd))
	{	
		lvcol.mask  = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
		if ( cols[col].row_images )
		{
			lvcol.fmt |= LVCFMT_BITMAP_ON_RIGHT;
		}
		while ( wcslen(cols[col].name) != 0 ) 
		{ 
			lvcol.iSubItem  = col;
			lvcol.pszText   = cols[col].name;
			lvcol.cx        = cols[col].width;
			lvcol.fmt      |= cols[col].align;

			ListView_InsertColumn(hwnd, col, &lvcol);
			col++;
		}
	}
}


BOOL _open_file_dialog(
		HWND     h_parent,
		wchar_t *s_path,
		int      size,
		wchar_t *s_title
	)
{
	OPENFILENAME ofn = { sizeof(ofn), h_parent };

	ofn.lpstrFile  = s_path;
	ofn.nMaxFile   = size;

	ofn.lpstrTitle = s_title;
	ofn.FlagsEx    = OFN_EX_NOPLACESBAR;

	if (GetOpenFileName(&ofn))
	{
		return TRUE;
	} else {
		return FALSE;
	}	
}


BOOL _save_file_dialog(
		HWND     h_parent,
		wchar_t *s_path,
		int      size,
		wchar_t *s_title
	)
{
	OPENFILENAME ofn = { sizeof(ofn), h_parent };
	ofn.lpstrFile = s_path;

	ofn.lpstrTitle = s_title;	
	ofn.nMaxFile  = size;	

	ofn.Flags = OFN_FORCESHOWHIDDEN | OFN_HIDEREADONLY;
	ofn.FlagsEx = OFN_EX_NOPLACESBAR;

	if ( GetSaveFileName(&ofn) )
	{
		return TRUE;
	} else {
		return FALSE;
	}
}


/*
BOOL _message_with_check(
		HWND      h_parent,
		wchar_t  *s_message,
		wchar_t  *s_check_label,
		BOOL     *check_state
		)
{
	MSGBOXPARAMS params = { sizeof(MSGBOXPARAMS), h_parent };

	params.lpszCaption = L"Warning";
	params.lpszText    = s_message;
	params.dwStyle     = MB_YESNO | MB_ICONWARNING;

	return MessageBoxIndirect( &params ) == IDYES;

	MessageDIg();

}
*/

/*
public:
  CMessageBoxPatcher
    ( LPCTSTR lpCheckBoxString,
    bool bNoMoreByDefault = false
    )
    : CThunk<CMessageBoxPatcher, HOOKPROC>((TMFP)CBTProc, this),
    m_bNoMore(bNoMoreByDefault),
    m_lpCheckBoxString(lpCheckBoxString),
    m_hwndCheckBox(NULL),
    m_hwndMessageBox(NULL)
  {
    m_hHook = ::SetWindowsHookEx(WH_CBT, GetThunk(), NULL,
      ::GetCurrentThreadId());
  }

  ~CMessageBoxPatcher()
  {
    if (m_hHook)
      ::UnhookWindowsHookEx(m_hHook);
  }

  bool GetBoxState() const
  {
    return m_bNoMore;
  }

private:
  HHOOK      m_hHook;
  HWND       m_hwndCheckBox;
  HWND       m_hwndMessageBox;
  bool       m_bNoMore;
  LPCTSTR    m_lpCheckBoxString;
};

inline int WINAPI MessageBox
  ( IN HWND hwnd,
  IN LPCTSTR lpText,
  IN LPCTSTR lpCaption,
  IN UINT uType,
  IN LPCTSTR lpCheckBoxString,
  IN OUT PBOOL pbNoMore
  )
{
  CMessageBoxPatcher  patcher(lpCheckBoxString, !!*pbNoMore);
  int          nRet;

  nRet = ::MessageBox(hwnd, lpText, lpCaption, uType);
  *pbNoMore = patcher.GetBoxState();
  return nRet;
}
*/

