#ifndef _UICODE_
#define _UICODE_

#include <commctrl.h>
#include "pass_check.h"
#include "resource.h"

#define IDS_MOUNT				   L"Mount"
#define IDS_UNMOUNT		     L"Unmount"
#define IDS_ENCRYPT			   L"Encrypt"
#define IDS_DECRYPT			   L"Decrypt"

#define IDS_CHPASS			   L"Change Pasword"
#define IDS_UPD_VOL        L"Update to last volume format"

#define IDS_BOOTINSTALL    L"Install Bootloader"
#define IDS_BOOTREMOVE     L"Remove Bootloader"
#define IDS_BOOTUPDATE     L"Update Bootloader"
#define IDS_BOOTCHANGECGF  L"Change Config"

#define IDS_MOUNTALL       L"Mount All"
#define IDS_UNMOUNTALL     L"Unmount All"

#define IDS_SETTINGS       L"Settings"
#define IDS_ABOUT          L"About"
#define IDS_EXIT           L"Exit"

#define DC_HOMEPAGE        L"http://freed0m.org/index.php/DiskCryptor"
#define DC_FORUMPAGE       L"http://freed0m.org/forum"
#define DC_NAME			  	   L"DiskCryptor"

#define COL_SIZE              1
#define COL_LABEL             2
#define COL_TYPE              3
#define COL_STATUS            4
#define COL_MOUNTED           5

#define LGHT_CLR		          50
#define DARK_CLR              45

#define WM_APP_TRAY           1
#define WM_APP_SHOW           2
#define WM_APP_FILE           3
#define WM_APP_CHANGE_CONFIG  4 

#define MAX_PASS		          64
#define WM_THEMECHANGED       794

#define WM_USER_CLICK         WM_USER + 01 

#define CL_WHITE              RGB(255,255,255)
#define CL_BLUE               RGB(0,0,255)
#define CL_GREEN              RGB(0,255,0)
#define CL_RED                RGB(255,0,0)

#define PRG_STEP				      9000

#define __set_check(hwnd, id, state) (SendMessage(GetDlgItem( \
	hwnd, id), BM_SETCHECK, state, 0))

#define __get_check(hwnd, id) (SendMessage(GetDlgItem( \
	hwnd, id), BM_GETCHECK, 0, 0) == BST_CHECKED)

#define _menu_onoff(enable) \
	( enable ? MF_ENABLED : MF_GRAYED )

typedef struct _colinfo {
	wchar_t *name;
	int width;
} colinfo;

typedef struct _tblinfo {
	int id;
	wchar_t *items[5];
	colinfo cols[2];
	
} tblinfo;

typedef struct __wnd_data {
	WNDPROC old_proc;
	BOOL state;
	UINT vk;
	HWND dlg;
} _wnd_data, *_pwnd_data;

typedef struct __tab_data {
	HWND curr;
	HWND active;
} _tab_data;

typedef struct __static_view {	
	int id;
	HWND hwnd;
	COLORREF color;
} _static_view;

typedef struct __combo_list {
	int val;
	wchar_t *display;
} _combo_list;

typedef struct __ctl_init {
	wchar_t *display;
	int id;
	int val;
} _ctl_init;

extern colinfo _main_headers[ ];
extern colinfo _boot_headers[ ];
extern colinfo _part_by_id_headers[ ];

extern _combo_list wipe_modes[ ];
extern _combo_list kb_layouts[ ];

extern _combo_list boot_type_ext[ ];
extern _combo_list boot_type_all[ ];

extern _combo_list show_pass[ ];
extern _combo_list auth_tmount[ ];

extern _combo_list bad_pass_act[ ];
extern _combo_list auth_type[ ];

extern wchar_t *_info_table_items[ ];
extern wchar_t *_act_table_items[ ];

extern _ctl_init hotks_edit[ ];
extern _ctl_init hotks_chk[ ];
extern _ctl_init hotks_static[ ];

extern _static_view pass_gr_ctls[ ];
extern _static_view pass_pe_ctls[ ];

BOOL _list_set_item(
		HWND hlist,
		DWORD item,
		DWORD subitem,
		wchar_t *text
	);

BOOL _list_insert_item(
		HWND hlist,
		DWORD item,
		DWORD subitem,
		wchar_t *text,
		int state
	);

void _list_set_item_text(
		HWND hlist,
		DWORD item,
		DWORD subitem,
		wchar_t *text
	);

BOOL _list_insert_col(
		HWND hlist,
		int cx
	);

LPARAM _get_item_index(
		HWND hlist,
		int index
	);

LPARAM _get_sel_item(HWND hlist);

void _tray_icon(char install);
BOOL _ui_init(HINSTANCE hinst);

void __unsub_class(HWND hwnd);
void _draw_static(LPDRAWITEMSTRUCT itst);

char *_get_item (
		HWND hlist,
		DWORD item,
		DWORD subitem
	);

BOOL _input_verify(
		HWND     ide_pass,
		HWND     ide_verify,
		int      kb_layout,
		wchar_t  *err,
		int      sym_len
		
	);

INT_PTR _ctl_color(
		WPARAM wparam,
		COLORREF color
	);

DWORD _cl(
		int index,
		char prc
	);

_wnd_data *__sub_class(
		HWND hwnd,
		HWND dlg,
		char key
	);

LRESULT 
CALLBACK 
_key_proc(
		HWND hwnd,
		UINT msg,
		WPARAM wparam,
		LPARAM lparam
	);

LRESULT 
CALLBACK 
_static_proc(
		HWND hwnd,
		UINT msg,
		WPARAM wparam,
		LPARAM lparam
	);

BOOL 
CALLBACK 
__sub_enum(
		HWND hwnd,
		LPARAM lParam
	);

int _find_list_item(
		HWND hlist,
		wchar_t *text,
		int column
	);

void *wnd_get_long(
		HWND wnd, 
		int index
	);

void *wnd_set_long(
		HWND wnd, 
		int index, 
		void *ptr
	);

BOOL 
CALLBACK 
_enum_proc(
		HWND hwnd,
		LPARAM lparam
	);

void _show_pass_group(
		HWND hwnd,
		int flags,
		int layout
	);

void _draw_pass_rating(
		HWND hwnd,
		char *pass,
		int kb_layout,
		wchar_t *err,
		int *entropy
	);

void _get_item_text(
		HWND hlist,
		int item,
		int subitem,
		wchar_t *text,
		int chars
	);

void _init_combo(
		HWND hwnd, 
		_combo_list *list,
		int val,
		BOOL or
	);

void _enb_but_this(
		HWND parent,
		int skip,
		BOOL enable
	);

void _init_list_headers(
		HWND hwnd,
		colinfo *cols
	);

int _get_combo_val(
		HWND hwnd, 
		_combo_list *list
	);

extern HINSTANCE __hinst;

extern HFONT __font_bold;
extern HFONT __font_link;
extern HFONT __font_small;

extern HCURSOR __cur_hand;
extern HCURSOR __cur_arrow;

extern HIMAGELIST __img;
extern HIMAGELIST __dsk_img;

extern HWND __dlg;
extern HWND __dlg_shrink;
extern HWND __dlg_act_info;

#ifdef _WIN64
 #define GWL_USERDATA GWLP_USERDATA
 #define GWL_WNDPROC  GWLP_WNDPROC
#endif

#endif
