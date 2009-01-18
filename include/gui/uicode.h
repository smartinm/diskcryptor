#ifndef _UICODE_
#define _UICODE_

#include <commctrl.h>
#include "pass.h"
#include "resource.h"

#define IDS_MOUNT				      L"Mount"
#define IDS_UNMOUNT		        L"Unmount"
#define IDS_ENCRYPT			      L"Encrypt"
#define IDS_DECRYPT			      L"Decrypt"

#define IDS_FORMAT            L"Format"
#define IDS_REENCRYPT         L"Reencrypt"

#define IDS_CHPASS			      L"Change Password"

#define IDS_BOOTINSTALL       L"Install Loader"
#define IDS_BOOTREMOVE        L"Remove Loader"
#define IDS_BOOTCREATE        L"Create Loader"
#define IDS_SAVECHANGES       L"Save Changes"

#define IDS_BOOTUPDATE        L"Update Loader"
#define IDS_BOOTCHANGECGF     L"Change Config"

#define IDS_MOUNTALL          L"Mount All"
#define IDS_UNMOUNTALL        L"Unmount All"

#define IDS_SETTINGS          L"Settings"
#define IDS_ABOUT             L"About"
#define IDS_EXIT              L"Exit"

#define IDS_EMPTY_LIST        L"< .. list is empty .. >"

#define IDS_USE_KEYFILES      L"Use Keyfiles"
#define IDS_USE_KEYFILE       L"Use Keyfile"

#define IDS_MODE_NAME         L"XTS"
#define IDS_PRF_NAME          L"HMAC-SHA-512"

#define DC_HOMEPAGE           L"http://diskcryptor.net/"
#define DC_FORUMPAGE          L"http://diskcryptor.net/forum"
#define DC_NAME			  	      L"DiskCryptor"

#define DC_MUTEX		  	      L"DC_UI_MUTEX"
#define DC_CLASS		  	      L"DC_UI_DLG_CLASS"

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

#define WM_THEMECHANGED       794
#define WM_USER_CLICK         WM_USER + 01 

#define CL_WHITE              RGB(255,255,255)
#define CL_BLUE               RGB(0,0,255)
#define CL_GREEN              RGB(0,255,0)
#define CL_RED                RGB(255,0,0)

#define CL_WARNING            RGB(218,18,18)
#define CL_WARNING_BG         RGB(255,170,160)
#define CL_WARNING_BG_LT      RGB(255,215,215)

#define PRG_STEP				      9000
#define MAIN_DLG_MIN_HEIGHT   380

#define _set_check(hwnd, id, state) (SendMessage(GetDlgItem( \
	hwnd, id), BM_SETCHECK, state, 0))

#define _get_check(hwnd, id) (SendMessage(GetDlgItem( \
	hwnd, id), BM_GETCHECK, 0, 0) == BST_CHECKED)

#define _menu_onoff(enable) \
	( enable ? MF_ENABLED : MF_GRAYED )

typedef struct _colinfo 
{
	wchar_t *name;
	int      width;
} colinfo;

typedef struct _tblinfo 
{
	int      id;
	wchar_t *items[5];
	colinfo  cols[2];	
} tblinfo;

typedef struct __wnd_data 
{
	WNDPROC old_proc;
	BOOL    state;
	UINT    vk;
	HWND    dlg;
	void   *data;
} _wnd_data, *_pwnd_data;

typedef struct __tab_data 
{
	HWND curr;
	HWND active;
} _tab_data;

typedef struct __static_view 
{
	int      id;
	HWND     hwnd;
	COLORREF color;
} _static_view;

typedef struct __init_list 
{
	int      val;
	wchar_t *display;
} _init_list;

typedef struct __ctl_init 
{
	wchar_t *display;
	int      id;
	int      val;
} _ctl_init;

typedef struct __size_move_ctls 
{
	int anchor;
	int id;
	int val;
	int dx;
	int dy;
} _size_move_ctls;


typedef struct __wz_sheets {
	int  id;
	HWND hwnd;
	BOOL show;
} _wz_sheets;

#define WPAGE_ENC_TYPE      0x0000
#define WPAGE_ENC_FRMT      0x0001
#define WPAGE_ENC_CONF      0x0002
#define WPAGE_ENC_BOOT      0x0003
#define WPAGE_ENC_PASS      0x0004

#define CTL_LDR_MBR         0x0000
#define CTL_LDR_STICK       0x0001
#define CTL_LDR_ISO         0x0002
#define CTL_LDR_PXE         0x0003

extern colinfo _main_headers[ ];
extern colinfo _boot_headers[ ];

extern colinfo _part_by_id_headers[ ];
extern colinfo _benchmark_headers[ ];

extern _init_list wipe_modes[ ];
extern _init_list kb_layouts[ ];

extern _init_list boot_type_ext[ ];
extern _init_list boot_type_all[ ];

extern _init_list show_pass[ ];
extern _init_list auth_tmount[ ];

extern _init_list bad_pass_act[ ];
extern _init_list auth_type[ ];

extern _init_list cipher_names[ ];
extern _init_list loader_type[ ];

extern _init_list pass_status[ ];

extern wchar_t *_info_table_items[ ];
extern wchar_t *_act_table_items[ ];

extern _ctl_init hotks_edit[ ];
extern _ctl_init hotks_chk[ ];
extern _ctl_init hotks_static[ ];

extern _static_view pass_gr_ctls[ ];
extern _static_view pass_pe_ctls[ ];

typedef struct __dlg_templateex {
	WORD  dlgVer;
	WORD  signature;
	DWORD helpID;
	DWORD exStyle;
	DWORD style;
	WORD  cDlgItems;
	short x;
	short y;
	short cx;
	short cy;
} _dlg_templateex;

BOOL _list_set_item(
		HWND     hlist,
		DWORD    item,
		DWORD    subitem,
		wchar_t *text
	);

BOOL _list_insert_item(
		HWND     hlist,
		DWORD    item,
		DWORD    subitem,
		wchar_t *text,
		int      state
	);

void _list_set_item_text(
		HWND     hlist,
		DWORD    item,
		DWORD    subitem,
		wchar_t *text
	);

BOOL _list_insert_col(
		HWND hlist,
		int  cx
	);

void _init_mount_points(
		HWND hwnd
	);

LPARAM _get_item_index(
		HWND hlist,
		int  index
	);

LPARAM _get_sel_item(HWND hlist);

void _tray_icon(char install);
BOOL _ui_init(HINSTANCE hinst);

void __unsub_class(HWND hwnd);
void _draw_static(LPDRAWITEMSTRUCT itst);

BOOL _folder_choice(
		HWND     hwnd, 
		wchar_t *path, 
		wchar_t *title
	);

char *_get_item (
		HWND  hlist,
		DWORD item,
		DWORD subitem
	);

void _relative_move(
		HWND h_anchor,
		HWND h_child,
		int  dt,
		BOOL dy,
		BOOL border_correct
	);

void _resize_ctl(
		HWND h_ctl,
		int  dy,
		int  dx,
		BOOL border_correct
	);

void _relative_rect(
		HWND  hwnd,
		RECT *rc
	);

void _middle_ctl(
		HWND h_anchor,
		HWND h_child,
		BOOL border_correct
	);

INT_PTR _ctl_color(
		WPARAM   wparam,
		COLORREF color
	);

DWORD _cl(
		int  index,
		char prc
	);

_wnd_data *_sub_class(
		HWND hwnd,
		HWND dlg,
		char key
	);

LRESULT 
CALLBACK 
_key_proc(
		HWND   hwnd,
		UINT   msg,
		WPARAM wparam,
		LPARAM lparam
	);

LRESULT 
CALLBACK 
_static_proc(
		HWND   hwnd,
		UINT   msg,
		WPARAM wparam,
		LPARAM lparam
	);

BOOL 
CALLBACK 
__sub_enum(
		HWND   hwnd,
		LPARAM lParam
	);

int _find_list_item(
		HWND     hlist,
		wchar_t *text,
		int      column
	);

void *wnd_get_long(
		HWND wnd, 
		int  index
	);

void *wnd_set_long(
		HWND  wnd, 
		int   index, 
		void *ptr
	);

BOOL 
CALLBACK 
_enum_proc(
		HWND   hwnd,
		LPARAM lparam
	);

void _show_pass_group(
		HWND hwnd,
		int  flags,
		int  layout
	);

void _get_item_text(
		HWND     hlist,
		int      item,
		int      subitem,
		wchar_t *text,
		int      chars
	);

int _init_combo(
		HWND        hwnd, 
		_init_list *list,
		DWORD       val,
		BOOL        or,
		int         bits
	);

void _enb_but_this(
		HWND parent,
		int  skip,
		BOOL enable
	);

void _init_list_headers(
		HWND     hwnd,
		colinfo *cols
	);

int _draw_proc(
		int     message,
		LPARAM lparam
	);

BOOL _is_duplicated_item(
		HWND     h_list,
		wchar_t *s_item
	);

int _get_combo_val(HWND hwnd, _init_list *list);
wchar_t *_get_text_name(int val, _init_list *list);

extern HINSTANCE __hinst;

extern HFONT __font_bold;
extern HFONT __font_link;
extern HFONT __font_small;

extern HCURSOR __cur_hand;
extern HCURSOR __cur_arrow;
extern HCURSOR __cur_wait;

extern HIMAGELIST __img;
extern HIMAGELIST __dsk_img;

extern HWND __dlg;
extern HWND __dlg_act_info;

#ifdef _WIN64
 #define GWL_USERDATA GWLP_USERDATA
 #define GWL_WNDPROC  GWLP_WNDPROC
#endif

#endif
