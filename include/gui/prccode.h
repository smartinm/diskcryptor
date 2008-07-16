#ifndef _PRCCODE_
#define _PRCCODE_

#include "uicode.h"
#include "drv_ioctl.h"
#include "main.h"

#define QR_MOUNT        1
#define QR_CHANGE_PASS  2
#define QR_EMBD_PASS    3

#define BOOT_SHEETS     3
#define MAIN_SHEETS     2
#define BOOT_WZR_SHEETS 2

#define set_flag(var,flag,value) if ((value) == 0) { (var) &= ~(flag); } else { (var) |= (flag); }

typedef struct _dlgpass {
	char *pass;
	char *new_pass;

	int query;
	_dnode *node;

} dlgpass, *pdlgpass;


INT_PTR 
CALLBACK
_install_dlg_proc(
		HWND hwnd,
		UINT message,
		WPARAM wparam,
		LPARAM lparam
	);

INT_PTR 
CALLBACK
_options_dlg_proc(
		HWND hwnd,
		UINT message,
		WPARAM wparam,
		LPARAM lparam
	);

INT_PTR 
CALLBACK
_wizard_encrypt_dlg_proc(
		HWND hwnd,
		UINT message,
		WPARAM wparam,
		LPARAM lparam
	);

int _dlg_get_pass(
		HWND hwnd,
		dlgpass *pass
	);

int _dlg_config_loader(
		HWND hwnd,
		BOOL external
	);

int _dlg_options(HWND hwnd);
void _dlg_about(HWND hwnd);

INT_PTR CALLBACK
_main_dialog_proc(
		HWND hwnd,
		UINT message,
		WPARAM wparam,
		LPARAM lparam
	);

INT_PTR 
CALLBACK
_wizard_boot_dlg_proc(
		HWND hwnd,
		UINT message,
		WPARAM wparam,
		LPARAM lparam
	);

void __stdcall 
_timer_handle(
		HWND hwnd,
		UINT msg,
		UINT_PTR id,
		DWORD tickcount
	);

int _shrink_volume(
	   HWND parent, vol_inf *vol, sh_data *shd
	   );

void _update_info_table( );



#endif
