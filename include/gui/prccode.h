#ifndef _PRCCODE_
#define _PRCCODE_

#include "uicode.h"
#include "drv_ioctl.h"
#include "main.h"

#define MAIN_SHEETS       2
#define BOOT_WZR_SHEETS   2

typedef struct _dlgpass 
{
	_dnode  *node;
	dc_pass *pass;
	dc_pass *new_pass;
	wchar_t *mnt_point;

} dlgpass, *pdlgpass;


INT_PTR 
CALLBACK
_install_dlg_proc(
		HWND   hwnd,
		UINT   message,
		WPARAM wparam,
		LPARAM lparam
	);

INT_PTR 
CALLBACK
_options_dlg_proc(
		HWND   hwnd,
		UINT   message,
		WPARAM wparam,
		LPARAM lparam
	);

INT_PTR 
CALLBACK
_wizard_encrypt_dlg_proc(
		HWND   hwnd,
		UINT   message,
		WPARAM wparam,
		LPARAM lparam
	);

int _dlg_get_pass(
		HWND     hwnd,
		dlgpass *pass
	);

int _dlg_change_pass(
		HWND     hwnd,
		dlgpass *pass
	);

int _dlg_config_loader(
		HWND hwnd,
		BOOL external
	);

int _dlg_options(HWND hwnd);

void _dlg_about(HWND hwnd);
void _dlg_benchmark(HWND hwnd);

INT_PTR CALLBACK
_main_dialog_proc(
		HWND   hwnd,
		UINT   message,
		WPARAM wparam,
		LPARAM lparam
	);

INT_PTR 
CALLBACK
_wizard_boot_dlg_proc(
		HWND   hwnd,
		UINT   message,
		WPARAM wparam,
		LPARAM lparam
	);

void __stdcall 
_timer_handle(
		HWND     hwnd,
		UINT     msg,
		UINT_PTR id,
		DWORD    tickcount
	);

void _update_info_table( );



#endif
