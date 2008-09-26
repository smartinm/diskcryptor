#ifndef _SUBS_
#define _SUBS_

#include "uicode.h"
#include "main.h"

#define __msg_w(display, hwnd) (MessageBox( \
	hwnd, display, L"Warning", MB_YESNO | MB_ICONWARNING) == IDYES)

int _msg_i(HWND hwnd, wchar_t *format, ...);
int _msg_q(HWND hwnd, wchar_t *format, ...);

#define __msg_e(hwnd, display) (MessageBox( \
	hwnd, display, L"Error", MB_OK | MB_ICONERROR))

void _error_s(
		HWND hwnd,
		wchar_t *format, 
		int e_code, 
		...
	);

void _get_status_text(
		_dnode *st,
		wchar_t *text,
		int len
	);

wchar_t *_mark(
		double digit,
		wchar_t *text,
		wchar_t dec
	);

void *_extract_rsrc(
		int id,
		LPWSTR type,
		int *size
	);

void _trailing_slash(wchar_t *path);
void _reboot( );

#endif
