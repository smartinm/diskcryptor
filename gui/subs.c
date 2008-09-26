#include <windows.h>
#include <stdio.h>
#include "drv_ioctl.h"
#include "subs.h"
#include "misc.h"


void _error_s(
		HWND hwnd,
		wchar_t *format, 
		int e_code, 
		...
	)
{
	wchar_t msg[MAX_PATH - 20];
	wchar_t est[20];
	va_list args;

	va_start(args, e_code);

	if (format != NULL)
	{
		_vsnwprintf(
			msg, sizeof_w(msg), format, args
			);
	} else {
		msg[0] = 0;
	}

	va_end(args);

	if (e_code != ST_OK) 
	{
		_snwprintf(
			est, sizeof_w(est), L"\nError code: %d", e_code
			);

		wcscat(msg, est);
	}

	__msg_e(hwnd, msg);
}


static int _msg_va(HWND hwnd, wchar_t *format, wchar_t *caption, int type, va_list args)
{
	wchar_t msg[MAX_PATH];
	
	if (format != NULL)
	{
		_vsnwprintf(
			msg, sizeof_w(msg), format, args
			);
	} else {
		msg[0] = 0;
	}

	return MessageBox(hwnd, msg, caption, type);
}


int _msg_i(HWND hwnd, wchar_t *format, ...)
{
	va_list args;
	int     resl;

	va_start(args, format);

	resl = _msg_va(
		hwnd, format, L"Information", MB_OK | MB_ICONINFORMATION, args
		);

	va_end(args);

	return resl;
}


int _msg_q(HWND hwnd, wchar_t *format, ...)
{
	va_list args;
	int     resl;

	va_start(args, format);

	resl = _msg_va(
		hwnd, format, L"Confirm", MB_YESNO | MB_ICONQUESTION, args
		);

	va_end(args);

	return resl == IDYES;
}


void _get_status_text(
		_dnode *node,
		wchar_t *text,
		int len
	)
{
	wchar_t *act_name = L"";
	dc_status *st = &node->mnt.info.status;

	*text = L'\0';
	if (st &&st->dsk_size) {

		_dact *act = _create_act_thread(node, -1, -1);
		if (st->flags & F_ENABLED) wcscpy(text, L"mounted");

		if (act && act->status == ACT_RUNNING) {

			int prc = (int)(st->tmp_size/(st->dsk_size/100));
			if (act->act == ACT_DECRYPT) prc = 100 - prc;

			switch (act->act) {
				case ACT_REENCRYPT: act_name = L"reencrypt"; break;
				case ACT_ENCRYPT:   act_name = L"encrypt";   break;

				case ACT_DECRYPT:   act_name = L"decrypt";   break;
				case ACT_FORMAT:    act_name = L"format";    break;
			}
			_snwprintf(text, len, L"%s %.02d%%", act_name, prc);

		}
	}
}

void _reboot( )
{
	int rlt;

	if ((rlt = enable_privilege(SE_SHUTDOWN_NAME)) == ST_OK) {
		ExitWindowsEx(EWX_REBOOT | EWX_FORCE, 0);
		ExitProcess(0);

	} else {
		_error_s(HWND_DESKTOP, NULL, rlt); 

	}
}


wchar_t *_mark(
		double digit,
		wchar_t *text,
		wchar_t dec
	)
{
	wchar_t dsp[100];
	wchar_t *result = text;

	wchar_t *pdsp = (wchar_t *)&dsp;
	size_t trim, k;

	_snwprintf(pdsp, 50, L"%.2f", digit);
	trim = wcslen(pdsp)%3;
	mincpy(text, dsp, trim);

	for ( pdsp += trim, text += trim,
				k = wcslen(pdsp)/3-1;
				k; k-- ) {

		if (trim) *text++ = '\x2c'; else trim = 1;
		mincpy(text, pdsp, 3);
		text += 3; pdsp += 3;

	}
	if (dec) mincpy(text, pdsp, 3);
	*text = '\0';

	return result;

}


void _trailing_slash(wchar_t *path)
{
	int len = (int)(wcslen(path));

	if (len && (path[len - 1] != L'\\')) 
	{
		path[len] = L'\\'; 
		path[len + 1] = 0;
	}
}


void *_extract_rsrc(
		int id,
		LPWSTR type,
		int *size
	)
{
	void *data = NULL;
	
	HGLOBAL hglb;
	HRSRC hres;

	hres = 
		FindResource(
			__hinst,
			MAKEINTRESOURCE(id), 
			type
	);
	
	if (hres) {
		*size = SizeofResource(__hinst, hres);

		hglb = LoadResource(__hinst, hres);
		data = LockResource(hglb);
	} 

	return data;
}


