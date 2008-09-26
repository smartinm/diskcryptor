#include <windows.h>
#include <stdio.h>
#include <wchar.h>
#include "..\sys\driver.h"
#include "autorun.h"
#include "ntdll.h"
#include "misc.h"

static wchar_t run_key[]      = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
static wchar_t run_once_key[] = L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce";
static wchar_t run_v_name[]   = L"DiskCryptor";

int autorun_set(int run)
{
	wchar_t  name[MAX_PATH];
	wchar_t  path[MAX_PATH];
	HKEY     hkey = NULL;
	wchar_t *kname;
	int      resl;	
	u32      cb;
	
	GetModuleFileName(
		NULL, name, sizeof_w(name)
		);

	_snwprintf(
		path, sizeof_w(path), L"\"%s\" -h", name
		);	

	if (is_win_vista() != 0) {
		kname = run_once_key;
	} else {
		kname = run_key;
	}

	do
	{
		if (run != 0) 
		{
			if (RegCreateKey(HKEY_LOCAL_MACHINE, kname, &hkey)) {
				resl = ST_ACCESS_DENIED; break;
			}

			cb = (u32)(wcslen(path) * sizeof(wchar_t));

			if (RegSetValueEx(hkey, run_v_name, 0, REG_SZ, pv(path), cb)) {
				resl = ST_ACCESS_DENIED; break;
			}
			resl = ST_OK;
		} else 
		{
			if (RegOpenKey(HKEY_LOCAL_MACHINE, kname, &hkey)) {
				resl = ST_ACCESS_DENIED; break;
			}

			if (RegDeleteValue(hkey, run_v_name)) {
				resl = ST_ACCESS_DENIED; break;
			}
			resl = ST_OK;
		}
	} while (0);

	if (hkey != NULL) {
		RegCloseKey(hkey);
	}

	return resl;
}


int on_app_start(wchar_t *cmd_line)
{
	PROCESS_BASIC_INFORMATION pbi;
	wchar_t                   name[MAX_PATH];
	wchar_t                   path[MAX_PATH];
	HKEY                      hkey;	
	int                       resl, autorn;
	u32                       cb, pid;
	int                       isvista;	
	NTSTATUS                  status;
	HANDLE                    h_proc;
	STARTUPINFO               si;
	PROCESS_INFORMATION       pi;
	wchar_t                  *w_pid;
 
    pid = 0; autorn = 0;
	if (wcsstr(cmd_line, L"-h") != NULL) {
		autorn = 1;
	} else 
	{
		if (w_pid = wcsstr(cmd_line, L"-p")) {
			autorn = 1; pid = wcstoul(w_pid + 2, NULL, 10); 
		}
	}

	isvista = is_win_vista();

	if (isvista != 0)
	{
		/* update autorun if old autorun found */
		if (RegCreateKey(HKEY_LOCAL_MACHINE, run_key, &hkey) == 0) 
		{
			cb = sizeof(path);

			if (RegQueryValueEx(hkey, run_v_name, 0, NULL, pv(path), &cb) == 0) {
				RegDeleteValue(hkey, run_v_name);
				autorun_set(1);
			}

			RegCloseKey(hkey);
		}
	}

	do
	{
		if (autorn == 0) {
			resl = ST_OK; break;
		}

		if (isvista != 0)
		{
			if (pid == 0) 
			{
				status = NtQueryInformationProcess(
					GetCurrentProcess(), ProcessBasicInformation, &pbi, sizeof(pbi), NULL
					);

				if (status == 0) 
				{
					GetModuleFileName(
						NULL, name, sizeof(name)
						);

					_snwprintf(
						path, sizeof_w(path), L"\"%s\" -p%u", name, (u32)(pbi.InheritedFromUniqueProcessId)
						);

					zeroauto(&si, sizeof(si));
					si.cb = sizeof(si);

					if (CreateProcess(
						NULL, path, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) 
					{
						CloseHandle(pi.hProcess);
						CloseHandle(pi.hThread);
					}
				}
				resl = ST_NEED_EXIT;
			} else 
			{
				if (h_proc = OpenProcess(SYNCHRONIZE, FALSE, pid)) {
					WaitForSingleObject(h_proc, INFINITE);
					CloseHandle(h_proc);
				} else {
					Sleep(500);
				}

				autorun_set(1);
				resl = ST_AUTORUNNED;
			}
		} else {
			resl = ST_AUTORUNNED;
		}
	} while (0);

	return resl;
}