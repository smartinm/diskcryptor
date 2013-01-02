/*
    *
    * DiskCryptor - open source partition encryption tool
	* Copyright (c) 2009
	* ntldr <ntldr@diskcryptor.net> PGP key ID - 0xC48251EB4F8E4E6E
    * 

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 3 as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <windows.h>
#include "defines.h"
#include "dcapi.h"

static HINSTANCE h_inst_dll;
       u32       h_tls_idx;

void *dc_extract_rsrc(int *size, int id)
{
	HGLOBAL hglb;
	HRSRC   hres;
	PVOID   data = NULL;

	hres = FindResource(
		h_inst_dll, MAKEINTRESOURCE(id), L"EXEFILE");
	
	if (hres != NULL) 
	{
		size[0] = SizeofResource(h_inst_dll, hres);
		hglb  = LoadResource(h_inst_dll, hres);
		data  = LockResource(hglb);
	} 

	return data;
}

u32 dc_get_prog_path(wchar_t *path, u32 n_size)
{
	u32 len;

	len = GetModuleFileName(
		h_inst_dll, path, n_size);

	path[len] = 0;

	while ( (len != 0) && (path[len] != L'\\') ) {
		len--;
	}

	path[len] = 0;

	return len;
}

BOOL WINAPI DllMain(
    HINSTANCE h_inst, u32 dw_reason, void *reserved
	)
{
	if (dw_reason == DLL_PROCESS_ATTACH)
	{
		h_tls_idx  = TlsAlloc();
		h_inst_dll = h_inst;

		if (h_tls_idx != TLS_OUT_OF_INDEXES) {
			DisableThreadLibraryCalls(h_inst);
		} else {
			return FALSE;
		}
		CreateMutex(NULL, FALSE, L"DISKCRYPTOR_MUTEX");
	}
	return TRUE;
}