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
		h_inst_dll, MAKEINTRESOURCE(id), L"EXEFILE"
		);
	
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
		h_inst_dll, path, n_size
		);

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
	if (dw_reason = DLL_PROCESS_ATTACH)
	{
		h_tls_idx  = TlsAlloc();
		h_inst_dll = h_inst;

		if (h_tls_idx != TLS_OUT_OF_INDEXES) {
			DisableThreadLibraryCalls(h_inst);
		} else {
			return FALSE;
		}
	}
	return TRUE;
}