#ifndef _DCAPI_
#define _DCAPI_

#include "defines.h"

#ifdef DCAPI_DLL
 #define dc_api __declspec(dllexport)
#else
 #define dc_api __declspec(dllimport)
#endif

#ifdef DCAPI_DLL
 dc_api void *dc_extract_rsrc(int *size, int id);
 u32   dc_get_prog_path(wchar_t *path, u32 n_size);
#endif

#ifdef DCAPI_DLL
 extern u32 h_tls_idx;
#endif

#endif