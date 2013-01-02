#ifndef _CD_ENC_H_
#define _CD_ENC_H_

#include "xts_fast.h"
#include "volume_header.h"
#include "dcapi.h"

typedef int (cd_callback)(u64 iso_sz, u64 enc_sz, void *param);

int dc_api 
  dc_encrypt_cd(
	  wchar_t *src_path, wchar_t *dst_path, dc_pass *pass, 
	  int      cipher, cd_callback callback, void *param
	  );

#endif