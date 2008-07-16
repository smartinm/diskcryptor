#ifndef _SHRINK_
#define _SHRINK_

#include "dcapi.h"
#include "drv_ioctl.h"

#define SHRINK_BEGIN 0
#define SHRINK_STEP  1
#define SHRINK_END   2

typedef int (*sh_callback)(
	int stage, void *param, wchar_t *file, int status
	);

int dc_api dc_shrink_volume(
	  wchar_t *root, u32 shrink_size, sh_callback callback, void *param, sh_data *shd
	  );


#endif