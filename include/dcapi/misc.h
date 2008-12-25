#ifndef _MISC_
#define _MISC_

#include "dcapi.h"

/* exported functions */
int dc_api enable_privilege(wchar_t *name);
int dc_api is_admin();
int dc_api is_wow64();
int dc_api is_win_vista();

void dc_api *secure_alloc(u32 size);
void dc_api secure_free(void *mem);

int dc_api dc_get_hdd_name(
	  int dsk_num, wchar_t *name, size_t max_name
	  );
	  
HANDLE dc_api dc_disk_open(int dsk_num);	  

void dc_api dc_format_byte_size(
	   wchar_t *wc_buf, int wc_size, u64 num_bytes
	   );

wchar_t dc_api *dc_get_cipher_name(int cipher_id);
wchar_t dc_api *dc_get_mode_name(int mode_id);
wchar_t dc_api *dc_get_prf_name(int prf_id);

int dc_api dc_format_fs(wchar_t *root, wchar_t *fs);
int dc_api save_file(wchar_t *name, void *data, int size);
int dc_api load_file(wchar_t *name, void **data, int *size);

/* private functions for internal use */

int dc_fs_type(u8 *buff);

int dc_disk_read(
	  HANDLE hdisk, void *buff, int size, u64 offset
	  );

int dc_disk_write(
	  HANDLE hdisk, void *buff, int size, u64 offset
	  );

#define FS_UNK   0
#define FS_FAT12 1
#define FS_FAT16 2
#define FS_FAT32 3
#define FS_NTFS  4

#endif