#ifndef _DISK_NAME_H_
#define _DISK_NAME_H_

int dc_api dc_get_hdd_name(
	  int dsk_num, wchar_t *name, size_t max_name
	  );

#endif