#ifndef _STORAGE_H_
#define _STORAGE_H_

int  dc_create_storage(dev_hook *hook, u64 *storage);
void dc_delete_storage(dev_hook *hook);

HANDLE dc_open_storage_file(
		 wchar_t *dev_name, u32 disposition, ACCESS_MASK access
		 );

#endif