#ifndef _MISC_VOLUME_H_
#define _MISC_VOLUME_H_

void dc_random_sectors(dev_hook *hook, u64 offset, u32 length);

int dc_backup_header(wchar_t *dev_name, char *password, void *out);
int dc_restore_header(wchar_t *dev_name, char *password, void *in);

int dc_change_pass(
	  wchar_t *dev_name, s8 *old_pass, s8 *new_pass, u8 new_prf
	  );

int dc_update_volume(s16 *dev_name, s8 *password, dc_ioctl *s_sh);

int dc_format_start(wchar_t *dev_name, char *password, crypt_info *crypt);
int dc_format_step(wchar_t *dev_name, int wp_mode);
int dc_format_done(wchar_t *dev_name);

#endif