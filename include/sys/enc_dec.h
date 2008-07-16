#ifndef _ENC_DEC_
#define _ENC_DEC_

typedef void (*s_callback)(void*,void*,int);

int dc_enable_sync_mode(dev_hook *hook);
int dc_encrypt_start(wchar_t *dev_name, char *password, int wp_mode);
int dc_decrypt_start(wchar_t *dev_name, char *password);

int dc_send_async_packet(
	  wchar_t *dev_name, u32 type, void *param, s_callback on_complete, void *cb_param
	  );

int dc_send_sync_packet(wchar_t *dev_name, u32 type, void *param);

void dc_sync_all_encs();

int dc_change_pass(s16 *dev_name, s8 *old_pass, s8 *new_pass);
int dc_update_volume(s16 *dev_name, s8 *password, dc_ioctl *s_sh);

typedef struct _sync_packet {
	LIST_ENTRY entry_list;
	u32        type;
	PIRP       irp;
	void      *param;
	s_callback on_complete;
	void      *cb_param;

} sync_packet;

#define S_OP_ENC_BLOCK  0
#define S_OP_DEC_BLOCK  1
#define S_OP_SYNC       2
#define S_OP_FINALIZE   3
#define S_OP_SET_KEY    4
#define S_OP_SET_SHRINK 8

#define S_INIT_NONE    0
#define S_INIT_ENC     1
#define S_INIT_DEC     2
#define S_CONTINUE_ENC 3

#endif