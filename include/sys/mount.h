#ifndef _MOUNT_
#define _MOUNT_

#include "devhook.h"
#include "enc_dec.h"

void dc_add_password(char *pass);
void dc_clean_pass_cache();
void dc_clean_keys();

aes_key *dc_init_hdr_key(dc_header *header, char *password);
aes_key *dc_decrypt_header(dc_header *header, char *password);

int dc_mount_device(wchar_t *dev_name, char *passwod);

int dc_process_unmount(dev_hook *hook, int opt);

void dc_process_unmount_async(
		dev_hook *hook, s_callback on_complete, void *param
		);

int dc_write_header(
	  dev_hook *hook, dc_header *header, u64 offset, char *password
	  );

int dc_unmount_device(wchar_t *dev_name, int force);

void dc_unmount_all(int force);

int dc_mount_all(s8 *password);
int dc_num_mount();

NTSTATUS
  dc_probe_mount(
     IN PDEVICE_OBJECT dev_obj, 
	 IN PIRP           irp
	 );

void dc_init_mount();

#define MAX_MNT_PROBES 32

#endif