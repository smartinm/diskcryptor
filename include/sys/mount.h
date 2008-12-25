#ifndef _MOUNT_
#define _MOUNT_

#include "devhook.h"
#include "enc_dec.h"

void dc_add_password(dc_pass *pass);
void dc_clean_pass_cache();
void dc_clean_keys();

void dc_init_hdr_key(dc_key *hdr_key, dc_header *header, int cipher, dc_pass *password);

int dc_mount_device(wchar_t *dev_name, dc_pass *password);
int dc_process_unmount(dev_hook *hook, int opt);

void dc_process_unmount_async(
		dev_hook *hook, s_callback on_complete, void *param
		);

int dc_unmount_device(wchar_t *dev_name, int force);

void dc_unmount_all(int force);

int dc_mount_all(dc_pass *password);
int dc_num_mount();

NTSTATUS dc_probe_mount(dev_hook *hook, PIRP irp);

void dc_init_mount();

#define MAX_MNT_PROBES 32

#endif