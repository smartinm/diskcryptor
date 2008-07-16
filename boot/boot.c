/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2008 
    * ntldr <ntldr@freed0m.org> PGP key ID - 0xC48251EB4F8E4E6E
    *

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "boot.h"
#include "bios.h"
#include "misc.h"
#include "hdd.h"
#include "kbd_layout.h"
#include "pkcs5.h"
#include "malloc.h"

ldr_config conf = {
	CFG_SIGN1, CFG_SIGN2, CFG_SIGN3, CFG_SIGN4,
	DC_BOOT_VER, 
	LT_GET_PASS | LT_MESSAGE | LT_DSP_PASS | LT_MASK_PASS,
	ET_MESSAGE | ET_RETRY,
	BT_MBR_BOOT,
	0, 
	0,         /* options         */
	KB_QWERTY, /* keyboard layout */
	{ 0 },
	"enter password: ",
	"password incorrect\n",
	{ 0 }, { 0 },
	0 /* timeout */
};

u8 boot_dsk;

int on_int13(rm_ctx *ctx)
{
	hdd_inf *hdd;
	void    *buff;
	lba_p   *lba = NULL;
	u16      numb;
	u64      start;
	int      need = 0;
	int      res;
	u8       func;

	if (hdd = find_hdd(ctx->dl)) 
	{
		func = ctx->ah;

		if ( (func == 0x02) || (func == 0x03) )
		{
			start = ((ctx->ch + ((ctx->cl & 0xC0) << 2)) * 
				     hdd->max_head + ctx->dh) * hdd->max_sect + (ctx->cl & 0x3F) - 1;
			buff  = pm_off(ctx->es, ctx->bx);
			numb  = ctx->al;
			need  = 1; 
		}

		if ( (func == 0x42) || (func == 0x43) )
		{
			lba   = pm_off(ctx->ds, ctx->si);
			start = lba->sector;
			buff  = pm_off(lba->dst_sel, lba->dst_off);
			numb  = lba->numb;
			need  = 1; 
		}
	}

	if (need != 0) 
	{
		res = dc_disk_io(
			    hdd, buff, numb, start, 
				(func == 0x02) || (func == 0x42)
				);

		if (res != 0) 
		{
			ctx->ah   = 0;
			ctx->efl &= ~FL_CF;

			if (lba != NULL) {
				lba->numb = numb;
			} else {
				ctx->al = (u8)numb;
			}
		} else {
			ctx->efl |= FL_CF;
		}
	}

	return need;
}

static int dc_get_password() 
{
	u32 s_time;
	u32 pos;
	u8  ch;	

	/* clear keyboard buffer */
	while (_kbhit() != 0) {
		_getch();
	}

	if (conf.logon_type & LT_MESSAGE) {
		puts(conf.eps_msg);
	}

	if (conf.options & OP_EPS_TMO) {
		s_time = get_rtc_time();
	}

	for (pos = 0;;)
	{
		if (conf.options & OP_EPS_TMO)
		{
			do
			{
				if (get_rtc_time() - s_time >= conf.timeout) {
					pos = 0; goto ep_exit;
				}
			} while (_kbhit() == 0);

			if (conf.options & OP_TMO_STOP) {
				conf.options &= ~OP_EPS_TMO;
			}
		}

		ch = _getch();

		if (conf.kbd_layout == KB_QWERTZ) {
			ch = to_qwertz(ch);
		}

		if (conf.kbd_layout == KB_AZERTY) {
			ch = to_azerty(ch);
		}

		if (ch == '\r') {
			break;
		}

		if (ch == 8) 
		{
			if (pos > 0) 
			{
				if (conf.logon_type & LT_DSP_PASS) {
					_putch(8);
				}
				conf.pass_buf[--pos] = 0;
			}

			if (conf.logon_type & LT_DSP_PASS) { 
				setchar(' ');
			}
			continue;
		}

		if ( (ch < ' ') || (ch > '~') || (pos == MAX_PASSWORD) ) {
			continue;
		}

		conf.pass_buf[pos++] = ch;

		if (conf.logon_type & LT_DSP_PASS) 
		{
			if (conf.logon_type & LT_MASK_PASS) {
				_putch('*');
			} else {
				_putch(ch);
			}
		}
	}
ep_exit:;
	if (conf.logon_type & LT_DSP_PASS) {
		_putch('\n');
	}

	if (pos != 0) {
		conf.pass_buf[pos] = 0;
	}

	/* clear BIOS keyboard buffer to prevent password leakage */
	/* see http://www.ouah.org/Bios_Information_Leakage.txt for more details */
	zeromem(pv(0x41E), 32);

	return (pos != 0);
}

static int dc_decrypt_header(
			  dc_header *header, s8 *pass
			  )
{
	dc_header hcopy;
	u8        dk[DISKKEY_SIZE];
	aes_key   hdr_key;
	int       succs  = 0;
	
	/* copy header to temp buffer */
	memcpy(&hcopy, header, sizeof(dc_header));

	/* try to decrypt header */
	sha1_pkcs5_2(
		pass, strlen(pass), 
		hcopy.salt,
		PKCS5_SALT_SIZE, 
		2000, dk, 
		DISK_IV_SIZE + MAX_KEY_SIZE
		);
		
	aes_lrw_init_key(
		&hdr_key, dk + DISK_IV_SIZE, dk
		);

	aes_lrw_decrypt(
		pv(&hcopy.sign),
		pv(&hcopy.sign),
		HEADER_ENCRYPTEDDATASIZE,
		0, &hdr_key
		);

	/* Magic 'TRUE' */
	if ( (hcopy.sign == DC_TRUE_SIGN) || (hcopy.sign == DC_DTMP_SIGN) ) {
		/* copy decrypted header to out */
		memcpy(header, &hcopy, sizeof(dc_header));
		succs = 1;
	}
	
	/* prevent leaks */
	zeromem(dk,       sizeof(dk));
	zeromem(&hcopy,   sizeof(hcopy));
	zeromem(&hdr_key, sizeof(hdr_key));

	return succs;
}

static int dc_mount_parts()
{
	dc_header   header;
	list_entry *entry;
	prt_inf    *prt;
	int         n_mount;

	/* mount partitions on all disks */
	n_mount = 0;
	entry   = prt_head.flink;

	while (entry != &prt_head)
	{
		prt   = contain_record(entry, prt_inf, entry_glb);
		entry = entry->flink;

		do
		{
			/* read volume header */
			if (dc_partition_io(prt, &header, 1, 0, 1) == 0) {					
				break;
			}	

			if (dc_decrypt_header(&header, conf.pass_buf) == 0) 
			{
				/* probe mount volume with backup header */
				if (dc_partition_io(prt, &header, 1, prt->size - 2, 1) == 0) {					
					break;
				}

				if (dc_decrypt_header(&header, conf.pass_buf) == 0) {
					break;
				}
			}

			if ( (prt->flags = header.flags) & VF_TMP_MODE )
			{
				prt->tmp_size     = header.tmp_size / SECTOR_SIZE;
				prt->tmp_save_off = header.tmp_save_off / SECTOR_SIZE;
			}
		
			/* initialize disk key */
			aes_lrw_init_key(
				prt->d_key = malloc(sizeof(aes_key)), 
				header.key_data + DISK_IV_SIZE,
				header.key_data
				);

			prt->disk_id = header.disk_id; 
			n_mount++;
		} while (0);
	}

	/* prevent leaks */
	zeromem(&header, sizeof(header));

	return n_mount;
}

static void boot_from_mbr(hdd_inf *hdd)
{
	if ( !(conf.options & OP_EXTERNAL) && (hdd->dos_numb == boot_dsk) ) {
		memcpy(pv(0x7C00), conf.save_mbr, SECTOR_SIZE);
	} else {
		dc_disk_io(hdd, pv(0x7C00), 1, 0, 1);
	}

	bios_jump_boot(hdd->dos_numb);
}

static void boot_from_partition(prt_inf *prt)
{
	dc_partition_io(prt, pv(0x7C00), 1, 0, 1);

	/* check MBR signature */
	if (p16(0x7C00+510)[0] != 0xAA55) {
		puts("partition unbootable\n");
	} else {
		bios_jump_boot(prt->hdd->dos_numb);
	}
}


static void dc_password_error(prt_inf *active) 
{
	if (conf.error_type & ET_MESSAGE) {
		puts(conf.err_msg);
	}

	if (conf.error_type & ET_REBOOT) {
		bios_reboot();
	}

	if (conf.error_type & ET_BOOT_ACTIVE)
	{
		if (active == NULL) {
			puts("active partition not found\n");
		} else {
			boot_from_partition(active);
		}
	}

	if (conf.error_type & ET_EXIT_TO_BIOS) {
		bios_call(0x18, NULL);
	}
}

/* find first HDD contain active partition */
static hdd_inf *find_bootable_hdd() 
{
	list_entry *entry;
	prt_inf    *prt;

	entry = prt_head.flink;

	while (entry != &prt_head)
	{
		prt   = contain_record(entry, prt_inf, entry_glb);
		entry = entry->flink;

		if ( (prt->active != 0) && 
			 ( !(conf.options & OP_EXTERNAL) || (prt->hdd->dos_numb != boot_dsk) ) )
		{
			return prt->hdd;
		}
	}

	return NULL;
}


void boot_main()
{
	list_entry *entry;
	hdd_inf    *hdd;
	prt_inf    *prt, *active;
	char       *error;
	int         login;
	
	active = NULL; error = NULL;
	login = 0;
	
	/* prepare MBR copy buffer */
	memcpy(conf.save_mbr + 432, p8(0x7C00) + 432, 80);

	if (dc_scan_partitions() == 0) {
		error = "partitions not found\n";
		goto error;
	}
	
	if (hdd = find_hdd(boot_dsk))
	{
		/* find active partition on boot disk */
		entry = hdd->part_head.flink;
		
		while (entry != &hdd->part_head)
		{
			prt   = contain_record(entry, prt_inf, entry_hdd);
			entry = entry->flink;

			if (prt->active != 0) {
				active = prt; break;
			}
		}
	}
retry_auth:;	
	if (conf.logon_type & LT_GET_PASS) 
	{
		login = dc_get_password();

		if ( (conf.options & OP_NOPASS_ERROR) && (login == 0) ) 
		{
			dc_password_error(active);

			if (conf.error_type & ET_RETRY) {
				goto retry_auth;
			} else {
				/* halt system */
				__halt();
			}
		}
	}

	if ( (dc_mount_parts() == 0) && (login != 0) ) 
	{
		dc_password_error(active);

		if (conf.error_type & ET_RETRY) {
			goto retry_auth;
		} else {
			/* halt system */
			__halt();
		}
	}

	switch (conf.boot_type)
	{
		case BT_MBR_BOOT: 			  
		  {
			  if (hdd == NULL) {
				  error = "boot disk not found\n";
				  goto error;
			  }
			  boot_from_mbr(hdd);
		  }
	    break;
		case BT_MBR_FIRST: 
		  {
			  if ( (hdd = find_bootable_hdd()) == NULL ) {
				  error = "boot disk not found\n";
				  goto error;
			  }			 
			  boot_from_mbr(hdd);
		  }
	    break;
		case BT_ACTIVE:
		  {
			  if (active == NULL) {
				  error = "active partition not found\n";
				  goto error;
			  } else {	  
				  boot_from_partition(active);
			  }
		  }
	  	break;
		case BT_AP_PASSWORD:
		  {
			  /* find first partition with appropriate password */
			  entry = prt_head.flink;

			  while (entry != &prt_head)
			  {
				  prt   = contain_record(entry, prt_inf, entry_glb);
				  entry = entry->flink;

				  if ( (prt->extend == 0) && (prt->d_key != NULL) ) {
					  boot_from_partition(prt);
				  }
			  }

			  error = "bootable partition not mounted\n";
			  goto error;
		  }
	    break;
		case BT_DISK_ID:
		  {
			  /* find partition by disk_id */
			  entry = prt_head.flink;

			  while (entry != &prt_head)
			  {
				  prt   = contain_record(entry, prt_inf, entry_glb);
				  entry = entry->flink;

				  if ( (prt->extend == 0) && (prt->d_key != NULL) &&
					   (prt->disk_id == conf.disk_id) ) 
				  {
					  boot_from_partition(prt);
				  }
			  }
			  
			  error = "disk_id equal partition not found\n";
			  goto error;
		  }
		break;
	}

error:;
	if (error != NULL) {
		puts(error); 
	}	
	while (1);
}