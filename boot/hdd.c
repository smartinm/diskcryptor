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
#include "misc.h"
#include "hdd.h"
#include "crypto.h"
#include "malloc.h"

list_entry hdd_head;
list_entry prt_head;

int dc_bios_io(
	  hdd_inf *hdd, void *buff, 
	  u16      sectors, u64 start,
	  int      read
	  )
{
	lba_p  lba;
	rm_ctx ctx;
	u32    soff, head;
	u32    hoff, coff;
	u8     flag;

	if (read != 0) {
		flag = 2;
	} else {
		flag = 3;
	}

	if (hdd->lba_mode != 0) 
	{
		lba.size    = sizeof(lba); 
		lba.unk     = 0;
		lba.dst_sel = rm_seg(buff);
		lba.dst_off = rm_off(buff);
		lba.numb    = sectors; 
		lba.sector  = start;
		ctx.si      = rm_off(&lba); 
		ctx.ds      = rm_seg(&lba); 
		ctx.dl      = hdd->dos_numb; 
		ctx.ah      = 0x40 | flag;		
	} else 
	{
		soff   = ((u32)start % hdd->max_sect + 1);
		head   = (u32)((u32)start / hdd->max_sect);
		hoff   = head % hdd->max_head;
		coff   = head / hdd->max_head;
		ctx.ah = flag;
		ctx.al = (u8)sectors;
		ctx.dh = (u8)hoff; 
		ctx.dl = hdd->dos_numb;
		ctx.ch = (u8)coff;
		ctx.cl = (u8)( ((coff & 0x0300) >> 2) | soff);
		ctx.es = rm_seg(buff);
		ctx.bx = rm_off(buff);	
	}

	return bios_call(0x13, &ctx);
}

static int dc_find_hdds() 
{
	hdd_inf *hdd;
	rm_ctx   ctx;
	int      num = 0;
	int      i;

	/* detect all HDDs */
	for (i = 0x80; i < 0xFF; i++) 
	{
		/* get drive geometry */
		ctx.ah = 0x08; ctx.dl = i;
				
		if ( (bios_call(0x13, &ctx) != 0) && (ctx.ah == 0) ) 
		{
			hdd = malloc(sizeof(hdd_inf));
			hdd->dos_numb = i;
			hdd->max_head = ctx.dh + 1;
			hdd->max_sect = ctx.cl & 0x3F;

			_insert_tail_list(&hdd_head, &hdd->entry);
			_init_list_head(&hdd->part_head);

			/* check for LBA support */
			ctx.bx = 0x55AA; ctx.ah = 0x41; 
			ctx.dl = i;

			do
			{
				if (bios_call(0x13, &ctx) == 0) {
					break;
				}

				if ( (ctx.bx != 0xAA55) || !(ctx.cl & 1) ) {
					break;
				}

				hdd->lba_mode = 1; 
			} while (0);

			num++;
		} else {
			break;
		}
	}

	return num;	
}

hdd_inf *find_hdd(u8 num)
{
	list_entry *entry;
	hdd_inf    *hdd;

	/* find HDD */
	entry = hdd_head.flink;

	while (entry != &hdd_head)
	{
		hdd   = contain_record(entry, hdd_inf, entry);
		entry = entry->flink;

		if (hdd->dos_numb == num) {
			return hdd;
		}
	}

	return NULL;
}

 

static
int scan_hdd_off(hdd_inf *hdd, u64 off, u64 ext_off)
{
	u8       mbr[512];
	pt_ent  *pt;
	prt_inf *prt;
	int      num;
	int      found = 0;
	u64      pt_off;
	u64      ex_off;

	do
	{
		/* read MBR */
		if (dc_bios_io(hdd, mbr, 1, off + ext_off, 1) == 0) {
			break;
		}

		/* check MBR signature */
		if (p16(mbr+510)[0] != 0xAA55) {
			break;
		}

		pt = (void *)(mbr + 446);

		for (num = 4; num; num--, pt++)
		{
			if (pt->os == 0) {
				break;
			}

			pt_off = pt->start_sect;

			if ( (pt->os == 5) || (pt->os == 0x0F) ) 
			{
				if (ext_off == 0) {
					ex_off = pt_off;
					pt_off = 0;
				} else {
					ex_off = ext_off;
				}

				found += scan_hdd_off(hdd, pt_off, ex_off);
			} else 
			{				
				prt = malloc(sizeof(prt_inf));
				prt->begin  = pt_off + off + ext_off;
				prt->end    = prt->begin + pt->prt_size;
				prt->size   = pt->prt_size;
				prt->active = (pt->active == 0x80);
				prt->extend = (ext_off != 0);			
				prt->hdd    = hdd;
				prt->d_key  = NULL; found++;

				_insert_tail_list(&hdd->part_head, &prt->entry_hdd);
				_insert_tail_list(&prt_head, &prt->entry_glb);				
			}			
		}
	} while (0);

	return found;
}

static
int dc_partition_enc_read(
	  prt_inf *prt, void *buff, 
	  u16 sectors, u64 start
	  )
{
	int res;

	res = dc_bios_io(
		prt->hdd, buff, sectors, start + prt->begin + 1, 1
		);

	if (res != 0) 
	{
		aes_lrw_decrypt(
			buff, buff, sectors * 512, start, prt->d_key
			); 
	}
	
	return res;
}

static
int dc_partition_enc_write(
	  prt_inf *prt, void *buff, 
	  u16      sectors,  u64 start
	  )
{
	int res;

	/* encrypt buffer */
	aes_lrw_encrypt(
		buff, buff, sectors * 512, start, prt->d_key
		);

	/* write buffer to disk */
	res = dc_bios_io(
		prt->hdd, buff, sectors, start + prt->begin + 1, 0
		);

	/* decrypt buffer to save original data */
	aes_lrw_decrypt(
		buff, buff, sectors * 512, start, prt->d_key
		);

	return res;
}


int dc_partition_io(
	  prt_inf *prt, void *buff, 
	  u16 sectors, u64 start, int read
	  )
{
	u64  o1, o3;
	u16  s1, s2, s3;	
	u8  *p1, *p2, *p3;
	u64  tmp, end;
	int  res;

	if (prt->d_key != NULL)
	{
		if (prt->flags & VF_TMP_MODE) 
		{
			o1  = o3 = 0;
			s1  = s2 = s3 = 0;
			p1  = p2 = p3 = NULL;
			tmp = prt->tmp_size;
			end = start + sectors;	

			if (start > tmp) {
				o3 = start; s3 = sectors; p3 = buff;
			} else
			{
				if ( (start <= tmp) && ((start+sectors) > tmp) )
				{
					o1 = start; s1 = (u16)(tmp - start); p1 = buff;
					s2 = 1; p2 = p1 + (s1 * SECTOR_SIZE);
					o3 = start + s1 + s2; s3 = sectors - s1 - s2; p3 = p2 + (s2 * SECTOR_SIZE);
				} else {
					o1 = start; s1 = sectors; p1 = buff;
				}				
			}

			if (read != 0)
			{
				/* read encrypted part */
				if (s1 != 0) {
					res = dc_partition_enc_read(prt, p1, s1, o1);
				}

				/* read temporary part */
				if (s2 != 0) {					
					res = dc_bios_io(prt->hdd, p2, s2, prt->tmp_save_off + prt->begin, 1);
				}

				/* read unencrypted part */
				if (s3 != 0) {	
					res = dc_bios_io(prt->hdd, p3, s3, o3 + prt->begin, 1);
				}
			} else 
			{
				/* write encrypted part */
				if (s1 != 0) {
					res = dc_partition_enc_write(prt, p1, s1, o1);
				}

				/* write temporary part */
				if (s2 != 0) {
					res = dc_bios_io(prt->hdd, p2, s2, prt->tmp_save_off + prt->begin, 0);
				}

				/* write unencrypted part */
				if (s3 != 0) {				
					res = dc_bios_io(prt->hdd, p3, s3, o3 + prt->begin, 0);
				}
			}
		} else 
		{
			if (read != 0) {
				res = dc_partition_enc_read(prt, buff, sectors, start);
			} else {
				res = dc_partition_enc_write(prt, buff, sectors, start);
			}
		}		
	} else {
		res = dc_bios_io(
			    prt->hdd, buff, sectors, start + prt->begin, read
				);
	}

	return res;
}


int dc_disk_io(
	  hdd_inf *hdd, void *buff, 
	  u16      sectors, u64 start,
	  int      read
	  )
{
	list_entry *entry;
	prt_inf    *prt;
	u8          old[512];
	u16         ov_size;
	int         saved = 0;
	int         res   = 0;
	int         found = 0;

	entry = hdd->part_head.flink;

	while (entry != &hdd->part_head)
	{
		prt   = contain_record(entry, prt_inf, entry_hdd);
		entry = entry->flink;

		/* overlapped partition start IO  */
		if ( (start < prt->begin) && (start + sectors > prt->begin) ) 
		{
			ov_size = (u16)(prt->begin - start);
			
			res = dc_disk_io(hdd, buff, ov_size, start, read) && 
				  dc_disk_io(hdd, p8(buff) + ov_size * 512,  
				    sectors - ov_size, prt->begin, read);

			found = 1; break;
		} else 

		/* overlapped partition end IO  */
		if ( (start < prt->end) && (start + sectors > prt->end) ) 
		{
			ov_size = (u16)(prt->end - start);
						
			res = dc_disk_io(hdd, buff, ov_size, start, read) && 
				  dc_disk_io(hdd, p8(buff) + ov_size * 512,
				    sectors - ov_size, prt->end, read);

			found = 1; break;
		} else

		/* normal partition IO */
		if ( (start >= prt->begin) && (start + sectors < prt->end) )
		{
			res = dc_partition_io(
				prt, buff, sectors, start - prt->begin, read
				);
			found = 1; break;
		}  
	}

	if (found == 0) 
	{
		/* emulate write to MBR */
		if ( !(conf.options & OP_EXTERNAL) && (hdd->dos_numb == boot_dsk) &&
			  (start == 0) && (read == 0) ) 
		{
			/* save old buffer */
			fastcpy(old, buff, SECTOR_SIZE);
			/* read my MBR */
			dc_bios_io(hdd, buff, 1, 0, 1);
			/* copy partition table to MBR */
			fastcpy(p8(buff) + 432, old + 432, 80);
			saved = 1;
		}

		res = dc_bios_io(hdd, buff, sectors, start, read);

		if (saved != 0) {
			/* restore old buffer */
			fastcpy(buff, old, SECTOR_SIZE);
		}
	}

	return res;
}

int dc_scan_partitions()
{
	list_entry *entry;
	hdd_inf    *hdd;
	int         found = 0;

	/* initialize lists */
	_init_list_head(&hdd_head);
	_init_list_head(&prt_head);

	/* find all HDDs */
	if (dc_find_hdds() != 0)
	{
		/* find all partitions on HDD */
		entry = hdd_head.flink;

		while (entry != &hdd_head)
		{
			hdd   = contain_record(entry, hdd_inf, entry);
			entry = entry->flink;
			found += scan_hdd_off(hdd, 0, 0);
		}
	}

	return found;
}