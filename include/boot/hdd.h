#ifndef _HDD_
#define _HDD_

#ifdef BOOT_LDR
 #include "crypto.h"
 #include "linklist.h"
#endif

#pragma pack (push, 1)

typedef struct _lba_p
{
	u8  size;
	u8  unk;
	u16 numb;
	u16 dst_off;
	u16 dst_sel;
	u64 sector;

} lba_p;

#ifdef BOOT_LDR

typedef struct _hdd_inf
{
	list_entry entry;
	list_entry part_head;
	u8         dos_numb;
	u8         lba_mode;
	u8         max_head;
	u8         max_sect;

} hdd_inf;

typedef struct _prt_inf {
	list_entry entry_hdd;
	list_entry entry_glb;
	hdd_inf   *hdd;
	aes_key   *d_key;
	u8         active;
	u8         extend;
	u64        begin;
	u64        end;
	u64        size;
	u8         flags;
	u64        tmp_size;
	u64        tmp_save_off;
	u32        disk_id;

} prt_inf;

#endif

typedef struct _pt_ent {
	u8  active;
	u8  start_head;
	u16 start_cyl;
	u8  os;
	u8  end_head;
	u16 end_cyl;
	u32 start_sect;
	u32 prt_size;

} pt_ent;

#pragma pack (pop)

#ifdef BOOT_LDR

int dc_bios_io(
	  hdd_inf *hdd, void *buff, 
	  u16      sectors, u64 start,
	  int      read
	  );

int dc_partition_io(
	  prt_inf *prt, void *buff, 
	  u16 sectors, u64 start, int read
	  );

int dc_disk_io(
	  hdd_inf *hdd, void *buff, 
	  u16      sectors, u64 start,
	  int      read
	  );

hdd_inf *find_hdd(u8 num);
int      dc_scan_partitions();

#ifdef BOOT_LDR
 extern list_entry hdd_head;
 extern list_entry prt_head;
#endif

#endif

#endif