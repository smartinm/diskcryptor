#ifndef _MAIN_
#define _MAIN_

#include "..\sys\driver.h"
#include "drvinst.h"
#include "drv_ioctl.h"
#include "mbrinst.h"
#include "linklist.h"

extern list_entry __drives;
extern list_entry __volumes;
extern list_entry __action;

extern CRITICAL_SECTION crit_sect;
extern int _tmr_elapse[ ];

#define IDC_TIMER		 0x4100

#define MAIN_TIMER    0x0000
#define PROC_TIMER    0x0001
#define RAND_TIMER    0x0002
#define HIDE_TIMER    0x0003
#define SHRN_TIMER    0x0004
#define POST_TIMER    0x0005

#define DA_INSTAL     0x0001
#define DA_REMOVE     0x0002
#define DA_UPDATE     0x0003

#define ACT_STOPPED   0x0001
#define ACT_PAUSED    0x0002
#define ACT_RUNNING   0x0003

#define ACT_ENCRYPT   0x0001
#define ACT_DECRYPT   0x0002

#define ACT_REENCRYPT 0x0003
#define ACT_FORMAT    0x0004

typedef struct _timer_info {
	int id;
	int elapse;

} timer_info;

extern int __status;
extern dc_conf_data __config;

static wchar_t drv_msk[ ] = L"%s\\drivers\\%s.sys";

#define __execute(path) (ShellExecuteW(NULL, \
	L"open", path, NULL, NULL, SW_SHOWNORMAL))

typedef struct __dact {	
	list_entry list;	
	LARGE_INTEGER begin;
	HANDLE thread;
	int act;
	int status;
	int wp_mode;
	__int64 last_size;
	wchar_t device[MAX_PATH];

} _dact;

typedef struct __dmnt {	
	vol_inf info;
	wchar_t label[MAX_PATH];
	wchar_t fs[MAX_PATH];

} _dmnt;

typedef struct __droot {
	list_entry vols;
	u32 dsk_num;
	drive_inf info;
	wchar_t dsk_name[MAX_PATH];

} _droot;

typedef struct __dlg {
	BOOL q_format;
	wchar_t *fs_name;
	int act_type;
	int rlt;

} _dlg;

typedef struct __dnode {
	list_entry list;	
	BOOL is_root;
	BOOL exists;
	_droot root;
	_dmnt mnt;
	_dlg dlg;

} _dnode;

typedef struct _shrink_thread_info {
	vol_inf *vol;
	int      rlt;
	sh_data *shd;

} shrink_thread_info;

typedef struct _bench_item {
	wchar_t *alg;
	wchar_t *mode;
	double   speed;

} bench_item;

void _refresh_menu( );
void _refresh(char main);

void _state_menu(
		HMENU menu,
		UINT state
	);

void _menu_decrypt(_dnode *node);
void _menu_encrypt(_dnode *node);

void _menu_format(_dnode *node);
void _menu_reencrypt(_dnode *node);

void _menu_unmount(_dnode *node);
void _menu_mount(_dnode *node);

void _menu_mountall( );
void _menu_unmountall( );

void _menu_change_pass(_dnode *node);
void _menu_clear_cache( );

void _menu_update_volume(_dnode *node);
void _menu_about( );

void _menu_backup_header(_dnode *node);
void _menu_restore_header(_dnode *node);

void _menu_wizard(_dnode *node);

BOOL _is_active_item(LPARAM lparam);
BOOL _is_root_item(LPARAM lparam);

BOOL _is_enabled_item(LPARAM lparam);
BOOL _is_splited_item(LPARAM lparam);

BOOL _is_marked_item(LPARAM lparam);
BOOL _is_curr_in_group(HWND hwnd);

BOOL _is_simple_list(HWND hwnd);
BOOL _is_warning_item(LPARAM lparam);

int _benchmark(
		bench_item *bench,
		int mode		
	);

int _list_volumes(
		list_entry *volumes
	);

void _load_diskdrives(
		HWND hwnd,
		list_entry *volumes,
		char vcount
	);

void _list_devices(
		HWND hlist,
		BOOL fixed,
		int sel
	);

BOOL _list_part_by_disk_id(
		HWND hwnd,
		int disk_id
	);

int _set_boot_loader(
		HWND hwnd,
		int dsk_num
	);

BOOL _is_boot_device(vol_inf *vol);
BOOL _is_removable_media(int dsk_num);

char *_get_pass(
		HWND hwnd,
		int edit_pass
	);

void _wipe_pass_control(
		HWND hwnd,
		int edit_pass
	);

_dact *_create_act_thread(
		_dnode *node,
		int act_type, /*-1 - search*/
		int act_status
	);

void _set_timer(
		int index,
		BOOL set,
		BOOL refresh
	);

int _menu_set_loader_vol(
		HWND hwnd,
		wchar_t *vol,
		int dsk_num,
		int type
	);

int _menu_unset_loader_mbr(
		HWND hwnd,
		wchar_t *vol,
		int dsk_num,
		int type
	);

int _menu_update_loader(
		HWND hwnd,
		wchar_t *vol,
		int dsk_num
	);

int _menu_set_loader_file(
		HWND hwnd,
		wchar_t *path,
		BOOL iso
	);

int _drv_action(
		int action, 
		int version
	);

void _check_driver(
		HWND hwnd,
		size_t buff_size,
		char set
	);

void _get_driver_path(
		wchar_t *name, 
		wchar_t *path
	);


#endif
