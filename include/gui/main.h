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

#define MAIN_TIMER   0
#define PROC_TIMER   1
#define RAND_TIMER   2
#define HIDE_TIMER   3
#define SHRN_TIMER   4

#define DA_INSTAL    1
#define DA_REMOVE    2
#define DA_UPDATE    3

#define ACT_STOPPED  1
#define ACT_PAUSED   2
#define ACT_RUNNING  3

#define ACT_ENCRYPT  1
#define ACT_DECRYPT  2

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

typedef struct __dnode {
	list_entry list;	
	BOOL is_root;
	BOOL exists;
	_droot root;
	_dmnt mnt;	

} _dnode;

typedef struct _shrink_thread_info {
	vol_inf *vol;
	int      rlt;
	sh_data *shd;

} shrink_thread_info;

void _refresh_menu( );
void _refresh(char main);

void _state_menu(
		HMENU menu,
		UINT state
	);

void _menu_decrypt(_dnode *node);
void _menu_encrypt(_dnode *node);

void _menu_unmount(_dnode *node);
void _menu_mount(_dnode *node);

void _menu_mountall( );
void _menu_unmountall( );

void _menu_change_pass(_dnode *node);
void _menu_clear_cache( );

void _menu_update_volume(_dnode *node);
void _menu_about( );

BOOL _is_active_item(LPARAM lparam);
BOOL _is_root_item(LPARAM lparam);

BOOL _is_enabled_item(LPARAM lparam);
BOOL _is_splited_item(LPARAM lparam);

BOOL _is_marked_item(LPARAM lparam);
BOOL _is_curr_in_group(HWND hwnd);

BOOL _is_simple_list(HWND hwnd);

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
