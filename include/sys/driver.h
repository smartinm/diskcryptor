#ifndef _DRIVER_
#define _DRIVER_

#include "defines.h"
#include "version.h"

#ifdef KMDF_MAJOR_VERSION
 #include <ntdddisk.h>
 #include <ntddstor.h>
 #include <ntddvol.h>
 #include "crypto.h"
 #include "speed_test.h"
#endif

#ifndef _WCHAR_T_DEFINED 
 typedef short wchar_t;
#endif

#define DC_GET_VERSION       CTL_CODE(FILE_DEVICE_UNKNOWN, 0,  METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DC_CTL_ADD_PASS      CTL_CODE(FILE_DEVICE_UNKNOWN, 1,  METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DC_CTL_CLEAR_PASS    CTL_CODE(FILE_DEVICE_UNKNOWN, 2,  METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DC_CTL_MOUNT         CTL_CODE(FILE_DEVICE_UNKNOWN, 3,  METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DC_CTL_MOUNT_ALL     CTL_CODE(FILE_DEVICE_UNKNOWN, 4,  METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DC_CTL_UNMOUNT       CTL_CODE(FILE_DEVICE_UNKNOWN, 5,  METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DC_CTL_UNMOUNT_ALL   CTL_CODE(FILE_DEVICE_UNKNOWN, 6,  METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DC_CTL_STATUS        CTL_CODE(FILE_DEVICE_UNKNOWN, 7,  METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DC_CTL_ADD_SEED      CTL_CODE(FILE_DEVICE_UNKNOWN, 8,  METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DC_CTL_CHANGE_PASS   CTL_CODE(FILE_DEVICE_UNKNOWN, 9,  METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DC_CTL_ENCRYPT_START CTL_CODE(FILE_DEVICE_UNKNOWN, 10, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DC_CTL_DECRYPT_START CTL_CODE(FILE_DEVICE_UNKNOWN, 11, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DC_CTL_ENCRYPT_STEP  CTL_CODE(FILE_DEVICE_UNKNOWN, 12, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DC_CTL_DECRYPT_STEP  CTL_CODE(FILE_DEVICE_UNKNOWN, 13, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DC_CTL_SYNC_STATE    CTL_CODE(FILE_DEVICE_UNKNOWN, 14, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DC_CTL_RESOLVE       CTL_CODE(FILE_DEVICE_UNKNOWN, 15, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DC_CTL_UPDATE_VOLUME CTL_CODE(FILE_DEVICE_UNKNOWN, 16, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DC_CTL_SET_SHRINK    CTL_CODE(FILE_DEVICE_UNKNOWN, 17, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DC_CTL_GET_RAND      CTL_CODE(FILE_DEVICE_UNKNOWN, 18, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DC_CTL_SPEED_TEST    CTL_CODE(FILE_DEVICE_UNKNOWN, 19, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DC_CTL_BSOD          CTL_CODE(FILE_DEVICE_UNKNOWN, 20, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DC_CTL_GET_CONF      CTL_CODE(FILE_DEVICE_UNKNOWN, 21, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DC_CTL_SET_CONF      CTL_CODE(FILE_DEVICE_UNKNOWN, 22, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DC_CTL_LOCK_MEM      CTL_CODE(FILE_DEVICE_UNKNOWN, 23, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DC_CTL_UNLOCK_MEM    CTL_CODE(FILE_DEVICE_UNKNOWN, 24, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define FSCTL_LOCK_VOLUME               CTL_CODE(FILE_DEVICE_FILE_SYSTEM,  6, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_UNLOCK_VOLUME             CTL_CODE(FILE_DEVICE_FILE_SYSTEM,  7, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_DISMOUNT_VOLUME           CTL_CODE(FILE_DEVICE_FILE_SYSTEM,  8, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define DC_TRUE_SIGN 0x45555254
#define DC_DTMP_SIGN 0x504D5444

// Header key derivation
#define PKCS5_SALT_SIZE			64

// Master key + secondary key (LRW mode)
#define DISKKEY_SIZE			256
#define DISK_IV_SIZE			32

// Volume header byte offsets
#define	HEADER_USERKEY_SALT		0
#define HEADER_ENCRYPTEDDATA	PKCS5_SALT_SIZE
#define	HEADER_DISKKEY			256

// Volume header sizes
#define HEADER_SIZE					512
#define HEADER_ENCRYPTEDDATASIZE	(HEADER_SIZE - HEADER_ENCRYPTEDDATA)

#define SECTOR_SIZE                 512
#define HIDDEN_VOL_HEADER_OFFSET	(HEADER_SIZE + SECTOR_SIZE * 2)	

#define MIN_PASSWORD			1		// Minimum password length
#define MAX_PASSWORD			64		// Maximum password length

#define MAX_DEVICE              64 // maximum device name length

#define MAX_KEY_SIZE            120
#define DC_RESERVED_SIZE        (15 * SECTOR_SIZE)
#define DC_BACKUP_OFFSET(hook)  ((hook)->dsk_size - (SECTOR_SIZE * 2))

#define TC_VOL_REQ_PROG_VERSION			0x0500
#define TC_VOLUME_HEADER_VERSION		0x0003 

#define DC_DEVICE_NAME L"\\Device\\TcWde"
#define DC_LINK_NAME   L"\\DosDevices\\TcWde"
#define DC_WIN32_NAME  L"\\\\.\\TcWde"

#pragma pack (push, 1)

typedef struct _dc_ioctl {
	u8  passw1[MAX_PASSWORD + 1]; /* password                         */
	u8  passw2[MAX_PASSWORD + 1]; /* new password (for changing pass) */
	u16 device[MAX_DEVICE + 1];
	int force;   /* dismount flags                  */
	int status;  /* operation status code           */
	int wp_mode; /* data wipe mode (for encryption) */
	int n_mount; /* number of mounted devices       */
	u16 shrink_off;
	u32 shrink_val;

} dc_ioctl;

typedef struct _dc_lock_ctl {
	void *data;
	u32   size;
	int   resl;

} dc_lock_ctl;

/* hook control flags */
#define F_NONE           0x00
#define F_ENABLED        0x01 /* device mounted                   */
#define F_SYNC           0x02 /* syncronous IRP processing mode   */
#define F_SYSTEM         0x04 /* this is a system device          */
#define F_REMOVABLE      0x08 /* this is removable device         */
#define F_HIBERNATE      0x10 /* this device used for hibernation */
#define F_UNSUPRT        0x20 /* device unsupported */
#define F_DISABLE        0x40 /* device temporary disabled */
#define F_SHRINK_PENDING 0x80

/* unmount flags */
#define UM_FORCE    0x01 /* unmount volume if FSCTL_LOCK_VOLUME fail */
#define UM_NOFSCTL  0x02 /* no send FSCTL_DISMOUNT_VOLUME            */
#define UM_NOSYNC   0x04 /* no stop syncronous mode thread */

#define TEST_BLOCK_LEN 1024*1024 /* speed test block size */
#define TEST_BLOCK_NUM 10        /* number of test blocks */

/* operation status codes */
#define ST_OK             0  /* operation completed successfull */
#define ST_ERROR          1  /* unknown error    */
#define ST_NF_DEVICE      2  /* device not found */
#define ST_RW_ERR         3  /* read/write error */
#define ST_PASS_ERR       4  /* invalid password */
#define ST_ALR_MOUNT      5  /* device has already mounted */
#define ST_NO_MOUNT       6  /* device not mounted */
#define ST_LOCK_ERR       7  /* error on volume locking  */
#define ST_UNMOUNTABLE    8  /* device is unmountable */
#define ST_NOMEM          9  /* not enought memory */
#define ST_ERR_THREAD     10 /* error on creating system thread */
#define ST_INV_WIPE_MODE  11 /* invalid data wipe mode */
#define ST_INV_DATA_SIZE  12 /* invalid data size */
#define ST_ACCESS_DENIED  13 /* access denied */
#define ST_NF_FILE        14 /* file not found */
#define ST_IO_ERROR       15 /* disk I/O error */
#define ST_UNK_FS         16 /* unsupported file system */
#define ST_ERR_BOOT       17 /* invalid FS bootsector, please format partition */      
#define ST_MBR_ERR        18 /* MBR is corrupted */
#define ST_BLDR_INSTALLED 19 /* bootloader is already installed */
#define ST_NF_SPACE       20 /* not enough space after partitions to install bootloader */
#define ST_BLDR_NOTINST   21 /* bootloader is not installed */
#define ST_INV_BLDR_SIZE  22 /* invalid bootloader size */
#define ST_BLDR_NO_CONF   23 /* bootloader corrupted, config not found */
#define ST_BLDR_OLD_VER   24 /* old bootloader can not be configured */
#define ST_AUTORUNNED     25 /* */
#define ST_NEED_EXIT      26 /* */
#define ST_NO_ADMIN       27 /* user not have admin privilegies */
#define ST_NF_BOOT_DEV    28 /* boot device not found */
#define ST_REG_ERROR      29 /* can not open registry key */
#define ST_NF_REG_KEY     30 /* registry key not found */
#define ST_SCM_ERROR      31 /* can not open SCM database */
#define ST_FINISHED       32 /* encryption finished */
#define ST_INSTALLED      32 /* driver already installed */
#define ST_INV_SECT       34 /* device has unsupported sector size */
#define ST_CLUS_USED      35 /* shrinking error, last clusters are used */
#define ST_NF_PT_SPACE    36 /* not enough free space in partition to continue encrypting */
#define ST_MEDIA_CHANGED  37 /* removable media changed */
#define ST_NO_MEDIA       38 /* no removable media in device */
#define ST_DEVICE_BUSY    39 /* device is busy */
#define ST_INV_MEDIA_TYPE 40 /* media type not supported */
#define ST_FORMAT_NEEDED  41 /* */
#define ST_CANCEL         42 /* */
#define ST_INV_VOL_VER    43 /* invalid volume version */

/* data wipe modes */
#define WP_NONE    0 /* no data wipe                           */
#define WP_DOD_E   1 /* US DoD 5220.22-M (8-306. / E)          */
#define WP_DOD     2 /* US DoD 5220.22-M (8-306. / E, C and E) */
#define WP_GUTMANN 3 /* Gutmann   */

/* registry config flags */
#define CONF_FORCE_DISMOUNT   0x01
#define CONF_CACHE_PASSWORD   0x02
#define CONF_EXPLORER_MOUNT   0x04
#define CONF_WIPEPAS_LOGOFF   0x08
#define CONF_DISMOUNT_LOGOFF  0x10
#define CONF_AUTO_START       0x20
#define CONF_QUEUE_IO         0x40

typedef struct _dc_status {
	u64     dsk_size;
	u64     tmp_size;
	u32     flags;
	u32     disk_id;
	s32     paging_count;	
	int     wp_mode;
	u16     vf_version;   /* volume format version */
	wchar_t mnt_point[MAX_PATH];

} dc_status;

typedef struct _dc_conf {
	u32 conf_flags;
	u32 load_flags;

} dc_conf;

#define IS_UNMOUNTABLE(d) ( !((d)->flags & (F_SYSTEM | F_HIBERNATE)) && \
                             ((d)->paging_count == 0) )


typedef struct _dc_header {
	u8  salt[64];
	u32 sign;
	u16 version;
	u16 req_ver;
	u32 key_crc;
	u8  reserved1[16];
	u64 hidden_size;  /* hidden volume size */
	u64 vol_size;     /* volume size */
	u64 enc_start;    /* encrypted area start (for TC compatible, not used) */
	u64 enc_size;     /* encrypted area size (for TC compatible, not used)  */

	u32 disk_id;      
	u8  flags;        /* volume flags */
	u8  tmp_wp_mode;  /* data wipe mode */
	u64 tmp_size;     /* size of encrypted area */
	u64 tmp_save_off; /* temporary buffer saving offset */
	u16 shrink_off;   /* offset in FS header    */
	u32 shrink_val;   /* new value in FS header */

	u8  reserved2[104];
	u8  key_data[256];

} dc_header;

#define VF_NONE           0x00
#define VF_TMP_MODE       0x01 /* temporary encryption mode */
#define VF_SHRINK_PENDING 0x02 /* volume can be shrinked at next mount */

#pragma pack (pop)

#define OS_UNK   0
#define OS_WIN2K 1
#define OS_VISTA 2

#ifdef KMDF_MAJOR_VERSION
 extern PDEVICE_OBJECT dc_device;
 extern PDRIVER_OBJECT dc_driver;
 extern u32            dc_os_type; 
 extern u32            dc_data_lock;
 extern u32            dc_io_count;
 extern u32            dc_conf_flags;
 extern u32            dc_load_flags;  
#endif


#endif