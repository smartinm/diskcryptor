#ifndef _VOLUME_H_
#define _VOLUME_H_

#include "defines.h"

#define DC_TRUE_SIGN 0x45555254
#define DC_DTMP_SIGN 0x504D5444
#define IS_DC_SIGN(x) ( ((x) == DC_TRUE_SIGN) || ((x) == DC_DTMP_SIGN) )

// Header key derivation
#define PKCS5_SALT_SIZE			64

// Master key + secondary key (LRW mode)
#define DISKKEY_SIZE			256
#define LRW_TWEAK_SIZE          32
#define MAX_KEY_SIZE            (32*3)
#define PKCS_DERIVE_MAX         (max(LRW_TWEAK_SIZE+MAX_KEY_SIZE,MAX_KEY_SIZE*2))

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

#define DC_RESERVED_SIZE        (15 * SECTOR_SIZE)
#define DC_BACKUP_OFFSET(hook)  ((hook)->dsk_size - (SECTOR_SIZE * 2))

#define TC_VOL_REQ_PROG_VERSION			0x0500
#define TC_VOLUME_HEADER_VERSION		0x0003 

#define VF_NONE           0x00
#define VF_TMP_MODE       0x01 /* temporary encryption mode */
#define VF_SHRINK_PENDING 0x02 /* volume can be shrinked at next mount */
#define VF_REENCRYPT      0x04 /* volume re-encryption in progress */

#define ENC_BLOCK_SIZE  (1280 * 1024)

#pragma pack (push, 1)

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

#pragma pack (pop)


#endif