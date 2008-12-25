#ifndef _BOOT_
#define _BOOT_

#include "defines.h"
#include "version.h"
#include "volume.h"
#include "bios.h"

#define MAX_MOUNT 8

#define LT_GET_PASS  1 /* entering password needed       */
#define LT_EMBED_KEY 2 /* use embedded key               */
#define LT_MESSAGE   4 /* display enter password message */
#define LT_DSP_PASS  8 /* display '*'                    */

#define ET_MESSAGE      1  /* display error message      */
#define ET_REBOOT       2  /* reboot after 1 second      */
#define ET_BOOT_ACTIVE  4  /* boot from active partition */
#define ET_EXIT_TO_BIOS 8  /* exit to bios               */
#define ET_RETRY        16 /* retry authentication again */

#define BT_MBR_BOOT     1 /* load boot disk MBR                                  */
#define BT_MBR_FIRST    2 /* load first disk MBR                                 */
#define BT_ACTIVE       3 /* boot from active partition on boot disk             */
#define BT_AP_PASSWORD  4 /* boot from first partition with appropriate password */
#define BT_DISK_ID      5 /* find partition by disk_id                           */

#define KB_QWERTY       0 /* QWERTY keyboard layout */
#define KB_QWERTZ       1 /* QWERTZ keyboard layout */
#define KB_AZERTY       2 /* AZERTY keyboard layout */

#define OP_EXTERNAL     1 /* this option indicate external bootloader usage       */
#define OP_EPS_TMO      2 /* set time limit for password entering                 */
#define OP_TMO_STOP     4 /* cancel timeout if any key pressed                    */
#define OP_NOPASS_ERROR 8 /* use incorrect password action if no password entered */

#pragma pack (push, 1)

#define CFG_SIGN1 0x1434A669
#define CFG_SIGN2 0x7269DA46

typedef struct _ldr_config {
	u32     sign1;
	u32     sign2;
	u32     ldr_ver;
	u8      logon_type;
	u8      error_type;
	u8      boot_type;
	u32     disk_id;
	u16     options;
	u8      kbd_layout;
	char    eps_msg[128];
	char    err_msg[128];
	u8      save_mbr[512];
	u32     timeout; /* time limit for password entering */
	u8      emb_key[64];

} ldr_config;

#pragma pack (pop)

#ifdef BOOT_LDR
 extern u8         boot_dsk;
 extern ldr_config conf;
 
 int  on_int13(rm_ctx *ctx);
 void boot_main();
#endif

#endif