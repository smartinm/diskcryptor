#ifndef _DRVINST_
#define _DRVINST_

#include "dcapi.h"
#include "drv_ioctl.h"

#define HOT_MAX 4 /* maximun mumber of hotkeys */

typedef struct dc_conf_data {
	u32 build;
	u32 conf_flags;
	u32 load_flags;
	u32 hotkeys[HOT_MAX];

} dc_conf_data;

int dc_api dc_load_conf(dc_conf_data *conf);
int dc_api dc_save_conf(dc_conf_data *conf);
int dc_api dc_remove_driver();
int dc_api dc_install_driver();
int dc_api dc_driver_status();
int dc_api dc_update_driver();



#endif
