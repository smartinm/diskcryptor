/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2008-2009
    * ntldr <ntldr@diskcryptor.net> PGP key ID - 0xC48251EB4F8E4E6E
    *

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 3 as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <ntifs.h>
#include "defines.h"
#include "devhook.h"
#include "misc.h"
#include "fsf_control.h"
#include "dc_fsf\dc_fsf.h"

static SETDEVFLAGS  fsf_set_flags;
static SETCONFFLAGS fsf_set_conf;

static u32 dc_get_hook_flags(wchar_t *dev_name)
{
	dev_hook *hook;
	u32       flags = 0;

	if (hook = dc_find_hook(dev_name)) {
		flags = hook->flags;
		dc_deref_hook(hook);
	}

	return flags;
}

void dc_fsf_connect()
{
	IO_STATUS_BLOCK iosb;
	fsf_functl      ioctl;
	NTSTATUS        status;
	HANDLE          h_dev;

	h_dev = io_open_device(DC_FSF_DEVICE_NAME);

	if (h_dev != NULL)
	{
		ioctl.get_flags = dc_get_hook_flags;
		ioctl.set_flags = NULL;

		status = ZwDeviceIoControlFile(
			h_dev, NULL, NULL, NULL, &iosb, DC_FSF_FUNCTL, &ioctl, sizeof(ioctl), &ioctl, sizeof(ioctl));

		if (NT_SUCCESS(status) != FALSE) {
			fsf_set_flags = ioctl.set_flags;
			fsf_set_conf  = ioctl.set_conf;
		}
		ZwClose(h_dev);
	}
}

void dc_fsf_set_flags(wchar_t *dev_name, u32 flags)
{
	if (fsf_set_flags == NULL) {
		dc_fsf_connect();
	}

	if (fsf_set_flags != NULL) {
		fsf_set_flags(dev_name, flags);
	}
}

void dc_fsf_set_conf()
{
	if (fsf_set_conf != NULL) {
		fsf_set_conf(dc_conf_flags);
	}
}
