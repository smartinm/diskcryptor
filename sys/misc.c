/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2007-2008 
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
#include <ntdddisk.h>
#include <ntddcdrm.h>
#include <stdio.h>
#include <stdarg.h>
#include "defines.h"
#include "driver.h"
#include "misc.h"
#include "devhook.h"
#include "debug.h"
#include "misc_mem.h"
#include "disk_info.h"

void wait_object_infinity(void *wait_obj)
{
	KeWaitForSingleObject(wait_obj, Executive, KernelMode, FALSE, NULL);
}

int start_system_thread(PKSTART_ROUTINE thread_start, void *param, HANDLE *handle)
{
	OBJECT_ATTRIBUTES obj_a;
	HANDLE            h_thread;
	NTSTATUS          status;

	InitializeObjectAttributes(&obj_a, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

	status = PsCreateSystemThread(
		&h_thread, THREAD_ALL_ACCESS, &obj_a, NULL, NULL, thread_start, param);

	if (NT_SUCCESS(status) == FALSE) {
		return ST_ERR_THREAD;
	}
	if (handle == NULL) {
		ZwClose(h_thread);
	} else {
		*handle = h_thread;		
	}
	return ST_OK;
}


int dc_set_default_security(HANDLE h_object)
{
	SID_IDENTIFIER_AUTHORITY autort = SECURITY_NT_AUTHORITY;
	PSID                     adm_sid;
	PSID                     sys_sid;
	PACL                     sys_acl;
	ULONG                    dacl_sz;
	NTSTATUS                 status;
	SECURITY_DESCRIPTOR      sc_desc;
	int                      resl;

	adm_sid = NULL; sys_sid = NULL; 
	sys_acl = NULL;
	do
	{
		adm_sid = mm_alloc(RtlLengthRequiredSid(2), 0);
		sys_sid = mm_alloc(RtlLengthRequiredSid(1), 0);

		if ( (adm_sid == NULL) || (sys_sid == NULL) ) {
			resl = ST_NOMEM; break;
		}

		RtlInitializeSid(adm_sid, &autort, 2); 
		RtlInitializeSid(sys_sid, &autort, 1);

		RtlSubAuthoritySid(adm_sid, 0)[0] = SECURITY_BUILTIN_DOMAIN_RID;
		RtlSubAuthoritySid(adm_sid, 1)[0] = DOMAIN_ALIAS_RID_ADMINS;
		RtlSubAuthoritySid(sys_sid, 0)[0] = SECURITY_LOCAL_SYSTEM_RID;

		dacl_sz = sizeof(ACL) + (2 * sizeof(ACCESS_ALLOWED_ACE)) +
			SeLengthSid(adm_sid) + SeLengthSid(sys_sid) + 8;
		
		if ( (sys_acl = mm_alloc(dacl_sz, 0)) == NULL) {
			resl = ST_NOMEM; break;
		}
		status = RtlCreateAcl(sys_acl, dacl_sz, ACL_REVISION);

		if (NT_SUCCESS(status) == FALSE) {
			resl = ST_ERROR; break;
		}
		status = RtlAddAccessAllowedAce(
			sys_acl, ACL_REVISION, GENERIC_ALL, sys_sid);

		if (NT_SUCCESS(status) == FALSE) {
			resl = ST_ERROR; break;
		}
		status = RtlAddAccessAllowedAce(
			sys_acl, ACL_REVISION, GENERIC_ALL, adm_sid);

		if (NT_SUCCESS(status) == FALSE) {
			resl = ST_ERROR; break;
		}
		status = RtlCreateSecurityDescriptor(&sc_desc, SECURITY_DESCRIPTOR_REVISION1);

		if (NT_SUCCESS(status) == FALSE) {
			resl = ST_ERROR; break;
		}
		status = RtlSetDaclSecurityDescriptor(&sc_desc, TRUE, sys_acl, FALSE);

		if (NT_SUCCESS(status) == FALSE) {
			resl = ST_ERROR; break;
		}

		status = ZwSetSecurityObject(h_object, DACL_SECURITY_INFORMATION, &sc_desc);

		if (NT_SUCCESS(status) != FALSE) {
			resl = ST_OK;
		} else {
			resl = ST_ERROR;
		}
	} while (0);

	if (sys_acl != NULL) { mm_free(sys_acl); }
	if (adm_sid != NULL) { mm_free(adm_sid); }
	if (sys_sid != NULL) { mm_free(sys_sid); }

	return resl;
}

int dc_resolve_link(wchar_t *sym_link, wchar_t *target, u16 length)
{
	UNICODE_STRING    u_name;
	OBJECT_ATTRIBUTES obj;
	NTSTATUS          status;
	HANDLE            handle;
	int               resl;

	RtlInitUnicodeString(&u_name, sym_link);

	InitializeObjectAttributes(
		&obj, &u_name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	do
	{
		status = ZwOpenSymbolicLinkObject(&handle, GENERIC_READ, &obj);

		if (NT_SUCCESS(status) == FALSE) {
			handle = NULL; resl = ST_ERROR; break;
		}
		u_name.Buffer        = target;
		u_name.Length        = 0;
		u_name.MaximumLength = length - 2;

		status = ZwQuerySymbolicLinkObject(handle, &u_name, NULL);

		if (NT_SUCCESS(status) == FALSE) {
			resl = ST_ERROR; break;
		} else {
			resl = ST_OK;
		}
		target[u_name.Length >> 1] = 0;
	} while (0);

	if (handle != NULL) {
		ZwClose(handle);
	}
	return resl;
}

int dc_get_mount_point(dev_hook *hook, wchar_t *buffer, u16 length)
{
	NTSTATUS       status;
	UNICODE_STRING name;
	int            resl;

	status = RtlVolumeDeviceToDosName(hook->orig_dev, &name);

	buffer[0] = 0; resl = ST_ERROR;

	if (NT_SUCCESS(status) != FALSE) 
	{
		if (name.Length < length) {
			mincpy(buffer, name.Buffer, name.Length);
			buffer[name.Length >> 1] = 0; 
			resl = ST_OK;
		} 
		ExFreePool(name.Buffer);
	}
	return resl;
}

void dc_query_object_name(void *object, wchar_t *buffer, u16 length)
{
	u8                       buf[256];
	POBJECT_NAME_INFORMATION inf = pv(buf);
	u32                      bytes;
	NTSTATUS                 status;

	status = ObQueryNameString(object, inf, sizeof(buf), &bytes);

	if (NT_SUCCESS(status) != FALSE) {
		bytes = min(length, inf->Name.Length);
		mincpy(buffer, inf->Name.Buffer, bytes);
		buffer[bytes >> 1] = 0;
	} else {
		buffer[0] = 0;
	}
}

u64 intersect(u64 *i_st, u64 start1, u64 size1, u64 start2, u64 size2)
{
	u64 end, i;	
	end = min(start1 + size1, start2 + size2);
	*i_st = i = max(start1, start2);
	return (i < end) ? end - i : 0;
}

void dc_delay(u32 msecs)
{
	LARGE_INTEGER time;

	time.QuadPart = d64(msecs) * -10000;	
	KeDelayExecutionThread(KernelMode, FALSE, &time);
}
