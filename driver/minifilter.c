/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2010
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
#include <fltKernel.h>
#include <ntstrsafe.h>
#include "defines.h"
#include "minifilter.h"
#include "debug.h"
#include "devhook.h"
#include "misc_volume.h"

typedef struct _mf_context {
	dev_hook *hook;
	u64       dcsys_id;
} mf_context;

static NTSTATUS mf_instance_setup(
  PCFLT_RELATED_OBJECTS objects, FLT_INSTANCE_SETUP_FLAGS flags, DEVICE_TYPE dev_type, FLT_FILESYSTEM_TYPE fs_type)
{
	wchar_t        buff[128];
	UNICODE_STRING name = { 0, 127, buff };
	dev_hook      *hook;
	NTSTATUS       status;
	mf_context    *mf_ctx;

	if (dev_type != FILE_DEVICE_DISK_FILE_SYSTEM) {
		return STATUS_FLT_DO_NOT_ATTACH;
	}
	if (NT_SUCCESS(FltGetVolumeName(objects->Volume, &name, NULL)) == FALSE) {
		return STATUS_FLT_DO_NOT_ATTACH;
	} else {
		name.Buffer[name.Length / sizeof(wchar_t)] = 0;
	}
	if ( (hook = dc_find_hook(name.Buffer)) == NULL ) {
		return STATUS_FLT_DO_NOT_ATTACH;
	}
	status = FltAllocateContext(
		objects->Filter, FLT_INSTANCE_CONTEXT, sizeof(mf_context), NonPagedPool, &mf_ctx);

	if (NT_SUCCESS(status) == FALSE) {
		dc_deref_hook(hook); return STATUS_FLT_DO_NOT_ATTACH;
	} else {
		mf_ctx->hook = hook; mf_ctx->dcsys_id = 0;
	}
	status = FltSetInstanceContext(
		objects->Instance, FLT_SET_CONTEXT_KEEP_IF_EXISTS, mf_ctx, NULL);

	FltReleaseContext(mf_ctx);

	if (NT_SUCCESS(status) == FALSE) {
		dc_deref_hook(hook); return STATUS_FLT_DO_NOT_ATTACH;
	}
	return STATUS_SUCCESS;
}

static void mf_teardown_complete(
  PCFLT_RELATED_OBJECTS objects, FLT_INSTANCE_TEARDOWN_FLAGS reason)
{
	mf_context *mf_ctx;

	if ( (NT_SUCCESS(FltGetInstanceContext(objects->Instance, &mf_ctx)) == FALSE) ||
		 (mf_ctx == NULL) )
	{
		return;
	}
	dc_deref_hook(mf_ctx->hook);
		
	FltDeleteContext(mf_ctx);
	FltReleaseContext(mf_ctx);
}

static int is_dcsys(wchar_t *buff, u32 length)
{
	return (length >= 14) && ((length == 14) || (buff[7] == L':')) &&
		   (_wcsnicmp(buff, L"$dcsys$", 7) == 0);
}

static u64 mf_query_dcsys_id(dev_hook *hook, PCFLT_RELATED_OBJECTS objects)
{
	wchar_t                   buff[MAX_PATH];
	FILE_INTERNAL_INFORMATION info;
	OBJECT_ATTRIBUTES         obj_a;
	UNICODE_STRING            name;
	IO_STATUS_BLOCK           iosb;
	HANDLE                    h_file = NULL;
	PFILE_OBJECT              p_file = NULL;
	NTSTATUS                  status;

	status = RtlStringCchPrintfW(buff, MAX_PATH, L"%s\\$dcsys$", hook->dev_name);
	if (NT_SUCCESS(status) == FALSE) return 0;

	RtlInitUnicodeString(&name, buff);
	InitializeObjectAttributes(&obj_a, &name, OBJ_KERNEL_HANDLE, NULL, NULL);

	status = FltCreateFile(objects->Filter, objects->Instance, &h_file, GENERIC_READ, 
		&obj_a, &iosb, NULL, 0, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0, 0);

	if (NT_SUCCESS(status) == FALSE) {
		h_file = NULL; goto exit;
	}
	status = ObReferenceObjectByHandle(h_file, 0, NULL, KernelMode, &p_file, NULL);

	if (NT_SUCCESS(status) == FALSE) {
		p_file = NULL; goto exit;
	}
	status = FltQueryInformationFile(
		objects->Instance, p_file, &info, sizeof(info), FileInternalInformation, NULL);
exit:
	if (p_file != NULL) ObDereferenceObject(p_file);
	if (h_file != NULL) FltClose(h_file);

	return NT_SUCCESS(status) != FALSE ? info.IndexNumber.QuadPart : 0;
}

static FLT_PREOP_CALLBACK_STATUS mf_irp_mj_create(
  PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS objects, PVOID *post_ctx)
{
	mf_context *mf_ctx;
	wchar_t    *p_buff = objects->FileObject->FileName.Buffer;
	u16         length = objects->FileObject->FileName.Length;
	int         denied = 0;

	if ( (NT_SUCCESS(FltGetInstanceContext(objects->Instance, &mf_ctx)) == FALSE) ||
		 (mf_ctx == NULL) )
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	if (mf_ctx->hook->flags & F_PROTECT_DCSYS)
	{
		if (data->Iopb->Parameters.Create.Options & FILE_OPEN_BY_FILE_ID)
		{
			if ( (mf_ctx->dcsys_id == 0) && (KeGetCurrentIrql() == PASSIVE_LEVEL) ) {
				mf_ctx->dcsys_id = mf_query_dcsys_id(mf_ctx->hook, objects);
			}
			denied = (mf_ctx->dcsys_id != 0) && 
				     (length == 8) && (p64(p_buff)[0] == mf_ctx->dcsys_id);
		} else
		{
			while (length != 0 && p_buff[0] == L'\\') {
				p_buff++, length -= sizeof(wchar_t);
			}
			denied = is_dcsys(p_buff, length);
		}
	}
	FltReleaseContext(mf_ctx);

	if (denied != 0) 
	{
		data->IoStatus.Status      = STATUS_ACCESS_DENIED; 
		data->IoStatus.Information = 0;

		return FLT_PREOP_COMPLETE;
	}
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static FLT_PREOP_CALLBACK_STATUS mf_directory_control(
  PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS objects, PVOID *post_ctx)
{
	FILE_INFORMATION_CLASS i_class;
	int                    is_root;
	mf_context            *mf_ctx;
	int                    postop;

	if ( (dc_conf_flags & CONF_HIDE_DCSYS) == 0 || data->Iopb->MinorFunction != IRP_MN_QUERY_DIRECTORY ) {
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	i_class = data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass;

	if (i_class != FileBothDirectoryInformation && i_class != FileDirectoryInformation &&
		i_class != FileFullDirectoryInformation && i_class != FileIdBothDirectoryInformation &&
		i_class != FileIdFullDirectoryInformation && i_class != FileNamesInformation)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	__try
	{
		is_root = objects->FileObject->FileName.Length == sizeof(wchar_t) &&
			      objects->FileObject->FileName.Buffer && objects->FileObject->FileName.Buffer[0] == L'\\';
	}
	__except(EXCEPTION_EXECUTE_HANDLER) {
		is_root = 0;
	}
	if (is_root == 0) {
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	if ( (NT_SUCCESS(FltGetInstanceContext(objects->Instance, &mf_ctx)) != FALSE) &&
		 (mf_ctx != NULL) )
	{
		postop = (mf_ctx->hook->flags & F_PROTECT_DCSYS) != 0;
		FltReleaseContext(mf_ctx);
	} else {
		postop = 0;
	}
	return postop != 0 ? FLT_PREOP_SYNCHRONIZE : FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static int is_dcsys_di(void *di, FILE_INFORMATION_CLASS i_class)
{
	wchar_t *f_name;
	u32      length;

	switch (i_class) 
	{
		case FileBothDirectoryInformation: 
			{
				FILE_BOTH_DIR_INFORMATION *inf = di;
				f_name = inf->FileName; 
				length = inf->FileNameLength;
			}
		break;
		case FileDirectoryInformation:
			{
				FILE_DIRECTORY_INFORMATION *inf = di;
				f_name = inf->FileName; 
				length = inf->FileNameLength;
			}
		break;
		case FileFullDirectoryInformation:
			{
				FILE_FULL_DIR_INFORMATION *inf = di;
				f_name = inf->FileName; 
				length = inf->FileNameLength;
			}
		break;
		case FileIdBothDirectoryInformation:
			{
				FILE_ID_BOTH_DIR_INFORMATION *inf = di;
				f_name = inf->FileName; 
				length = inf->FileNameLength;
			}
		break;
		case FileIdFullDirectoryInformation:
			{
				FILE_ID_FULL_DIR_INFORMATION *inf = di;
				f_name = inf->FileName; 
				length = inf->FileNameLength;
			}
		break;
		case FileNamesInformation:
			{
				FILE_NAMES_INFORMATION *inf = di;
				f_name = inf->FileName; 
				length = inf->FileNameLength;
			}
		break;
	}
	return is_dcsys(f_name, length);
}


static FLT_POSTOP_CALLBACK_STATUS mf_post_directory_control(
  PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS objects, void *context, FLT_POST_OPERATION_FLAGS flags)
{
	FILE_INFORMATION_CLASS     i_class = data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass;
	FILE_BOTH_DIR_INFORMATION *cur_dir = data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;
	FILE_BOTH_DIR_INFORMATION *lst_dir = NULL;
	u32                        length  = data->Iopb->Parameters.DirectoryControl.QueryDirectory.Length;

	if (NT_SUCCESS(data->IoStatus.Status) == FALSE) {
		return FLT_POSTOP_FINISHED_PROCESSING;
	}
	__try
	{
		if (data->Iopb->OperationFlags & SL_RETURN_SINGLE_ENTRY)
		{
			if (is_dcsys_di(cur_dir, i_class) != 0)
			{
				if (data->Iopb->OperationFlags & SL_RESTART_SCAN)
				{
					data->IoStatus.Status      = STATUS_NO_MORE_FILES;
					data->IoStatus.Information = 0;
				} else {
					FltReissueSynchronousIo(objects->Instance, data);
				}
			}
		} else
		{
			for (;;)
			{
				if (is_dcsys_di(cur_dir, i_class) != 0)
				{
					if (cur_dir->NextEntryOffset != 0)
					{
						if (cur_dir->NextEntryOffset <= length) {
							memmove(cur_dir, addof(cur_dir, cur_dir->NextEntryOffset), length - cur_dir->NextEntryOffset);
						}
					} else
					{
						if (lst_dir == NULL)
						{
							data->IoStatus.Status      = STATUS_NO_MORE_FILES;
							data->IoStatus.Information = 0;
						} else {
							lst_dir->NextEntryOffset = 0;
						}
					}
					break;
				}
				if ( (cur_dir->NextEntryOffset == 0) || (cur_dir->NextEntryOffset > length) ) {
					break;
				} else {
					lst_dir = cur_dir; length -= cur_dir->NextEntryOffset; 
					cur_dir = addof(cur_dir, cur_dir->NextEntryOffset);
				}
			}
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER) {
	}
	return FLT_POSTOP_FINISHED_PROCESSING;
}

static FLT_PREOP_CALLBACK_STATUS mf_filesystem_control(
  PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS objects, PVOID *post_ctx)
{
	mf_context *mf_ctx;
	void       *p_buff = data->Iopb->Parameters.FileSystemControl.Buffered.SystemBuffer;
	u32         length = data->Iopb->Parameters.FileSystemControl.Buffered.InputBufferLength;
	u32         fs_cod = data->Iopb->Parameters.FileSystemControl.Buffered.FsControlCode;

	if (data->Iopb->MinorFunction != IRP_MN_USER_FS_REQUEST) {
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	if (fs_cod != FSCTL_EXTEND_VOLUME && fs_cod != FSCTL_SHRINK_VOLUME) {
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	if ( (NT_SUCCESS(FltGetInstanceContext(objects->Instance, &mf_ctx)) != FALSE) &&
		 (mf_ctx != NULL) )
	{
		if (IS_STORAGE_ON_END(mf_ctx->hook->flags) != 0)
		{
			dc_update_volume(mf_ctx->hook);

			if (fs_cod == FSCTL_EXTEND_VOLUME && length >= sizeof(u64)) {
				p64(p_buff)[0] -= mf_ctx->hook->head_len / mf_ctx->hook->bps;
			}
			if (fs_cod == FSCTL_SHRINK_VOLUME && length >= sizeof(SHRINK_VOLUME_INFORMATION))
			{
				PSHRINK_VOLUME_INFORMATION info = p_buff;
				dev_hook                  *hook = mf_ctx->hook;

				if (info->NewNumberOfSectors != 0) {
					info->NewNumberOfSectors -= hook->head_len / hook->bps;
				}
			}
		}
		FltReleaseContext(mf_ctx);
	}
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static const FLT_OPERATION_REGISTRATION mf_op_callbacks[] = {
	{ IRP_MJ_CREATE,              0, mf_irp_mj_create,      NULL },
	{ IRP_MJ_DIRECTORY_CONTROL,   0, mf_directory_control,  mf_post_directory_control },
	{ IRP_MJ_FILE_SYSTEM_CONTROL, 0, mf_filesystem_control, NULL },
    { IRP_MJ_OPERATION_END }
};

static const FLT_CONTEXT_REGISTRATION mf_contexts[] = {
	{ FLT_INSTANCE_CONTEXT, 0, NULL, sizeof(mf_context), '4_cd', NULL, NULL, NULL },
	{ FLT_CONTEXT_END }
};

static const FLT_REGISTRATION mf_registration = {
    sizeof(FLT_REGISTRATION),                       //  Size
    FLT_REGISTRATION_VERSION_0200,                  //  Version
    FLTFL_REGISTRATION_DO_NOT_SUPPORT_SERVICE_STOP, //  Flags
    mf_contexts,                                    //  Context
    mf_op_callbacks,                                //  Operation callbacks
    NULL,                                           //  MiniFilterUnload
    mf_instance_setup,                              //  InstanceSetup
    NULL,                                           //  InstanceQueryTeardown
    NULL,                                           //  InstanceTeardownStart
    mf_teardown_complete,                           //  InstanceTeardownComplete
    NULL,                                           //  GenerateFileName
    NULL,                                           //  GenerateDestinationFileName
    NULL                                            //  NormalizeNameComponent
};

void mf_init(PDRIVER_OBJECT drv_obj)
{
	PFLT_FILTER mf_filter;

	if (NT_SUCCESS(FltRegisterFilter(drv_obj, &mf_registration, &mf_filter)) == FALSE) {
		return;
	}
	if (NT_SUCCESS(FltStartFiltering(mf_filter)) == FALSE) {
		FltUnregisterFilter(mf_filter);
	}
}