/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2008-2009
    * ntldr <PGP key ID - 0xC48251EB4F8E4E6E>
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
#include <stdio.h>
#include "defines.h"
#include "fs_filter.h"
#include "misc.h"
#include "dc_fsf.h"

static
BOOLEAN  
  dcFastIoCheckifPossible( 
    PFILE_OBJECT     FileObject, 
	PLARGE_INTEGER   FileOffset, 
	ULONG            Length, 
    BOOLEAN          Wait, 
    ULONG            LockKey, 
    BOOLEAN          CheckForReadOperation,
    PIO_STATUS_BLOCK IoStatus, 
    PDEVICE_OBJECT   DeviceObject 
	);
static
BOOLEAN  
  dcFastIoRead( 
    PFILE_OBJECT     FileObject, 
    PLARGE_INTEGER   FileOffset, 
    ULONG            Length, 
    BOOLEAN          Wait, 
    ULONG            LockKey, 
    PVOID            Buffer,
    PIO_STATUS_BLOCK IoStatus, 
    PDEVICE_OBJECT   DeviceObject 
    );
static
BOOLEAN  
  dcFastIoWrite( 
    PFILE_OBJECT     FileObject, 
    PLARGE_INTEGER   FileOffset, 
    ULONG            Length, 
    BOOLEAN          Wait, 
    ULONG            LockKey, 
    PVOID            Buffer,
    PIO_STATUS_BLOCK IoStatus, 
    PDEVICE_OBJECT   DeviceObject 
    );
static
BOOLEAN  
  dcFastIoQueryBasicInfo( 
    PFILE_OBJECT            FileObject, 
    BOOLEAN                 Wait, 
    PFILE_BASIC_INFORMATION Buffer,
    PIO_STATUS_BLOCK        IoStatus, 
    PDEVICE_OBJECT          DeviceObject 
    );
static
BOOLEAN  
  dcFastIoQueryStandardInfo( 
    PFILE_OBJECT               FileObject, 
    BOOLEAN                    Wait, 
    PFILE_STANDARD_INFORMATION Buffer,
    PIO_STATUS_BLOCK           IoStatus, 
    PDEVICE_OBJECT             DeviceObject 
    );
static
BOOLEAN  
  dcFastIoLock( 
    PFILE_OBJECT     FileObject, 
    PLARGE_INTEGER   FileOffset,
    PLARGE_INTEGER   Length, 
    PEPROCESS        ProcessId, 
    ULONG            Key,
    BOOLEAN          FailImmediately, 
    BOOLEAN          ExclusiveLock,
    PIO_STATUS_BLOCK IoStatus, 
    PDEVICE_OBJECT   DeviceObject 
    );
static
BOOLEAN
  dcFastIoUnlockSingle( 
    PFILE_OBJECT     FileObject, 
    PLARGE_INTEGER   FileOffset,
    PLARGE_INTEGER   Length, 
    PEPROCESS        ProcessId, 
    ULONG            Key,
    PIO_STATUS_BLOCK IoStatus, 
    PDEVICE_OBJECT   DeviceObject 
    );
static
BOOLEAN
  dcFastIoUnlockAll( 
    PFILE_OBJECT     FileObject, 
    PEPROCESS        ProcessId,
    PIO_STATUS_BLOCK IoStatus, 
    PDEVICE_OBJECT   DeviceObject 
    );
static
BOOLEAN
  dcFastIoUnlockAllByKey( 
    PFILE_OBJECT     FileObject, 
    PEPROCESS        ProcessId, 
    ULONG            Key,
    PIO_STATUS_BLOCK IoStatus, 
    PDEVICE_OBJECT   DeviceObject 
    );
static
BOOLEAN  
  dcFastIoDeviceControl( 
    PFILE_OBJECT     FileObject, 
    BOOLEAN          Wait,
    PVOID            InputBuffer, 
    ULONG            InputBufferLength, 
    PVOID            OutputBuffer, 
    ULONG            OutputBufferLength, 
    ULONG            IoControlCode,
    PIO_STATUS_BLOCK IoStatus, 
    PDEVICE_OBJECT   DeviceObject 
    );
static
void dcFastIoDetachDevice( 
       PDEVICE_OBJECT SourceDevice, 
       PDEVICE_OBJECT TargetDevice 
	   );
static
BOOLEAN 
  dcFastIoQueryNetworkOpenInfo(
    PFILE_OBJECT     FileObject,
    BOOLEAN          Wait,
    void            *Buffer,
    PIO_STATUS_BLOCK IoStatus,
    PDEVICE_OBJECT   DeviceObject 
    );
static
BOOLEAN
  dcFastIoMdlRead( 
    PFILE_OBJECT     FileObject,
    PLARGE_INTEGER   FileOffset, 
    ULONG            Length,
    ULONG            LockKey, 
    PMDL            *MdlChain,
    PIO_STATUS_BLOCK IoStatus,
    PDEVICE_OBJECT   DeviceObject 
    );
static
BOOLEAN 
  dcFastIoMdlReadComplete( 
    PFILE_OBJECT   FileObject,
    PMDL           MdlChain, 
    PDEVICE_OBJECT DeviceObject 
    );
static
BOOLEAN
  dcFastIoPrepareMdlWrite( 
    PFILE_OBJECT     FileObject,
    PLARGE_INTEGER   FileOffset, 
    ULONG            Length,
    ULONG            LockKey, 
    PMDL            *MdlChain,
    PIO_STATUS_BLOCK IoStatus, 
    PDEVICE_OBJECT   DeviceObject 
    );
static
BOOLEAN 
  dcFastIoMdlWriteComplete( 
    PFILE_OBJECT   FileObject,
    PLARGE_INTEGER FileOffset, 
    PMDL           MdlChain, 
    PDEVICE_OBJECT DeviceObject 
    );
static
BOOLEAN
  dcFastIoReadCompressed( 
    PFILE_OBJECT     FileObject,
    PLARGE_INTEGER   FileOffset, 
    ULONG            Length,
    ULONG            LockKey, 
    PVOID            Buffer,
    PMDL            *MdlChain, 
    PIO_STATUS_BLOCK IoStatus,
    void            *CompressedDataInfo,
    ULONG            CompressedDataInfoLength, 
    PDEVICE_OBJECT   DeviceObject 
    );
static
BOOLEAN
  dcFastIoWriteCompressed( 
    PFILE_OBJECT     FileObject,
    PLARGE_INTEGER   FileOffset, 
    ULONG            Length,
    ULONG            LockKey, 
    PVOID            Buffer,
    PMDL            *MdlChain, 
    PIO_STATUS_BLOCK IoStatus,
    void            *CompressedDataInfo,
    ULONG            CompressedDataInfoLength, 
    PDEVICE_OBJECT   DeviceObject 
    );
static
BOOLEAN 
  dcFastIoMdlReadCompleteCompressed( 
    PFILE_OBJECT   FileObject,
    PMDL           MdlChain, 
    PDEVICE_OBJECT DeviceObject 
    );
static
BOOLEAN 
  dcFastIoMdlWriteCompleteCompressed( 
    PFILE_OBJECT   FileObject,
    PLARGE_INTEGER FileOffset, 
    PMDL           MdlChain, 
    PDEVICE_OBJECT DeviceObject 
    );
static
BOOLEAN 
  dcFastIoQueryOpen( 
    PIRP                           Irp,
    PFILE_NETWORK_OPEN_INFORMATION NetworkInformation,
    PDEVICE_OBJECT                 DeviceObject 
    );


static FAST_IO_DISPATCH fast_io_hook = {
	sizeof(FAST_IO_DISPATCH), 
    dcFastIoCheckifPossible,
    dcFastIoRead,
    dcFastIoWrite,
    dcFastIoQueryBasicInfo,
    dcFastIoQueryStandardInfo,
    dcFastIoLock,
    dcFastIoUnlockSingle,
    dcFastIoUnlockAll,
    dcFastIoUnlockAllByKey,
    dcFastIoDeviceControl,
    NULL,
    NULL, 
    dcFastIoDetachDevice,
    dcFastIoQueryNetworkOpenInfo,
    NULL, 
    dcFastIoMdlRead,
    dcFastIoMdlReadComplete,
    dcFastIoPrepareMdlWrite,
    dcFastIoMdlWriteComplete,
    dcFastIoReadCompressed,
    dcFastIoWriteCompressed,
    dcFastIoMdlReadCompleteCompressed,
    dcFastIoMdlWriteCompleteCompressed,
    dcFastIoQueryOpen,
    NULL, 
    NULL,
    NULL,
};

extern PDRIVER_OBJECT dc_fsf_driver;
extern PDEVICE_OBJECT dc_fsf_device;
extern GETDEVFLAGS    dc_get_flags;
extern u32            dc_conf_flags;
static LIST_ENTRY     fs_hooks_list_head;
static KMUTEX         fs_hooks_lock;

typedef struct _fsctl_ctx {
	WORK_QUEUE_ITEM  wrk_item;
	PDEVICE_OBJECT   dev_obj;
	PIRP             irp;
	
} fsctl_ctx;

#define is_device_ok(d) ((d) != dc_fsf_device)

#define is_fastio_ok(fastio, _io) ( \
	((fastio) != NULL) && \
	((fastio)->SizeOfFastIoDispatch >= FIELD_OFFSET(FAST_IO_DISPATCH, _io) + sizeof(void*)) && \
    ((fastio)->_io != NULL) )

static
BOOLEAN  
  dcFastIoCheckifPossible( 
    PFILE_OBJECT     FileObject, 
	PLARGE_INTEGER   FileOffset, 
	ULONG            Length, 
    BOOLEAN          Wait, 
    ULONG            LockKey, 
    BOOLEAN          CheckForReadOperation,
    PIO_STATUS_BLOCK IoStatus, 
    PDEVICE_OBJECT   DeviceObject 
	)
{
	FAST_IO_DISPATCH *fastio;
	dc_fs_hook       *fs_h;
	
	if (is_device_ok(DeviceObject) == 0) {
		return FALSE;
	}

	fs_h   = DeviceObject->DeviceExtension;
	fastio = fs_h->fs_drv->FastIoDispatch;

	if (is_fastio_ok(fastio, FastIoCheckIfPossible) != 0) 
	{
		return fastio->FastIoCheckIfPossible(
			FileObject, FileOffset, Length, Wait, LockKey, CheckForReadOperation, IoStatus, fs_h->orig_dev);
	} else {
		return FALSE;
	}
}

static
BOOLEAN  
  dcFastIoRead( 
    PFILE_OBJECT     FileObject, 
    PLARGE_INTEGER   FileOffset, 
    ULONG            Length, 
    BOOLEAN          Wait, 
    ULONG            LockKey, 
    PVOID            Buffer,
    PIO_STATUS_BLOCK IoStatus, 
    PDEVICE_OBJECT   DeviceObject 
    )
{
	FAST_IO_DISPATCH *fastio;
	dc_fs_hook       *fs_h;

	if (is_device_ok(DeviceObject) == 0) {
		return FALSE;
	}

	fs_h   = DeviceObject->DeviceExtension;
	fastio = fs_h->fs_drv->FastIoDispatch;

	if (is_fastio_ok(fastio, FastIoRead) != 0) 
	{
		return fastio->FastIoRead(
			FileObject, FileOffset, Length, Wait, LockKey, Buffer, IoStatus, fs_h->orig_dev);
	} else {
		return FALSE;
	}
}

static
BOOLEAN  
  dcFastIoWrite( 
    PFILE_OBJECT     FileObject, 
    PLARGE_INTEGER   FileOffset, 
    ULONG            Length, 
    BOOLEAN          Wait, 
    ULONG            LockKey, 
    PVOID            Buffer,
    PIO_STATUS_BLOCK IoStatus, 
    PDEVICE_OBJECT   DeviceObject 
    )
{
	FAST_IO_DISPATCH *fastio;
	dc_fs_hook       *fs_h;

	if (is_device_ok(DeviceObject) == 0) {
		return FALSE;
	}

	fs_h   = DeviceObject->DeviceExtension;
	fastio = fs_h->fs_drv->FastIoDispatch;

	if (is_fastio_ok(fastio, FastIoWrite) != 0) 
	{
		return fastio->FastIoWrite(
			FileObject, FileOffset, Length, Wait, LockKey, Buffer, IoStatus, fs_h->orig_dev);
	} else {
		return FALSE;
	}
}

static
BOOLEAN  
  dcFastIoQueryBasicInfo( 
    PFILE_OBJECT            FileObject, 
    BOOLEAN                 Wait, 
    PFILE_BASIC_INFORMATION Buffer,
    PIO_STATUS_BLOCK        IoStatus, 
    PDEVICE_OBJECT          DeviceObject 
    )
{
	FAST_IO_DISPATCH *fastio;
	dc_fs_hook       *fs_h;

	if (is_device_ok(DeviceObject) == 0) {
		return FALSE;
	}

	fs_h   = DeviceObject->DeviceExtension;
	fastio = fs_h->fs_drv->FastIoDispatch;

	if (is_fastio_ok(fastio, FastIoQueryBasicInfo) != 0) 
	{
		return fastio->FastIoQueryBasicInfo(
			FileObject, Wait, Buffer, IoStatus, fs_h->orig_dev);
	} else {
		return FALSE;
	}
}

static
BOOLEAN  
  dcFastIoQueryStandardInfo( 
    PFILE_OBJECT               FileObject, 
    BOOLEAN                    Wait, 
    PFILE_STANDARD_INFORMATION Buffer,
    PIO_STATUS_BLOCK           IoStatus, 
    PDEVICE_OBJECT             DeviceObject 
    )
{
	FAST_IO_DISPATCH *fastio;
	dc_fs_hook       *fs_h;

	if (is_device_ok(DeviceObject) == 0) {
		return FALSE;
	}

	fs_h   = DeviceObject->DeviceExtension;
	fastio = fs_h->fs_drv->FastIoDispatch;

	if (is_fastio_ok(fastio, FastIoQueryStandardInfo) != 0) 
	{
		return fastio->FastIoQueryStandardInfo(
			FileObject, Wait, Buffer, IoStatus, fs_h->orig_dev);
	} else {
		return FALSE;
	}
}

static
BOOLEAN  
  dcFastIoLock( 
    PFILE_OBJECT     FileObject, 
    PLARGE_INTEGER   FileOffset,
    PLARGE_INTEGER   Length, 
    PEPROCESS        ProcessId, 
    ULONG            Key,
    BOOLEAN          FailImmediately, 
    BOOLEAN          ExclusiveLock,
    PIO_STATUS_BLOCK IoStatus, 
    PDEVICE_OBJECT   DeviceObject 
    )
{
	FAST_IO_DISPATCH *fastio;
	dc_fs_hook       *fs_h;

	if (is_device_ok(DeviceObject) == 0) {
		return FALSE;
	}

	fs_h   = DeviceObject->DeviceExtension;
	fastio = fs_h->fs_drv->FastIoDispatch;

	if (is_fastio_ok(fastio, FastIoLock) != 0) 
	{
		return fastio->FastIoLock(
			FileObject, FileOffset, Length, ProcessId, Key, 
			FailImmediately, ExclusiveLock, IoStatus, fs_h->orig_dev);
	} else {
		return FALSE;
	}
}

static
BOOLEAN
  dcFastIoUnlockSingle( 
    PFILE_OBJECT     FileObject, 
    PLARGE_INTEGER   FileOffset,
    PLARGE_INTEGER   Length, 
    PEPROCESS        ProcessId, 
    ULONG            Key,
    PIO_STATUS_BLOCK IoStatus, 
    PDEVICE_OBJECT   DeviceObject 
    )
{
	FAST_IO_DISPATCH *fastio;
	dc_fs_hook       *fs_h;

	if (is_device_ok(DeviceObject) == 0) {
		return FALSE;
	}

	fs_h   = DeviceObject->DeviceExtension;
	fastio = fs_h->fs_drv->FastIoDispatch;

	if (is_fastio_ok(fastio, FastIoUnlockSingle) != 0) 
	{
		return fastio->FastIoUnlockSingle(
			FileObject, FileOffset, Length, ProcessId, Key, IoStatus, fs_h->orig_dev);
	} else {
		return FALSE;
	}
}

static
BOOLEAN
  dcFastIoUnlockAll( 
    PFILE_OBJECT     FileObject, 
    PEPROCESS        ProcessId,
    PIO_STATUS_BLOCK IoStatus, 
    PDEVICE_OBJECT   DeviceObject 
    )
{
	FAST_IO_DISPATCH *fastio;
	dc_fs_hook       *fs_h;

	if (is_device_ok(DeviceObject) == 0) {
		return FALSE;
	}

	fs_h   = DeviceObject->DeviceExtension;
	fastio = fs_h->fs_drv->FastIoDispatch;

	if (is_fastio_ok(fastio, FastIoUnlockAll) != 0) 
	{
		return fastio->FastIoUnlockAll(
			FileObject, ProcessId, IoStatus, fs_h->orig_dev);
	} else {
		return FALSE;
	}
}

static
BOOLEAN
  dcFastIoUnlockAllByKey( 
    PFILE_OBJECT     FileObject, 
    PEPROCESS        ProcessId, 
    ULONG            Key,
    PIO_STATUS_BLOCK IoStatus, 
    PDEVICE_OBJECT   DeviceObject 
    ) 
{
	FAST_IO_DISPATCH *fastio;
	dc_fs_hook       *fs_h;

	if (is_device_ok(DeviceObject) == 0) {
		return FALSE;
	}

	fs_h   = DeviceObject->DeviceExtension;
	fastio = fs_h->fs_drv->FastIoDispatch;

	if (is_fastio_ok(fastio, FastIoUnlockAllByKey) != 0) 
	{
		return fastio->FastIoUnlockAllByKey(
			FileObject, ProcessId, Key, IoStatus, fs_h->orig_dev);
	} else {
		return FALSE;
	}
}

static
BOOLEAN  
  dcFastIoDeviceControl( 
    PFILE_OBJECT     FileObject, 
    BOOLEAN          Wait,
    PVOID            InputBuffer, 
    ULONG            InputBufferLength, 
    PVOID            OutputBuffer, 
    ULONG            OutputBufferLength, 
    ULONG            IoControlCode,
    PIO_STATUS_BLOCK IoStatus, 
    PDEVICE_OBJECT   DeviceObject 
    )
{
	FAST_IO_DISPATCH *fastio;
	dc_fs_hook       *fs_h;

	if (is_device_ok(DeviceObject) == 0) {
		return FALSE;
	}

	fs_h   = DeviceObject->DeviceExtension;
	fastio = fs_h->fs_drv->FastIoDispatch;

	if (is_fastio_ok(fastio, FastIoDeviceControl) != 0) 
	{
		return fastio->FastIoDeviceControl(
			FileObject, Wait, InputBuffer, InputBufferLength, 
			OutputBuffer, OutputBufferLength, IoControlCode, IoStatus, fs_h->orig_dev);
	} else {
		return FALSE;
	}
}

static
BOOLEAN 
  dcFastIoQueryNetworkOpenInfo(
    PFILE_OBJECT     FileObject,
    BOOLEAN          Wait,
    void            *Buffer,
    PIO_STATUS_BLOCK IoStatus,
    PDEVICE_OBJECT   DeviceObject 
    )
{
	FAST_IO_DISPATCH *fastio;
	dc_fs_hook       *fs_h;

	if (is_device_ok(DeviceObject) == 0) {
		return FALSE;
	}

	fs_h   = DeviceObject->DeviceExtension;
	fastio = fs_h->fs_drv->FastIoDispatch;

	if (is_fastio_ok(fastio, FastIoQueryNetworkOpenInfo) != 0) 
	{
		return fastio->FastIoQueryNetworkOpenInfo(
			FileObject, Wait, Buffer, IoStatus, fs_h->orig_dev);
	} else {
		return FALSE;
	}
}


static
BOOLEAN
  dcFastIoMdlRead( 
    PFILE_OBJECT     FileObject,
    PLARGE_INTEGER   FileOffset, 
    ULONG            Length,
    ULONG            LockKey, 
    PMDL            *MdlChain,
    PIO_STATUS_BLOCK IoStatus,
    PDEVICE_OBJECT   DeviceObject 
    )
{
	FAST_IO_DISPATCH *fastio;
	dc_fs_hook       *fs_h;

	if (is_device_ok(DeviceObject) == 0) {
		return FALSE;
	}

	fs_h   = DeviceObject->DeviceExtension;
	fastio = fs_h->fs_drv->FastIoDispatch;

	if (is_fastio_ok(fastio, MdlRead) != 0) 
	{
		return fastio->MdlRead(
			FileObject, FileOffset, Length, LockKey, MdlChain, IoStatus, fs_h->orig_dev);
	} else {
		return FALSE;
	}
}

static
BOOLEAN 
  dcFastIoMdlReadComplete( 
    PFILE_OBJECT   FileObject,
    PMDL           MdlChain, 
    PDEVICE_OBJECT DeviceObject 
    )
{
	FAST_IO_DISPATCH *fastio;
	dc_fs_hook       *fs_h;

	if (is_device_ok(DeviceObject) == 0) {
		return FALSE;
	}

	fs_h   = DeviceObject->DeviceExtension;
	fastio = fs_h->fs_drv->FastIoDispatch;

	if (is_fastio_ok(fastio, MdlReadComplete) != 0) 
	{
		return fastio->MdlReadComplete(
			FileObject, MdlChain, fs_h->orig_dev);
	} else {
		return FALSE;
	}
}

static
BOOLEAN
  dcFastIoPrepareMdlWrite( 
    PFILE_OBJECT     FileObject,
    PLARGE_INTEGER   FileOffset, 
    ULONG            Length,
    ULONG            LockKey, 
    PMDL            *MdlChain,
    PIO_STATUS_BLOCK IoStatus, 
    PDEVICE_OBJECT   DeviceObject 
    )
{
	FAST_IO_DISPATCH *fastio;
	dc_fs_hook       *fs_h;

	if (is_device_ok(DeviceObject) == 0) {
		return FALSE;
	}

	fs_h   = DeviceObject->DeviceExtension;
	fastio = fs_h->fs_drv->FastIoDispatch;

	if (is_fastio_ok(fastio, PrepareMdlWrite) != 0) 
	{
		return fastio->PrepareMdlWrite(
			FileObject, FileOffset, Length, LockKey, MdlChain, IoStatus, fs_h->orig_dev);
	} else {
		return FALSE;
	}
}

static
BOOLEAN 
  dcFastIoMdlWriteComplete( 
    PFILE_OBJECT   FileObject,
    PLARGE_INTEGER FileOffset, 
    PMDL           MdlChain, 
    PDEVICE_OBJECT DeviceObject 
    )
{
	FAST_IO_DISPATCH *fastio;
	dc_fs_hook       *fs_h;

	if (is_device_ok(DeviceObject) == 0) {
		return FALSE;
	}

	fs_h   = DeviceObject->DeviceExtension;
	fastio = fs_h->fs_drv->FastIoDispatch;

	if (is_fastio_ok(fastio, MdlWriteComplete) != 0) 
	{
		return fastio->MdlWriteComplete(
			FileObject, FileOffset, MdlChain, fs_h->orig_dev);
	} else {
		return FALSE;
	}
}

static
BOOLEAN
  dcFastIoReadCompressed( 
    PFILE_OBJECT     FileObject,
    PLARGE_INTEGER   FileOffset, 
    ULONG            Length,
    ULONG            LockKey, 
    PVOID            Buffer,
    PMDL            *MdlChain, 
    PIO_STATUS_BLOCK IoStatus,
    void            *CompressedDataInfo,
    ULONG            CompressedDataInfoLength, 
    PDEVICE_OBJECT   DeviceObject 
    )
{
	FAST_IO_DISPATCH *fastio;
	dc_fs_hook       *fs_h;

	if (is_device_ok(DeviceObject) == 0) {
		return FALSE;
	}

	fs_h   = DeviceObject->DeviceExtension;
	fastio = fs_h->fs_drv->FastIoDispatch;

	if (is_fastio_ok(fastio, FastIoReadCompressed) != 0) 
	{
		return fastio->FastIoReadCompressed(
			FileObject, FileOffset, Length, LockKey, Buffer, MdlChain, 
			IoStatus, CompressedDataInfo, CompressedDataInfoLength, fs_h->orig_dev);
	} else {
		return FALSE;
	}
}

static
BOOLEAN
  dcFastIoWriteCompressed( 
    PFILE_OBJECT     FileObject,
    PLARGE_INTEGER   FileOffset, 
    ULONG            Length,
    ULONG            LockKey, 
    PVOID            Buffer,
    PMDL            *MdlChain, 
    PIO_STATUS_BLOCK IoStatus,
    void            *CompressedDataInfo,
    ULONG            CompressedDataInfoLength, 
    PDEVICE_OBJECT   DeviceObject 
    )
{
	FAST_IO_DISPATCH *fastio;
	dc_fs_hook       *fs_h;

	if (is_device_ok(DeviceObject) == 0) {
		return FALSE;
	}

	fs_h   = DeviceObject->DeviceExtension;
	fastio = fs_h->fs_drv->FastIoDispatch;

	if (is_fastio_ok(fastio, FastIoWriteCompressed) != 0) 
	{
		return fastio->FastIoWriteCompressed(
			FileObject, FileOffset, Length, LockKey, Buffer, MdlChain, 
			IoStatus, CompressedDataInfo, CompressedDataInfoLength, fs_h->orig_dev);
	} else {
		return FALSE;
	}
}

static
BOOLEAN 
  dcFastIoMdlReadCompleteCompressed( 
    PFILE_OBJECT   FileObject,
    PMDL           MdlChain, 
    PDEVICE_OBJECT DeviceObject 
    )
{
	FAST_IO_DISPATCH *fastio;
	dc_fs_hook       *fs_h;

	if (is_device_ok(DeviceObject) == 0) {
		return FALSE;
	}

	fs_h   = DeviceObject->DeviceExtension;
	fastio = fs_h->fs_drv->FastIoDispatch;

	if (is_fastio_ok(fastio, MdlReadCompleteCompressed) != 0) {
		return fastio->MdlReadCompleteCompressed(FileObject, MdlChain, fs_h->orig_dev);
	} else {
		return FALSE;
	}
}

static
BOOLEAN 
  dcFastIoMdlWriteCompleteCompressed( 
    PFILE_OBJECT   FileObject,
    PLARGE_INTEGER FileOffset, 
    PMDL           MdlChain, 
    PDEVICE_OBJECT DeviceObject 
    )
{
	FAST_IO_DISPATCH *fastio;
	dc_fs_hook       *fs_h;

	if (is_device_ok(DeviceObject) == 0) {
		return FALSE;
	}

	fs_h   = DeviceObject->DeviceExtension;
	fastio = fs_h->fs_drv->FastIoDispatch;

	if (is_fastio_ok(fastio, MdlWriteCompleteCompressed) != 0) 
	{
		return fastio->MdlWriteCompleteCompressed(
			FileObject, FileOffset, MdlChain, fs_h->orig_dev);
	} else {
		return FALSE;
	}
}

static
BOOLEAN 
  dcFastIoQueryOpen( 
    PIRP                           Irp,
    PFILE_NETWORK_OPEN_INFORMATION NetworkInformation,
    PDEVICE_OBJECT                 DeviceObject 
    )
{
	FAST_IO_DISPATCH  *fastio;
	dc_fs_hook        *fs_h;
	PIO_STACK_LOCATION irp_sp;
	BOOLEAN            succs;

	if (is_device_ok(DeviceObject) == 0) {
		return FALSE;
	}

	fs_h   = DeviceObject->DeviceExtension;
	fastio = fs_h->fs_drv->FastIoDispatch;

	if (is_fastio_ok(fastio, FastIoQueryOpen) != 0) 
	{
		irp_sp = IoGetCurrentIrpStackLocation(Irp);

		/*
		   Before calling the next filter, we must make sure their device
           object is in the current stack entry for the given IRP
        */
        irp_sp->DeviceObject = fs_h->orig_dev;

		succs = fastio->FastIoQueryOpen(
			Irp, NetworkInformation, fs_h->orig_dev);

		/* Restore the IRP back to our device object */
		irp_sp->DeviceObject = DeviceObject;
	} else {
		succs = FALSE;
	}

	return succs;
}


static
void dcFastIoDetachDevice( 
       PDEVICE_OBJECT SourceDevice, 
       PDEVICE_OBJECT TargetDevice 
	   )
{
	dc_fs_hook *fs_h;

	if (is_device_ok(SourceDevice) == 0) {
		return;
	}

	fs_h = SourceDevice->DeviceExtension;

	wait_object_infinity(&fs_hooks_lock);

	if (fs_h->entry_list.Flink != NULL) {
		RemoveEntryList(&fs_h->entry_list);
	}

	KeReleaseMutex(&fs_hooks_lock, FALSE);

	IoDetachDevice(TargetDevice);
    IoDeleteDevice(SourceDevice);
}

static void dc_fsf_get_dcsys_id(dc_fs_hook *fs_h)
{
	FILE_INTERNAL_INFORMATION info;
	IO_STATUS_BLOCK           iosb;
	HANDLE                    h_file = NULL;
	NTSTATUS                  status;

	fs_h->my_thread = PsGetCurrentThread();

	if (h_file = dc_open_storage(fs_h->dev_name))
	{
		status = ZwQueryInformationFile(
			h_file, &iosb, &info, sizeof(info), FileInternalInformation);

		if (NT_SUCCESS(status) != FALSE) {
			fs_h->dcsys_id = info.IndexNumber.QuadPart;
		}
		ZwClose(h_file);
	}
	fs_h->my_thread = NULL;
}


static int is_dcsys(wchar_t *buff, u32 length)
{
	return (length >= 14) && ((length == 14) || (buff[7] == L':')) &&
		   (_wcsnicmp(buff, L"$dcsys$", 7) == 0);
}

NTSTATUS
  dc_fsf_create(
     PDEVICE_OBJECT dev_obj, PIRP irp
	 )
{
	PIO_STACK_LOCATION irp_sp;
	dc_fs_hook        *fs_h;
	int                denied;
	wchar_t           *buff;
	u16                length;

	fs_h   = dev_obj->DeviceExtension;
	irp_sp = IoGetCurrentIrpStackLocation(irp);
	buff   = irp_sp->FileObject->FileName.Buffer;
	length = irp_sp->FileObject->FileName.Length;
	denied = 0;

	if ( (dc_get_flags == NULL) || (fs_h->flags & F_PROTECT_DCSYS) )
	{
		if (irp_sp->Parameters.Create.Options & FILE_OPEN_BY_FILE_ID)
		{
			if ( (fs_h->dcsys_id == 0) && (KeGetCurrentIrql() == PASSIVE_LEVEL) ) {
				dc_fsf_get_dcsys_id(fs_h);
			}

			denied = (fs_h->dcsys_id != 0) && 
				     (length == 8) && (p64(buff)[0] == fs_h->dcsys_id);
		} else 
		{
			while ( (length != 0) && (buff[0] == L'\\') ) {			
				buff++, length -= sizeof(wchar_t);
			}

			denied = (is_dcsys(buff, length) != 0) && 
				     ( (fs_h->my_thread == NULL) || (irp->Tail.Overlay.Thread != fs_h->my_thread) );
		}
	}

	if (denied != 0) {
		return dc_complete_irp(irp, STATUS_ACCESS_DENIED, 0);
	} else {
		return dc_forward_irp(dev_obj, irp);
	}
}

static
dc_fs_hook *dc_fsf_attach_device(
			  PDEVICE_OBJECT fs_dev, int is_volume, wchar_t *dev_name)
{
	
	PDEVICE_OBJECT hook_dev;
	NTSTATUS       status;
	dc_fs_hook    *fs_h = NULL;
	
	do
	{
		status = IoCreateDevice(
			dc_fsf_driver, sizeof(dc_fs_hook), NULL, fs_dev->DeviceType, 0, FALSE, &hook_dev);

		if (NT_SUCCESS(status) == FALSE) {
			break;
		}

		zeroauto(hook_dev->DeviceExtension, sizeof(dc_fs_hook));

		hook_dev->Flags           |= fs_dev->Flags & (DO_BUFFERED_IO | DO_DIRECT_IO | DO_SUPPORTS_TRANSACTIONS);
		hook_dev->Characteristics |= fs_dev->Characteristics & FILE_DEVICE_SECURE_OPEN;
		hook_dev->Flags           &= ~DO_DEVICE_INITIALIZING;

		fs_h           = hook_dev->DeviceExtension;
		fs_h->hook_dev = hook_dev;
		fs_h->orig_dev = IoAttachDeviceToDeviceStack(hook_dev, fs_dev);
						
		if (fs_h->orig_dev == NULL) {
			IoDeleteDevice(hook_dev); fs_h = NULL; break;
		} else {
			fs_h->fs_drv = fs_h->orig_dev->DriverObject;
		}

		if (is_volume != 0) {
			wcscpy(fs_h->dev_name, dev_name);
			InsertTailList(&fs_hooks_list_head, &fs_h->entry_list);
		}
	} while (0);

	return fs_h;
}

static 
void dc_mount_complete_worker(fsctl_ctx *fctx)
{
	wchar_t        dev_name[MAX_DEVICE + 1];
	PLIST_ENTRY    entry;
	dc_fs_hook    *fs_h;
	PDEVICE_OBJECT dev_obj;
	int            duple;

	if (NT_SUCCESS(fctx->irp->IoStatus.Status) != FALSE)
	{
		wait_object_infinity(&fs_hooks_lock);

		dev_obj = fctx->dev_obj->Vpb->DeviceObject;
		entry   = fs_hooks_list_head.Flink;
		duple   = 0;

		while (entry != &fs_hooks_list_head)
		{
			fs_h  = CONTAINING_RECORD(entry, dc_fs_hook, entry_list);
			entry = entry->Flink;

			if (fs_h->orig_dev == dev_obj) {
				duple = 1; break;
			}
		}

		if (duple == 0) 
		{
			dc_query_object_name(
				fctx->dev_obj, dev_name, sizeof(dev_name));

			fs_h = dc_fsf_attach_device(dev_obj, 1, dev_name);

			if ( (fs_h != NULL) && (dc_get_flags != NULL) ) {
				fs_h->flags = dc_get_flags(dev_name);			
			}
		}

		KeReleaseMutex(&fs_hooks_lock, FALSE);
	}

	IoCompleteRequest(fctx->irp, IO_NO_INCREMENT);
	ExFreePool(fctx);
}

static
NTSTATUS
  dc_fs_mount_complete(
    PDEVICE_OBJECT dev_obj, PIRP irp, fsctl_ctx *fctx
    )
{
	if (KeGetCurrentIrql() > PASSIVE_LEVEL)
	{
		ExQueueWorkItem(
			&fctx->wrk_item, DelayedWorkQueue);
	} else {
		dc_mount_complete_worker(fctx);
	}

	return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
  dc_fsf_fsctl(
     PDEVICE_OBJECT dev_obj, PIRP irp
	 )
{
	PIO_STACK_LOCATION irp_sp;
	dc_fs_hook        *fs_h;
	fsctl_ctx         *fctx;
	NTSTATUS           status;
	u32                minorf, fsc_cd;

	if (dev_obj == dc_fsf_device) {
		return dc_complete_irp(irp, STATUS_INVALID_DEVICE_REQUEST, 0);
	}
	
	fs_h   = dev_obj->DeviceExtension;
	irp_sp = IoGetCurrentIrpStackLocation(irp);
	minorf = irp_sp->MinorFunction;
	fsc_cd = irp_sp->Parameters.FileSystemControl.FsControlCode;
	
	if ( (minorf == IRP_MN_MOUNT_VOLUME) && 
		 (fctx = ExAllocatePool(NonPagedPool, sizeof(fsctl_ctx))) )
	{
		ExInitializeWorkItem(
			&fctx->wrk_item, dc_mount_complete_worker, fctx);

		fctx->dev_obj = irp_sp->Parameters.MountVolume.Vpb->RealDevice;
		fctx->irp     = irp;

		IoCopyCurrentIrpStackLocationToNext(irp);

		IoSetCompletionRoutine(
			irp, dc_fs_mount_complete,	fctx, TRUE, TRUE, TRUE);

		status = IoCallDriver(fs_h->orig_dev, irp);
	} else 
	{
		/* prevent encrypted file system size changing */
		if ( (fs_h->flags & F_ENABLED) && (minorf == IRP_MN_USER_FS_REQUEST) &&
			 ( (fsc_cd == FSCTL_SHRINK_VOLUME) || (fsc_cd == FSCTL_EXTEND_VOLUME) ) )
		{
			status = dc_complete_irp(irp, STATUS_ACCESS_DENIED, 0);
		} else {
			status = dc_forward_irp(dev_obj, irp);
		}
	}

	return status;
}

static int is_dcsys_di(void *di, FILE_INFORMATION_CLASS iclass)
{
	wchar_t *f_name;
	u32      length;

	switch (iclass) 
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

NTSTATUS
  dc_fsf_dirctl(
     PDEVICE_OBJECT dev_obj, PIRP irp
	 )
{
	FILE_BOTH_DIR_INFORMATION *bdi, *ldi;
	PIO_STACK_LOCATION         irp_sp;
	dc_fs_hook                *fs_h;
	NTSTATUS                   status;
	wchar_t                   *buff;
	u32                        length;
	ULONG_PTR                  transf;
	int                        is_root;
	FILE_INFORMATION_CLASS     iclass;

	if (dev_obj == dc_fsf_device) {
		return dc_complete_irp(irp, STATUS_INVALID_DEVICE_REQUEST, 0);
	}

	fs_h   = dev_obj->DeviceExtension;
	irp_sp = IoGetCurrentIrpStackLocation(irp);
	iclass = irp_sp->Parameters.QueryDirectory.FileInformationClass;

	if ( !(dc_conf_flags & CONF_HIDE_DCSYS) || !(fs_h->flags & F_PROTECT_DCSYS)   || 
		 (irp_sp->MinorFunction != IRP_MN_QUERY_DIRECTORY) ||
		 ( (iclass != FileBothDirectoryInformation) && (iclass != FileDirectoryInformation) &&
		   (iclass != FileFullDirectoryInformation) && (iclass != FileIdBothDirectoryInformation) &&
		   (iclass != FileIdFullDirectoryInformation) && (iclass != FileNamesInformation) ) )
	{
		return dc_forward_irp(dev_obj, irp);
	}

	buff   = irp_sp->FileObject->FileName.Buffer;
	length = irp_sp->FileObject->FileName.Length;	

	__try {
		is_root = (length == sizeof(wchar_t)) && (buff != NULL) && (buff[0] == L'\\');
	}
	__except(EXCEPTION_EXECUTE_HANDLER) {
		is_root = 0;
	}

	if (is_root == 0) {
		return dc_forward_irp(dev_obj, irp);
	}

	status = dc_forward_irp_sync(dev_obj, irp);
	transf = irp->IoStatus.Information;

	if (NT_SUCCESS(status) != FALSE)
	{
		bdi    = irp->UserBuffer;
		length = irp_sp->Parameters.NotifyDirectory.Length;
		ldi    = NULL;

		__try 
		{
			if (irp_sp->Flags & SL_RETURN_SINGLE_ENTRY)
			{
				if (is_dcsys_di(bdi, iclass) != 0)
				{
					if (irp_sp->Flags & SL_RESTART_SCAN) {
						status = STATUS_NO_MORE_FILES; transf = 0;
					} else {
						status = dc_forward_irp_sync(dev_obj, irp);
						transf = irp->IoStatus.Information;
					}
				}
			} else
			{
				for (;;)
				{
					if (is_dcsys_di(bdi, iclass) != 0)
					{
						if (bdi->NextEntryOffset != 0) 
						{
							if (bdi->NextEntryOffset <= length) {
								memmove(bdi, addof(bdi, bdi->NextEntryOffset), length - bdi->NextEntryOffset);
							}
						} else
						{
							if (ldi != NULL) {
								ldi->NextEntryOffset = 0;
							} else {
								status = STATUS_NO_MORE_FILES;
								transf = 0;
							}
						}
						break;
					}

					if ( (bdi->NextEntryOffset == 0) || (bdi->NextEntryOffset > length) ) {
						break;
					} else {
						ldi = bdi; length -= bdi->NextEntryOffset; 
						bdi = addof(bdi, bdi->NextEntryOffset);
					}
				}
			}
		}
		__except(EXCEPTION_EXECUTE_HANDLER) {}
	}

	return dc_complete_irp(irp, status, transf);
}

static
void dc_fs_change_notification(
	   PDEVICE_OBJECT dev_obj, BOOLEAN fs_active
	   )
{
	PDEVICE_OBJECT our_dev;

	if (dev_obj->DeviceType != FILE_DEVICE_DISK_FILE_SYSTEM) {
		return;
	}

	if (fs_active != 0) {
		dc_fsf_attach_device(dev_obj, 0, NULL);
	} else 
	{
		while (our_dev = dev_obj->AttachedDevice)
		{
			if (our_dev->DriverObject == dc_fsf_driver) {
				IoDetachDevice(dev_obj);
				IoDeleteDevice(our_dev); break;
			}
			dev_obj = our_dev;
		}
	}
}


void dc_fsf_set_flags(wchar_t *dev_name, u32 flags)
{
	PLIST_ENTRY  entry;
	dc_fs_hook  *fs_h;

	wait_object_infinity(&fs_hooks_lock);

	entry = fs_hooks_list_head.Flink;

	while (entry != &fs_hooks_list_head)
	{
		fs_h  = CONTAINING_RECORD(entry, dc_fs_hook, entry_list);
		entry = entry->Flink;

		if (_wcsicmp(fs_h->dev_name, dev_name) == 0) {
			fs_h->flags = flags;
			if (!(flags & F_PROTECT_DCSYS)) { fs_h->dcsys_id = 0; }
		}
	}

	KeReleaseMutex(&fs_hooks_lock, FALSE);
}

void dc_fsf_sync_all()
{
	PLIST_ENTRY  entry;
	dc_fs_hook  *fs_h;

	wait_object_infinity(&fs_hooks_lock);

	entry = fs_hooks_list_head.Flink;

	while (entry != &fs_hooks_list_head)
	{
		fs_h  = CONTAINING_RECORD(entry, dc_fs_hook, entry_list);
		entry = entry->Flink;		
		fs_h->flags = dc_get_flags(fs_h->dev_name);		
	}

	KeReleaseMutex(&fs_hooks_lock, FALSE);
}

NTSTATUS dc_init_fsf()
{
	dc_fsf_driver->FastIoDispatch = &fast_io_hook;

	InitializeListHead(&fs_hooks_list_head);
	KeInitializeMutex(&fs_hooks_lock, 0);

	return IoRegisterFsRegistrationChange(dc_fsf_driver, dc_fs_change_notification);
}
