#ifndef _DC_FSF_H_
#define _DC_FSF_H_

typedef u32  (*GETDEVFLAGS)(wchar_t *dev_name);
typedef void (*SETDEVFLAGS)(wchar_t *dev_name, u32 flags);

#define DC_FSF_FUNCTL      CTL_CODE(FILE_DEVICE_UNKNOWN, 100, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DC_FSF_DEVICE_NAME L"\\Device\\dc_fsf"
#define DC_FSF_REG_KEY     L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\dc_fsf"

typedef struct _fsf_functl {
	GETDEVFLAGS get_flags;
	SETDEVFLAGS set_flags;

} fsf_functl;

#endif