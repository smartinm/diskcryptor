#ifndef _DEBUG_
#define _DEBUG_

void dbg_ioctl_print(u32 ioctl);

#ifdef DBG_FILE
 void debug_out(char *format, ...);
#endif

#endif

