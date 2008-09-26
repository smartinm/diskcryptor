#ifndef _CRC32_
#define _CRC32_

#include "defines.h"
#include "cryptodef.h"

#ifndef NO_CRC32
 u32 crc32(u8 *dat, u32 len);
#endif

#endif
