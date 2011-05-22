#include <windows.h>
#include "defines.h"
#include "crc32.h"

int test_crc32()
{
	u32 test[256];
	int i;

	for (i = 0; i < 256; i++) {
		test[i] = i;
	}
	if (crc32(pv(test), sizeof(test)) != 0xf0e359bb) {
		return 0;
	}
	return 1;
}