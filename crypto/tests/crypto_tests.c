#include <windows.h>
#include <stdio.h>
#include <conio.h>
#include "sha512_test.h"
#include "pkcs5_test.h"
#include "aes_test.h"
#include "twofish_test.h"
#include "serpent_test.h"
#include "xts_test.h"
#ifdef SMALL_CODE
	#include "aes_padlock_small.h"
	#include "xts_aes_test.h"
#else
	#include "aes_padlock.h"
	#include "xts_fast.h"
	#include "xts_aes_ni.h"
	#include "xts_serpent_sse2.h"
	#include "xts_serpent_avx.h"
	#include "crc32_test.h"
#endif

int main(int argc, char *argv[])
{
#if !defined(SMALL_CODE) || !defined(_M_X64)
	printf("VIA-Padlock support: %d\n", aes256_padlock_available());
#endif
#ifndef SMALL_CODE
	printf("AES-NI support: %d\n", xts_aes_ni_available());
	printf("SSE2 support: %d\n", xts_serpent_sse2_available());
	printf("AVX  support: %d\n", xts_serpent_avx_available());
	printf("crc32: %d\n", test_crc32());
#endif	
	printf("sha512: %d\n", test_sha512());
	printf("pkcs5: %d\n", test_pkcs5());
	printf("Aes-256: %d\n", test_aes256());
	printf("Twofish-256: %d\n", test_twofish256());
	printf("Seprent-256: %d\n", test_serpent256());
	printf("XTS: %d\n", test_xts_mode());
#ifdef SMALL_CODE
	printf("XTS-AES: %d\n", test_xts_aes_only());
#endif

	_getch(); return 0;
}