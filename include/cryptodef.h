#ifndef _CRYPTODEF_
#define _CRYPTODEF_

#ifdef BOOT_LDR
 #define SMALL_CODE
 #define NO_CRC32
 #define AES_C
 #define AES_ASM_VIA
#endif

#if defined(IS_DRIVER)
 #define CRYPT_TESTS
#endif

#if defined(IS_DRIVER) || defined(DCAPI_DLL)
 #define TWOFISH_ASM 
 #define AES_ASM_2
 #define AES_ASM_VIA
#ifdef _M_IX86 
 #define AES_ASM_1 
#endif
#endif  /* IS_DRIVER */

#define calign __declspec(align(16))

#if defined(AES_ASM_1) || defined(AES_ASM_2) || defined(AES_ASM_VIA)
 #define pcall stdcall
#else
 #define pcall
#endif

#ifdef SMALL_CODE
 #define memcpy mincpy
#endif
#endif

