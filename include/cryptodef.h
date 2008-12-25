#ifndef _CRYPTODEF_
#define _CRYPTODEF_

#ifdef BOOT_LDR
 #define SMALL_CODE
 #define NO_CRC32
#endif

#ifdef IS_DRIVER
 #define ASM_CRYPTO
 #define TWOFISH_ASM
 #define CRYPT_TESTS
#ifdef _M_IX86 
 #define AES_ASM
#endif  /* _M_IX86 */
#endif  /* IS_DRIVER */


#ifdef ASM_CRYPTO
 #define pcall stdcall
#else
 #define pcall
#endif

#ifdef SMALL_CODE
 #define memcpy mincpy
#endif
#endif

