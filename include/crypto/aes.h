#ifndef _AES256_
#define _AES256_

#include "defines.h"
#include "cryptodef.h"

#define ROUNDS 14

typedef calign struct _aes256_key
{
	calign u32 enc_key[4 *(ROUNDS + 1)];
	calign u32 dec_key[4 *(ROUNDS + 1)];
#ifdef AES_ASM_1
	calign u8 dk_code[4096];
	calign u8 ek_code[4096];
#endif
} aes256_key;

typedef void (pcall *aescode)(unsigned char *in, unsigned char *out, aes256_key *key);

#ifdef AES_C
 void pcall aes256_decrypt_c(unsigned char *in, unsigned char *out, aes256_key *key);
 void pcall aes256_encrypt_c(unsigned char *in, unsigned char *out, aes256_key *key);
#endif

#if defined(AES_C) && !defined(AES_ASM_1) && !defined(AES_ASM_2) && !defined(AES_ASM_VIA)
 #define aes256_decrypt aes256_decrypt_c
 #define aes256_encrypt aes256_encrypt_c

 #define aes256_decrypt_ptr(key) ( aes256_decrypt_c )
 #define aes256_encrypt_ptr(key) ( aes256_encrypt_c )
 #define AES_STATIC
#endif

#if defined(AES_ASM_1) && !defined(AES_ASM_2) && !defined(AES_C) && !defined(AES_ASM_VIA)
 #define aes256_decrypt(in, out, key) ((aescode)(key)->dk_code)(in, out, key)
 #define aes256_encrypt(in, out, key) ((aescode)(key)->ek_code)(in, out, key)

 #define aes256_decrypt_ptr(key) ((aescode)((aes256_key*)(key))->dk_code)
 #define aes256_encrypt_ptr(key) ((aescode)((aes256_key*)(key))->ek_code)
#endif

#if defined(AES_ASM_VIA)
 int  pcall aes256_ace_available();
 void pcall aes256_decrypt_ace(unsigned char *in, unsigned char *out, aes256_key *key);
 void pcall aes256_encrypt_ace(unsigned char *in, unsigned char *out, aes256_key *key);

#ifdef _M_IX86
 static void __forceinline aes256_ace_rekey() {
	 __asm {
		 pushfd
		 popfd
	 }
 }
#else  /* _M_IX86 */
 #define aes256_ace_rekey()
#endif /* _M_IX86 */
#else  /* AES_ASM_VIA */
 #define aes256_ace_available() (0)
#endif /* AES_ASM_VIA */

#if defined(AES_ASM_2)
 void pcall aes256_decrypt_gd(unsigned char *in, unsigned char *out, aes256_key *key);
 void pcall aes256_encrypt_gd(unsigned char *in, unsigned char *out, aes256_key *key);
#endif

#if defined(AES_ASM_2) && !defined(AES_ASM_1) && !defined(AES_C) && !defined(AES_ASM_VIA)
 #define aes256_decrypt aes256_decrypt_gd
 #define aes256_encrypt aes256_encrypt_gd

 #define aes256_decrypt_ptr(key) ( aes256_decrypt )
 #define aes256_encrypt_ptr(key) ( aes256_encrypt )
 #define AES_STATIC
#endif

#if (defined(AES_ASM_1) && defined(AES_ASM_2)) || defined(AES_ASM_VIA)
 extern aescode p_aes_encrypt;
 extern aescode p_aes_decrypt;

#if defined(AES_ASM_1)
 #define aes256_decrypt(in, out, key)( \
   (p_aes_decrypt != NULL) ? p_aes_decrypt(in, out, key) : ((aescode)(key)->dk_code)(in, out, key) )
 #define aes256_encrypt(in, out, key)( \
   (p_aes_encrypt != NULL) ? p_aes_encrypt(in, out, key) : ((aescode)(key)->ek_code)(in, out, key) )

 #define aes256_decrypt_ptr(key) ( \
   (p_aes_decrypt != NULL) ? p_aes_decrypt : ((aescode)((aes256_key*)(key))->dk_code) )
 #define aes256_encrypt_ptr(key) ( \
   (p_aes_encrypt != NULL) ? p_aes_encrypt : ((aescode)((aes256_key*)(key))->ek_code) )
#else  /* AES_ASM_1 */
 #define aes256_decrypt(in, out, key)(p_aes_decrypt(in, out, key))
 #define aes256_encrypt(in, out, key)(p_aes_encrypt(in, out, key))

 #define aes256_decrypt_ptr(key) ( p_aes_decrypt )
 #define aes256_encrypt_ptr(key) ( p_aes_encrypt )
#endif /* AES_ASM_1 */

 void aes256_select_alg(int no_hw_crypt);
#else
 #define aes256_select_alg(x)
#endif

void aes256_set_key(unsigned char *data, aes256_key *key);

#ifdef SMALL_CODE
 void aes256_gentab();
#else
 #define aes256_gentab()
#endif

#define AES_KEY_SIZE   32
#define AES_BLOCK_SIZE 16

#endif