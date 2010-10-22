/*
    *
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
#include "defines.h"
#include "xts_fast.h"
#include "aes_asm.h"
#include "aes_padlock.h"
#include "xts_aes_ni.h"
#include "xts_serpent_sse2.h"

typedef __declspec(align(1)) union _m128 {
    u32 v32[4];    
    u64 v64[2];    
} m128;

static xts_proc aes_selected_encrypt;
static xts_proc aes_selected_decrypt;

#ifdef _M_IX86
static xts_proc serpent_selected_encrypt;
static xts_proc serpent_selected_decrypt;
#endif

#ifdef _M_X64
#define def_tweak \
	u64 t0, t1; m128

#define load_tweak() \
	t0 = t.v64[0]; t1 = t.v64[1];

#define tweak_xor(_in, _out)         \
	p64(_out)[0] = p64(_in)[0] ^ t0; \
	p64(_out)[1] = p64(_in)[1] ^ t1;

#define next_tweak()             \
	cf = (t1 >> 63) * 135;       \
	t1 = (t1 << 1) | (t0 >> 63); \
	t0 = (t0 << 1) ^ cf;

#define copy_tweak(_buf) \
	p64(_buf)[0] = t0; p64(_buf)[1] = t1;
#else
#define def_tweak    m128
#define load_tweak()

#define tweak_xor(_in, _out)               \
	p64(_out)[0] = p64(_in)[0] ^ t.v64[0]; \
	p64(_out)[1] = p64(_in)[1] ^ t.v64[1];

#define next_tweak()             \
	cf = (t.v32[3] >> 31) * 135; \
	t.v64[1] <<= 1;              \
	t.v32[2] |= t.v32[1] >> 31;  \
	t.v64[0] <<= 1;              \
	t.v32[0] ^= cf;

#define copy_tweak(_buf) \
	memcpy(_buf, &t, sizeof(t))
#endif

#ifdef IS_DRIVER
 static NPAGED_LOOKASIDE_LIST padlock_tmp_mem;
 static u32                   padlock_tmp_ok;

 #define padlock_alloc_tmp()    ( ExAllocateFromNPagedLookasideList(&padlock_tmp_mem) )
 #define padlock_free_tmp(_tmp) ( ExFreeToNPagedLookasideList(&padlock_tmp_mem, _tmp) )
#else
 #define padlock_alloc_tmp()    ( malloc(XTS_SECTOR_SIZE*2) )
 #define padlock_free_tmp(_tmp) ( free(_tmp) )
#endif

#define DEF_XTS_PROC(func_name, tweak_name, crypt_name, key_field) \
                                                                   \
static void _stdcall func_name( \
    const unsigned char *in, unsigned char *out, size_t len, u64 offset, xts_key *key) \
{                                                                                      \
	def_tweak t;                                                                       \
	m128      idx;                                                                     \
	size_t    cf;                                                                      \
    u32       i;                                                                       \
	                                                                                   \
	idx.v64[0] = offset / XTS_SECTOR_SIZE;                                             \
	idx.v64[1] = 0;                                                                    \
	do                                                                                 \
	{                                                                                  \
		/* update tweak unit index */                                                  \
		idx.v64[0]++;                                                                  \
		/* derive first tweak value */                                                 \
		tweak_name(pv(&idx), pv(&t), &key->tweak_k.key_field);                         \
		load_tweak();                                                                  \
                                                                                       \
		for (i = 0; i < XTS_BLOCKS_IN_SECTOR; i++)                                     \
		{                                                                              \
			tweak_xor(in, out);                                                        \
			crypt_name(out, out, &key->crypt_k.key_field);                             \
			tweak_xor(out, out);                                                       \
                                                                                       \
			/* update pointers */                                                      \
			in += XTS_BLOCK_SIZE; out += XTS_BLOCK_SIZE;                               \
                                                                                       \
			/* derive next tweak value */                                              \
			next_tweak();                                                              \
		}                                                                              \
	} while (len -= XTS_SECTOR_SIZE);                                                  \
}

#define DEF_XTS_AES_PADLOCK(func_name, crypt_name, basic_name) \
	                                                           \
static void _stdcall func_name( \
    const unsigned char *in, unsigned char *out, size_t len, u64 offset, xts_key *key) \
{                                                                                      \
	def_tweak align16 t;                                                               \
	m128      align16 idx;                                                             \
	u8               *buff, *tweak;                                                    \
	size_t            cf, i;                                                           \
	                                                                                   \
	if ( (buff = padlock_alloc_tmp()) == NULL ) {                                      \
		basic_name(in, out, len, offset, key);                                         \
		return;                                                                        \
	}                                                                                  \
	tweak      = buff + XTS_SECTOR_SIZE;                                               \
	idx.v64[0] = offset / XTS_SECTOR_SIZE;                                             \
	idx.v64[1] = 0;                                                                    \
	do                                                                                 \
	{                                                                                  \
		/* update tweak unit index */                                                  \
		idx.v64[0]++;                                                                  \
		/* derive first tweak value */                                                 \
		aes256_padlock_rekey();                                                        \
		aes256_padlock_encrypt(pv(&idx), pv(&t), 1, &key->tweak_k.aes);                \
		load_tweak();                                                                  \
		                                                                               \
		for (i = 0; i < XTS_BLOCKS_IN_SECTOR; i++) {                                   \
			copy_tweak(tweak + i*XTS_BLOCK_SIZE); next_tweak();                        \
		}                                                                              \
		for (i = 0; i < XTS_SECTOR_SIZE / sizeof(u64); i++) {                          \
			p64(buff)[i] = p64(in)[i] ^ p64(tweak)[i];                                 \
		}                                                                              \
		aes256_padlock_rekey();                                                        \
		crypt_name(buff, buff, XTS_BLOCKS_IN_SECTOR, &key->crypt_k.aes);               \
		                                                                               \
		for (i = 0; i < XTS_SECTOR_SIZE / sizeof(u64); i++) {                          \
			p64(out)[i] = p64(buff)[i] ^ p64(tweak)[i];                                \
		}                                                                              \
		/* update pointers */                                                          \
		in += XTS_SECTOR_SIZE; out += XTS_SECTOR_SIZE;                                 \
	} while (len -= XTS_SECTOR_SIZE);                                                  \
                                                                                       \
	padlock_free_tmp(buff);                                                            \
}

DEF_XTS_PROC(xts_aes_basic_encrypt, aes256_asm_encrypt, aes256_asm_encrypt, aes);
DEF_XTS_PROC(xts_aes_basic_decrypt, aes256_asm_encrypt, aes256_asm_decrypt, aes);

DEF_XTS_PROC(xts_twofish_encrypt, twofish256_encrypt, twofish256_encrypt, twofish);
DEF_XTS_PROC(xts_twofish_decrypt, twofish256_encrypt, twofish256_decrypt, twofish);

#ifdef _M_IX86
 DEF_XTS_PROC(xts_serpent_basic_encrypt, serpent256_encrypt, serpent256_encrypt, serpent);
 DEF_XTS_PROC(xts_serpent_basic_decrypt, serpent256_encrypt, serpent256_decrypt, serpent);
#endif

DEF_XTS_AES_PADLOCK(xts_aes_padlock_encrypt, aes256_padlock_encrypt, xts_aes_basic_encrypt);
DEF_XTS_AES_PADLOCK(xts_aes_padlock_decrypt, aes256_padlock_decrypt, xts_aes_basic_decrypt);

static void _stdcall xts_aes_encrypt(
    const unsigned char *in, unsigned char *out, size_t len, u64 offset, xts_key *key)
{
#if defined(_M_IX86) && defined(IS_DRIVER)
	KFLOATING_SAVE state;
	xts_proc       selected;

	if ((selected = aes_selected_encrypt) == xts_aes_ni_encrypt)
	{
		if (KeGetCurrentIrql() <= DISPATCH_LEVEL && NT_SUCCESS(KeSaveFloatingPointState(&state)) ) {
			xts_aes_ni_encrypt(in, out, len, offset, key);
			KeRestoreFloatingPointState(&state);
		} else {
			xts_aes_basic_encrypt(in, out, len, offset, key);
		}
	} else {
		selected(in, out, len, offset, key);
	}
#else
	aes_selected_encrypt(in, out, len, offset, key);
#endif
}

static void _stdcall xts_aes_decrypt(
    const unsigned char *in, unsigned char *out, size_t len, u64 offset, xts_key *key)
{
#if defined(_M_IX86) && defined(IS_DRIVER)
	KFLOATING_SAVE state;
	xts_proc       selected;

	if ((selected = aes_selected_decrypt) == xts_aes_ni_decrypt)
	{
		if (KeGetCurrentIrql() <= DISPATCH_LEVEL && NT_SUCCESS(KeSaveFloatingPointState(&state)) ) {
			xts_aes_ni_decrypt(in, out, len, offset, key);
			KeRestoreFloatingPointState(&state);
			return;
		} else {
			xts_aes_basic_decrypt(in, out, len, offset, key);
		}
	} else {
		selected(in, out, len, offset, key);
	}
#else
	aes_selected_decrypt(in, out, len, offset, key);
#endif
}

#ifdef _M_IX86

static void _stdcall xts_serpent_encrypt(
    const unsigned char *in, unsigned char *out, size_t len, u64 offset, xts_key *key)
{
#ifdef IS_DRIVER
	KFLOATING_SAVE state;
	xts_proc       selected;

	if ( (selected = serpent_selected_encrypt) == xts_serpent_sse2_encrypt)
	{
		if (KeGetCurrentIrql() <= DISPATCH_LEVEL && NT_SUCCESS(KeSaveFloatingPointState(&state)) ) {
			xts_serpent_sse2_encrypt(in, out, len, offset, key);
			KeRestoreFloatingPointState(&state);
		} else {
			xts_serpent_basic_encrypt(in, out, len, offset, key);
		}
	} else {
		selected(in, out, len, offset, key);
	}
#else
	serpent_selected_encrypt(in, out, len, offset, key);
#endif
}

static void _stdcall xts_serpent_decrypt(
    const unsigned char *in, unsigned char *out, size_t len, u64 offset, xts_key *key)
{
#ifdef IS_DRIVER
	KFLOATING_SAVE state;
	xts_proc       selected;

	if ( (selected = serpent_selected_decrypt) == xts_serpent_sse2_decrypt)
	{
		if (KeGetCurrentIrql() <= DISPATCH_LEVEL && NT_SUCCESS(KeSaveFloatingPointState(&state)) ) {
			xts_serpent_sse2_decrypt(in, out, len, offset, key);
			KeRestoreFloatingPointState(&state);
		} else {
			xts_serpent_basic_decrypt(in, out, len, offset, key);
		}
	} else {
		selected(in, out, len, offset, key);
	}
#else
	serpent_selected_decrypt(in, out, len, offset, key);
#endif
}
#else  /* _M_IX86 */
 #define xts_serpent_encrypt xts_serpent_sse2_encrypt
 #define xts_serpent_decrypt xts_serpent_sse2_decrypt
#endif /* _M_IX86 */

static void _stdcall xts_aes_twofish_encrypt(
    const unsigned char *in, unsigned char *out, size_t len, u64 offset, xts_key *key)
{
	xts_twofish_encrypt(in, out, len, offset, key);
	xts_aes_encrypt(out, out, len, offset, key);
}

static void _stdcall xts_aes_twofish_decrypt(
    const unsigned char *in, unsigned char *out, size_t len, u64 offset, xts_key *key)
{
	xts_aes_decrypt(in, out, len, offset, key);
	xts_twofish_decrypt(out, out, len, offset, key);
}

static void _stdcall xts_twofish_serpent_encrypt(
    const unsigned char *in, unsigned char *out, size_t len, u64 offset, xts_key *key)
{
	xts_serpent_encrypt(in, out, len, offset, key);
	xts_twofish_encrypt(out, out, len, offset, key);
}

static void _stdcall xts_twofish_serpent_decrypt(
    const unsigned char *in, unsigned char *out, size_t len, u64 offset, xts_key *key)
{
	xts_twofish_decrypt(in, out, len, offset, key);
	xts_serpent_decrypt(out, out, len, offset, key);
}

static void _stdcall xts_serpent_aes_encrypt(
    const unsigned char *in, unsigned char *out, size_t len, u64 offset, xts_key *key)
{
	xts_aes_encrypt(in, out, len, offset, key);
	xts_serpent_encrypt(out, out, len, offset, key);
}

static void _stdcall xts_serpent_aes_decrypt(
    const unsigned char *in, unsigned char *out, size_t len, u64 offset, xts_key *key)
{
	xts_serpent_decrypt(in, out, len, offset, key);
	xts_aes_decrypt(out, out, len, offset, key);
}

static void _stdcall xts_aes_twofish_serpent_encrypt(
    const unsigned char *in, unsigned char *out, size_t len, u64 offset, xts_key *key)
{
	xts_serpent_encrypt(in, out, len, offset, key);
	xts_twofish_encrypt(out, out, len, offset, key);
	xts_aes_encrypt(out, out, len, offset, key);
}

static void _stdcall xts_aes_twofish_serpent_decrypt(
    const unsigned char *in, unsigned char *out, size_t len, u64 offset, xts_key *key)
{
	xts_aes_decrypt(in, out, len, offset, key);
	xts_twofish_decrypt(out, out, len, offset, key);
	xts_serpent_decrypt(out, out, len, offset, key);
}

void xts_set_key(const unsigned char *key, int alg, xts_key *skey)
{
	switch (alg) 
	{
		case CF_AES:
			aes256_asm_set_key(key, &skey->crypt_k.aes);
			aes256_asm_set_key(key + XTS_KEY_SIZE, &skey->tweak_k.aes);

			skey->encrypt = xts_aes_encrypt;
			skey->decrypt = xts_aes_decrypt;
		break;
		case CF_TWOFISH:
			twofish256_set_key(key, &skey->crypt_k.twofish);
			twofish256_set_key(key + XTS_KEY_SIZE, &skey->tweak_k.twofish);

			skey->encrypt = xts_twofish_encrypt;
			skey->decrypt = xts_twofish_decrypt;
		break;
		case CF_SERPENT:
			serpent256_set_key(key, &skey->crypt_k.serpent);
			serpent256_set_key(key + XTS_KEY_SIZE, &skey->tweak_k.serpent);

			skey->encrypt = xts_serpent_encrypt;
			skey->decrypt = xts_serpent_decrypt;
		break;
		case CF_AES_TWOFISH:
			twofish256_set_key(key, &skey->crypt_k.twofish);
			aes256_asm_set_key(key + XTS_KEY_SIZE, &skey->crypt_k.aes);			
			twofish256_set_key(key + XTS_KEY_SIZE*2, &skey->tweak_k.twofish);
			aes256_asm_set_key(key + XTS_KEY_SIZE*3, &skey->tweak_k.aes);

			skey->encrypt = xts_aes_twofish_encrypt;
			skey->decrypt = xts_aes_twofish_decrypt;
		break;
		case CF_TWOFISH_SERPENT:
			serpent256_set_key(key, &skey->crypt_k.serpent);
			twofish256_set_key(key + XTS_KEY_SIZE, &skey->crypt_k.twofish);			
			serpent256_set_key(key + XTS_KEY_SIZE*2, &skey->tweak_k.serpent);
			twofish256_set_key(key + XTS_KEY_SIZE*3, &skey->tweak_k.twofish);

			skey->encrypt = xts_twofish_serpent_encrypt;
			skey->decrypt = xts_twofish_serpent_decrypt;
		break;
		case CF_SERPENT_AES:
			aes256_asm_set_key(key, &skey->crypt_k.aes);
			serpent256_set_key(key + XTS_KEY_SIZE, &skey->crypt_k.serpent);			
			aes256_asm_set_key(key + XTS_KEY_SIZE*2, &skey->tweak_k.aes);
			serpent256_set_key(key + XTS_KEY_SIZE*3, &skey->tweak_k.serpent);

			skey->encrypt = xts_serpent_aes_encrypt;
			skey->decrypt = xts_serpent_aes_decrypt;
		break;
		case CF_AES_TWOFISH_SERPENT:
			serpent256_set_key(key, &skey->crypt_k.serpent);
			twofish256_set_key(key + XTS_KEY_SIZE, &skey->crypt_k.twofish);
			aes256_asm_set_key(key + XTS_KEY_SIZE*2, &skey->crypt_k.aes);
			serpent256_set_key(key + XTS_KEY_SIZE*3, &skey->tweak_k.serpent);
			twofish256_set_key(key + XTS_KEY_SIZE*4, &skey->tweak_k.twofish);
			aes256_asm_set_key(key + XTS_KEY_SIZE*5, &skey->tweak_k.aes);

			skey->encrypt = xts_aes_twofish_serpent_encrypt;
			skey->decrypt = xts_aes_twofish_serpent_decrypt;
		break;
	}	
}

void xts_init(int hw_crypt)
{
#ifdef _M_IX86
	if (xts_serpent_sse2_available() != 0) {
		serpent_selected_encrypt = xts_serpent_sse2_encrypt;
		serpent_selected_decrypt = xts_serpent_sse2_decrypt;		
	} else {
		serpent_selected_encrypt = xts_serpent_basic_encrypt;
		serpent_selected_decrypt = xts_serpent_basic_decrypt;
	}
#endif
	if ( (hw_crypt != 0) && (xts_aes_ni_available() != 0) ) {
		aes_selected_encrypt = xts_aes_ni_encrypt;
		aes_selected_decrypt = xts_aes_ni_decrypt;
		return;
	}
	if ( (hw_crypt != 0) && (aes256_padlock_available() != 0) ) 
	{
#ifdef IS_DRIVER
		if (lock_xchg(&padlock_tmp_ok, 1) == 0) {
			ExInitializeNPagedLookasideList(&padlock_tmp_mem, NULL, NULL, 0, PAGE_SIZE, 'ldap', 0);
		}
#endif
		aes_selected_encrypt = xts_aes_padlock_encrypt;
		aes_selected_decrypt = xts_aes_padlock_decrypt;
		return;
	}
	aes_selected_encrypt = xts_aes_basic_encrypt;
	aes_selected_decrypt = xts_aes_basic_decrypt;
}