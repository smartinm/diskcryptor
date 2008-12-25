/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2007-2008 
    * ntldr <ntldr@freed0m.org> PGP key ID - 0xC48251EB4F8E4E6E
    *

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <ntifs.h>
#include "defines.h"
#include "prng.h"
#include "sha512.h"
#include "misc.h"
#include "aes.h"
#include "debug.h"

typedef struct _seed_data {
	PEPROCESS       seed1;
	HANDLE          seed2;
	PKTHREAD        seed3;
	HANDLE          seed4;
	ULONG           seed5;
	ULONGLONG       seed6;
	KPRIORITY       seed7;
	ULONG           seed8;
	ULONG           seed9;
	LARGE_INTEGER   seed10;
	ULONGLONG       seed11;
	KPROCESSOR_MODE seed12;
	PVOID           seed13;
	PIRP            seed14;
	MM_SYSTEMSIZE   seed15;
	LARGE_INTEGER   seed16;
	NTSTATUS        seed17;
	UUID            seed18;	
	ULONG           seed19;	
	LARGE_INTEGER   seed20;
	LARGE_INTEGER   seed21;
	ULONG_PTR       seed22;
	ULONG_PTR       seed23;
		  
} seed_data;

typedef struct _ext_seed {
	u64 seed1;
	u64 seed2;

} ext_seed;

#define RNG_POOL_SIZE 640

static u8          key_pool[AES_KEY_SIZE];  /* key for encrypt output data */
static u8          rnd_pool[RNG_POOL_SIZE]; /* random data pool            */
static int         rnd_pos;     /* position for add new data to pool */
static u64         reseed_cnt;  /* reseed counter  */
static u64         getrnd_cnt;  /* getrand counter */
static KMUTEX      rnd_mutex;
static aes256_key *rnd_key;

static void rnd_pool_mix()
{
	sha512_ctx sha_ctx;
	int        i, n;
	u8         hval[SHA512_DIGEST_SIZE];

	for (i = 0; i < RNG_POOL_SIZE; i += SHA512_DIGEST_SIZE)
	{
		sha512_init(&sha_ctx);
		sha512_hash(&sha_ctx, rnd_pool, sizeof(rnd_pool));
		sha512_done(&sha_ctx, hval);

		for (n = 0; n < SHA512_DIGEST_SIZE; n++) {
			rnd_pool[i + n] += hval[n];
		}
	}

	/* Prevent leaks */
	zeroauto(hval, sizeof(hval));
	zeroauto(&sha_ctx, sizeof(sha_ctx));
}



void rnd_add_buff(void *data, int size)
{
	sha512_ctx sha_ctx;
	ext_seed   seed;
	u8         hval[SHA512_DIGEST_SIZE];
	int        pos, i;

	/* add counter and timestamp to seed data to prevent hash recurrence */
	seed.seed1 = __rdtsc();
	seed.seed2 = reseed_cnt++;

	/* hash input data */
	sha512_init(&sha_ctx);
	sha512_hash(&sha_ctx, data, size);
	sha512_hash(&sha_ctx, pv(&seed), sizeof(seed));
	sha512_done(&sha_ctx, hval);

	/* add hash value to seed buffer */
	for (i = 0; i < SHA512_DIGEST_SIZE; i++)
	{
		if ( (pos = rnd_pos) >= RNG_POOL_SIZE) {
			pos = 0; 
		}

		rnd_pool[pos] += hval[i];
		rnd_pos        = pos + 1;
	}

	/* add hash value to key buffer */
	for (i = 0; i < SHA512_DIGEST_SIZE; i++) {
		key_pool[i % AES_KEY_SIZE] += hval[i];
	}
	
	/* prevent leaks */
	zeroauto(&sha_ctx, sizeof(sha_ctx));
	zeroauto(&hval, sizeof(hval));
	zeroauto(&seed, sizeof(seed));
}



void rnd_reseed_now()
{
	seed_data seed;

	KeQuerySystemTime(&seed.seed20);
	
	seed.seed1  = PsGetCurrentProcess();
	seed.seed2  = PsGetCurrentProcessId();
	seed.seed3  = KeGetCurrentThread();
	seed.seed4  = PsGetCurrentThreadId();
	seed.seed5  = KeGetCurrentProcessorNumber();
	seed.seed6  = KeQueryInterruptTime();
	seed.seed7  = KeQueryPriorityThread(seed.seed3);
	seed.seed10 = KeQueryPerformanceCounter(NULL);
	seed.seed11 = __rdtsc();
	seed.seed12 = ExGetPreviousMode();
	seed.seed13 = IoGetInitialStack();
	seed.seed14 = IoGetTopLevelIrp();
	seed.seed15 = MmQuerySystemSize();
	seed.seed16 = PsGetProcessExitTime();
	seed.seed17 = ExUuidCreate(&seed.seed18);
	seed.seed19 = RtlRandom(&seed.seed8);
	
	KeQueryTickCount(&seed.seed21);
	IoGetStackLimits(&seed.seed22, &seed.seed23);

	rnd_add_buff(&seed, sizeof(seed));
	
	/* Prevent leaks */	
	zeroauto(&seed, sizeof(seed));
}

void rnd_get_bytes(u8 *buf, int len)
{
	sha512_ctx  sha_ctx;
	u8          hval[SHA512_DIGEST_SIZE];
	int         c_len, idx, i;
	ext_seed    seed;

	if (reseed_cnt < 256) {
		DbgMsg("RNG not have sufficient entropy (%d reseeds), collect it now\n", reseed_cnt);
	}
	/* in RNG not have sufficient entropy, then collect it now */
	while (reseed_cnt < 256) 
	{
		dc_delay(1); /* wait 1 millisecond */
		rnd_reseed_now();
	}

	wait_object_infinity(&rnd_mutex);

	/* derive AES key from key pool */
	aes256_set_key(
		key_pool, rnd_key);

	/* mix pool state before get data from it */
	rnd_pool_mix();

	/* idx - position for extraction pool data */
	idx = 0;
	do
	{
		c_len      = min(len, SHA512_DIGEST_SIZE);
		seed.seed1 = getrnd_cnt++;
		seed.seed2 = len;

		/* collect additional entropy before extract data block */
		rnd_reseed_now();

		sha512_init(&sha_ctx);
		sha512_hash(&sha_ctx, rnd_pool + idx, SHA512_DIGEST_SIZE);
		sha512_hash(&sha_ctx, pv(&seed), sizeof(seed));
		sha512_done(&sha_ctx, hval);

		/* encrypt hash value with AES in ECB mode */		
		for (i = 0; i < SHA512_DIGEST_SIZE; i += AES_BLOCK_SIZE) {
			aes256_encrypt(hval + i, hval + i, rnd_key);
		}

		/* copy data to output */
		memcpy(buf, hval, c_len);

		/* increment extraction pointer */
		if ( (idx += SHA512_DIGEST_SIZE) == RNG_POOL_SIZE ) {
			/* if all data from pool extracted then 
			  mix pool for use new entropy added with reseeds */
			rnd_pool_mix(); idx = 0; 
		}

		/* collect additional entropy after extract data block */		
		rnd_reseed_now();

		/* update buffer pointer and remaining length */
		buf += c_len; len -= c_len;
	} while (len != 0);

	/* mix pool after get data to prevent "could boot" attacks to generated keys */
	rnd_pool_mix();

	/* Prevent leaks */
	zeroauto(rnd_key, sizeof(aes256_key));
	zeroauto(&sha_ctx, sizeof(sha_ctx));
	zeroauto(hval, sizeof(hval));
	zeroauto(&seed, sizeof(seed));

	KeReleaseMutex(&rnd_mutex, FALSE);
}

rnd_ctx *rnd_fast_init() 
{
	rnd_ctx *ctx;
	u8       key[32];

	if (ctx = mem_alloc(sizeof(rnd_ctx))) 
	{
		rnd_get_bytes(key, sizeof(key));
		aes256_set_key(key, &ctx->key);

		ctx->index.a = 0;
		ctx->index.b = 0;
	}

	/* prevent leaks */
	zeroauto(key, sizeof(key));

	return ctx;
}

void rnd_fast_free(rnd_ctx *ctx)
{
	/* prevent leaks */
	zeroauto(ctx, sizeof(rnd_ctx));
	mem_free(ctx);
}

void rnd_fast_rand(rnd_ctx *ctx, u8 *buf, int len)
{
	u8  buff[16];
	int c_len;

	do
	{
		/* encrypt counter with AES in CTR mode */
		aes256_encrypt(
			pv(&ctx->index), buff, &ctx->key);

		/* increment counter */
		if (++ctx->index.b == 0) {
			++ctx->index.a;
		}

		/* copy data to out */
		c_len = min(len, sizeof(buff));
		memcpy(buf, buff, c_len);

		buf += c_len; len -= c_len;
	} while (len != 0);

	/* prevent leaks */
	zeroauto(buff, sizeof(buff));
}

int rnd_init_prng()
{
	if ( (rnd_key = mem_alloc(sizeof(aes256_key))) == NULL ) {
		return ST_NOMEM;
	}

	KeInitializeMutex(&rnd_mutex, 0);

	rnd_reseed_now();

	return ST_OK;
}