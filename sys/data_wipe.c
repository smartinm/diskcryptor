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
#include "devhook.h"
#include "data_wipe.h"
#include "misc.h"

static wipe_mode dod_mode = { /* US DoD 5220.22-M (8-306. / E, C and E) */
	7, 
	{
		{ P_PAT,  { 0x55, 0x55, 0x55 } }, // 1
		{ P_PAT,  { 0xAA, 0xAA, 0xAA } }, // 2
		{ P_RAND, { 0x00, 0x00, 0x00 } }, // 3
		{ P_PAT,  { 0x00, 0x00, 0x00 } }, // 4
		{ P_PAT,  { 0x55, 0x55, 0x55 } }, // 5
		{ P_PAT,  { 0xAA, 0xAA, 0xAA } }, // 6
		{ P_RAND, { 0x00, 0x00, 0x00 } }  // 7
	}
};

static wipe_mode dod_mode_e = { /* US DoD 5220.22-M (8-306. / E) */
	3, 
	{
		{ P_PAT,  { 0x00, 0x00, 0x00 } }, // 1
		{ P_PAT,  { 0xFF, 0xFF, 0xFF } }, // 2
		{ P_RAND, { 0x00, 0x00, 0x00 } }  // 3
	}
};

static wipe_mode gutmann_mode = { /* Gutmann */
	35,
	{
		{ P_RAND, { 0x00, 0x00, 0x00 } }, // 1
		{ P_RAND, { 0x00, 0x00, 0x00 } }, // 2
		{ P_RAND, { 0x00, 0x00, 0x00 } }, // 3
		{ P_RAND, { 0x00, 0x00, 0x00 } }, // 4
		{ P_PAT,  { 0x55, 0x55, 0x55 } }, // 5
		{ P_PAT,  { 0xAA, 0xAA, 0xAA } }, // 6
		{ P_PAT,  { 0x92, 0x49, 0x24 } }, // 7
		{ P_PAT,  { 0x49, 0x24, 0x92 } }, // 8
		{ P_PAT,  { 0x24, 0x92, 0x49 } }, // 9
		{ P_PAT,  { 0x00, 0x00, 0x00 } }, // 10
		{ P_PAT,  { 0x11, 0x11, 0x11 } }, // 11
		{ P_PAT,  { 0x22, 0x22, 0x22 } }, // 12
		{ P_PAT,  { 0x33, 0x33, 0x33 } }, // 13
		{ P_PAT,  { 0x44, 0x44, 0x44 } }, // 14
		{ P_PAT,  { 0x55, 0x55, 0x55 } }, // 15
		{ P_PAT,  { 0x66, 0x66, 0x66 } }, // 16
		{ P_PAT,  { 0x77, 0x77, 0x77 } }, // 17
		{ P_PAT,  { 0x88, 0x88, 0x88 } }, // 18
		{ P_PAT,  { 0x99, 0x99, 0x99 } }, // 19
		{ P_PAT,  { 0xAA, 0xAA, 0xAA } }, // 20
		{ P_PAT,  { 0xBB, 0xBB, 0xBB } }, // 21
		{ P_PAT,  { 0xCC, 0xCC, 0xCC } }, // 22
		{ P_PAT,  { 0xDD, 0xDD, 0xDD } }, // 23
		{ P_PAT,  { 0xEE, 0xEE, 0xEE } }, // 24
		{ P_PAT,  { 0xFF, 0xFF, 0xFF } }, // 25
		{ P_PAT,  { 0x92, 0x49, 0x24 } }, // 26
		{ P_PAT,  { 0x49, 0x24, 0x92 } }, // 27
		{ P_PAT,  { 0x24, 0x92, 0x49 } }, // 28
		{ P_PAT,  { 0x6D, 0xB6, 0xDB } }, // 29
		{ P_PAT,  { 0xB6, 0xDB, 0x6D } }, // 30
		{ P_PAT,  { 0xDB, 0x6D, 0xB6 } }, // 31
		{ P_RAND, { 0x00, 0x00, 0x00 } }, // 32
		{ P_RAND, { 0x00, 0x00, 0x00 } }, // 33
		{ P_RAND, { 0x00, 0x00, 0x00 } }, // 34
		{ P_RAND, { 0x00, 0x00, 0x00 } }  // 35
	}
};

static wipe_mode *wipe_modes[] = {
	NULL, 
	&dod_mode_e, 
	&dod_mode, 
	&gutmann_mode
};


int dc_wipe_init(
		wipe_ctx *ctx,
		void     *hook, 
		int       max_size,
		int       method
		)
{
	int resl;

	do
	{
		ctx->buff = NULL;
		ctx->rand = NULL;
		
		if (method > sizeof(wipe_modes) / sizeof(wipe_mode)) {
			resl = ST_INV_WIPE_MODE;
			break;
		}

		ctx->mode = wipe_modes[method];
		resl      = ST_NOMEM;

		if (ctx->mode != NULL) 
		{
			if ( (ctx->buff = mem_alloc(max_size)) == NULL ) {
				break;
			}

			if ( (ctx->rand = rnd_fast_init()) == NULL ) {
				break;
			}
		}

		ctx->hook = hook;
		ctx->size = max_size;
		resl      = ST_OK;
	} while (0);

	if (resl != ST_OK) 
	{
		if (ctx->buff != NULL) {
			mem_free(ctx->buff);
		}

		if (ctx->rand != NULL) {
			rnd_fast_free(ctx->rand);
		}
	}

	return resl;
}

void dc_wipe_free(wipe_ctx *ctx)
{
	if (ctx->buff != NULL) 
	{
		/* prevent leaks */
		zeromem(ctx->buff, ctx->size);
		mem_free(ctx->buff);
	}

	if (ctx->rand != NULL) {
		rnd_fast_free(ctx->rand);
	}
}

int dc_wipe_process(wipe_ctx *ctx, u64 offset, int size)
{
	wipe_mode *mode = ctx->mode;
	u8        *buff = ctx->buff;
	int        resl;
	int        i, j;

	do
	{
		if (size > ctx->size) {
			resl = ST_INV_DATA_SIZE; break;
		}

		if (mode == NULL) {
			resl = ST_OK; break;
		}

		for (i = 0; i < mode->passes; i++) 
		{			
			if (mode->pass[i].type == P_PAT) 
			{
				for (j = 0; j < size; j++) {
					buff[j] = mode->pass[i].patt[j % 3];
				}
			} else {
				rnd_fast_rand(ctx->rand, buff, size);
			}

			resl = dc_device_rw(
				ctx->hook, IRP_MJ_WRITE, buff, size, offset);

			if (resl != ST_OK) {
				break;
			}
		}
	} while (0);

	return resl;
}