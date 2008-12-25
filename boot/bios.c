/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2008 
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

#include "boot.h"
#include "bios.h"
#include "misc.h"
#include "e820.h"

       bd_data *bd_dat;
static u8       d80_swap;

void set_ctx(u16 ax, rm_ctx *ctx)
{
	/* zero all registers */
	zeroauto(ctx, sizeof(rm_ctx));
	/* set initial segments */
	ctx->ds = rm_seg(bd_dat->bd_base);
	ctx->es = ctx->ds;
	/* set AX value */
	ctx->ax = ax;
}

int bios_call(int num, rm_ctx *ctx)
{
	/* copy initial context to real mode buffer */
	if (ctx != NULL) {
		autocpy(&bd_dat->rmc, ctx, sizeof(rm_ctx));
	}

	/* get interrupt seg/off */
	if ( (num == 0x13) && (bd_dat->old_int13 != 0) ) {
		bd_dat->segoff = bd_dat->old_int13;
	} else {
		bd_dat->segoff = p32(0)[num];
	}

	bd_dat->rmc.efl = FL_IF;
	/* call to real mode */
	bd_dat->call_rm();
	
	/* copy changed context */
	if (ctx != NULL) {
		autocpy(ctx, &bd_dat->rmc, sizeof(rm_ctx));
	}

	return (bd_dat->rmc.efl & FL_CF) == 0;
}

void bios_jump_boot(u8 disk)
{
	d80_swap = disk;
	bd_dat->rmc.dx  = 0x80;
	bd_dat->rmc.efl = FL_IF; /* enable interrupts */
	bd_dat->segoff  = 0x7C00;
	bd_dat->jump_rm();
}

void bios_reboot()
{
	bd_dat->rmc.ax  = 0x0472;
	bd_dat->rmc.di  = bd_dat->rmc.ax;
	bd_dat->rmc.efl = 0; /* disable interrupts */
	bd_dat->segoff  = 0x0FFFF0000;
	bd_dat->jump_rm();
}


static void int13_callback()
{
	rm_ctx ctx;
	u16    p_efl = bd_dat->push_fl;

	if (bd_dat->rmc.dl == 0x80) {
		bd_dat->rmc.dl = d80_swap;
	} else if (bd_dat->rmc.dl == d80_swap) {
		bd_dat->rmc.dl = 0x80;
	}

	/* copy context to temporary buffer */
	autocpy(&ctx, &bd_dat->rmc, sizeof(rm_ctx));

	/* call on_int13 */
	if (on_int13(&ctx) == 0) 
	{
		/* interrupt is not processed */
		/* call original handler */
		bd_dat->rmc.efl = FL_IF; /* enable interrupts */
		bd_dat->segoff  = bd_dat->old_int13;
		bd_dat->call_rm();
	} else {
		/* setup new context */
		autocpy(&bd_dat->rmc, &ctx, sizeof(rm_ctx));
	}	

	/* copy saved interrupt flag to exit context */
	bd_dat->rmc.efl = (bd_dat->rmc.efl & ~FL_IF) | (p_efl & FL_IF);
}

static void add_smap(e820entry *map) 
{
	if ( (bd_dat->mem_map.n_map < E820MAX) && (map->size != 0) ) {
		autocpy(&bd_dat->mem_map.map[bd_dat->mem_map.n_map++], map, sizeof(e820entry));
	}
}

static void bios_create_smap()
{
	rm_ctx     ctx;
	e820map    map;
	e820entry *ent, tmp;
	u32        base, size;
	int        i;

	/* setup initial context */
	set_ctx(0, &ctx);
	/* get system memory map */
	map.n_map = 0; base = bd_dat->bd_base; 
	size = bd_dat->bd_size;
	do
	{
		ctx.eax = 0x0000E820;
		ctx.edx = 0x534D4150;
		ctx.ecx = sizeof(e820entry);
		ctx.es  = rm_seg(&map.map[map.n_map]);
		ctx.di  = rm_off(&map.map[map.n_map]);

		if ( (bios_call(0x15, &ctx) == 0) || (ctx.eax != 0x534D4150) ) {
			break;
		}
	} while ( (++map.n_map < E820MAX) && (ctx.ebx != 0) );

	/* append my real mode block to second region */
	if ( (map.n_map >= 2) && (map.map[0].type == E820_RAM) && 
		 (map.map[1].type == E820_RESERVED) && (map.map[0].base == 0) &&
		 (map.map[1].base == map.map[0].size) &&
		 (base + size == map.map[0].size) )
	{
		map.map[0].size  = base;
		map.map[1].base  = map.map[0].size;
		map.map[1].size += size;		
	}
	
	/* build new memory map without my regions */
	for (i = 0; i < map.n_map; i++)
	{
		ent = &map.map[i];

		if ( (ent->type == E820_RAM) && 
			 (in_reg(base, ent->base, ent->size) != 0) )
		{
			tmp.base = ent->base;
			tmp.size = base - ent->base;
			tmp.type = ent->type;
			add_smap(&tmp);

			tmp.base = base;
			tmp.size = size;
			tmp.type = E820_RESERVED;
			add_smap(&tmp);

			tmp.base = base + size;
			tmp.size = ent->base + ent->size - tmp.base;
			tmp.type = ent->type;
			add_smap(&tmp);
		} else {
			add_smap(ent);
		}
	}
}

void bios_hook_ints()
{
	/* setup new base memory size */
	p16(0x0413)[0] -= d16(bd_dat->bd_size / 1024);
	/* hook bios interrupts */
	bd_dat->hook_ints();
}

void bios_main(bd_data *bdb)
{
	bd_dat       = bdb;
	/* setup initial pointers */
	bdb->int_cbk = int13_callback;
	/* create new memory map */
	bios_create_smap();		
	/* call boot_main proc */
	boot_dsk = bdb->boot_dsk;		
	boot_main();
}
