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

static rb_data *rb_dat;
static e820map  mem_map;
static u8       d80_swap;

int bios_call(int num, rm_ctx *ctx)
{
	/* copy initial context to real mode buffer */
	if (ctx != NULL) {
		fastcpy(&rb_dat->rmc, ctx, sizeof(rm_ctx));
	}

	/* get interrupt seg/off */
	if (num == 0x13) {
		rb_dat->segoff = rb_dat->old_int13;
	} else {
		rb_dat->segoff = p32(0)[num];
	}

	/* set initial flags */
	rb_dat->rmc.efl = FL_IF;	
	/* call to real mode */
	rb_dat->call_rm();
	
	/* copy changed context */
	if (ctx != NULL) {
		fastcpy(ctx, &rb_dat->rmc, sizeof(rm_ctx));
	}

	return (rb_dat->rmc.efl & FL_CF) == 0;
}

void bios_jump_boot(u8 boot_dsk)
{
	d80_swap = boot_dsk;
	rb_dat->rmc.dx  = 0x80;
	rb_dat->rmc.efl = 0;
	rb_dat->segoff  = 0x7C00;
	rb_dat->call_rm();
}

void bios_reboot()
{
	rb_dat->segoff = 0x0FFFF0000;
	rb_dat->call_rm();
}

static void on_int15()
{
	if ((int)rb_dat->rmc.ebx < mem_map.n_map)
	{
		/* copy smap_entry to buffer */
		fastcpy(
			pm_off(rb_dat->rmc.es, rb_dat->rmc.di), 
			&mem_map.map[rb_dat->rmc.ebx], sizeof(e820entry)
			);

		if (++rb_dat->rmc.ebx == mem_map.n_map) {			
			rb_dat->rmc.ebx = 0;
		}

		rb_dat->rmc.eax = 0x534D4150;
		rb_dat->rmc.ecx = sizeof(e820entry);
		rb_dat->rmc.efl &= ~FL_CF;
	} else {
		rb_dat->rmc.ebx = 0;
		rb_dat->rmc.efl |= FL_CF;
	}
}

static void int_callback()
{
	rm_ctx ctx;

	if (rb_dat->int_num == 0x15) {
		on_int15();	
	} else 
	{
		if (rb_dat->int_num == 0x13) 
		{
			if (rb_dat->rmc.dl == 0x80) {
				rb_dat->rmc.dl = d80_swap;
			} else if (rb_dat->rmc.dl == d80_swap) {
				rb_dat->rmc.dl = 0x80;
			}

			/* copy context to temporary buffer */
			fastcpy(&ctx, &rb_dat->rmc, sizeof(rm_ctx));

			/* call on_int13 */
			if (on_int13(&ctx) == 0) 
			{
				/* interrupt is not processed */
				/* call original handler */
				rb_dat->segoff = rb_dat->old_int13;
				rb_dat->call_rm();
			} else {
				/* setup new context */
				fastcpy(&rb_dat->rmc, &ctx, sizeof(rm_ctx));
			}
		}
	}
}

static void add_smap(e820entry *map) 
{
	if ( (mem_map.n_map < E820MAX) && (map->size != 0) ) {
		fastcpy(&mem_map.map[mem_map.n_map++], map, sizeof(e820entry));
	}
}

static int split_smap(e820entry *map, u32 base, u32 size)
{
	e820entry tmp;
	int       split;

	if (in_reg(base, map->base, map->size) != 0) 
	{
		tmp.base = map->base;
		tmp.size = base - map->base;
		tmp.type = map->type;
		add_smap(&tmp);

		tmp.base = base;
		tmp.size = size;
		tmp.type = E820_RESERVED;
		add_smap(&tmp);

		tmp.base = base + size;
		tmp.size = map->base + map->size - tmp.base;
		tmp.type = map->type;
		add_smap(&tmp);
		split = 1;
	} else {
		split = 0;
	}
	return split;
}

void bios_create_smap()
{
	rm_ctx     ctx;
	e820map    map;
	e820entry *ent;
	int        rb_ok, i;

	/* get system memory map */
	ctx.ebx = 0; map.n_map = 0; rb_ok = 0;
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
		 (rb_dat->rb_base + rb_dat->rb_size == map.map[0].size) )
	{
		map.map[0].size  = rb_dat->rb_base;
		map.map[1].base  = map.map[0].size;
		map.map[1].size += rb_dat->rb_size;
		rb_ok = 1;
	}
	
	/* build new memory map without my regions */
	for (i = 0; i < map.n_map; i++)
	{
		ent = &map.map[i];

		if ( (split_smap(ent, rb_dat->pm_base, rb_dat->pm_size) == 0) &&
			 ( (rb_ok != 0) || (split_smap(ent, rb_dat->rb_base, rb_dat->rb_size) == 0) ) )
		{
			add_smap(ent);
		}
	}
}



void bios_main(rb_data *rbd)
{
	/* setup initial pointers */
	rb_dat       = rbd;
	rbd->int_cbk = int_callback;
	/* create new memory map */
	bios_create_smap();	
	/* setup new base memory size */
	p16(0x0413)[0] -= (u16)(rbd->rb_size / 1024);
	/* hook bios interrupts */
	rbd->hook_ints();
	/* call boot_main proc */
	boot_dsk = rbd->boot_dsk;		
	boot_main();
}