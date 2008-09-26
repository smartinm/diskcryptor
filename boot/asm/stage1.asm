;
;   *
;   * DiskCryptor - open source partition encryption tool
;   * Copyright (c) 2008
;   * ntldr <ntldr@freed0m.org> PGP key ID - 0xC48251EB4F8E4E6E
;   *
;   This program is free software: you can redistribute it and/or modify
;   it under the terms of the GNU General Public License as published by
;   the Free Software Foundation, either version 3 of the License, or
;   (at your option) any later version.
;
;   This program is distributed in the hope that it will be useful,
;   but WITHOUT ANY WARRANTY; without even the implied warranty of
;   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;   GNU General Public License for more details.
;
;   You should have received a copy of the GNU General Public License
;   along with this program.  If not, see <http://www.gnu.org/licenses/>.
;
org 0

include 'win32a.inc'
include 'macro.inc'
include 'pe.inc'
include 'struct.inc'

use16
 nop
 nop
 nop
 nop
 ; all bootloader data are loaded to memory
 ; setup real mode segment registers
 cli
 mov	ax, cs
 mov	ds, ax
 mov	gs, ax
 xor	bx, bx
 mov	es, bx
 mov	fs, bx
 mov	ss, bx
 ; setup initial realmode stack
 mov	sp, 4000h
 sti
 ; save boot disk
 push	dx
 ; setup data area pointer
 mov	di, 5000h
 ; get system memory map
 xor	ebx, ebx
 xor	ebp, ebp
smap_get:
 mov	eax, 0000E820h
 mov	edx, 534D4150h
 mov	ecx, 24 
 int	15h 
 jc	    smap_done
 cmp	eax, 0x534D4150
 jnz	smap_done
 ; find memory higher 1mb
 xor	eax, eax
 mov	edx, 1024*1024	       ; 1mb
 cmp	dword [es:di+10h], 1   ; check memory type
 jnz	smap_nxt
 ; memory > 4gb don't interested
 cmp	dword [es:di+04h], eax ; check high address
 jnz	smap_nxt
 mov	ebp, [es:di+00h]
 cmp	ebp, edx	       ; check low address
 jc		smap_nxt
 ; if size > 4gb then use 4gb - 64k limit
 cmp	dword [es:di+0Ch], eax ; check high size
 jz		@F
 mov	ecx, 0FFFF0000h
 jmp	smap_found
@@:
 ; get memory size
 mov	ecx, [es:di+08h]
 ; size must be > 512kb
 cmp	ecx, 512 * 1024
 jc	smap_nxt
 ; base + size must be >= 16mb
 mov	edx, 1024*1024*16 ; 16mb
 cmp	ebp, edx
 jnc	smap_found
 cmp	ecx, edx
 jnc	smap_found
 lea	eax, [ebp+ecx]
 cmp	eax, edx
 jnc	smap_found
 ; load next map entry
smap_nxt:
 test	ebx, ebx
 jnz	smap_get
smap_done:
 ; display error
 call	e_msg_1
 db 'not enough extended memory',13,10,0
smap_found:
 ; regusters here:
 ;  ebp - memory chunk base
 ;  ecx - memory chunk size
 push	ecx
 ; get code base
 call	next
next:
 pop	bx
 add	bx, 0 - $ + 1
 ; bx - code base
 ; get base memory size
 mov	dx, [fs:0413h]
 sub	dx, rb_kbs
 shl	dx, 6
 ; copy real mode block to top of base memory
 mov	es, dx
 xor	di, di
 lea	si, [bx+rb_block]
 mov	cx, rb_size
 cld
 rep movsb
 ; move memory size to edi
 pop	edi
 ; restore boot disk
 pop	dx
 ; push return address
 lea	ax, [bx+pm_loader]
 push	ax
 ; jump to resident block
 push	es
 xor	ax, ax
 push	ax
 retf

e_msg_1:
 pop	si
@@:
 lodsb
 test	al, al
 jz	$
 mov	ah, 0Eh
 xor	bx, bx
 int	10h
 jmp	@B
 
 
pm_loader: ; protected mode loader
use32
 add	ecx, rbb
 ; registers here:
 ;  ebp - memory chunk base
 ;  edi - memory chunk size
 ;  ecx - real mode block
 push	ecx
 ; get embedded PE image address
 call	next2
next2:
 pop	esi
 add	esi, rb_block + boot_data - next2
 ; load PE image to extended memory
 mov	edx, [esi+IMAGE_DOS_HEADER.e_lfanew]
 add	edx, esi
 mov	ecx, [edx+IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage]
 ; add 4k for stack and align size to 4k
 add	ecx, 4096 + 4095
 and	ecx, 0FFFFF000h 
 ; setup new image location
 add	ebp, edi
 sub	ebp, ecx
 ; GRUB compatibility hack
 mov	eax, ebp
 and	eax, 0FFF00000h
 cmp	eax, 03FF00000h
 jnz	@F
 sub	ebp, 1024 * 1024 
@@: 
 ; align image base to 4k
 and	ebp, 0FFFFF000h 
 ; save image location to rbb
 mov	[fs:rbb.pm_base], ebp
 mov	[fs:rbb.pm_size], ecx
 ; zero memory before map sections
 mov	edi, ebp
 xor	eax, eax
 rep stosb
 ; copy image headers
 push	esi ; [esp] - orig image base
 mov	ecx, [edx+IMAGE_NT_HEADERS.OptionalHeader.SizeOfHeaders]
 mov	edi, ebp
 rep movsb
 ; copy sections
 movzx	ebx, [edx+IMAGE_NT_HEADERS.FileHeader.NumberOfSections]
 movzx	ecx, [edx+IMAGE_NT_HEADERS.FileHeader.SizeOfOptionalHeader]
 add	edx, ecx
 add	edx, IMAGE_NT_HEADERS.OptionalHeader ; edx - first IMAGE_SECTION_HEADER
@@:
 mov	esi, [edx+IMAGE_SECTION_HEADER.PointerToRawData]
 mov	edi, [edx+IMAGE_SECTION_HEADER.VirtualAddress]
 mov	ecx, [edx+IMAGE_SECTION_HEADER.SizeOfRawData]
 add	esi, [esp]
 add	edi, ebp
 ; copy section
 push	esi
 push	ecx
 rep movsb
 pop	ecx
 pop	edi
 ; zero old section data to prevent embedded password leak
 xor	eax, eax
 rep stosb
 add	edx, sizeof.IMAGE_SECTION_HEADER
 dec	ebx
 jnz	@B
 pop	ecx ; original PE image does not needed later
 ; get new nt headers
 mov	edi, ebp
 add	edi, [ebp+IMAGE_DOS_HEADER.e_lfanew]  ; edi - IMAGE_NT_HEADERS
 ; process image relocations
 mov	edx, [edi+IMAGE_NT_HEADERS.OptionalHeader.RelocDirectory.VirtualAddress]
 test	edx, edx
 jz	rel_done
 add	edx, ebp ; edx - PIMAGE_BASE_RELOCATION
rel_loop:
 cmp	[edx+IMAGE_BASE_RELOCATION.SizeOfBlock], 0
 jz	rel_done
 ; get the IMAGE_FIXUP_ENTRY
 lea	esi, [edx+sizeof.IMAGE_BASE_RELOCATION] ; esi - IMAGE_FIXUP_ENTRY
 ; get number of fixups
 mov	ecx, [edx+IMAGE_BASE_RELOCATION.SizeOfBlock]
 sub	ecx, sizeof.IMAGE_BASE_RELOCATION
 shr	ecx, 1
fix_loop:
 ; get fixup
 lodsw
 ; check fixup type and fix only IMAGE_REL_BASED_HIGHLOW fixups
 mov	bx, ax
 shr	bx, 12
 cmp	bx, 3
 jnz	rel_nofix
 ; calculate fixup VA
 and	eax, 0FFFh
 add	eax, [edx+IMAGE_BASE_RELOCATION.VirtualAddress]
 add	eax, ebp
 ; fix data on pointer
 mov	ebx, [eax]
 add	ebx, ebp
 sub	ebx, [edi+IMAGE_NT_HEADERS.OptionalHeader.ImageBase]
 mov	[eax], ebx
rel_nofix:
 loop	fix_loop
 add	edx, [edx+IMAGE_BASE_RELOCATION.SizeOfBlock]
 jmp	rel_loop
rel_done:
 ; get image entry point
 mov	ebx, [edi+IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint]
 add	ebx, ebp  ; ebx - entry point
 ; get rbb pointer
 pop	ecx
 ; switch to new stack
 mov	eax, [fs:rbb.pm_base]
 add	eax, [fs:rbb.pm_size]
 mov	esp, eax
 ; push rbb to new stack
 push	ecx
 ; jump to entry point 
 call	ebx
 jmp	$


rb_block: ; real mode block

use16
org 0
 jmp	pm_enable
 rbb	rb_data ; define real mode block data

NSEG  = 0
DSEG  = 1 shl 3 ; 32-bit data selector
CSEG  = 2 shl 3 ; 32-bit code selector
ESEG  = 3 shl 3 ; 32-bit extended data selector
RCSEG = 4 shl 3 ; 16-bit code selector
RDSEG = 5 shl 3 ; 16-bit data selector


gdtr:					; Global Descriptors Table Register
  dw 6*8-1				; limit of GDT (size minus one)
  dd gdt				; linear address of GDT

gdt rw 4				; null desciptor
    dw 0FFFFh, 0, 9200h, 0CFh		; 32-bit data desciptor
    dw 0FFFFh, 0, 9A00h, 0CFh		; 32-bit code desciptor
pm32_edes:
    dw 0FFFFh, 0, 9200h, 0CFh		; 32-bit extended data desciptor
pm16_cdes:
    dw 0FFFFh, 0, 9E00h, 0		; 16 bit code desciptor
pm16_ddes:
    dw 0FFFFh, 0, 9200h, 0		; 16 bit data desciptor

regs_load:
use16
 mov	eax, [cs:rbb.rmc.eax]
 mov	ecx, [cs:rbb.rmc.ecx]
 mov	edx, [cs:rbb.rmc.edx]
 mov	ebx, [cs:rbb.rmc.ebx]
 mov	ebp, [cs:rbb.rmc.ebp]
 mov	esi, [cs:rbb.rmc.esi]
 mov	edi, [cs:rbb.rmc.edi]
 push	[cs:rbb.rmc.efl]
 push	[cs:rbb.rmc.ds]
 push	[cs:rbb.rmc.es]
 pop	es
 pop	ds
 popfd
 ret

regs_save:
use16
 mov	[cs:rbb.rmc.eax], eax
 mov	[cs:rbb.rmc.ecx], ecx
 mov	[cs:rbb.rmc.edx], edx
 mov	[cs:rbb.rmc.ebx], ebx
 mov	[cs:rbb.rmc.ebp], ebp
 mov	[cs:rbb.rmc.esi], esi
 mov	[cs:rbb.rmc.edi], edi
 push	es
 push	ds
 pushfd
 pop	[cs:rbb.rmc.efl]
 pop	[cs:rbb.rmc.ds]
 pop	[cs:rbb.rmc.es]
 ret

call_rm:
use32
 pushad
 ; switch to RM
 call	jump_to_rm
use16
 ; load registers
 call	regs_load
 pushf
 cli
 call	far [cs:rbb.segoff]
 ; save changed registers
 call	regs_save
 ; return to pmode
 call	jump_to_pm
use32
 popad
 ret

jump_rm:
use32
 ; switch to RM
 call	jump_to_rm
use16
 ; load registers
 call	regs_load
 ; jump to RM code
 jmp	far [cs:rbb.segoff]

hook_ints:
use32
 ; switch to RM
 call	jump_to_rm
use16
 ; nook int15
 xor	ax, ax
 mov	fs, ax
 ; hook int13
 mov	eax, [fs:4Ch]
 mov	[rbb.old_int13], eax	 
 mov	word [fs:4Ch], new_int13 
 mov	word [fs:4Eh], cs
 ; hook int15
 mov	eax, [fs:54h]
 mov	[rbb.old_int15], eax
 mov	word [fs:54h], new_int15
 mov	word [fs:56h], cs
 ; return to pmode
 call	jump_to_pm
use32
 ret

new_int13:
use16
 push	13h
 jmp	int_callback

new_int15:
use16
 cmp	ax, 0E820h
 jnz	@F
 cmp	edx, 0534D4150h
 jnz	@F
 push	15h
 jmp	int_callback
@@:
 jmp	far [cs:rbb.old_int15]

int_callback:
use16
 ; get interrupt number
 pop	[cs:rbb.int_num]
 ; save segment registers
 push	fs
 push	gs
 ; save registers
 call	regs_save
 ; save flags
 mov	bp, sp
 push	word [ss:bp+8]
 pop	word [cs:rbb.push_fl]
 call	jump_to_pm
use32
 ; call to PM callback
 call	[fs:rbb.int_cbk]
 ; return to RM
 call	jump_to_rm
use16
 ; load registers
 call	regs_load
 ; load segment registers
 pop	gs
 pop	fs
 retf	2


pm_enable:
use16
 ; save boot disk
 mov	[cs:rbb.boot_dsk], dl
 ; get return address
 xor	edx, edx
 pop	dx
 ; setup segment registers
 xor	ecx, ecx
 mov	cx, cs
 mov	ds, cx
 ; get rb_block offset
 shl	ecx, 4
 mov	[rbb.rb_base], ecx
 ; setup temporary PM stack to 5000h
 mov	[rbb.esp_32], 5000h
 mov	[rbb.rb_size], rb_kbs * 1024
 ; inverse real mode block signature in runtime
 ; to prevent finding it in false location
 not	[rbb.sign1]
 not	[rbb.sign2]
 ; correct GDT address
 add	[gdtr+2], ecx
 ; correct descriptors
 or	[pm16_cdes+2], ecx
 or	[pm16_ddes+2], ecx
 or	[pm32_edes+2], ecx
 ; correct PM/RM jumps
 add	[pm_jump], ecx
 mov	word [rm_jump], cs
 ; setup callback pointers
 lea	eax, [ecx+call_rm]
 mov	[rbb.call_rm], eax
 lea	eax, [ecx+jump_rm]
 mov	[rbb.jump_rm], eax
 lea	eax, [ecx+hook_ints]
 mov	[rbb.hook_ints], eax
 ; calculate pmode return address
 xor	eax, eax
 mov	ax, gs
 shl	eax, 4
 add	eax, edx
 mov	[rbb.segoff], eax
 ; jump to pmode
 call	jump_to_pm
use32
 ; return to caller
 jmp	[fs:rbb.segoff]

include 'a20.inc'

e_msg_2:
use16
 pop	si
@@:
 mov	al, [cs:si]
 inc	si
 test	al, al
 jz	$
 mov	ah, 0Eh
 xor	bx, bx
 int	10h
 jmp	@B

jump_to_pm:
use16
 ; disable interrupts
 cli
 ; test a20 gate
 call	a20_test_fast
 jnz	@F
 ; enable A20 gate
 call	enable_a20
 jnc	@F
 call	e_msg_2
 db 'a20 gate is not enabled',13,10,0
@@:
 ; get return address
 pop	ax
 movzx	eax, ax
 mov	[cs:rbb.ret_32], eax
 ; save real mode stack
 mov	[cs:rbb.sp_16], sp
 mov	[cs:rbb.ss_16], ss
 ; setup ds
 mov	ax, cs
 mov	ds, ax
 ; load GDTR
 lgdt	[gdtr]
 ; switch to protected mode
 mov	eax, cr0
 or	eax, 1
 mov	cr0, eax
 ; jump to PM code
pm_jump = $+2
 jmp32	CSEG:pm_start
pm_start:
use32
 ; load 4 GB data descriptor
 mov	ax, ESEG
 mov	fs, ax
 mov	ax, DSEG      
 mov	ds, ax
 mov	es, ax
 mov	gs, ax
 mov	ss, ax
 ; load PM stack
 mov	esp, [fs:rbb.esp_32]
 ; return to caller
 mov	eax, [fs:rbb.ret_32]
 add	eax, [fs:rbb.rb_base]
 push	eax
 ret

jump_to_rm:
use32
 ; get return address
 pop	[fs:rbb.ret_32]
 ; save PM stack
 mov	[fs:rbb.esp_32], esp
 ; load PM16 selector
 mov	ax, RDSEG
 mov	ds, ax
 mov	es, ax
 mov	ss, ax
 mov	fs, ax
 mov	gs, ax
 ; jump to PM16
 jmp	RCSEG:pm16_start
pm16_start:
use16
 ; clear PM bit in cr0
 mov	eax, cr0
 and	eax, 0FFFFFFFEh 
 mov	cr0, eax
 ; jump to real mode
rm_jump = $+3
 jmp	0:rm_start
rm_start:
 ; load RM segments
 mov	ax, cs
 mov	ds, ax
 mov	es, ax
 mov	fs, ax
 mov	gs, ax
 ; load RM stack
 xor	esp, esp
 mov	ss, [rbb.ss_16]
 mov	sp, [rbb.sp_16]
 ; return to caller
 mov	eax, [rbb.ret_32]
 sub	eax, [rbb.rb_base]
 push	ax
 ret

rb_size = $
rb_kbs	= (rb_size / 1024) + 1

repeat	512-(($+rb_block) mod 512)
 db 0
end repeat


boot_data:

