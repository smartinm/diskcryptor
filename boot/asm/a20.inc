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
use16

; IN  - cx=loops
; OUT - ZF=0 for A20 on, ZF=1 for A20 off.
a20_test:
 push	fs
 push	es
 push	cx
 xor	ax, ax
 mov	fs, ax	; fs = 0
 dec	ax
 mov	es, ax	; es = 0xffff
 mov	eax, [fs:200h]
 push	eax	       ; save old dword
@@:
 inc	eax
 mov	[fs:200h], eax
 call	io_delay       ; Serialize and make delay constant
 cmp	eax, [es:210h]
 loopz	@B
 pop	eax
 mov	[fs:200h], eax ; restore saved dword
 pop	cx
 pop	es
 pop	fs
 ret

a20_test_fast: ; ZF=0 for A20 on, ZF=1 for A20 off.
 push	fs
 push	es
 xor	ax, ax
 mov	fs, ax	; fs = 0
 dec	ax
 mov	es, ax	; es = 0xffff
 mov	ax, [fs:200h]
 push	ax
 cmp	ax, [es:210h]
 jnz	@F
 not	ax
 mov	[fs:200h], ax
 cmp	ax, [es:210h]
@@:
 pop	word [fs:200h]
 pop	es
 pop	fs
 ret

io_delay:
 push	ax
 mov	al, 80h
 out	80h, al
 pop	ax
 ret

enable_a20:
 pushad
 mov	dx, 255 ; number of times to try
a20_retry:
 mov	cx, 32	; number of A20 test loops
 ; first, check to see if A20 is already enabled
 call	a20_test
 jnz	a20_done
 ; try enabling A20 through the keyboard controller
 call	enable_a20_kbc
 xor	cx, cx
 dec	cx	 ; cx = 0xffff
 call	a20_test
 jnz	a20_done
 ; finally, try enabling the "fast A20 gate"
 call	enable_a20_fast
 call	a20_test
 jnz	a20_done
 ; next retry
 dec	dx
 jnz	a20_retry
 ; a20 not enabled
 stc	; set CF=1
 jmp	@F
a20_done:
 ; a20 enabled
 clc	; set CF=0
@@:
 popad
 ret


enable_a20_fast:
 in	al, 92h
 test	al, 2
 jnz	@F	 ; chipset bug: do nothing if already set
 or	al, 2	 ; enable A20
 and	al, 0FEh ; do not reset machine
 out	92h, al
@@:
 ret

empty_8042:
 push	cx
 xor	cx, cx
 dec	cx	 ; cx = 0xffff
@@:
 call	io_delay
 in	al, 64h  ; read 8042 status from port 64h
 cmp	al, 0FFh ; legacy-free machine without keyboard
 jz	@F
 test	al, 1	 ; is output buffer(data FROM keyboard) full?
 jnz	empty_1
 test	al, 2	 ; is input buffer(data TO keyboard) empty?
 jnz	empty_2  ; no, wait until time out
 jmp	@F	 ; both input buffer and output buffer are empty
empty_1:
 call	io_delay
 in	al, 60h  ; read output buffer and discard input
empty_2:
 loop	@B
@@:
 pop	cx
 ret

enable_a20_kbc:
 call	empty_8042
 mov	al, 0D1h  ; command write
 out	64h, al
 call	empty_8042
 mov	al, 0DFh  ; A20 on
 out	60h, al
 call	empty_8042
 ret

