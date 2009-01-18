;***************************************************************************
;*   Copyright (C) 2006 by Joachim Fritschi, <jfritschi@freenet.de>        *
;*   adapted for DiskCryptor by ntldr <ntldr@diskcryptor.net>                  *
;*       PGP key ID - 0xC48251EB4F8E4E6E                                   *
;*                                                                         *
;*   This program is free software; you can redistribute it and/or modify  *
;*   it under the terms of the GNU General Public License as published by  *
;*   the Free Software Foundation; either version 2 of the License, or     *
;*   (at your option) any later version.                                   *
;*                                                                         *
;*   This program is distributed in the hope that it will be useful,       *
;*   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
;*   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
;*   GNU General Public License for more details.                          *
;*                                                                         *
;*   You should have received a copy of the GNU General Public License     *
;*   along with this program; if not, write to the                         *
;*   Free Software Foundation, Inc.,                                       *
;*   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
;***************************************************************************

format MS64 COFF

section '.text' code readable executable

a_offset  EQU	0
b_offset  EQU	4
c_offset  EQU	8
d_offset  EQU	12

; Structure of the crypto context struct
s0  EQU    0	   ; S0 Array 256 Words each
s1  EQU    1024    ; S1 Array
s2  EQU    2048    ; S2 Array
s3  EQU    3072    ; S3 Array
w   EQU    4096    ; 8 whitening keys (word)
k   EQU    4128    ; key 1-32 ( word )

; define a few register aliases to allow macro substitution
R0  EQU   rax
R0D EQU   eax
R0B EQU   al
R0H EQU   ah

R1  EQU   rbx
R1D EQU   ebx
R1B EQU   bl
R1H EQU   bh

R2  EQU   rcx
R2D EQU   ecx
R2B EQU   cl
R2H EQU   ch

R3  EQU   rdx
R3D EQU   edx
R3B EQU   dl
R3H EQU   dh


; performs input whitening
macro input_whitening src,context,offset
{
  xor src, [w+(context)+offset]
}

; performs input whitening
macro output_whitening src,context,offset
{
  xor src, [w+16+(context)+offset]
}


; * a input register containing a (rotated 16)
; * b input register containing b
; * c input register containing c
; * d input register containing d (already rol $1)
; * operations on a and b are interleaved to increase performance
macro encrypt_round a,b,c,d,round
{
	movzx	edi,  b#B
	mov	r11d, [r8+rdi*4+s1]
	movzx	edi,  a#B
	mov	r9d,  [r8+rdi*4+s2]
	movzx	edi,  b#H
	ror	b#D,  16
	xor	r11d, [r8+rdi*4+s2]
	movzx	edi,  a#H
	ror	a#D,  16
	xor	r9d,  [r8+rdi*4+s3]
	movzx	edi,  b#B
	xor	r11d, [r8+rdi*4+s3]
	movzx	edi,  a#B
	xor	r9d,  [r8+rdi*4]
	movzx	edi,  b#H
	ror	b#D,  15
	xor	r11d, [r8+rdi*4]
	movzx	edi,  a#H
	xor	r9d,  [r8+rdi*4+s1]
	add	r9d,  r11d
	add	r11d, r9d
	add	r9d,  [r8+k+round]
	xor	c#D,  r9d
	rol	c#D,  15
	add	r11d, [r8+k+4+round]
	xor	d#D,  r11d
}

; * a input register containing a(rotated 16)
; * b input register containing b
; * c input register containing c
; * d input register containing d (already rol $1)
; * operations on a and b are interleaved to increase performance
; * during the round a and b are prepared for the output whitening
macro encrypt_last_round a,b,c,d,round
{
	mov	r10d, b#D
	shl	r10,  32
	movzx	edi,  b#B
	mov	r11d, [r8+rdi*4+s1]
	movzx	edi,  a#B
	mov	r9d,  [r8+rdi*4+s2]
	movzx	edi,  b#H
	ror	b#D,  16
	xor	r11d, [r8+rdi*4+s2]
	movzx	edi,  a#H
	ror	a#D,  16
	xor	r9d,  [r8+rdi*4+s3]
	movzx	edi,  b#B
	xor	r11d, [r8+rdi*4+s3]
	movzx	edi,  a#B
	xor	r9d,  [r8+rdi*4]
	xor	r10,  a
	movzx	edi,  b#H
	xor	r11d, [r8+rdi*4]
	movzx	edi,  a#H
	xor	r9d,  [r8+rdi*4+s1]
	add	r9d,  r11d
	add	r11d, r9d
	add	r9d,  [r8+k+round]
	xor	c#D,  r9d
	ror	c#D,  1
	add	r11d, [r8+k+4+round]
	xor	d#D,  r11d
}

; * a input register containing a
; * b input register containing b (rotated 16)
; * c input register containing c (already rol $1)
; * d input register containing d
; * operations on a and b are interleaved to increase performance
macro decrypt_round a,b,c,d,round
{
	movzx	edi,  a#B
	mov	r9d,  [r8+rdi*4]
	movzx	edi,  b#B
	mov	r11d, [r8+rdi*4+s3]
	movzx	edi,  a#H
	ror	a#D,  16
	xor	r9d,  [r8+rdi*4+s1]
	movzx	edi,  b#H
	ror	b#D,  16
	xor	r11d, [r8+rdi*4]
	movzx	edi,  a#B
	xor	r9d,  [r8+rdi*4+s2]
	movzx	edi,  b#B
	xor	r11d, [r8+rdi*4+s1]
	movzx	edi,  a#H
	ror	a#D,  15
	xor	r9d,  [r8+rdi*4+s3]
	movzx	edi,  b#H
	xor	r11d, [r8+rdi*4+s2]
	add	r9d,  r11d
	add	r11d, r9d
	add	r9d,  [r8+k+round]
	xor	c#D,  r9d
	add	r11d, [r8+k+4+round]
	xor	d#D,  r11d
	rol	d#D,  15
}

; * a input register containing a
; * b input register containing b
; * c input register containing c (already rol $1)
; * d input register containing d
; * operations on a and b are interleaved to increase performance
; * during the round a and b are prepared for the output whitening
macro decrypt_last_round a,b,c,d,round
{
	movzx	edi,  a#B
	mov	r9d,  [r8+rdi*4]
	movzx	edi,  b#B
	mov	r11d, [r8+rdi*4+s3]
	movzx	edi,  b#H
	ror	b#D,  16
	xor	r11d, [r8+rdi*4]
	movzx	edi,  a#H
	mov	r10d, b#D
	shl	r10,  32
	xor	r10,  a
	ror	a#D,  16
	xor	r9d,  [r8+rdi*4+s1]
	movzx	edi,  b#B
	xor	r11d, [r8+rdi*4+s1]
	movzx	edi,  a#B
	xor	r9d,  [r8+rdi*4+s2]
	movzx	edi,  b#H
	xor	r11d, [r8+rdi*4+s2]
	movzx	edi,  a#H
	xor	r9d,  [r8+rdi*4+s3]
	add	r9d,  r11d
	add	r11d, r9d
	add	r9d,  [r8+k+round]
	xor	c#D,  r9d
	add	r11d, [r8+k+4+round]
	xor	d#D,  r11d
	ror	d#D,  1
}

public twofish_enc_blk as 'twofish_encrypt'
public twofish_dec_blk as 'twofish_decrypt'

twofish_enc_blk:
	pushq	R1
	push	rsi
	push	rdi
	; r8 contains the crypto tfm adress
	; rdx contains the output adress
	; rcx contains the input adress
	mov	rsi, rdx

	mov	R1, [rcx]
	mov	R3, [rcx+8]

	input_whitening R1, r8, a_offset
	input_whitening R3, r8, c_offset
	mov	R0D, R1D
	rol	R0D, 16
	shr	R1, 32
	mov	R2D, R3D
	shr	R3, 32
	rol	R3D, 1

	encrypt_round R0,R1,R2,R3,0
	encrypt_round R2,R3,R0,R1,8
	encrypt_round R0,R1,R2,R3,2*8
	encrypt_round R2,R3,R0,R1,3*8
	encrypt_round R0,R1,R2,R3,4*8
	encrypt_round R2,R3,R0,R1,5*8
	encrypt_round R0,R1,R2,R3,6*8
	encrypt_round R2,R3,R0,R1,7*8

	encrypt_round R0,R1,R2,R3,8*8
	encrypt_round R2,R3,R0,R1,9*8
	encrypt_round R0,R1,R2,R3,10*8
	encrypt_round R2,R3,R0,R1,11*8
	encrypt_round R0,R1,R2,R3,12*8
	encrypt_round R2,R3,R0,R1,13*8
	encrypt_round R0,R1,R2,R3,14*8
	encrypt_last_round R2,R3,R0,R1,15*8

	output_whitening r10, r8, a_offset
	mov	[rsi], r10

	shl	R1, 32
	xor	R1, R0

	output_whitening R1, r8, c_offset
	mov	[rsi+8], R1

	pop	rdi
	pop	rsi

	popq	R1
	ret

twofish_dec_blk:
	pushq	R1
	push	rsi
	push	rdi
	; r8 contains the crypto tfm adress
	; rdx contains the output adress
	; rcx contains the input adress
	mov	rsi, rdx

	mov	R1, [rcx]
	mov	R3, [rcx+8]

	output_whitening R1, r8, a_offset
	output_whitening R3, r8, c_offset
	mov	R0D, R1D
	shr	R1, 32
	rol	R1D, 16
	mov	R2D, R3D
	shr	R3, 32
	rol	R2D, 1

	decrypt_round R0,R1,R2,R3,15*8
	decrypt_round R2,R3,R0,R1,14*8
	decrypt_round R0,R1,R2,R3,13*8
	decrypt_round R2,R3,R0,R1,12*8
	decrypt_round R0,R1,R2,R3,11*8
	decrypt_round R2,R3,R0,R1,10*8
	decrypt_round R0,R1,R2,R3,9*8
	decrypt_round R2,R3,R0,R1,8*8
	decrypt_round R0,R1,R2,R3,7*8
	decrypt_round R2,R3,R0,R1,6*8
	decrypt_round R0,R1,R2,R3,5*8
	decrypt_round R2,R3,R0,R1,4*8
	decrypt_round R0,R1,R2,R3,3*8
	decrypt_round R2,R3,R0,R1,2*8
	decrypt_round R0,R1,R2,R3,1*8
	decrypt_last_round R2,R3,R0,R1,0

	input_whitening r10, r8, a_offset
	mov	[rsi], r10

	shl	R1, 32
	xor	R1, R0

	input_whitening R1, r8, c_offset
	mov	[rsi+8], R1

	pop	rdi
	pop	rsi

	popq	R1
	ret
