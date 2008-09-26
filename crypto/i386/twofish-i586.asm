;***************************************************************************
;*   Copyright (C) 2006 by Joachim Fritschi, <jfritschi@freenet.de>        *
;*   adapted for DiskCryptor by ntldr <ntldr@freed0m.org>                  *
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

format MS COFF

section '.text' code readable executable

in_blk	  EQU  4  ; input byte array address parameter
out_blk   EQU  8  ; output byte array address parameter
tfm	  EQU  12 ; Twofish context structure

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
R0D EQU   eax
R0B EQU   al
R0H EQU   ah

R1D EQU   ebx
R1B EQU   bl
R1H EQU   bh

R2D EQU   ecx
R2B EQU   cl
R2H EQU   ch

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

;
; * a input register containing a (rotated 16)
; * b input register containing b
; * c input register containing c
; * d input register containing d (already rol $1)
; * operations on a and b are interleaved to increase performance

macro encrypt_round a,b,c,d,round
{
	push	d#D
	movzx	edi, b#B
	mov	d#D, [ebp+edi*4+s1]
	movzx	edi, a#B
	mov	esi, [ebp+edi*4+s2]
	movzx	edi, b#H
	ror	b#D, 16
	xor	d#D, [ebp+edi*4+s2]
	movzx	edi, a#H
	ror	a#D, 16
	xor	esi, [ebp+edi*4+s3]
	movzx	edi, b#B
	xor	d#D, [ebp+edi*4+s3]
	movzx	edi, a#B
	xor	esi, [ebp+edi*4]
	movzx	edi, b#H
	ror	b#D, 15
	xor	d#D, [ebp+edi*4]
	movzx	edi, a#H
	xor	esi, [ebp+edi*4+s1]
	pop	edi
	add	esi, d#D
	add	d#D, esi
	add	esi, [ebp+k+round]
	xor	c#D, esi
	rol	c#D, 15
	add	d#D, [ebp+k+4+round]
	xor	d#D, edi
}

; * a input register containing a (rotated 16)
; * b input register containing b
; * c input register containing c
; * d input register containing d (already rol $1)
; * operations on a and b are interleaved to increase performance
; * last round has different rotations for the output preparation
macro encrypt_last_round a,b,c,d,round
{
	push	d#D
	movzx	edi, b#B
	mov	d#D, [ebp+edi*4+s1]
	movzx	edi, a#B
	mov	esi, [ebp+edi*4+s2]
	movzx	edi, b#H
	ror	b#D, 16
	xor	d#D, [ebp+edi*4+s2]
	movzx	edi, a#H
	ror	a#D, 16
	xor	esi, [ebp+edi*4+s3]
	movzx	edi, b#B
	xor	d#D, [ebp+edi*4+s3]
	movzx	edi, a#B
	xor	esi, [ebp+edi*4]
	movzx	edi, b#H
	ror	b#D, 16
	xor	d#D, [ebp+edi*4]
	movzx	edi, a#H
	xor	esi, [ebp+edi*4+s1]
	pop	edi
	add	esi, d#D
	add	d#D, esi
	add	esi, [ebp+k+round]
	xor	c#D, esi
	ror	c#D, 1
	add	d#D, [ebp+k+4+round]
	xor	d#D, edi
}

; * a input register containing a
; * b input register containing b (rotated 16)
; * c input register containing c
; * d input register containing d (already rol $1)
; * operations on a and b are interleaved to increase performance
macro decrypt_round a,b,c,d,round
{
	push	c#D
	movzx	edi, a#B
	mov	c#D, [ebp+edi*4]
	movzx	edi, b#B
	mov	esi, [ebp+edi*4+s3]
	movzx	edi, a#H
	ror	a#D, 16
	xor	c#D, [ebp+edi*4+s1]
	movzx	edi, b#H
	ror	b#D, 16
	xor	esi, [ebp+edi*4]
	movzx	edi, a#B
	xor	c#D, [ebp+edi*4+s2]
	movzx	edi, b#B
	xor	esi, [ebp+edi*4+s1]
	movzx	edi, a#H
	ror	a#D, 15
	xor	c#D, [ebp+edi*4+s3]
	movzx	edi, b#H
	xor	esi, [ebp+edi*4+s2]
	pop	edi
	add	c#D, esi
	add	esi, c#D
	add	c#D, [ebp+k+round]
	xor	c#D, edi
	add	esi, [ebp+k+4+round]
	xor	d#D, esi
	rol	d#D, 15
}

; * a input register containing a
; * b input register containing b (rotated 16)
; * c input register containing c
; * d input register containing d (already rol $1)
; * operations on a and b are interleaved to increase performance
; * last round has different rotations for the output preparation
macro decrypt_last_round a,b,c,d,round
{
	push	c#D
	movzx	edi, a#B
	mov	c#D, [ebp+edi*4]
	movzx	edi, b#B
	mov	esi, [ebp+edi*4+s3]
	movzx	edi, a#H
	ror	a#D, 16
	xor	c#D, [ebp+edi*4+s1]
	movzx	edi, b#H
	ror	b#D, 16
	xor	esi, [ebp+edi*4]
	movzx	edi, a#B
	xor	c#D, [ebp+edi*4+s2]
	movzx	edi, b#B
	xor	esi, [ebp+edi*4+s1]
	movzx	edi, a#H
	ror	a#D, 16
	xor	c#D, [ebp+edi*4+s3]
	movzx	edi, b#H
	xor	esi, [ebp+edi*4+s2]
	pop	edi
	add	c#D, esi
	add	esi, c#D
	add	c#D, [ebp+k+round]
	xor	c#D, edi
	add	esi, [ebp+k+4+round]
	xor	d#D, esi
	ror	d#D, 1
}

public twofish_enc_blk as '_twofish_encrypt@12'
public twofish_dec_blk as '_twofish_decrypt@12'

twofish_enc_blk:
	push	ebp		       ; save registers according to calling convention
	push	ebx
	push	esi
	push	edi
	mov	ebp, [tfm + 16+esp]    ; abuse the base pointer: set new base bointer to the crypto tfm
	mov	edi, [in_blk+16+esp]   ; input adress in edi

	mov	eax, [edi]
	mov	ebx, [b_offset+edi]
	mov	ecx, [c_offset+edi]
	mov	edx, [d_offset+edi]
	input_whitening eax, ebp, a_offset
	ror	eax, 16
	input_whitening ebx, ebp, b_offset
	input_whitening ecx, ebp, c_offset
	input_whitening edx, ebp, d_offset
	rol	edx, 1

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

	output_whitening eax, ebp, c_offset
	output_whitening ebx, ebp, d_offset
	output_whitening ecx, ebp, a_offset
	output_whitening edx, ebp, b_offset
	mov	edi, [out_blk+16+esp]
	mov	[c_offset+edi], eax
	mov	[d_offset+edi], ebx
	mov	[edi], ecx
	mov	[b_offset+edi], edx
	pop	edi
	pop	esi
	pop	ebx
	pop	ebp
	retn	0Ch


twofish_dec_blk:
	push	ebp		       ; save registers according to calling convention*/
	push	ebx
	push	esi
	push	edi


	mov	ebp, [tfm + 16+esp]    ; abuse the base pointer: set new base bointer to the crypto tfm
	mov	edi, [in_blk + 16+esp] ; input adress in edi

	mov	eax, [edi]
	mov	ebx, [b_offset+edi]
	mov	ecx, [c_offset+edi]
	mov	edx, [d_offset+edi]
	output_whitening eax, ebp, a_offset
	output_whitening ebx, ebp, b_offset
	ror	ebx, 16
	output_whitening ecx, ebp, c_offset
	output_whitening edx, ebp, d_offset
	rol	ecx, 1

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

	input_whitening eax, ebp, c_offset
	input_whitening ebx, ebp, d_offset
	input_whitening ecx, ebp, a_offset
	input_whitening edx, ebp, b_offset
	mov	edi, [out_blk + 16+esp]
	mov	[c_offset+edi], eax
	mov	[d_offset+edi], ebx
	mov	[edi], ecx
	mov	[b_offset+edi], edx

	pop	edi
	pop	esi
	pop	ebx
	pop	ebp
	retn	0Ch
