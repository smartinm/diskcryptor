;
;   *
;   * DiskCryptor - open source partition encryption tool
;   * Copyright (c) 2009
;   * ntldr <ntldr@diskcryptor.net> PGP key ID - 0xC48251EB4F8E4E6E
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
bits 64

%define NEH_LOAD_KEY	00000080h      ; load schedule from memory
%define NEH_ENCRYPT	00000000h      ; encryption
%define NEH_DECRYPT	00000200h      ; decryption
%define NEH_KEY128	00000000h+0ah  ; 128 bit key
%define NEH_KEY192	00000400h+0ch  ; 192 bit key
%define NEH_KEY256	00000800h+0eh  ; 256 bit key
%define NEH_ENC_LOAD	(NEH_ENCRYPT | NEH_LOAD_KEY)
%define NEH_DEC_LOAD	(NEH_DECRYPT | NEH_LOAD_KEY)

align 16
enc_cwd dd (NEH_ENC_LOAD | NEH_KEY256), 0, 0
align 16
dec_cwd dd (NEH_DEC_LOAD | NEH_KEY256), 0, 0

global aes256_ace_available
global aes256_encrypt_ace
global aes256_decrypt_ace

align 32
aes256_ace_available:
 push	 rbx
 ; test for VIA CPU
 mov	 eax, 0C0000000h
 cpuid
 cmp	 eax, 0C0000001h
 jb	 no_ace
 ; read VIA flags
 mov	 eax, 0C0000001h
 cpuid
 and	 edx, 0C0h ; ACE_MASK,CPUID EDX code for ACE
 cmp	 edx, 0C0h ; ACE_MASK,CPUID EDX code for ACE
 jnz	 no_ace
 ; ACE present
 xor	 rax, rax
 inc	 eax
 jmp	 end_ace
no_ace:
 xor	 rax, rax
end_ace:
 pop	 rbx
 ret

align	32
aes256_encrypt_ace:
 push	 rbx
 push	 rsi
 push	 rdi
 mov	 rsi, rcx ; in
 mov	 rdi, rdx ; out
 mov	 rbx, r8  ; key
 lea	 rdx, [enc_cwd wrt rip]
 xor	 rcx, rcx
 inc	 ecx
 db 0F3h, 0Fh, 0A7h, 0C8h
 pop	 rdi
 pop	 rsi
 pop	 rbx
 ret

align	32
aes256_decrypt_ace
 push	 rbx
 push	 rsi
 push	 rdi
 mov	 rsi, rcx	  ; in
 mov	 rdi, rdx	  ; out
 lea	 rbx, [r8+4*15*4] ; key
 lea	 rdx, [dec_cwd wrt rip]
 xor	 rcx, rcx
 inc	 ecx
 db 0F3h, 0Fh, 0A7h, 0C8h
 pop	 rdi
 pop	 rsi
 pop	 rbx
 ret

