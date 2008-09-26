;
;   *
;   * DiskCryptor - open source partition encryption tool
;   * Copyright (c) 2007-2008
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

format MS COFF

section '.text' code readable executable  

public gf128_mul64 as '_gf128_mul64@12'

gf_a = 4
gf_b = 8
gf_p = 12

gf128_mul64: ; a, b, p
 push  ebp
 push  esi
 push  edi
 push  ebx
 mov   esi, esp
 mov   ebp, [esi+10h+gf_p]
 mov   edi, [esi+10h+gf_b]
 xor   eax, eax
 mov   [ebp+00h], eax
 mov   [ebp+04h], eax
 mov   [ebp+08h], eax
 mov   [ebp+0Ch], eax
 mov   eax, [esi+10h+gf_a]
 mov   ebx, [eax+00h]
 mov   ecx, [eax+04h]
 mov   edx, [eax+08h]
 mov   esi, [eax+0Ch]
 mov   ebp, 63
bit_loop:
 push  edx
 mov   eax, 31
 mov   edx, ebp
 shr   edx, 5
 sub   eax, ebp
 mov   edx, [edi+edx*4]
 bswap edx
 bt    edx, eax
 pop   edx
 jnc   no_xor 
 mov   eax, [esp+10h+gf_p]
 xor   [eax+00h], ebx
 xor   [eax+04h], ecx
 xor   [eax+08h], edx
 xor   [eax+0Ch], esi
no_xor:
 test  ebx, 128
 bswap ebx
 bswap ecx
 bswap edx
 bswap esi
 clc
 rcl   esi, 1
 rcl   edx, 1
 rcl   ecx, 1
 rcl   ebx, 1
 bswap ebx
 bswap ecx
 bswap edx
 bswap esi
 jz    @F
 xor   esi, 87000000h
@@:
 mov   eax, ebp
 dec   ebp
 test  eax, eax
 jnz   bit_loop
 pop   ebx
 pop   edi
 pop   esi
 pop   ebp
 retn  0Ch


