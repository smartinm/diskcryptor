;
;   *
;   * DiskCryptor - open source partition encryption tool
;   * Copyright (c) 2007
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

.386p

include callconv.inc     
             
EXTRNP _gf128mul64_table,3 



_TEXT$00 SEGMENT DWORD PUBLIC 'CODE'

cPublicProc _aes_lrw_process, 7
 push	 ebp 
 push    esi
 push    edi
 push    ebx
 sub     esp, 10h 
 mov     esi, [esp+2Ch]   ; len  
 mov     edi, [esp+28h]   ; out
 mov     ebx, [esp+24h]   ; in
 lea     eax, [esp+30h]   ; idx 
 mov     ecx, [esp+38h]   ; key
 lea     ebp, [ecx+8000h] ; inctab
 mov     edx, esp         ; t
 stdCall _gf128mul64_table, <edx, eax, ecx>
crypt_loop:
 ; load data from input
 mov     eax, [ebx+00h] 
 mov     ecx, [ebx+04h] 
 mov     edx, [ebx+08h]
 xor     eax, [esp+00h]
 xor     ecx, [esp+04h]
 xor     edx, [esp+08h]
 mov     [edi+00h], eax
 mov     [edi+04h], ecx
 mov     [edi+08h], edx
 mov     eax, [ebx+0Ch]
 xor     eax, [esp+0Ch] 
 mov     [edi+0Ch], eax
 mov     ecx, edi
 mov     edx, edi
 call    dword ptr [esp+3Ch]
 mov     eax, [esp+00h]
 mov     ecx, [esp+04h]
 mov     edx, [esp+08h]
 xor     [edi+00h], eax
 xor     [edi+04h], ecx
 xor     [edi+08h], edx 
 mov     eax, [esp+0Ch]
 xor     [edi+0Ch], eax
 sub     esi, 10h
 jz      exit
 ; get index in inctab
 mov     eax, [esp+30h]
 not     eax
 bsf     edx, eax
 jnz     @F
 mov     eax, [esp+34h]
 not     eax
 bsf     edx, eax
 lea     edx, [edx+20h]
 jnz     @F
 mov     edx, 40h 
@@:
 shl     edx, 4
 add     edx, ebp
 mov     eax, [edx+00h]
 mov     ecx, [edx+04h]
 xor     [esp+00h], eax
 xor     [esp+04h], ecx
 mov     eax, [edx+08h]
 mov     ecx, [edx+0Ch] 
 xor     [esp+08h], eax
 xor     [esp+0Ch], ecx
 ; in += 16; out += 16; idx++;
 add     ebx, 10h
 add     edi, 10h
 add     dword ptr [esp+30h], 1
 adc     dword ptr [esp+34h], 0
 jmp     crypt_loop
 exit: 
 add     esp, 10h
 pop     ebx
 pop     edi
 pop     esi
 pop     ebp
stdRET  _aes_lrw_process
stdENDP _aes_lrw_process

_TEXT$00   ends
end
