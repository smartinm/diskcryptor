;*******************************************************************************
;llshl.asm - long shift left
;
;Entry:
;       EDX:EAX - long value to be shifted
;       CL    - number of bits to shift by
;
;Exit:
;       EDX:EAX - shifted value
;*******************************************************************************

format MS COFF

section '.text' code readable executable

public __allshl as '__allshl'

__allshl:
	cmp	cl, 64
	jae	clean
	cmp	cl, 32
	jae	@f
	shld	edx, eax, cl
	shl	eax, cl
	ret

@@:	mov	edx, eax
	xor	eax, eax
	and	cl, 31
	shl	edx, cl
	ret

clean:	xor	eax, eax
	mov	edx, eax
	ret
