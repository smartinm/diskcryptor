
struct rm_ctx
  union
    eax  dd ?
    ax	 dw ?
    union
      al db ?
      ah db ?
    ends
  ends
  union
    ecx  dd ?
    cx	 dw ?
    union
      cl db ?
      ch db ?
    ends
  ends
  union
    edx  dd ?
    dx	 dw ?
    union
      dl db ?
      dh db ?
    ends
  ends
  union
    ebx  dd ?
    bx	 dw ?
    union
      bl db ?
      bh db ?
    ends
  ends
  union
    ebp  dd ?
    bp	 dw ?
  ends
  union
    esi  dd ?
    si	 dw ?
  ends
  union
    edi  dd ?
    di	 dw ?
  ends
  efl	 dd ?
  ds	 dw ?
  es	 dw ?
ends

struct ldr_info
 password  rb 65  ; bootauth password
ends

struct rb_data
  sign1     dd 0FE0AC0AAh ; 01F53F55h
  sign2     dd 061BC9E1Bh ; 9E4361E4h
  sign3     dd 013B3F73Dh
  rb_base   dd ?     ; real mode block base
  rb_size   dd ?     ; real mode block size (including 4kb for stack)
  pm_base   dd ?     ; pmode image base
  pm_size   dd ?     ; pmode image size
  info	    ldr_info
  ; volatile data
  ret_32    dd ?   ; return address for RM <-> PM jump
  sp_16     dw ?   ; real mode stack
  ss_16     dw ?   ; real mode ss
  esp_32    dd ?   ; pmode stack
  segoff    dd ?   ; real mode call seg/off
  jump_rm   dd ?   ; real mode jump proc
  call_rm   dd ?   ; real mode call proc
  hook_ints dd ?   ; hook interrupts proc
  int_cbk   dd ?   ; protected mode callback
  int_num   dw ?   ; interrupt number
  boot_dsk  db ?   ; boot disk number
  old_int15 dd ?   ; old int15 handler
  old_int13 dd ?   ; old int13 handler
  rmc	    rm_ctx ; real mode call context
  push_fl   dw ?   ; flags pushed to stack
  buff	    rb 32  ; 32 bytes buffer
ends
