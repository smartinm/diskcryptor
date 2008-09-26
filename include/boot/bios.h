#ifndef _BIOS_
#define _BIOS_

#pragma pack (push, 1)

typedef struct _rm_ctx {
	union
	{
		u32 eax;
		union 
		{
			u16 ax;
			struct {
				u8  al;
				u8  ah;
			};
		};
	};
	union
	{
		u32 ecx;
		union 
		{
			u16 cx;
			struct {
				u8  cl;
				u8  ch;
			};
		};
	};
	
	union
	{
		u32 edx;
		union 
		{
			u16 dx;		
			struct {
				u8  dl;
				u8  dh;
			};
		};
	};

	union
	{
		u32 ebx;
		union 
		{
			u16 bx;
			struct {
				u8  bl;
				u8  bh;
			};
		};
	};

	union {
		u32 ebp;
		u16 bp;
	};
	
	union {
		u32 esi;
		u16 si;
	};
	
	union {
		u32 edi;
		u16 di;
	};

	u32 efl;	
	u16 ds;
	u16 es;

} rm_ctx;

typedef struct _ldr_info {
	char   password[MAX_PASSWORD + 1]; /* bootauth password */
} ldr_info;

typedef struct _rb_data {	
	u32      sign1;        /*  */
	u32      sign2;        /*  */
	u32      sign3;        /*  */
	u32      rb_base;      /* real mode block base                            */
	u32      rb_size;      /* real mode block size (including stack)          */
	u32      pm_base;      /* pmode image base          */
	u32      pm_size;      /* pmode image size          */
	ldr_info info;
	/* volatile data */
	u32      ret_32;       /* return address for RM <-> PM jump               */
	u16      sp_16;        /* real mode stack                                 */
	u16      ss_16;        /* real mode ss                                    */ 
	u32      esp_32;       /* pmode stack                                     */	
	u32      segoff;       /* real mode call seg/off    */	
	void   (*jump_rm)();   /* real mode jump proc       */
	void   (*call_rm)();   /* real mode call proc       */
	void   (*hook_ints)(); /* hook interrupts proc      */
	void    *int_cbk;      /* protected mode callback   */
	u16      int_num;      /* interrupt number          */	
	u8       boot_dsk;     /* boot disk number          */
	u32      old_int15;    /* old int15 handler         */
	u32      old_int13;    /* old int13 handler         */
	rm_ctx   rmc;          /* real mode call context    */
	u16      push_fl;      /* flags pushed to stack     */
	u8       buff[32];     /* 32 bytes buffer */
} rb_data;

typedef struct _rb_legacy {
	u32    sign1;        /*  */
	u32    sign2;        /*  */
	u32    ret_32;       /* return address for RM <-> PM jump               */
	u32    esp_16;       /* real mode stack                                 */
	u16    ss_16;        /* real mode ss                                    */ 
	u32    esp_32;       /* pmode stack                                     */	
	u32    rb_base;      /* real mode block base                            */
	u32    rb_size;      /* real mode block size (including 2kb for stack)  */
	u32    rb_code;      /* real mode block code area */
	u32    pm_base;      /* pmode image base          */
	u32    pm_size;      /* pmode image size          */	
} rb_legacy;


#pragma pack (pop)

#define FL_CF		0x0001		// Carry Flag
#define FL_RESV1	0x0002		// Reserved - Must be 1
#define FL_PF		0x0004		// Parity Flag
#define FL_RESV2	0x0008		// Reserved - Must be 0
#define FL_AF		0x0010		// Auxiliary Flag
#define FL_RESV3	0x0020		// Reserved - Must be 0
#define FL_ZF		0x0040		// Zero Flag
#define FL_SF		0x0080		// Sign Flag
#define FL_TF		0x0100		// Trap Flag (Single Step)
#define FL_IF		0x0200		// Interrupt Flag
#define FL_DF		0x0400		// Direction Flag
#define FL_OF		0x0800		// Overflow Flag

#define pm_off(seg,off) (pv(((u32)seg << 4) + (u32)off) )
#define rm_seg(off)     ((u16)((u32)off >> 4))
#define rm_off(off)     ((u16)((u32)off & 0x0F))

#ifdef BOOT_LDR
 void set_ctx(u16 ax, rm_ctx *ctx);
 int  bios_call(int num, rm_ctx *ctx);
 void bios_jump_boot(u8 disk);
 void bios_reboot();

 extern rb_data *rb_dat;
#endif

#define MTRRcap_MSR     0x0fe
#define MTRRdefType_MSR 0x2ff

#define MTRRphysBase_MSR(reg) (0x200 + 2 * (reg))
#define MTRRphysMask_MSR(reg) (0x200 + 2 * (reg) + 1)

#define CR0_CD      (1 << 30)
#define MTRR_DEF_E  (1 << 11)
#define MTRR_V      (1 << 11)
#define CPUID_MTRR  (1 << 12)



#endif