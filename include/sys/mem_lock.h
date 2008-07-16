#ifndef _MEM_LOCK_
#define _MEM_LOCK_

void mem_lock_init();
int  dc_lock_mem(void *mem, u32 size, void *f_obj);
int  dc_unlock_mem(void *mem, void *f_obj);
void dc_clean_locked_mem(void *f_obj);

#endif