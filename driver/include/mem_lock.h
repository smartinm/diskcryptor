#ifndef _MEM_LOCK_H_
#define _MEM_LOCK_H_

int  mm_lock_user_memory(void *mem, u32 size, void *key);
void mm_unlock_user_memory(void *mem, void *key);
void mm_init_mem_lock();

#endif