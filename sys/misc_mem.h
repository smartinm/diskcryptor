#ifndef _MISC_MEM_H_
#define _MISC_MEM_H_

void *mm_map_mdl_success(PMDL mdl);
PMDL  mm_allocate_mdl_success(void *data, u32 size);
void *mm_alloc_success(POOL_TYPE pool, SIZE_T bytes, u32 tag);

#define mem_alloc_success(_x) ( mm_alloc_success(NonPagedPoolCacheAligned, (_x), '4_cd') )

#endif