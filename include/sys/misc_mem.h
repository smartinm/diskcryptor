#ifndef _MISC_MEM_H_
#define _MISC_MEM_H_

#define MEM_SECURE  1  /* memory block contain private data */
#define MEM_ZEROED  2  /* allocated block can be zeroed     */
#define MEM_SUCCESS 4  /* block must be allocated anymore   */
#define MEM_FAST    8  /* allocate from lookasize list      */
#define MEM_PADDED  16

void *mm_map_mdl_success(PMDL mdl);
PMDL  mm_allocate_mdl_success(void *data, u32 size);
void *mm_alloc_success(POOL_TYPE pool, SIZE_T bytes, u32 tag);

void *mm_alloc(size_t size, int flags);
void  mm_free(void *mem);

void mm_init();
void mm_uninit();

#endif