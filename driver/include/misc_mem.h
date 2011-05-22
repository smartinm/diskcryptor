#ifndef _MISC_MEM_H_
#define _MISC_MEM_H_

#define MEM_SECURE  0x01  /* memory block contain private data */
#define MEM_ZEROED  0x02  /* allocated block can be zeroed     */
#define MEM_SUCCESS 0x04  /* block must be allocated anymore   */
#define MEM_FAST    0x08  /* allocate from lookasize list      */
#define MEM_PAGED   0x10  /* allocate from paged pool */

/* function types declaration */
ALLOCATE_FUNCTION mm_alloc_success;

void *mm_map_mdl_success(PMDL mdl);
PMDL  mm_allocate_mdl_success(void *data, u32 size);
PIRP  mm_allocate_irp_success(CCHAR StackSize);
void *mm_alloc_success(POOL_TYPE pool, SIZE_T bytes, u32 tag);

void *mm_alloc(size_t size, int flags);
void  mm_free(void *mem);

void mm_init();
void mm_uninit();

#endif