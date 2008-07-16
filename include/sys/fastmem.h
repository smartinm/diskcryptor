#ifndef _FASTMEM_
#define _FASTMEM_

#define MAX_MEM_SIZE  1024*1024  /* maximum fast allocate           */
#define NUM_MEM_LISTS 10         /* number of lookaside lists       */
#define MEM_INC       512        /* block length increment          */
#define MEM_ADD       100        /* additional memory size on block */

void *fast_alloc(size_t size);
void  fast_free(void *mem);

void fastmem_init();
void fastmem_free();

#endif