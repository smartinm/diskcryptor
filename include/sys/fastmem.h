#ifndef _FASTMEM_
#define _FASTMEM_

void *fast_alloc(size_t size);
void  fast_free(void *mem);

void fastmem_init();
void fastmem_free();

#endif