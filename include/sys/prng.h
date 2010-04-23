#ifndef _PRNG_
#define _PRNG_

#include "defines.h"
#include "aes_key.h"

void rnd_add_buff(void *data, int size);
void rnd_reseed_now();
int  rnd_get_bytes(u8 *buf, int len);
int  rnd_init_prng();

#endif