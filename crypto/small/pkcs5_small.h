#ifndef _PKCS5_SMALL_H_
#define _PKCS5_SMALL_H_

void sha512_hmac(const char *k, size_t k_len, const char *d, size_t d_len, char *out);

void sha512_pkcs5_2(
	   int i_count,
	   const void *pwd,  size_t pwd_len, 
	   const char *salt, size_t salt_len,
	   char *dk,   size_t dklen
	   );

#endif