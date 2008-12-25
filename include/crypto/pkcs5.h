#ifndef _PKCS5_
#define _PKCS5_

void sha512_hmac(char *k, size_t k_len, char *d, size_t d_len, char *out);

void sha512_pkcs5_2(
	   int i_count,
	   void *pwd,  size_t pwd_len, 
	   char *salt, size_t salt_len, 		  
	   char *dk, size_t dklen
	   );

#endif