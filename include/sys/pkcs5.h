#ifndef _PKCS5_
#define _PKCS5_

void sha1_hmac(char *k, size_t k_len, char *d, size_t d_len, char *out);

void sha1_pkcs5_2(
		  char *pwd,  size_t pwd_len, 
		  char *salt, size_t salt_len, 
		  int iterations, 
		  char *dk, size_t dklen
		  );

#endif