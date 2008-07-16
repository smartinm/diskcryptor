#ifndef _PKCS5_
#define _PKCS5_

void sha1_hmac(char *k, int k_len, char *d, int d_len, char *out);

void sha1_pkcs5_2(
		  char *pwd,  int pwd_len, 
		  char *salt, int salt_len, 
		  int iterations, 
		  char *dk, int dklen
		  );

#endif