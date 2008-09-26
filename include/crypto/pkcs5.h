#ifndef _PKCS5_
#define _PKCS5_

#define PRF_HMAC_SHA512 0
#define PRF_HMAC_SHA1   1
#define PRF_NUM         2

void pkcs5_2_prf(
		  int   prf_id, int i_count,
		  char *pwd,  size_t pwd_len, 
		  char *salt, size_t salt_len, 		  
		  char *dk, size_t dklen
		  );

#ifdef CRYPT_TESTS
 void make_hmac(int prf_id, char *k, size_t k_len, char *d, size_t d_len, char *out);
#endif

#endif