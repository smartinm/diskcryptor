#ifndef _PKCS5_H_
#define _PKCS5_H_

void _stdcall sha512_hmac(const void *k, size_t k_len, const void *d, size_t d_len, char *out);
void _stdcall sha512_pkcs5_2(int i_count, const void *pwd, size_t pwd_len, const char *salt, size_t salt_len, char *dk, size_t dklen);

#endif