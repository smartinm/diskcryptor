#ifndef _CRYPTO_HEAD_H_
#define _CRYPTO_HEAD_H_

#include "volume.h"
#include "xts_fast.h"

int dc_decrypt_header(xts_key *hdr_key, dc_header *header, dc_pass *password);

#endif