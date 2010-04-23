#include "defines.h"
#include "crypto_head.h"
#include "pkcs5.h"
#include "crc32.h"
#include "misc_mem.h"

int dc_decrypt_header(xts_key *hdr_key, dc_header *header, dc_pass *password)
{
	u8        dk[DISKKEY_SIZE];
	int       i, succs = 0;
	dc_header *hcopy;

	if ( (hcopy = mm_alloc(sizeof(dc_header), MEM_SECURE)) == NULL ) {
		return 0;
	}
	sha512_pkcs5_2(
		1000, password->pass, password->size, 
		header->salt, PKCS5_SALT_SIZE, dk, PKCS_DERIVE_MAX);

	for (i = 0; i < CF_CIPHERS_NUM; i++)
	{
		xts_set_key(dk, i, hdr_key);

		xts_decrypt(
			pv(header), pv(hcopy), sizeof(dc_header), 0, hdr_key);

		/* Magic 'DCRP' */
		if (hcopy->sign != DC_VOLM_SIGN) {
			continue;
		}
		/* Check CRC of header */
		if (hcopy->hdr_crc != crc32(pv(&hcopy->version), DC_CRC_AREA_SIZE)) {
			continue;
		}			
		/* copy decrypted part to output */
		autocpy(&header->sign, &hcopy->sign, DC_ENCRYPTEDDATASIZE);
		succs = 1; break;
	}
	/* prevent leaks */
	zeroauto(dk, sizeof(dk));
	mm_free(hcopy);

	return succs;
}