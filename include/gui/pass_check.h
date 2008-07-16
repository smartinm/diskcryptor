#ifndef _PASS_CHECK_
#define _PASS_CHECK_

typedef struct _pass_inf
{
	int flags;   /* character groups flags     */
	int entropy; /* password entropy (in bits) */
	int length;  /* password length            */
} pass_inf;

#define P_AZ_L  1
#define P_AZ_H  2
#define P_09    4
#define P_SPACE 8
#define P_SPCH  16
#define P_NCHAR 32

void check_password(char *pass, pass_inf *inf);

#endif