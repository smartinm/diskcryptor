#include <windows.h>
#include "pass_check.h"
#include "defines.h"

void check_password(char *pass, pass_inf *inf)
{
	int flags = 0;
	u32 maxc  = 0;
	int len   = 0;
	int bits;
	s8  c;

	for (; c = *pass++; len++) 
	{
		do
		{
			if ( (c >= 'a') && (c <= 'z') ) {
				flags |= P_AZ_L;
				break;
			}

			if ( (c >= 'A') && (c <= 'Z') ) {
				flags |= P_AZ_H;
				break;
			}

			if ( (c >= '0') && (c <= '9') ) {
				flags |= P_09;
				break;
			}

			if (c == ' ') {
				flags |= P_SPACE;
				break;
			}

			if ( ((c >= '!') && (c <= '/')) ||
				 ((c >= ':') && (c <= '@')) ||
				 ((c >= '[') && (c <= '`')) ||
				 ((c >= '{') && (c <= '~')) ||
				 ((c >= '‘') && (c <= '—')) ||				 
				 (c == '‚') || (c == '„') || (c == '…') || 
				 (c == '‹') || (c == '›') || (c == '¦') ) 
			{
				flags |= P_SPCH;
				break;
			} else {
				flags |= P_NCHAR;
			}
		} while (0);
	}

	if (flags & P_09) {
		maxc += '9' - '0' + 1;
	}

	if (flags & P_AZ_L) {
		maxc += 'z' - 'a' + 1;
	}

	if (flags & P_AZ_H) {
		maxc += 'Z' - 'A' + 1;
	}

	if (flags & P_SPACE) {
		maxc++;
	}

	if (flags & P_SPCH) {
		maxc += ('/' - '!') + ('@' - ':') + ('`' - '[') + 
			    ('~' - '{') + ('—' - '‘') + 6;
	}

	if (flags & P_NCHAR) {
		maxc += 64;
	}

	if (bsr(&bits, maxc) == 0) {
		bits = 0;
	}
	
	inf->flags   = flags;
	inf->entropy = len * (bits+1);
	inf->length  = len;
}