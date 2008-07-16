/*
    *
    * diskspeed - disk speed test tool
	* Copyright (c) 2008 
	* ntldr <ntldr@freed0m.org> PGP key ID - 0xC48251EB4F8E4E6E
    *

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <windows.h>
#include <stdio.h>
#include "defines.h"

void print_usage()
{
	wprintf(
		L"Usage:\n\n"
		L"diskspeed [disk] [type] [-b] [block size]\n\n"
		L"  disk - determine disk for test speed\n"
		L"  type - test type\n"
		L"    -r  - linear read test\n"
		L"    -rw - chunked read/write test\n"
		L"  -b - test block size in KBytes (optional)\n"
		L"  Examples of use:\n"
		L"   diskspeed c: -r\n"
		L"   diskspeed c: -rw -b 1024\n"
		);
}

#define TEST_SIZE 1024*1024*100 /* 100mb */

int wmain(int argc, wchar_t *argv[])
{
	HANDLE  h_disk;
	wchar_t device[MAX_PATH];
	int     t_read;
	int     t_write;
	int     block;
	void   *data = NULL;
	ULONG   offset;
	ULONG   bytes, time;
	double  speed;

	if (argc < 3)
	{
		print_usage();
	} else 
	{
		do
		{
			if (argv[1][0] != L'\\') 
			{
				_snwprintf(
					device, sizeof_w(device), L"\\\\.\\%c:", argv[1][0]
					);
			} else {
				wcsncpy(device, argv[1], sizeof_w(device));
			}

			t_read = 0; t_write = 0; offset = 0;

			if (_wcsicmp(argv[2], L"-r") == 0) {
				t_read = 1;
			}

			if (_wcsicmp(argv[2], L"-rw") == 0) {
				t_read = 1; t_write = 1;
			}

			if ( (argc == 5) && (_wcsicmp(argv[3], L"-b") == 0) ) {
				block = _wtoi(argv[4]) * 1024;
			} else {
				block = 1024*1024;
			}

			if ( (t_read == 0) && (t_write == 0) ) {
				print_usage();
				break;
			}

			if ( (TEST_SIZE % block) || (block > TEST_SIZE) ) {
				wprintf(L"invalid block size\n");
				break;
			}

			if ( (data = malloc(block)) == NULL ) {
				wprintf(L"not enough memory for testing\n");
				break;
			}

			h_disk = CreateFile(
				device, GENERIC_READ | GENERIC_WRITE, 
				FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL
				);

			if (h_disk == INVALID_HANDLE_VALUE) {
				wprintf(L"device \"%s\" can not be opened\n", device);
				break;
			}

			wprintf(L"test started, please wait...\n");

			time = GetTickCount();

			for (; offset < TEST_SIZE; offset += block)
			{
				if (t_read != 0) 
				{
					SetFilePointer(h_disk, offset, NULL, FILE_BEGIN);

					if (ReadFile(h_disk, data, block, &bytes, NULL) == FALSE) {
						wprintf(L"disk read error\n");
						break;
					}
				}

				if (t_write != 0) 
				{
					SetFilePointer(h_disk, offset, NULL, FILE_BEGIN);
					
					if (WriteFile(h_disk, data, block, &bytes, NULL) == FALSE) {
						wprintf(L"disk write error\n");
						break;
					}
				}
			}

			time = GetTickCount() - time;

			CloseHandle(h_disk);

			speed = TEST_SIZE / ((double)time / 1000) / 1024 / 1024;

			wprintf(L"test completed, speed: %f mb/s\n", speed);
		} while (0);

		if (data != NULL) {
			free(data);
		}
	}

	return 0;
}