#include <windows.h>
#include <stdio.h>
#include <conio.h>
#include "defines.h"

int       g_argc;
wchar_t **g_argv;

void cls_console() 
{
	CONSOLE_SCREEN_BUFFER_INFO csbi;
	COORD                      pos;
	u32                        bytes;
	HANDLE                     console = GetStdHandle(STD_OUTPUT_HANDLE);

	GetConsoleScreenBufferInfo(console, &csbi);

	pos.X = 0; pos.Y = 0;
	FillConsoleOutputCharacter(
		console, ' ', csbi.dwSize.X * csbi.dwSize.Y, pos, &bytes);

	SetConsoleCursorPosition(console, pos); 
}

char getchr(char min, char max) 
{
	char ch;

	do
	{
		ch = _getch();
	} while ( (ch < min) || (ch > max) );

	return ch;
}

int is_param(wchar_t *name)
{
	int i;
	
	for (i = 0; i < g_argc; i++)
	{
		if (_wcsicmp(g_argv[i], name) == 0) {
			return 1;
		}
	}

	return 0;
}

wchar_t *get_param(wchar_t *name)
{
	int i;
	
	for (i = 0; i < g_argc-1; i++)
	{
		if (_wcsicmp(g_argv[i], name) == 0) {
			return g_argv[i+1];
		}
	}

	return NULL;
}

void clean_cmd_line()
{
	wchar_t *cmd_w = GetCommandLineW();
	char    *cmd_a = GetCommandLineA();
	zeromem(cmd_w, wcslen(cmd_w) * sizeof(wchar_t));
	zeromem(cmd_a, strlen(cmd_a) * sizeof(char));	
}

/*
    fucking Micro$oft!!!
	gets  - unsafe (buffer overflows)
	cgets - not work on Vista x64
	fgets - not work on win2k sp2 because __iob_func not found in msvcrt.dll
*/
int s_gets(char *buff, int size)
{
	int pn = 0;
	u8  ch;
	
	while ((ch = _getch()) != '\r')
	{
		if ( (ch == 0) || (ch == 0xE0) ) {
			_getch();
		} else if (ch == 8) 
		{
			if (pn > 0) {
				pn--; _putch(8); _putch(' '); _putch(8);
			}
		} else 
		{
			if (pn < (size - 1)) {
				buff[pn++] = ch; _putch(ch);
			}
		}
	}
	_putch('\n'); buff[pn] = 0;
	return buff[0] != 0;
}


int s_wgets(wchar_t *buff, int size)
{
	char buf[MAX_PATH];

	if (s_gets(buf, min(size / sizeof(wchar_t), MAX_PATH)) != 0) {
		mbstowcs(buff, buf, size);
	} else {
		buff[0] = 0;
	}
	return buff[0] != 0;
}