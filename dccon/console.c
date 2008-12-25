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

int s_gets(char *buff, size_t size)
{
	char buf[MAX_PATH];
	buf[0] = d8(min(127, size-2));
	buff[0] = 0;
	if (_cgets(buf) == buf + 2) {
		strcpy(buff, buf + 2);
	}
	return buff[0] != 0;
}

int s_wgets(wchar_t *buff, size_t size)
{
	char buf[MAX_PATH];

	if (s_gets(buf, sizeof(buf)) != 0)
	{
		mbstowcs(buff, buf, sizeof(buf));
		return 1;
	} else {
		return 0;
	}		
}