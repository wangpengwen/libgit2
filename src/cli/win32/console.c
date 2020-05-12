#include <conio.h>

#include "cli.h"

int cli_console_coords(int *cols, int *rows, int fd)
{
	HANDLE handle;
	CONSOLE_SCREEN_BUFFER_INFO info;

	if ((handle = _get_osfhandle(fd)) == -1) {
		git_error_set(GIT_ERROR_OS, "failed to get handle for file descriptor");
		return -1;
	}

	if (!GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &info)) {
		git_error_set(GIT_ERROR_OS, "failed to query screen buffer");
		return -1;
	}

	if (cols)
		*cols = info.srWindow.Right - info.srWindow.Left + 1;

	if (rows)
		*rows = info.srWindow.Bottom - info.srWindow.Top + 1;

	return 0;
}
