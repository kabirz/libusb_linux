#include <locale.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "libusbi.h"

int libusb_setlocale(const char *locale)
{
	if (strncasecmp("en", locale, 2) == 0)
		return LIBUSB_SUCCESS;
	else
		return LIBUSB_ERROR_NOT_FOUND;
}

const char *libusb_strerror(enum libusb_error errcode)
{
	const char* errors[LIBUSB_ERROR_COUNT] = {
		"Success",
		"Input/Output Error",
		"Invalid parameter",
		"Access denied (insufficient permissions)",
		"No such device (it may have been disconnected)",
		"Entity not found",
		"Resource busy",
		"Operation timed out",
		"Overflow",
		"Pipe error",
		"System call interrupted (perhaps due to signal)",
		"Insufficient memory",
		"Operation not supported or unimplemented on this platform",
		"Other error",
	};
	return errors[errcode];
}
