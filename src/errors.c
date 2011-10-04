/*
 * Error codes and representation
 */

#include <wicked/netinfo.h>

static const char *	ni_errors[__NI_ERROR_MAX] = {
[NI_SUCCESS]				= "Success",
[NI_ERROR_GENERAL_FAILURE]		= "General failure",
[NI_ERROR_INVALID_ARGS]			= "Invalid arguments",
[NI_ERROR_INTERFACE_NOT_KNOWN]		= "Interface not known",
[NI_ERROR_INTERFACE_BAD_HIERARCHY]	= "Interface bad hierarchy",
[NI_ERROR_INTERFACE_IN_USE]		= "Interface in use",
[NI_ERROR_INTERFACE_NOT_UP]		= "Interface not up",
[NI_ERROR_INTERFACE_NOT_DOWN]		= "Interface not down",
[NI_ERROR_CANNOT_CONFIGURE_ADDRESS]	= "Cannot configure addresss",
[NI_ERROR_CANNOT_CONFIGURE_ROUTE]	= "Cannot configure route",
};

const char *
ni_strerror(int errcode)
{
	const char *errstring = NULL;

	if (errcode < 0)
		errcode = -errcode;
	if (errcode < __NI_ERROR_MAX)
		errstring = ni_errors[errcode];
	if (errstring == NULL)
		return "<bad error code>";

	return errstring;
}
