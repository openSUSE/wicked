/*
 * Logging functions; internal use only
 *
 * Copyright (C) 2010 Olaf Kirch <okir@suse.de>
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include "logging.h"

unsigned int		ni_debug = 0;
static unsigned int	ni_log_syslog = 0;

int
ni_enable_debug(const char *fac)
{
	if (!strcmp(fac, "all"))
		ni_debug = ~0;
	else if (!strcmp(fac, "most"))
		ni_debug = ~(NI_TRACE_XPATH);
	else if (!strcmp(fac, ""))
		ni_debug = NI_TRACE_IFCONFIG;
	else if (!strcmp(fac, "readwrite"))
		ni_debug = NI_TRACE_READWRITE;
	else if (!strcmp(fac, "extension"))
		ni_debug = NI_TRACE_EXTENSION;
	else if (!strcmp(fac, "xpath"))
		ni_debug = NI_TRACE_XPATH;
	else if (!strcmp(fac, "wicked"))
		ni_debug = NI_TRACE_WICKED;
	else if (!strcmp(fac, "events"))
		ni_debug = NI_TRACE_EVENTS;
	else
		return -1;

	return 0;
}

void
ni_log_destination_syslog(const char *program)
{
	openlog(program, LOG_NDELAY, LOG_DAEMON);
	ni_log_syslog = 1;
}

void
ni_warn(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (!ni_log_syslog) {
		fprintf(stderr, "Warning: ");
		vfprintf(stderr, fmt, ap);
		fprintf(stderr, "\n");
	} else {
		vsyslog(LOG_NOTICE, fmt, ap);
	}
	va_end(ap);
}

void
ni_error(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (!ni_log_syslog) {
		fprintf(stderr, "Error: ");
		vfprintf(stderr, fmt, ap);
		fprintf(stderr, "\n");
	} else {
		vsyslog(LOG_WARNING, fmt, ap);
	}
	va_end(ap);
}

void
ni_trace(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (!ni_log_syslog) {
		fprintf(stderr, "::: ");
		vfprintf(stderr, fmt, ap);
		fprintf(stderr, "\n");
	} else {
		vsyslog(LOG_DEBUG, fmt, ap);
	}
	va_end(ap);
}

void
ni_fatal(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (!ni_log_syslog) {
		fprintf(stderr, "FATAL ERROR: *** ");
		vfprintf(stderr, fmt, ap);
		fprintf(stderr, " ***\n");
	} else {
		vsyslog(LOG_WARNING, fmt, ap);
	}
	va_end(ap);

	exit(1);
}
