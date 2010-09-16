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

#include <wicked/logging.h>

unsigned int		ni_debug = 0;
static unsigned int	ni_log_syslog = 0;

int
ni_enable_debug(const char *fac)
{
	char *copy, *s;
	int rv = 0;

	copy = strdup(fac);
	for (s = strtok(copy, ","); s; s = strtok(NULL, ",")) {
		int flags = 0;
		int not = 0;

		if (*s == '-') {
			not = 1;
			++s;
		}

		if (!strcmp(s, "all"))
			flags = ~0;
		else if (!strcmp(s, "most"))
			flags = ~(NI_TRACE_XPATH);
		else if (!strcmp(s, "ifconfig"))
			flags = NI_TRACE_IFCONFIG;
		else if (!strcmp(s, "readwrite"))
			flags = NI_TRACE_READWRITE;
		else if (!strcmp(s, "extension"))
			flags = NI_TRACE_EXTENSION;
		else if (!strcmp(s, "xpath"))
			flags = NI_TRACE_XPATH;
		else if (!strcmp(s, "wicked"))
			flags = NI_TRACE_WICKED;
		else if (!strcmp(s, "events"))
			flags = NI_TRACE_EVENTS;
		else {
			rv = -1;
			continue;
		}
		if (not)
			ni_debug &= ~flags;
		else
			ni_debug |= flags;
	}

	free(copy);
	return rv;
}

void
ni_debug_help(FILE *fp)
{
	fprintf(fp,
        "  all          All debug facilities\n"
        "  most         All debug facilities except xpath\n"
        "  wicked       Everything related to the wicked protocol\n"
        "  ifconfig     Interface configuration\n"
        "  readwrite    File read/write operations\n"
        "  extension    Handling of extension scripts\n"
        "  events       Netlink events (daemon only)\n"
        "  xpath        Parsing and execution of xpath formats\n"
	);
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
