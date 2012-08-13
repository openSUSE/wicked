/*
 * Logging functions; internal use only
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <wicked/logging.h>
#include <wicked/util.h>
#include "util_priv.h"

#define NI_TRACE_MOST	~(NI_TRACE_XPATH | NI_TRACE_WICKED_XML | NI_TRACE_DBUS)
#define NI_TRACE_ALL	~0U

unsigned int		ni_debug = 0;
static unsigned int	ni_log_syslog = 0;

/*
 * debug options short text representation
 */
static ni_intmap_t __debug_flags_names[] = {
	{ "ifconfig", 	NI_TRACE_IFCONFIG },
	{ "readwrite", 	NI_TRACE_READWRITE },
	{ "xpath", 	NI_TRACE_XPATH },
	{ "extension", 	NI_TRACE_EXTENSION },
	{ "wicked", 	NI_TRACE_WICKED },
	{ "wicked-xml",	NI_TRACE_WICKED_XML },
	{ "events", 	NI_TRACE_EVENTS },
	{ "dhcp", 	NI_TRACE_DHCP },
	{ "ipv6", 	NI_TRACE_IPV6 },
	{ "socket", 	NI_TRACE_SOCKET },
	{ "autoip", 	NI_TRACE_AUTOIP },
	{ "dbus", 	NI_TRACE_DBUS },
	{ "wireless", 	NI_TRACE_WIRELESS },
	{ "xml", 	NI_TRACE_XML },
	{ "objectmodel",NI_TRACE_OBJECTMODEL },
	{ "application",NI_TRACE_APPLICATION },
	{ "modem",	NI_TRACE_MODEM },

	{ "most", 	NI_TRACE_MOST },
	{ "all", 	NI_TRACE_ALL },
	{ NULL }
};

/*
 * debug options long text representation
 */
static ni_intmap_t __debug_flags_descriptions[] = {
	{ "Interface configuration", 			NI_TRACE_IFCONFIG },
	{ "File read/write operations", 		NI_TRACE_READWRITE },
	{ "Parsing and execution of xpath formats", 	NI_TRACE_XPATH },
	{ "Handling of extension scripts", 		NI_TRACE_EXTENSION },
	{ "Everything related to the wicked protocol", 	NI_TRACE_WICKED },
	{ "XML arguments and results of wicked calls", 	NI_TRACE_WICKED_XML },
	{ "Netlink events (daemon only)", 		NI_TRACE_EVENTS },
	{ "DHCP supplicant", 				NI_TRACE_DHCP },
	{ "IPv4LL supplicant", 				NI_TRACE_AUTOIP },
	{ "IPv6 address configuration", 		NI_TRACE_IPV6 },
	{ "Network socket send/receive", 		NI_TRACE_SOCKET },
	{ "DBus protocol",		 		NI_TRACE_DBUS },
	{ "Wireless handling",		 		NI_TRACE_WIRELESS },
	{ "XML processing",		 		NI_TRACE_XML },
	{ "Wicked object model",	 		NI_TRACE_OBJECTMODEL },
	{ "Application level activity",	 		NI_TRACE_APPLICATION },

	{ "All useful debug facilities :-)", 		NI_TRACE_MOST },
	{ "All debug facilities", 			NI_TRACE_ALL },

	{ NULL }
};

const char *
ni_debug_facility_to_name(unsigned int facility)
{
	return ni_format_int_mapped(facility, __debug_flags_names);
}

int
ni_debug_name_to_facility(const char *name, unsigned int *fac)
{
	return ni_parse_int_mapped(name, __debug_flags_names, fac);
}

const char *
ni_debug_facility_to_description(unsigned int facility)
{
	return ni_format_int_mapped(facility, __debug_flags_descriptions);
}

int
ni_enable_debug(const char *fac)
{
	char *copy, *s;
	int rv = 0;

	copy = xstrdup(fac);
	for (s = strtok(copy, ","); s; s = strtok(NULL, ",")) {
		unsigned int flags = 0;
		int not = 0;

		if (*s == '-') {
			not = 1;
			++s;
		}

		if (ni_debug_name_to_facility(s, &flags) < 0) {
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
	unsigned int i;

	for (i = 0; __debug_flags_descriptions[i].name; ++i) {
		fprintf(fp, "  %-10s\t%s\n",
				ni_debug_facility_to_name(__debug_flags_descriptions[i].value),
				__debug_flags_descriptions[i].name);
	}
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

/*
 * ni_error_extra is supposed to be used when you want to print extra error information
 * without outputting another "Error: " prefix
 */
void
ni_error_extra(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (!ni_log_syslog) {
		fprintf(stderr, "       ");
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
