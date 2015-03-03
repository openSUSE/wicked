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
#include <unistd.h>
#include <sys/time.h>
#include <time.h>

#include <wicked/logging.h>
#include <wicked/util.h>
#include "util_priv.h"

#define NI_LOG_PID	(1 << 0)
#define NI_LOG_TIME	(1 << 1)
#define NI_LOG_IDENT	(1 << 2)
#define NI_TRACE_NONE	0U
#define NI_TRACE_MINI	(NI_TRACE_IFCONFIG | NI_TRACE_READWRITE)
#define NI_TRACE_MOST	~(NI_TRACE_XPATH | NI_TRACE_WICKED_XML | NI_TRACE_DBUS)
#define NI_TRACE_ALL	~0U

unsigned int		ni_debug = 0;
unsigned int		ni_log_level = NI_LOG_NOTICE;
static ni_bool_t	ni_debug_user_specified = FALSE;
static unsigned int	ni_log_syslog;
static const char *	ni_log_ident;
static unsigned int	ni_log_opts;

static void		__ni_log_level_set(unsigned int level);

/*
 * debug options short text representation
 */
static const ni_intmap_t	__debug_flags_names[] = {
	{ "ifconfig", 	NI_TRACE_IFCONFIG },
	{ "readwrite", 	NI_TRACE_READWRITE },
	{ "xpath", 	NI_TRACE_XPATH },
	{ "extension", 	NI_TRACE_EXTENSION },
	{ "wicked", 	NI_TRACE_WICKED },
	{ "wicked-xml",	NI_TRACE_WICKED_XML },
	{ "events", 	NI_TRACE_EVENTS },
	{ "dhcp", 	NI_TRACE_DHCP },
	{ "ipv4", 	NI_TRACE_IPV4 },
	{ "ipv6", 	NI_TRACE_IPV6 },
	{ "socket", 	NI_TRACE_SOCKET },
	{ "autoip", 	NI_TRACE_AUTOIP },
	{ "dbus", 	NI_TRACE_DBUS },
	{ "wireless", 	NI_TRACE_WIRELESS },
	{ "xml", 	NI_TRACE_XML },
	{ "objectmodel",NI_TRACE_OBJECTMODEL },
	{ "application",NI_TRACE_APPLICATION },
	{ "modem",	NI_TRACE_MODEM },
	{ "lldp",	NI_TRACE_LLDP },
	{ "timer",	NI_TRACE_TIMER },

	{ "mini",	NI_TRACE_MINI },
	{ "most", 	NI_TRACE_MOST },
	{ "all", 	NI_TRACE_ALL  },
	{ "none", 	NI_TRACE_NONE },
	{ NULL }
};

/*
 * debug options long text representation
 */
static const ni_intmap_t	__debug_flags_descriptions[] = {
	{ "Interface configuration", 			NI_TRACE_IFCONFIG },
	{ "File read/write operations", 		NI_TRACE_READWRITE },
	{ "Parsing and execution of xpath formats", 	NI_TRACE_XPATH },
	{ "Handling of extension scripts", 		NI_TRACE_EXTENSION },
	{ "Everything related to the wicked protocol", 	NI_TRACE_WICKED },
	{ "XML arguments and results of wicked calls", 	NI_TRACE_WICKED_XML },
	{ "Netlink events (daemon only)", 		NI_TRACE_EVENTS },
	{ "DHCP supplicant", 				NI_TRACE_DHCP },
	{ "IPv4LL supplicant", 				NI_TRACE_AUTOIP },
	{ "IPv4 configuration", 			NI_TRACE_IPV4 },
	{ "IPv6 configuration", 			NI_TRACE_IPV6 },
	{ "Network socket send/receive", 		NI_TRACE_SOCKET },
	{ "DBus protocol",		 		NI_TRACE_DBUS },
	{ "Wireless handling",		 		NI_TRACE_WIRELESS },
	{ "XML processing",		 		NI_TRACE_XML },
	{ "Wicked object model",	 		NI_TRACE_OBJECTMODEL },
	{ "Application level activity",	 		NI_TRACE_APPLICATION },
	{ "Modem handling",				NI_TRACE_MODEM },
	{ "LLDP agent",					NI_TRACE_LLDP },
	{ "Internal timer",				NI_TRACE_TIMER },

	{ "Minimal debug facility set :-)", 		NI_TRACE_MINI },
	{ "All useful debug facility set :-)", 		NI_TRACE_MOST },
	{ "All debug facilities set", 			NI_TRACE_ALL  },

	{ NULL }
};

/*
 * Log level names and aliases
 */
static const ni_intmap_t	__log_level_names[] = {
	{ "error",	NI_LOG_ERROR	},
	{ "err",	NI_LOG_ERROR	},
	{ "warning",	NI_LOG_WARNING	},
	{ "warn",	NI_LOG_WARNING	},
	{ "notice",	NI_LOG_NOTICE	},
	{ "info",	NI_LOG_INFO	},
	{ "debug",	NI_LOG_DEBUG	},
	{ "debug1",	NI_LOG_DEBUG1	},
	{ "debug2",	NI_LOG_DEBUG2	},
	{ "debug3",	NI_LOG_DEBUG3	},
	{ NULL,		0		}
};

static const ni_intmap_t	__syslog_facility_names[] = {
	{ "user",	LOG_USER	},
	{ "daemon",	LOG_DAEMON	},
#if defined(LOG_LOCAL0)
	{ "local0",	LOG_LOCAL0	},
#endif
#if defined(LOG_LOCAL1)
	{ "local1",	LOG_LOCAL1	},
#endif
#if defined(LOG_LOCAL2)
	{ "local2",	LOG_LOCAL2	},
#endif
#if defined(LOG_LOCAL3)
	{ "local3",	LOG_LOCAL3	},
#endif
#if defined(LOG_LOCAL4)
	{ "local4",	LOG_LOCAL4	},
#endif
#if defined(LOG_LOCAL5)
	{ "local5",	LOG_LOCAL5	},
#endif
#if defined(LOG_LOCAL6)
	{ "local6",	LOG_LOCAL6	},
#endif
#if defined(LOG_LOCAL7)
	{ "local7",	LOG_LOCAL7	},
#endif
	{ NULL,		0		},
};


const char *
ni_debug_facility_to_name(unsigned int facility)
{
	return ni_format_uint_mapped(facility, __debug_flags_names);
}

int
ni_debug_name_to_facility(const char *name, unsigned int *fac)
{
	return ni_parse_uint_mapped(name, __debug_flags_names, fac);
}

const char *
ni_debug_facility_to_description(unsigned int facility)
{
	return ni_format_uint_mapped(facility, __debug_flags_descriptions);
}

static int
__ni_enable_debug(const char *fac)
{
	unsigned int _debug = 0;
	char *copy, *s;
	int rv = 0;

	copy = xstrdup(fac ? fac : "");
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
			_debug &= ~flags;
		else
			_debug |= flags;
	}

	free(copy);
	if (rv == 0) {
		ni_debug = _debug;
		if (ni_log_level < NI_LOG_DEBUG)
			__ni_log_level_set(NI_LOG_DEBUG);
	}
	return rv;
}

int
ni_enable_debug(const char *fac)
{
	ni_debug_user_specified = TRUE;
	return __ni_enable_debug(fac);
}

int
ni_debug_set_default(const char *fac)
{
	if (ni_debug_user_specified)
		return 0;

	return __ni_enable_debug(fac);
}

void
ni_debug_help(void)
{
	unsigned int i;

	for (i = 0; __debug_flags_descriptions[i].name; ++i) {
		printf("  %-10s\t%s\n",
				ni_debug_facility_to_name(__debug_flags_descriptions[i].value),
				__debug_flags_descriptions[i].name);
	}
}

void
ni_log_init(void)
{
	const char *var = getenv("WICKED_DEBUG");

	if (ni_string_empty(var) && (var = getenv("DEBUG"))) {
		if (ni_string_eq(var, "no"))
			var = "";
		else
		if (ni_string_eq(var, "yes"))
			var = "most";
	}
	if (!ni_string_empty(var))
		ni_enable_debug(var);

	if ((var = getenv("WICKED_LOG_LEVEL"))) {
		ni_log_level_set(var);
	}
}

unsigned int
ni_log_level_get(void)
{
	return ni_log_level;
}

void
__ni_log_level_set(unsigned int level)
{
	ni_log_level = level;
	switch (level) {
	case NI_LOG_ERROR:
		setlogmask(LOG_UPTO(LOG_ERR));
		break;
	case NI_LOG_WARNING:
		setlogmask(LOG_UPTO(LOG_WARNING));
		break;
	case NI_LOG_NOTICE:
		setlogmask(LOG_UPTO(LOG_NOTICE));
		break;
	case NI_LOG_INFO:
		setlogmask(LOG_UPTO(LOG_INFO));
		break;
	case NI_LOG_DEBUG:
	default:
		setlogmask(LOG_UPTO(LOG_DEBUG));
		break;
	}
}

ni_bool_t
ni_log_level_set(const char *name)
{
	unsigned int lvl;

	if (!name)
		return FALSE;

	/* accept only log level numbers for valid levels */
	if (ni_parse_uint_maybe_mapped(name, __log_level_names, &lvl, 0) != 0)
		return FALSE;

	if (lvl >= NI_LOG_DEBUG && !ni_debug)
		ni_debug = NI_TRACE_MINI;

	__ni_log_level_set(lvl);

	return TRUE;
}

void
ni_log_close(void)
{
	if (ni_log_syslog) {
		closelog();
	}
	ni_log_syslog = 0;
	ni_log_ident = NULL;
	ni_log_opts = 0;
}

void
ni_log_reopen(void)
{
	if (ni_log_syslog) {
		closelog();
		openlog(ni_log_ident, ni_log_opts, ni_log_syslog);
	}
}

static const ni_intmap_t *
ni_find_mapped_nname(const ni_intmap_t *map, const char *name, size_t len)
{
	while (map->name) {
		if (strlen(map->name) == len &&
		    strncasecmp(map->name, name, len) == 0)
			return map;
		++map;
	}
	return NULL;
}

static ni_bool_t
__ni_parse_flag_options(const ni_intmap_t *map, const char *args, unsigned int *options)
{
	unsigned int _options  = 0;
	const ni_intmap_t *opt;
	size_t beg, end;

	/*
	 * [option[,option]]
	 */
	beg = 0;
	end = strcspn(args, ",");
	while (end > beg) {
		if (!(opt = ni_find_mapped_nname(map, args+beg, end-beg)))
			return FALSE;

		_options |= opt->value;
		beg = end + strspn(args+end, ",");
		end = beg + strcspn(args+beg, ",");
	}

	if (options)
		*options = _options;
	return TRUE;

}

ni_bool_t
__ni_stderr_parse_args(const char *args, unsigned int *options)
{
	static const ni_intmap_t option_map[] = {
		{ "pid",	NI_LOG_PID	},
		{ "time",	NI_LOG_TIME	},
		{ "ident",	NI_LOG_IDENT	},
		{ NULL,		0		}
	};
	return __ni_parse_flag_options(option_map, args, options);
}

ni_bool_t
__ni_syslog_parse_args(const char *args, unsigned int *options, unsigned int *facility)
{
	static const ni_intmap_t *opt, option_map[] = {
		{ "perror",	LOG_PERROR	},
		{ "stderr",	LOG_PERROR	},
		{ "pid",	LOG_PID		},
		{ NULL,		0		}
	};
	unsigned int _options  = LOG_NDELAY | LOG_PID;
	unsigned int _facility = LOG_DAEMON;
	size_t end;

	/*
	 * [[facility]:[option[,option]]
	 */
	end = strcspn(args, ":");
	if (args[end] == ':') {
		if (!__ni_parse_flag_options(option_map, args+end+1, &_options))
			return FALSE;
	}
	if (end) {
		if (!(opt = ni_find_mapped_nname(__syslog_facility_names, args, end)))
			return FALSE;

		_facility = opt->value;
	}

	if (options)
		*options = _options | LOG_NDELAY;
	if (facility)
		*facility = _facility;

	return TRUE;
}

static ni_bool_t
ni_log_destination_syslog(const char *progname, const char *args)
{
	ni_log_close();

	if (!__ni_syslog_parse_args(args ? args : "",
				&ni_log_opts, &ni_log_syslog))
		return FALSE;

	ni_log_ident = progname;
	openlog(ni_log_ident, ni_log_opts, ni_log_syslog);
	return TRUE;
}

static ni_bool_t
ni_log_destination_stderr(const char *progname, const char *args)
{
	ni_log_close();

	ni_log_ident = progname;
	if (!__ni_stderr_parse_args(args ? args : "", &ni_log_opts))
		return FALSE;
	return TRUE;
}

ni_bool_t
ni_log_destination(const char *progname, const char *destination)
{
	static const struct {
		const char *name;
		ni_bool_t (*func)(const char *, const char *);
	} *dest, destination_map[] = {
		{ "stderr", ni_log_destination_stderr },
		{ "syslog", ni_log_destination_syslog },
		{ NULL,     NULL                      }
	};
	const char *options = "";
	size_t len;

	if (!destination)
		return FALSE;

	/*
	 * stderr[:[options]]
	 * syslog[:[facility]:[options]]
	 */
	len = strcspn(destination, ":");
	if (destination[len] == ':') {
		options = destination + len + 1;
	}

	for (dest = destination_map; dest->name; ++dest) {
		if (ni_string_len(dest->name) == len &&
		    !strncasecmp(dest->name, destination, len))
			return dest->func(progname, options);
	}
	return FALSE;
}

static inline void
__ni_log_stderr(const char *tag, const char *fmt, va_list ap, const char *end)
{
	/* rfc5424 / rfc3339 timestamp with ms precision, e.g.:
	 * 	2013-11-07T19:29:38.663870+01:00
	 */
	if (ni_log_opts & NI_LOG_TIME) {
		struct timeval tv;
		struct tm lt;
		char tzsign;

		gettimeofday(&tv, NULL);
		localtime_r(&tv.tv_sec, &lt);
		if (lt.tm_gmtoff < 0) {
			lt.tm_gmtoff *= -1;
			tzsign = '-';
		} else {
			tzsign = '+';
		}
		fprintf(stderr, "%04d-%02d-%02dT%02d:%02d:%02d.%06ld%c%02ld:%02ld ",
				lt.tm_year + 1900, lt.tm_mon + 1, lt.tm_mday,
				lt.tm_hour, lt.tm_min, lt.tm_sec, tv.tv_usec,
				tzsign, lt.tm_gmtoff/3600, (lt.tm_gmtoff%3600)/60);
	}

	if (ni_log_opts & NI_LOG_PID) {
		if (ni_log_opts & NI_LOG_IDENT)
			fprintf(stderr, "%s[%d]: ", ni_log_ident, getpid());
		else
			fprintf(stderr, "[%d]: ", getpid());
	} else if (ni_log_opts & NI_LOG_IDENT) {
		fprintf(stderr, "%s: ", ni_log_ident);
	}

	fprintf(stderr, "%s", tag);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "%s\n", end);
}

void
ni_info(const char *fmt, ...)
{
	va_list ap;

	if (ni_log_level < NI_LOG_INFO)
		return;

	va_start(ap, fmt);
	if (!ni_log_syslog) {
		__ni_log_stderr("Info: ", fmt, ap, "");
	} else {
		vsyslog(LOG_INFO, fmt, ap);
	}
	va_end(ap);
}

void
ni_note(const char *fmt, ...)
{
	va_list ap;

	if (ni_log_level < NI_LOG_NOTICE)
		return;

	va_start(ap, fmt);
	if (!ni_log_syslog) {
		__ni_log_stderr("Notice: ", fmt, ap, "");
	} else {
		vsyslog(LOG_NOTICE, fmt, ap);
	}
	va_end(ap);
}

void
ni_warn(const char *fmt, ...)
{
	va_list ap;

	if (ni_log_level < NI_LOG_WARNING)
		return;

	va_start(ap, fmt);
	if (!ni_log_syslog) {
		__ni_log_stderr("Warning: ", fmt, ap, "");
	} else {
		vsyslog(LOG_WARNING, fmt, ap);
	}
	va_end(ap);
}

void
ni_error(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (!ni_log_syslog) {
		__ni_log_stderr("Error: ", fmt, ap, "");
	} else {
		vsyslog(LOG_ERR, fmt, ap);
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
		__ni_log_stderr("       ", fmt, ap, "");
	} else {
		vsyslog(LOG_ERR, fmt, ap);
	}
	va_end(ap);
}

void
ni_trace(const char *fmt, ...)
{
	va_list ap;

	if (ni_log_level < NI_LOG_DEBUG)
		return;

	va_start(ap, fmt);
	if (!ni_log_syslog) {
		__ni_log_stderr("::: ", fmt, ap, "");
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
		__ni_log_stderr("FATAL ERROR: *** ", fmt, ap, " ***");
	} else {
		vsyslog(LOG_CRIT, fmt, ap);
	}
	va_end(ap);

	exit(1);
}

