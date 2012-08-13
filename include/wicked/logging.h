/*
 * Logging functions; internal use only
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_LOGGING_H__
#define __WICKED_LOGGING_H__

#ifdef __GNUC__
# define __fmtattr	__attribute__ ((format (printf, 1, 2)))
# define __noreturn	__attribute__ ((noreturn))
#else
# define __fmtattr	/* */
# define __noreturn	/* */
#endif

extern void	ni_warn(const char *, ...) __fmtattr;
extern void	ni_error(const char *, ...) __fmtattr;
extern void	ni_error_extra(const char *, ...) __fmtattr;
extern void	ni_trace(const char *, ...) __fmtattr;
extern void	ni_fatal(const char *, ...) __fmtattr __noreturn;

enum {
	NI_TRACE_IFCONFIG	= 0x000001,
	NI_TRACE_READWRITE	= 0x000002,
	NI_TRACE_XPATH		= 0x000004,
	NI_TRACE_EXTENSION	= 0x000008,
	NI_TRACE_WICKED		= 0x000010,
	NI_TRACE_EVENTS		= 0x000020,
	NI_TRACE_DHCP		= 0x000040,
	NI_TRACE_IPV6		= 0x000080,
	NI_TRACE_SOCKET		= 0x000100,
	NI_TRACE_AUTOIP		= 0x000200,
	NI_TRACE_WICKED_XML	= 0x000400,
	NI_TRACE_DBUS		= 0x000800,
	NI_TRACE_WIRELESS	= 0x001000,
	NI_TRACE_XML		= 0x002000,
	NI_TRACE_OBJECTMODEL	= 0x004000,
	NI_TRACE_APPLICATION	= 0x008000,
	NI_TRACE_MODEM		= 0x010000,
};

extern unsigned int	ni_debug;

#define __ni_debug(facility, fmt, args...) \
	do { \
		if (ni_debug & (facility)) \
			ni_trace(fmt, ##args); \
	} while (0)
#define ni_debug_ifconfig(fmt, args...)		__ni_debug(NI_TRACE_IFCONFIG, fmt, ##args)
#define ni_debug_readwrite(fmt, args...)	__ni_debug(NI_TRACE_READWRITE, fmt, ##args)
#define ni_debug_xpath(fmt, args...)		__ni_debug(NI_TRACE_XPATH, fmt, ##args)
#define ni_debug_extension(fmt, args...)	__ni_debug(NI_TRACE_EXTENSION, fmt, ##args)
#define ni_debug_wicked(fmt, args...)		__ni_debug(NI_TRACE_WICKED, fmt, ##args)
#define ni_debug_events(fmt, args...)		__ni_debug(NI_TRACE_EVENTS, fmt, ##args)
#define ni_debug_dhcp(fmt, args...)		__ni_debug(NI_TRACE_DHCP, fmt, ##args)
#define ni_debug_ipv6(fmt, args...)		__ni_debug(NI_TRACE_IPV6, fmt, ##args)
#define ni_debug_socket(fmt, args...)		__ni_debug(NI_TRACE_SOCKET, fmt, ##args)
#define ni_debug_autoip(fmt, args...)		__ni_debug(NI_TRACE_AUTOIP, fmt, ##args)
#define ni_debug_dbus(fmt, args...)		__ni_debug(NI_TRACE_DBUS, fmt, ##args)
#define ni_debug_wireless(fmt, args...)		__ni_debug(NI_TRACE_WIRELESS, fmt, ##args)
#define ni_debug_xml(fmt, args...)		__ni_debug(NI_TRACE_XML, fmt, ##args)
#define ni_debug_objectmodel(fmt, args...)	__ni_debug(NI_TRACE_OBJECTMODEL, fmt, ##args)
#define ni_debug_application(fmt, args...)	__ni_debug(NI_TRACE_APPLICATION, fmt, ##args)
#define ni_debug_modem(fmt, args...)		__ni_debug(NI_TRACE_MODEM, fmt, ##args)

#define ni_debug_wicked_xml(xml_node, fmt, args...) \
	do { \
		if (ni_debug & NI_TRACE_WICKED_XML) { \
			ni_trace(fmt, ##args); \
			xml_node_print_fn(xml_node, (void (*)(const char *, void *)) ni_trace, NULL); \
		} \
	} while (0)
#define ni_debug_none(fmt, args...)		do { } while (0)

#define __ni_string(x) #x


#include <stdlib.h>

#define ni_assert(stmt) \
	do { \
		if (!(stmt)) { \
			ni_error("Assertion failed: %s, line %u: %s", \
					__FILE__, __LINE__, __ni_string(stmt)); \
			abort(); \
		} \
	} while(0)

#define ni_warn_once(args...) \
	do { \
		static int __warned = 0; \
		if (!__warned) \
			ni_warn(args); \
		__warned = 1; \
	} while (0)

#endif /* __WICKED_LOGGING_H__ */
