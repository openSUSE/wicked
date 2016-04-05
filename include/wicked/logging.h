/*
 * Logging functions; internal use only
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_LOGGING_H__
#define __WICKED_LOGGING_H__

#include <wicked/types.h>

#ifdef __GNUC__
# define __fmtattr	__attribute__ ((format (printf, 1, 2)))
# define __noreturn	__attribute__ ((noreturn))
#else
# define __fmtattr	/* */
# define __noreturn	/* */
#endif

extern void		ni_info(const char *, ...) __fmtattr;
extern void		ni_note(const char *, ...) __fmtattr;
extern void		ni_warn(const char *, ...) __fmtattr;
extern void		ni_error(const char *, ...) __fmtattr;
extern void		ni_error_extra(const char *, ...) __fmtattr;
extern void		ni_trace(const char *, ...) __fmtattr;
extern void		ni_fatal(const char *, ...) __fmtattr __noreturn;

extern int		ni_enable_debug(const char *);
extern int		ni_debug_set_default(const char *);
extern void		ni_debug_help(void);
extern const char * 	ni_debug_facility_to_name(unsigned int);
extern int		ni_debug_name_to_facility(const char *, unsigned int *);
extern const char *	ni_debug_facility_to_description(unsigned int);

extern void		ni_log_init(void);
extern ni_bool_t	ni_log_level_set(const char *);
extern unsigned int	ni_log_level_get(void);

extern ni_bool_t	ni_log_destination(const char *program, const char *destination);
extern void		ni_log_reopen(void);
extern void		ni_log_close(void);

enum {
	NI_LOG_ERROR,
	NI_LOG_WARNING,
	NI_LOG_NOTICE,
	NI_LOG_INFO,
	NI_LOG_DEBUG,
	NI_LOG_DEBUG1,
	NI_LOG_DEBUG2,
	NI_LOG_DEBUG3
};

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
	NI_TRACE_LLDP		= 0x020000,
	NI_TRACE_TIMER		= 0x040000,
	NI_TRACE_IPV4		= 0x080000,
	NI_TRACE_ROUTE		= 0x100000,
};

extern unsigned int	ni_debug;
extern unsigned int	ni_log_level;

#define ni_log_level_at(level)			(ni_log_level >= (level))
#define ni_log_facility(facility)		(ni_debug & (facility))

#define ni_debug_guard(level, facility) \
	(ni_log_level_at(level) && ni_log_facility(facility))

#define __ni_debug(level, facility, fmt, args...) \
	do { \
		if (ni_debug_guard(level, facility)) \
			ni_trace(fmt, ##args); \
	} while (0)

#define ni_debug_ifconfig(fmt, args...)		__ni_debug(NI_LOG_DEBUG, NI_TRACE_IFCONFIG, fmt, ##args)
#define ni_debug_readwrite(fmt, args...)	__ni_debug(NI_LOG_DEBUG, NI_TRACE_READWRITE, fmt, ##args)
#define ni_debug_xpath(fmt, args...)		__ni_debug(NI_LOG_DEBUG, NI_TRACE_XPATH, fmt, ##args)
#define ni_debug_extension(fmt, args...)	__ni_debug(NI_LOG_DEBUG, NI_TRACE_EXTENSION, fmt, ##args)
#define ni_debug_wicked(fmt, args...)		__ni_debug(NI_LOG_DEBUG, NI_TRACE_WICKED, fmt, ##args)
#define ni_debug_events(fmt, args...)		__ni_debug(NI_LOG_DEBUG, NI_TRACE_EVENTS, fmt, ##args)
#define ni_debug_dhcp(fmt, args...)		__ni_debug(NI_LOG_DEBUG, NI_TRACE_DHCP, fmt, ##args)
#define ni_debug_ipv4(fmt, args...)		__ni_debug(NI_LOG_DEBUG, NI_TRACE_IPV4, fmt, ##args)
#define ni_debug_ipv6(fmt, args...)		__ni_debug(NI_LOG_DEBUG, NI_TRACE_IPV6, fmt, ##args)
#define ni_debug_socket(fmt, args...)		__ni_debug(NI_LOG_DEBUG, NI_TRACE_SOCKET, fmt, ##args)
#define ni_debug_autoip(fmt, args...)		__ni_debug(NI_LOG_DEBUG, NI_TRACE_AUTOIP, fmt, ##args)
#define ni_debug_dbus(fmt, args...)		__ni_debug(NI_LOG_DEBUG, NI_TRACE_DBUS, fmt, ##args)
#define ni_debug_wireless(fmt, args...)		__ni_debug(NI_LOG_DEBUG, NI_TRACE_WIRELESS, fmt, ##args)
#define ni_debug_xml(fmt, args...)		__ni_debug(NI_LOG_DEBUG, NI_TRACE_XML, fmt, ##args)
#define ni_debug_objectmodel(fmt, args...)	__ni_debug(NI_LOG_DEBUG, NI_TRACE_OBJECTMODEL, fmt, ##args)
#define ni_debug_application(fmt, args...)	__ni_debug(NI_LOG_DEBUG, NI_TRACE_APPLICATION, fmt, ##args)
#define ni_debug_modem(fmt, args...)		__ni_debug(NI_LOG_DEBUG, NI_TRACE_MODEM, fmt, ##args)
#define ni_debug_lldp(fmt, args...)		__ni_debug(NI_LOG_DEBUG, NI_TRACE_LLDP, fmt, ##args)
#define ni_debug_timer(fmt, args...)		__ni_debug(NI_LOG_DEBUG, NI_TRACE_TIMER, fmt, ##args)
#define ni_debug_route(fmt, args...)		__ni_debug(NI_LOG_DEBUG, NI_TRACE_ROUTE, fmt, ##args)

#define ni_debug_nanny				ni_debug_application

#define ni_debug_wicked_xml(xml_node, level, fmt, args...) \
	do { \
		if (ni_debug_guard(level, NI_TRACE_WICKED_XML)) { \
			ni_trace(fmt, ##args); \
			xml_node_print_debug(xml_node, NI_TRACE_WICKED_XML); \
		} \
	} while (0)

#define ni_debug_none(fmt, args...)		do { } while (0)

#define ni_debug_verbose(level, facility, fmt, args...) \
		__ni_debug(level, facility, fmt, ##args)

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
