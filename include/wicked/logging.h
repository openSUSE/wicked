/*
 * Logging functions; internal use only
 *
 * Copyright (C) 2010 Olaf Kirch <okir@suse.de>
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
extern void	ni_trace(const char *, ...) __fmtattr;
extern void	ni_fatal(const char *, ...) __fmtattr __noreturn;

enum {
	NI_TRACE_IFCONFIG	= 0x000001,
	NI_TRACE_READWRITE	= 0x000002,
	NI_TRACE_XPATH		= 0x000004,
	NI_TRACE_EXTENSION	= 0x000008,
	NI_TRACE_WICKED		= 0x000010,
	NI_TRACE_EVENTS		= 0x000020,
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

#endif /* __WICKED_LOGGING_H__ */
