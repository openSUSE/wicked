/*
 * Internal macros
 *
 * Copyright (C) 2011-2012 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_DEBUG_H__
#define __WICKED_DEBUG_H__

#define NI_TRACE_ENTER() \
				ni_debug_dbus("%s()", __FUNCTION__)
#define NI_TRACE_ENTER_ARGS(fmt, args...) \
				ni_debug_dbus("%s(" fmt ")", __FUNCTION__, ##args)
#define NI_TP()			ni_debug_dbus("TP - %s:%u", __FUNCTION__, __LINE__)

#define NI_XPATH_DEBUG_LEVEL	NI_LOG_DEBUG3

#define NI_DHCP6_HEXDUMP_LEVEL	NI_LOG_DEBUG3

#endif /* __WICKED_DEBUG_H__ */

