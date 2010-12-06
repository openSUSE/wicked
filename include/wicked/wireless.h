/*
 * Wireless declarations for netinfo.
 *
 * Copyright (C) 2010 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_WIRELESS_H__
#define __WICKED_WIRELESS_H__

#include <wicked/types.h>

typedef struct ni_wireless_network ni_wireless_network_t;

struct ni_wireless_network {
	char *			essid;
};

struct ni_wireless {
	ni_wireless_network_t	network;
	ni_hwaddr_t		acess_point;
};

typedef struct ni_wireless_network_array {
	unsigned int		count;
	ni_wireless_network_t **data;
} ni_wireless_network_array_t;

struct ni_wireless_scan {
	time_t			timestamp;
	time_t			lifetime;
	ni_wireless_network_array_t networks;
};

extern ni_wireless_network_t *ni_wireless_network_new(void);
extern void		ni_wireless_free(ni_wireless_t *);
extern void		ni_wireless_scan_free(ni_wireless_scan_t *);
extern void		ni_wireless_network_free(ni_wireless_network_t *);
extern void		ni_wireless_network_array_init(ni_wireless_network_array_t *);
extern void		ni_wireless_network_array_append(ni_wireless_network_array_t *, ni_wireless_network_t *);
extern void		ni_wireless_network_array_destroy(ni_wireless_network_array_t *);

#endif /* __WICKED_WIRELESS_H__ */
