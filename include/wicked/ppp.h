/*
 * Track ppp client end point state
 *
 * Copyright (C) 2012 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_PPP_H__
#define __WICKED_PPP_H__

#include <wicked/netinfo.h>

typedef struct ni_ppp_config ni_ppp_config_t;
struct ni_ppp_config {
	struct {
		char *		object_path;
		ni_modem_t *	modem;
		ni_netdev_t *	ethernet;
		char *		name;
	} device;

	unsigned int		mru;
	char *			hostname;
	char *			username;
	char *			password;
	char *			number;
	unsigned int		idle_timeout;
};

/*
 * For every ppp device, we need to store the /dev/ppp file descriptor
 * we used for creating the device.
 */
struct ni_ppp {
	char *			ident;
	char *			dirpath;

	unsigned int		unit;
	char			devname[IFNAMSIZ];
	int			devfd;

	ni_ppp_config_t	*	config;
};

extern ni_ppp_t *		ni_ppp_new(const char *);
extern void			ni_ppp_close(ni_ppp_t *);
extern int			ni_ppp_mkdir(ni_ppp_t *);
extern void			ni_ppp_free(ni_ppp_t *);

#endif /* __WICKED_PPP_H__ */

