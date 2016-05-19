/*
 *	Track ppp client end point state
 *
 *	Copyright (C) 2012-2016 SUSE Linux GmbH, Nuernberg, Germany.
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 *	Authors:
 *		Olaf Kirch <okir@suse.de>
 *		Pawel Wieczorkiewicz <pwieczorkiewicz@suse.de>
 *		Marius Tomaschewski <mt@suse.de>
 */
#ifndef WICKED_PPP_H
#define WICKED_PPP_H

#include <wicked/netinfo.h>

typedef struct ni_ppp_config			ni_ppp_config_t;
typedef struct ni_ppp_auth_config		ni_ppp_auth_config_t;
typedef struct ni_ppp_dns_config		ni_ppp_dns_config_t;
typedef struct ni_ppp_ipv4_config		ni_ppp_ipv4_config_t;
typedef struct ni_ppp_ipv6_config		ni_ppp_ipv6_config_t;

typedef struct ni_ppp_mode			ni_ppp_mode_t;
typedef struct ni_ppp_mode_pppoe		ni_ppp_mode_pppoe_t;

typedef enum {
	NI_PPP_MODE_UNKNOWN	= 0U,
	NI_PPP_MODE_PPPOE,
	NI_PPP_MODE_PPPOATM,
	NI_PPP_MODE_PPTP,
	NI_PPP_MODE_ISDN,
	NI_PPP_MODE_SERIAL,
} ni_ppp_mode_type_t;

struct ni_ppp_mode_pppoe {
	ni_netdev_ref_t			device;	/* ethernet device */
};

struct ni_ppp_mode {
	ni_ppp_mode_type_t		type;

	union {
		ni_ppp_mode_pppoe_t	pppoe;
	};
};

struct ni_ppp_auth_config {
	char *				hostname;
	char *				username;
	char *				password;
};

struct ni_ppp_dns_config {
	ni_bool_t			usepeerdns;
	ni_sockaddr_t			dns1;
	ni_sockaddr_t			dns2;
};

struct ni_ppp_ipv4_config {
	ni_sockaddr_t			local_ip;
	ni_sockaddr_t			remote_ip;

	struct {
		ni_bool_t		accept_local;
		ni_bool_t		accept_remote;
	} ipcp;
};

struct ni_ppp_ipv6_config {
	ni_bool_t			enabled;

	ni_sockaddr_t			local_ip;
	ni_sockaddr_t			remote_ip;

	struct {
		ni_bool_t		accept_local;
	} ipcp;
};

struct ni_ppp_config {
	ni_bool_t			debug;
	ni_bool_t			demand;
	ni_bool_t			persist;
	unsigned int			idle;
	unsigned int			maxfail;
	unsigned int			holdoff;

	ni_bool_t			multilink;
	char *				endpoint;

	ni_bool_t			defaultroute;

	ni_ppp_dns_config_t		dns;
	ni_ppp_auth_config_t		auth;
	ni_ppp_ipv4_config_t		ipv4;
	ni_ppp_ipv6_config_t		ipv6;
};

struct ni_ppp {
	ni_ppp_mode_t			mode;
	ni_ppp_config_t  		config;
};

extern ni_ppp_t *		ni_ppp_new(void);
extern void			ni_ppp_free(ni_ppp_t *);
extern ni_ppp_t *		ni_ppp_clone(ni_ppp_t *);

extern void			ni_ppp_mode_init(ni_ppp_mode_t *, ni_ppp_mode_type_t);
extern const char *		ni_ppp_mode_type_to_name(ni_ppp_mode_type_t);
extern ni_bool_t		ni_ppp_mode_name_to_type(const char *, ni_ppp_mode_type_t *);

#endif /* WICKED_PPP_H */
