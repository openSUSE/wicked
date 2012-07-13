/*
 *	DHCP6 supplicant
 *
 *	Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 *	Copyright (C) 2012 Marius Tomaschewski <mt@suse.de>
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
 *	You should have received a copy of the GNU General Public License along
 *	with this program; if not, see <http://www.gnu.org/licenses/> or write
 *	to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 *	Boston, MA 02110-1301 USA.
 *
 */
#ifndef   __WICKED_DHCP6_SUPPLICANT_H__
#define   __WICKED_DHCP6_SUPPLICANT_H__

#include <wicked/netinfo.h>	/* FIXME: required by addrconf.h ... */
#include <wicked/addrconf.h>
#include <wicked/socket.h>
#include <buffer.h>


/*
 * -- type definitions
 */
typedef struct ni_dhcp6_request	ni_dhcp6_request_t;
typedef struct ni_dhcp6_config	ni_dhcp6_config_t;
typedef struct ni_dhcp6_device	ni_dhcp6_device_t;


/*
 * -- supplicant actions
 */
extern int			ni_dhcp6_acquire(ni_dhcp6_device_t *, const ni_dhcp6_request_t *);
extern int			ni_dhcp6_release(ni_dhcp6_device_t *, const ni_uuid_t *);
extern void			ni_dhcp6_restart(void);

struct ni_dhcp6_status {
	uint16_t		code;
	char *			message;
};

struct ni_dhcp6_ia_addr {
	struct ni_dhcp6_ia_addr *next;

	struct in6_addr		addr;
	uint8_t			plen;
	uint32_t		preferred_lft;
	uint32_t		valid_lft;
	struct ni_dhcp6_status  *status;
};

struct ni_dhcp6_ia {
	struct ni_dhcp6_ia	*next;

	uint16_t		type;
	uint32_t		iaid;
	uint32_t		renewal_time;
	uint32_t		rebind_time;
	struct ni_dhcp6_ia_addr *addrs;
	struct ni_dhcp6_status  *status;
};

/*
 * -- supplicant request
 *
 * This is the on-the wire request we receive from supplicant.
 */
struct ni_dhcp6_request {
	ni_uuid_t		uuid;
	ni_bool_t		enabled;

	/* Options controlling which and how to make the requests */
	ni_bool_t		info_only;	/* stateless info request only  */
	ni_bool_t		rapid_commit;	/* try to use rapid commit flow */

	/* Options controlling what to put into the lease request */
	char *			hostname;
	char *			clientid;
#if 0
	char *			user_class;
	char *			vendor_class;

	unsigned int		lease_time;
	unsigned int		acquire_timeout; /* how long we try before we give up */
	unsigned int		max_transmits;   /* how many times we try to acquire  */
#endif

	/* Options what to update based on the info received from
	 * the DHCP server.
	 * This is a bitmap; individual bits correspond to
	 * NI_ADDRCONF_UPDATE_* (this is an index enum, not a bitmask) */
	unsigned int		update;

	/* Hmm... other options -> TODO:
	unsigned int		request_ia_na;
	unsigned int		request_ia_ta;
	unsigned int		request_ia_pd;
	 */
};


/*
 * -- request methods
 */
extern ni_dhcp6_request_t *	ni_dhcp6_request_new(void);
extern void			ni_dhcp6_request_free(ni_dhcp6_request_t *);


/*
 * -- device config
 *
 * This is what we turn the above ni_dhcp6_request_t into for
 * internal use.
 */
struct ni_dhcp6_config {
	ni_uuid_t			uuid;

	ni_bool_t			info_only;
	ni_bool_t			rapid_commit;

	char				hostname[256];
	char *				client_id;
	ni_opaque_t			client_duid;
	ni_string_array_t		user_class;
	struct {
		unsigned int		en;
		ni_string_array_t	data;
	} 				vendor_class;
	struct {
		unsigned int		en;
		ni_var_array_t		data;
	}				vendor_opts;
	unsigned int			lease_time;

	unsigned int			update;
};


/*
 * -- dhcp6 device
 *
 * Basically only ifindex, name, ... are needed to
 * be visible in dbus-api.c for dbus macros ...
 */
struct ni_dhcp6_device {
	struct ni_dhcp6_device *next;
	unsigned int		users;

	char *			ifname;
	ni_linkinfo_t		link;

	struct {
	    int			state;
	    unsigned int	fail_on_timeout : 1;
	    const ni_timer_t *	timer;
	} fsm;

	ni_socket_t *		sock;

	ni_sockaddr_t		client_addr;	/* our own address (link-local)     */
	ni_sockaddr_t		server_addr;	/* multicast or server unicast      */

	ni_dhcp6_request_t *	request;	/* the wicked request params/info   */
	ni_dhcp6_config_t *	config;		/* config built from request info   */
	ni_addrconf_lease_t *	lease;		/* last known / acquired lease      */

	struct timeval		start_time;	/* when we started managing         */
	struct {
	    struct timeval	start;		/* when we've sent first msg        */
	    unsigned int	count;		/* transfer count                   */
	    unsigned int	delay;		/* initial delay                    */
	    unsigned int	jitter;		/* jitter base for 1000 msec        */
	    unsigned int	duration;	/* max duration in msec             */
	    struct timeval	deadline;	/* next delay/timeout deadline      */
	    ni_timeout_param_t	params;		/* timeout parameters               */
	} retrans;

	unsigned int		failed : 1,
				notify : 1;

	struct {
	    uint32_t		xid;
#if 0
	    unsigned int	nak_backoff;	/* backoff timer when we get NAKs */
	    unsigned int	accept_any_offer : 1;
#endif
	} dhcp6;

	ni_buffer_t		message;

	struct {
	   ni_addrconf_lease_t *lease;
	   int			weight;
	} best_offer;

};


/*
 * -- device methods
 */
extern ni_dhcp6_device_t *	ni_dhcp6_device_new(const char *, const ni_linkinfo_t *);
extern ni_dhcp6_device_t *	ni_dhcp6_device_get(ni_dhcp6_device_t *);
extern void			ni_dhcp6_device_put(ni_dhcp6_device_t *);

extern ni_dhcp6_device_t *	ni_dhcp6_device_by_index(unsigned int);

extern void			ni_dhcp6_device_stop(ni_dhcp6_device_t *);

extern void			ni_dhcp6_device_event(ni_dhcp6_device_t *dev, ni_event_t event);

extern void			ni_dhcp6_device_set_request(ni_dhcp6_device_t *, ni_dhcp6_request_t *);

/*
 * -- events
 */
enum ni_dhcp6_event {
	NI_DHCP6_EVENT_ACQUIRED = NI_EVENT_LEASE_ACQUIRED,
	NI_DHCP6_EVENT_RELEASED = NI_EVENT_LEASE_RELEASED,
	NI_DHCP6_EVENT_LOST     = NI_EVENT_LEASE_LOST,
};

typedef void			ni_dhcp6_event_handler_t(enum ni_dhcp6_event,
							 const ni_dhcp6_device_t *,
							 ni_addrconf_lease_t *);

extern void			ni_dhcp6_set_event_handler(ni_dhcp6_event_handler_t);


#endif /* __WICKED_DHCP6_SUPPLICANT_H__ */
