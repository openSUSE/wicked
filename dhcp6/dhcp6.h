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
#include "dhcp6/options.h"
#include "buffer.h"

/*
 * -- type definitions
 */
typedef struct ni_dhcp6_request	ni_dhcp6_request_t;
typedef struct ni_dhcp6_config	ni_dhcp6_config_t;
typedef struct ni_dhcp6_device	ni_dhcp6_device_t;

/*
 * -- supplicant actions
 */
extern int			ni_dhcp6_acquire(ni_dhcp6_device_t *, const ni_dhcp6_request_t *, char **);
extern int			ni_dhcp6_release(ni_dhcp6_device_t *, const ni_uuid_t *);
extern void			ni_dhcp6_restart(void);

/*
 * -- fsm (dry) run modes
 */
typedef enum {
	NI_DHCP6_RUN_NORMAL,	/* normal renew loop	*/
	NI_DHCP6_RUN_LEASE,	/* get lease and stop	*/
	NI_DHCP6_RUN_OFFER,	/* get offer and stop	*/
} ni_dhcp6_run_t;

/*
 * -- supplicant request
 *
 * This is the on-the wire request we receive from supplicant.
 */
struct ni_dhcp6_request {
	ni_uuid_t		uuid;
	ni_bool_t		enabled;

	/* Options controlling which and how to make the requests */
	ni_dhcp6_run_t		dry_run;         /* normal run or get offer/lease only	*/
	ni_dhcp6_mode_t		mode;		 /* follow ra, request info/addr	*/
	ni_bool_t		rapid_commit;	 /* try to use rapid commit flow	*/
	unsigned int		acquire_timeout; /* how long we try before we give up	*/

	/* Options controlling what to put into the lease request */
	char *			hostname;
	char *			clientid;
#if 0
	char *			user_class;
	char *			vendor_class;

	unsigned int		lease_time;
	unsigned int		max_transmits;   /* how many times we try to acquire  */
#endif

	/* Options what to update based on the info received from
	 * the DHCP server.
	 * This is a bitmap; individual bits correspond to
	 * NI_ADDRCONF_UPDATE_* (this is an index enum, not a bitmask) */
	unsigned int		update;

	ni_dhcp6_ia_t *		ia_list;	/* IA_{NA,TA,PD}'s to request   */
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
	ni_uuid_t		uuid;

	ni_dhcp6_mode_t		mode;
	ni_dhcp6_run_t		dry_run;
	ni_bool_t		rapid_commit;
	unsigned int		acquire_timeout;

	ni_opaque_t		client_duid;	/* raw client id to use		*/
	ni_opaque_t		server_duid;	/* destination raw server id	*/

	char			hostname[256];
	ni_string_array_t	user_class;
	struct {
	    unsigned int	en;
	    ni_string_array_t	data;
	}			vendor_class;
	struct {
	    unsigned int	en;
	    ni_var_array_t	data;
	}			vendor_opts;
	unsigned int		lease_time;

	unsigned int		update;

	ni_dhcp6_ia_t *		ia_list;	/* IA_{NA,TA,PD}'s to request   */
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

	char *			ifname;		/* cached interface name	*/
	struct ni_dhcp6_link {
	    unsigned int	ifindex;	/* interface index		*/
	    ni_sockaddr_t	addr;		/* cached link-local address	*/
	    //ni_bool_t		ready;		/* device,link,network are up	*/
	}			link;

	uint32_t		iaid;		/* default IA interface-id	*/

	struct {
	    ni_socket_t *	sock;		/* multicast socket		*/
	    ni_sockaddr_t	dest;		/* relays & servers multicast	*/
	} mcast;

	struct timeval		start_time;	/* when we started managing     */
	ni_dhcp6_request_t *	request;	/* the wicked request params	*/
	ni_dhcp6_config_t *	config;		/* config built from request	*/
	ni_addrconf_lease_t *	lease;		/* last acquired lease		*/

	struct {
	    int			state;
	    unsigned int	fail_on_timeout : 1;
	    const ni_timer_t *	timer;
	} fsm;

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
	} dhcp6;
	ni_buffer_t		message;

	struct {
		char *		id;		/* lease ack server id string       */
		ni_opaque_t	duid;		/* lease ack server raw duid        */
		ni_sockaddr_t	addr;		/* lease ack server address	    */
	} server;

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
extern ni_dhcp6_device_t *	ni_dhcp6_device_by_index_show_all(unsigned int);

extern void			ni_dhcp6_device_set_request(ni_dhcp6_device_t *, ni_dhcp6_request_t *);
extern ni_bool_t		ni_dhcp6_device_check_ready(ni_dhcp6_device_t *);

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

extern void			ni_dhcp6_device_event(ni_dhcp6_device_t *, ni_netdev_t *, ni_event_t);
extern void			ni_dhcp6_address_event(ni_dhcp6_device_t *, ni_netdev_t *, ni_event_t, const ni_address_t *);
extern void			ni_dhcp6_prefix_event(ni_dhcp6_device_t *, ni_netdev_t *, ni_event_t, const ni_ipv6_ra_pinfo_t *);

/*
 * -- dhcp6 ia-addr
 *
 * Flag constants we use for recording
 * of lease ia address "states".
 *
 * TODO: move to another header file?
 * Do we ever need a bitmask?
 */
enum ni_dhcp6_ia_addr_flags {
	NI_DHCP6_IA_ADDR_EXPIRED	= 1U<<0,	/* expired -> garbage   */
	NI_DHCP6_IA_ADDR_DECLINE	= 1U<<1,	/* decline this address */
	NI_DHCP6_IA_ADDR_RELEASE	= 1U<<2,	/* release this address */
};

/*
 * -- dhcp6 ia
 *
 * Flag constants we use for recording
 * of lease ia "states".
 *
 * TODO: move to another header file?
 * Do we ever need a bitmask?
 */
enum ni_dhcp6_ia_flags {
	NI_DHCP6_IA_RENEW		= 1U<<0,	/* IA needs renew       */
	NI_DHCP6_IA_REBIND		= 1U<<1,	/* IA needs rebind      */
#if 0
	NI_DHCP6_IA_CONFIRM		= 1U<<2,	/* IA needs confirm     */
#endif
};

extern ni_dhcp6_ia_t *		ni_dhcp6_ia_na_new(unsigned int iaid);
extern ni_dhcp6_ia_t *		ni_dhcp6_ia_ta_new(unsigned int iaid);
extern ni_dhcp6_ia_t *		ni_dhcp6_ia_pd_new(unsigned int iaid);

extern ni_bool_t		ni_dhcp6_ia_type_na(ni_dhcp6_ia_t *);
extern ni_bool_t		ni_dhcp6_ia_type_ta(ni_dhcp6_ia_t *);
extern ni_bool_t		ni_dhcp6_ia_type_pd(ni_dhcp6_ia_t *);


#endif /* __WICKED_DHCP6_SUPPLICANT_H__ */
