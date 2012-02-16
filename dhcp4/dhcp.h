/*
 * netinfo dhcp supplicant
 *
 * Copyright (C) 2010 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_DHCP_PRIVATE_H__
#define __WICKED_DHCP_PRIVATE_H__


#include <sys/time.h>
#include <wicked/netinfo.h>
#include <wicked/addrconf.h>
#include <wicked/wicked.h>
#include <wicked/socket.h>
#include "netinfo_priv.h"
#include "buffer.h"

enum {
	NI_DHCP_STATE_INIT,
	NI_DHCP_STATE_SELECTING,
	NI_DHCP_STATE_REQUESTING,
	NI_DHCP_STATE_VALIDATING,
	NI_DHCP_STATE_BOUND,
	NI_DHCP_STATE_RENEWING,
	NI_DHCP_STATE_REBINDING,
	NI_DHCP_STATE_REBOOT,
	NI_DHCP_STATE_RENEW_REQUESTED,
	NI_DHCP_STATE_RELEASED,

	__NI_DHCP_STATE_MAX,
};

typedef struct ni_dhcp_message ni_dhcp_message_t;
typedef struct ni_dhcp_config ni_dhcp_config_t;

typedef struct ni_dhcp_device {
	struct ni_dhcp_device *	next;
	unsigned int		users;

	char *			ifname;
	ni_linkinfo_t		link;

	struct {
	    int			state;
	    unsigned int	fail_on_timeout : 1;
	    const ni_timer_t *	timer;
	} fsm;

	ni_capture_devinfo_t	system;

	time_t			start_time;	/* when we starting managing */

	ni_dhcp_config_t *	config;
	ni_addrconf_lease_t *	lease;

	ni_capture_t *		capture;
	int			listen_fd;	/* for DHCP only */

	unsigned int		failed : 1,
				notify : 1;

	struct {
	    uint32_t		xid;
	    unsigned int	nak_backoff;	/* backoff timer when we get NAKs */
	    unsigned int	accept_any_offer : 1;
	} dhcp;

	ni_buffer_t		message;

	struct {
	   ni_arp_socket_t *	handle;
	   unsigned int		nprobes;
	   unsigned int		nclaims;
	} arp;

	struct {
	   ni_addrconf_lease_t *lease;
	   int			weight;
	} best_offer;
} ni_dhcp_device_t;

#define NI_DHCP_RESEND_TIMEOUT_INIT	3	/* seconds */
#define NI_DHCP_RESEND_TIMEOUT_MAX	60	/* seconds */
#define NI_DHCP_REQUEST_TIMEOUT		60	/* seconds */
#define NI_DHCP_ARP_TIMEOUT		200	/* msec */

/* Initial discovery period while we scan all available leases. */
#define NI_DHCP_DISCOVERY_TIMEOUT	20	/* seconds */

enum {
	DHCP_DO_ARP		= 0x0001,
	DHCP_DO_HOSTNAME	= 0x0002,
	DHCP_DO_RESOLVER	= 0x0004,
	DHCP_DO_NIS		= 0x0008,
	DHCP_DO_NTP		= 0x0010,
	DHCP_DO_CSR		= 0x0020,
	DHCP_DO_MSCSR		= 0x0040,
	DHCP_DO_GATEWAY		= 0x0080,
};

/*
 * This is the on-the wire request we receive from clients.
 */
typedef struct ni_dhcp4_request {
	ni_addrconf_mode_t	type;		/* addrconf type */
	unsigned int		family;		/* address family */
	ni_uuid_t		uuid;

	unsigned int		settle_timeout;	/* wait that long before starting DHCP */
	unsigned int		acquire_timeout;/* how long we try before we give up */

	/* Options controlling what to put into the lease request */
	char *			hostname;
	char *			clientid;
	char *			vendor_class;
	unsigned int		lease_time;

	/* Options what to update based on the info received from
	 * the DHCP server.
	 * This is a bitmap; individual bits correspond to
	 * NI_ADDRCONF_UPDATE_* (this is an index enum, not a bitmask) */
	unsigned int		update;
} ni_dhcp4_request_t;

/*
 * This is what we turn the above ni_dhcp4_request_t into for
 * internal use.
 */
struct ni_dhcp_config {
	/* A combination of DHCP_DO_* flags above */
	unsigned int		flags;

	char			hostname[256];
	char			classid[48];
	int			fqdn;

	char			client_id[256];
	ni_opaque_t		raw_client_id;
	ni_opaque_t		userclass;

	unsigned int		initial_discovery_timeout;
	unsigned int		request_timeout;
	unsigned int		resend_timeout;
	unsigned int		max_lease_time;
};

enum ni_dhcp_event {
	NI_DHCP_EVENT_ACQUIRED =NI_EVENT_LEASE_ACQUIRED,
	NI_DHCP_EVENT_RELEASED =NI_EVENT_LEASE_RELEASED,
	NI_DHCP_EVENT_LOST =	NI_EVENT_LEASE_LOST
};

typedef void		ni_dhcp_event_handler_t(enum ni_dhcp_event event,
					const ni_dhcp_device_t *dev,
					ni_addrconf_lease_t *lease);

extern ni_dhcp_device_t *ni_dhcp_active;

extern void		ni_dhcp_set_event_handler(ni_dhcp_event_handler_t);

extern int		ni_dhcp_acquire(ni_dhcp_device_t *, const ni_dhcp4_request_t *);
extern int		ni_dhcp_release(ni_dhcp_device_t *, const ni_uuid_t *);

extern int		ni_dhcp_fsm_discover(ni_dhcp_device_t *);
extern int		ni_dhcp_fsm_release(ni_dhcp_device_t *);
extern int		ni_dhcp_fsm_process_dhcp_packet(ni_dhcp_device_t *, ni_buffer_t *);
extern int		ni_dhcp_fsm_commit_lease(ni_dhcp_device_t *, ni_addrconf_lease_t *);
extern int		ni_dhcp_fsm_recover_lease(ni_dhcp_device_t *, const ni_dhcp4_request_t *);
extern int		ni_dhcp_build_message(const ni_dhcp_device_t *,
				unsigned int, const ni_addrconf_lease_t *, ni_buffer_t *);
extern void		ni_dhcp_fsm_link_up(ni_dhcp_device_t *);
extern void		ni_dhcp_fsm_link_down(ni_dhcp_device_t *);

extern int		ni_dhcp_parse_response(const ni_dhcp_message_t *, ni_buffer_t *, ni_addrconf_lease_t **);

extern int		ni_dhcp_socket_open(ni_dhcp_device_t *);

extern int		ni_dhcp_device_start(ni_dhcp_device_t *);
extern void		ni_dhcp_device_stop(ni_dhcp_device_t *);
extern unsigned int	ni_dhcp_device_uptime(const ni_dhcp_device_t *, unsigned int);
extern ni_dhcp_device_t *ni_dhcp_device_new(const char *, const ni_linkinfo_t *);
extern ni_dhcp_device_t *ni_dhcp_device_by_index(unsigned int);
extern ni_dhcp_device_t *ni_dhcp_device_get(ni_dhcp_device_t *);
extern void		ni_dhcp_device_put(ni_dhcp_device_t *);
extern void		ni_dhcp_device_event(ni_dhcp_device_t *, ni_event_t);
extern int		ni_dhcp_device_reconfigure(ni_dhcp_device_t *, const ni_interface_t *);
extern void		ni_dhcp_device_set_lease(ni_dhcp_device_t *, ni_addrconf_lease_t *);
extern void		ni_dhcp_device_drop_lease(ni_dhcp_device_t *);
extern void		ni_dhcp_device_alloc_buffer(ni_dhcp_device_t *);
extern void		ni_dhcp_device_drop_buffer(ni_dhcp_device_t *);
extern int		ni_dhcp_device_send_message(ni_dhcp_device_t *, unsigned int, const ni_addrconf_lease_t *);
extern int		ni_dhcp_device_send_message_unicast(ni_dhcp_device_t *,
				unsigned int, const ni_addrconf_lease_t *);
extern void		ni_dhcp_device_arm_retransmit(ni_dhcp_device_t *dev);
extern void		ni_dhcp_device_disarm_retransmit(ni_dhcp_device_t *dev);
extern void		ni_dhcp_device_retransmit(ni_dhcp_device_t *);
extern void		ni_dhcp_device_force_retransmit(ni_dhcp_device_t *, unsigned int);
extern void		ni_dhcp_device_arp_close(ni_dhcp_device_t *);
extern void		ni_dhcp_parse_client_id(ni_opaque_t *, int, const char *);
extern void		ni_dhcp_set_client_id(ni_opaque_t *, const ni_hwaddr_t *);
extern void		ni_dhcp_device_drop_best_offer(ni_dhcp_device_t *);

extern int		ni_dhcp_xml_from_lease(const ni_addrconf_t *,
				const ni_addrconf_lease_t *, xml_node_t *);
extern int		ni_dhcp_xml_to_lease(const ni_addrconf_t *,
				ni_addrconf_lease_t *, const xml_node_t *);

extern const char *	ni_dhcp_config_vendor_class(void);
extern int		ni_dhcp_config_ignore_server(struct in_addr);
extern int		ni_dhcp_config_have_server_preference(void);
extern int		ni_dhcp_config_server_preference(struct in_addr);
extern unsigned int	ni_dhcp_config_max_lease_time(void);
extern void		ni_dhcp_config_free(ni_dhcp_config_t *);

#endif /* __WICKED_DHCP_PRIVATE_H__ */
