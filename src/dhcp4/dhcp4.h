/*
 * wicked dhcp4 supplicant
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_DHCP4_PRIVATE_H__
#define __WICKED_DHCP4_PRIVATE_H__


#include <sys/time.h>
#include <wicked/netinfo.h>
#include <wicked/addrconf.h>
#include <wicked/wicked.h>
#include <wicked/socket.h>
#include "netinfo_priv.h"
#include "buffer.h"

enum fsm_state {
	NI_DHCP4_STATE_INIT,
	NI_DHCP4_STATE_SELECTING,
	NI_DHCP4_STATE_REQUESTING,
	NI_DHCP4_STATE_VALIDATING,
	NI_DHCP4_STATE_BOUND,
	NI_DHCP4_STATE_RENEWING,
	NI_DHCP4_STATE_REBINDING,
	NI_DHCP4_STATE_REBOOT,

	__NI_DHCP4_STATE_MAX,
};

typedef struct ni_dhcp4_message ni_dhcp4_message_t;
typedef struct ni_dhcp4_config ni_dhcp4_config_t;
typedef struct ni_dhcp4_request	ni_dhcp4_request_t;

typedef struct ni_dhcp4_device {
	struct ni_dhcp4_device *	next;
	unsigned int		users;

	char *			ifname;
	ni_linkinfo_t		link;

	struct {
	    enum fsm_state	state;
	    const ni_timer_t *	timer;
	} fsm;

	struct {
	    const ni_timer_t *	timer;
	} defer;

	ni_capture_devinfo_t	system;

	struct timeval		start_time;	/* when we starting managing */

	ni_dhcp4_request_t *	request;
	ni_dhcp4_config_t *	config;
	ni_addrconf_lease_t *	lease;

	ni_capture_t *		capture;
	int			listen_fd;	/* for DHCP4 only */

	unsigned int		failed : 1,
				notify : 1;

	struct {
	    unsigned int	msg_code;
	    const ni_addrconf_lease_t *lease;
	} transmit;

	struct {
	    uint32_t		xid;
	    unsigned int	nak_backoff;	/* backoff timer when we get NAKs */
	    unsigned int	accept_any_offer : 1;
	} dhcp4;

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
} ni_dhcp4_device_t;

#define NI_DHCP4_RESEND_TIMEOUT_INIT	4	/* seconds */
#define NI_DHCP4_RESEND_TIMEOUT_MAX	64	/* seconds */
#define NI_DHCP4_REQUEST_TIMEOUT		60	/* seconds */
#define NI_DHCP4_ARP_TIMEOUT		200	/* msec */

/*
 * common NI_ADDRCONF_UPDATE_* + dhcp4 specific options
 */
enum {
	DHCP4_DO_ARP		= 0x00000001,
	DHCP4_DO_HOSTNAME	= 0x00000002,
	DHCP4_DO_DNS		= 0x00000004,
	DHCP4_DO_NIS		= 0x00000008,
	DHCP4_DO_NTP		= 0x00000010,
	DHCP4_DO_CSR		= 0x00000020,
	DHCP4_DO_MSCSR		= 0x00000040,
	DHCP4_DO_GATEWAY	= 0x00000080,
	DHCP4_DO_ROOT		= 0x00000100,
	DHCP4_DO_NDS		= 0x00000200,
	DHCP4_DO_SMB		= 0x00000400,
	DHCP4_DO_SIP		= 0x00000800,
	DHCP4_DO_LPR		= 0x00001000,
	DHCP4_DO_LOG		= 0x00002000,
	DHCP4_DO_POSIX_TZ	= 0x00004000,
	DHCP4_DO_MTU		= 0x00008000,
	DHCP4_DO_STATIC_ROUTES	= 0x00010000,
};

/*
 * fsm (dry) run modes
 */
typedef enum
{
	NI_DHCP4_RUN_NORMAL,	/* normal renew loop	*/
	NI_DHCP4_RUN_LEASE,	/* get lease and stop	*/
	NI_DHCP4_RUN_OFFER,	/* get offer and stop	*/
} ni_dhcp4_run_t;


/*
 * This is the on-the wire request we receive from clients.
 */
struct ni_dhcp4_request {
	ni_bool_t		enabled;
	ni_uuid_t		uuid;
	unsigned int		flags;
	ni_dhcp4_run_t		dry_run;	/* normal run or get offer/lease only	*/

	unsigned int		start_delay;	/* how long to delay start */
	unsigned int		defer_timeout;	/* how long we try before we defer	*/
	unsigned int		acquire_timeout;/* how long we try before we give up	*/

	unsigned int		lease_time;	/* to request specific lease time	*/
	ni_bool_t		recover_lease;	/* recover and reuse existing lease	*/
	ni_bool_t		release_lease;	/* release lease on drop request	*/

	/* Options controlling what to put into the lease request */
	char *			clientid;
	char *			vendor_class;
	ni_dhcp4_user_class_t	user_class;

	ni_dhcp_fqdn_t		fqdn;
	char *			hostname;
	unsigned int		route_priority;

	ni_string_array_t	request_options;

	/* Options what to update based on the info received from
	 * the DHCP4 server.
	 * This is a bitmap; individual bits correspond to
	 * NI_ADDRCONF_UPDATE_* (this is an index enum, not a bitmask) */
	unsigned int		update;
	ni_tristate_t		broadcast;
};

/*
 * This is what we turn the above ni_dhcp4_request_t into for
 * internal use.
 */
struct ni_dhcp4_config {
	ni_uuid_t		uuid;
	unsigned int		flags;
	ni_dhcp4_run_t		dry_run;

	ni_dhcp_fqdn_t		fqdn;
	char			hostname[255];
	char			classid[48];

	ni_opaque_t		client_id;
	ni_dhcp4_user_class_t	user_class;

	unsigned int		start_delay;
	unsigned int		defer_timeout;
	unsigned int		capture_retry_timeout;	/* timeout for first request */
	unsigned int		capture_max_timeout;	/* timeout for the capture */
	unsigned int		capture_timeout;	/* timeout for actual capture, then fsm restarts */
	unsigned int		elapsed_timeout;	/* elapsed time within fsm */
	unsigned int		acquire_timeout;	/* 0 means retry forever */

	/* A combination of DHCP4_DO_* flags above */
	unsigned int		update;
	unsigned int		doflags;
	ni_uint_array_t		request_options;

	ni_tristate_t		broadcast;

	unsigned int		route_priority;

	unsigned int		max_lease_time;
	ni_bool_t		recover_lease;
	ni_bool_t		release_lease;
};

enum ni_dhcp4_event {
	NI_DHCP4_EVENT_ACQUIRED =NI_EVENT_LEASE_ACQUIRED,
	NI_DHCP4_EVENT_RELEASED =NI_EVENT_LEASE_RELEASED,
	NI_DHCP4_EVENT_DEFERRED =NI_EVENT_LEASE_DEFERRED,
	NI_DHCP4_EVENT_LOST =	NI_EVENT_LEASE_LOST
};

typedef void		ni_dhcp4_event_handler_t(enum ni_dhcp4_event event,
					const ni_dhcp4_device_t *dev,
					ni_addrconf_lease_t *lease);

extern ni_dhcp4_device_t *ni_dhcp4_active;

extern void		ni_dhcp4_set_event_handler(ni_dhcp4_event_handler_t);

extern int		ni_dhcp4_acquire(ni_dhcp4_device_t *, const ni_dhcp4_request_t *);
extern int		ni_dhcp4_release(ni_dhcp4_device_t *, const ni_uuid_t *);
extern void		ni_dhcp4_restart_leases(void);

extern const char *	ni_dhcp4_fsm_state_name(enum fsm_state);
extern void		ni_dhcp4_fsm_init_device(ni_dhcp4_device_t *);
extern void		ni_dhcp4_fsm_release_init(ni_dhcp4_device_t *);
extern int		ni_dhcp4_fsm_process_dhcp4_packet(ni_dhcp4_device_t *, ni_buffer_t *, ni_sockaddr_t *);
extern int		ni_dhcp4_fsm_commit_lease(ni_dhcp4_device_t *, ni_addrconf_lease_t *);
extern int		ni_dhcp4_recover_lease(ni_dhcp4_device_t *);
extern int		ni_dhcp4_build_message(const ni_dhcp4_device_t *,
				unsigned int, const ni_addrconf_lease_t *, ni_buffer_t *);
extern void		ni_dhcp4_fsm_link_up(ni_dhcp4_device_t *);
extern void		ni_dhcp4_fsm_link_down(ni_dhcp4_device_t *);

extern int		ni_dhcp4_parse_response(const ni_dhcp4_config_t *, const ni_dhcp4_message_t *,
						ni_buffer_t *, ni_addrconf_lease_t **);

extern int		ni_dhcp4_socket_open(ni_dhcp4_device_t *);

extern ni_bool_t	ni_dhcp4_supported(const ni_netdev_t *);
extern int		ni_dhcp4_device_start(ni_dhcp4_device_t *);
extern void		ni_dhcp4_device_stop(ni_dhcp4_device_t *);
extern unsigned int	ni_dhcp4_device_uptime(const ni_dhcp4_device_t *, unsigned int);
extern ni_dhcp4_device_t *ni_dhcp4_device_new(const char *, const ni_linkinfo_t *);
extern ni_dhcp4_device_t *ni_dhcp4_device_by_index(unsigned int);
extern ni_dhcp4_device_t *ni_dhcp4_device_get(ni_dhcp4_device_t *);
extern void		ni_dhcp4_device_put(ni_dhcp4_device_t *);
extern void		ni_dhcp4_device_event(ni_dhcp4_device_t *, ni_netdev_t *, ni_event_t);
extern int		ni_dhcp4_device_reconfigure(ni_dhcp4_device_t *, const ni_netdev_t *);
extern void		ni_dhcp4_device_set_config(ni_dhcp4_device_t *, ni_dhcp4_config_t *);
extern void		ni_dhcp4_device_set_request(ni_dhcp4_device_t *, ni_dhcp4_request_t *);
extern void		ni_dhcp4_device_set_lease(ni_dhcp4_device_t *, ni_addrconf_lease_t *);
extern void		ni_dhcp4_device_drop_lease(ni_dhcp4_device_t *);
extern void		ni_dhcp4_device_alloc_buffer(ni_dhcp4_device_t *);
extern void		ni_dhcp4_device_drop_buffer(ni_dhcp4_device_t *);
extern int		ni_dhcp4_device_send_message(ni_dhcp4_device_t *, unsigned int, const ni_addrconf_lease_t *);
extern int		ni_dhcp4_device_send_message_unicast(ni_dhcp4_device_t *,
				unsigned int, const ni_addrconf_lease_t *);
extern void		ni_dhcp4_device_arm_retransmit(ni_dhcp4_device_t *dev);
extern void		ni_dhcp4_device_disarm_retransmit(ni_dhcp4_device_t *dev);
extern void		ni_dhcp4_device_retransmit(ni_dhcp4_device_t *);
extern void		ni_dhcp4_device_force_retransmit(ni_dhcp4_device_t *, unsigned int);
extern void		ni_dhcp4_device_arp_close(ni_dhcp4_device_t *);
extern ni_bool_t	ni_dhcp4_parse_client_id(ni_opaque_t *, unsigned short, const char *);
extern ni_bool_t	ni_dhcp4_set_config_client_id(ni_opaque_t *, const ni_dhcp4_device_t *);
extern void		ni_dhcp4_new_xid(ni_dhcp4_device_t *);
extern void		ni_dhcp4_device_set_best_offer(ni_dhcp4_device_t *, ni_addrconf_lease_t *, int);
extern void		ni_dhcp4_device_drop_best_offer(ni_dhcp4_device_t *);

extern int		ni_dhcp4_xml_from_lease(const ni_addrconf_lease_t *, xml_node_t *);
extern int		ni_dhcp4_xml_to_lease(ni_addrconf_lease_t *, const xml_node_t *);

extern const char *	ni_dhcp4_config_vendor_class(void);
extern int		ni_dhcp4_config_ignore_server(const char *);
extern int		ni_dhcp4_config_have_server_preference(void);
extern int		ni_dhcp4_config_server_preference_ipaddr(struct in_addr);
extern int		ni_dhcp4_config_server_preference_hwaddr(const ni_hwaddr_t *);
extern unsigned int	ni_dhcp4_config_max_lease_time(void);
extern void		ni_dhcp4_config_free(ni_dhcp4_config_t *);

extern ni_dhcp4_request_t *ni_dhcp4_request_new(void);
extern void		ni_dhcp4_request_free(ni_dhcp4_request_t *);

extern void		ni_objectmodel_dhcp4_init(void);

#endif /* __WICKED_DHCP4_PRIVATE_H__ */
