/*
 * netinfo dhcp supplicant
 *
 * Copyright (C) 2010 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_DHCP_PRIVATE_H__
#define __WICKED_DHCP_PRIVATE_H__


#include <sys/time.h>
#include <sys/poll.h>
#include <wicked/netinfo.h>
#include <wicked/wicked.h>
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

typedef struct ni_capture ni_capture_t;
typedef struct ni_dhcp_message ni_dhcp_message_t;
typedef struct ni_dhcp_config ni_dhcp_config_t;
typedef struct ni_dhcp_config options_t;

typedef struct ni_opaque {
	unsigned char	data[128];
	size_t		len;
} ni_opaque_t;

typedef struct ni_dhcp_device {
	struct ni_dhcp_device *next;

	char *		ifname;
	struct {
	    int		iftype;
	    int		arp_type;
	    int		ifindex;
	    unsigned	mtu;
	    ni_hwaddr_t	hwaddr;
	} system;

	time_t		start_time;	/* when we starting managing */

	ni_dhcp_config_t *config;
	ni_addrconf_lease_t *lease;

	ni_capture_t *	capture;
	int		listen_fd;	/* for DHCP only */

	unsigned int	failed : 1,
			notify : 1;

	int		state;
	uint32_t	xid;

	ni_buffer_t	message;
	struct {
	   unsigned int	timeout;
	   unsigned int	increment;
	   struct timeval deadline;
	} retrans;

	unsigned int	timeout;
	unsigned int	nak_backoff;	/* backoff timer when we get NAKs */
	struct timeval	expires;

	struct {
	   unsigned int	nprobes;
	   unsigned int	nclaims;
	} arp;

	char *		lease_filename;
} ni_dhcp_device_t;

#define NI_DHCP_RESEND_TIMEOUT_INIT	3 /* seconds */
#define NI_DHCP_RESEND_TIMEOUT_MAX	60 /* seconds */
#define NI_DHCP_REQUEST_TIMEOUT		60 /* seconds */

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

struct ni_dhcp_config {
	/* A combination of DHCP_DO_* flags above */
	unsigned int	flags;

	char		hostname[256];
	char		classid[48];
	int		fqdn;

	ni_opaque_t	clientid;
	ni_opaque_t	userclass;

	unsigned int	request_timeout;
	unsigned int	resend_timeout;
};

extern ni_dhcp_device_t *ni_dhcp_active;

extern ni_proxy_t *	ni_dhcp_proxy_start(void);
extern int		ni_dhcp_proxy_notify(ni_proxy_t *, const char *, xml_node_t *);

extern int		ni_dhcp_wait(struct pollfd *, unsigned int, unsigned int);
extern void		ni_dhcp_device_stop(ni_dhcp_device_t *);

extern int		ni_dhcp_fsm_discover(ni_dhcp_device_t *);
extern int		ni_dhcp_fsm_request(ni_dhcp_device_t *, const ni_addrconf_lease_t *);
extern int		ni_dhcp_fsm_arp_validate(ni_dhcp_device_t *);
extern int		ni_dhcp_fsm_renewal(ni_dhcp_device_t *);
extern int		ni_dhcp_fsm_rebind(ni_dhcp_device_t *);
extern int		ni_dhcp_fsm_decline(ni_dhcp_device_t *);
extern int		ni_dhcp_fsm_release(ni_dhcp_device_t *);
extern long		ni_dhcp_fsm_get_timeout(void);
extern void		ni_dhcp_fsm_check_timeout(void);
extern const char *	ni_dhcp_fsm_state_name(int);
extern int		ni_dhcp_fsm_process_dhcp_packet(ni_dhcp_device_t *, ni_buffer_t *);
extern int		ni_dhcp_fsm_process_arp_packet(ni_dhcp_device_t *, ni_buffer_t *);
extern int		ni_dhcp_fsm_commit_lease(ni_dhcp_device_t *, ni_addrconf_lease_t *);
extern int		ni_dhcp_build_message(const ni_dhcp_device_t *,
				unsigned int, const ni_addrconf_lease_t *, ni_buffer_t *);

extern int		ni_dhcp_build_send_header(ni_buffer_t *, struct in_addr, struct in_addr);
extern int		ni_dhcp_parse_response(const ni_dhcp_message_t *, ni_buffer_t *, ni_addrconf_lease_t **);

extern int		ni_dhcp_socket_open(ni_dhcp_device_t *);
extern ssize_t		ni_capture_broadcast(const ni_capture_t *, const void *, size_t);
extern void		ni_capture_free(ni_capture_t *);
extern int		ni_capture_desc(const ni_capture_t *);

extern int		ni_dhcp_device_start(ni_dhcp_device_t *);
extern unsigned int	ni_dhcp_device_uptime(const ni_dhcp_device_t *, unsigned int);
extern ni_dhcp_device_t *ni_dhcp_device_new(const char *, unsigned int);
extern ni_dhcp_device_t *ni_dhcp_device_find(const char *);
extern ni_dhcp_device_t *ni_dhcp_device_get_changed(void);
extern int		ni_dhcp_device_reconfigure(ni_dhcp_device_t *, const ni_interface_t *);
extern void		ni_dhcp_device_set_lease(ni_dhcp_device_t *, ni_addrconf_lease_t *);
extern void		ni_dhcp_device_drop_lease(ni_dhcp_device_t *);
extern void		ni_dhcp_device_alloc_buffer(ni_dhcp_device_t *);
extern void		ni_dhcp_device_drop_buffer(ni_dhcp_device_t *);
extern int		ni_dhcp_device_send_message(ni_dhcp_device_t *, unsigned int, const ni_addrconf_lease_t *);
extern void		ni_dhcp_device_arm_retransmit(ni_dhcp_device_t *dev);
extern void		ni_dhcp_device_disarm_retransmit(ni_dhcp_device_t *dev);
extern void		ni_dhcp_device_retransmit(ni_dhcp_device_t *);

extern void		ni_dhcp_config_free(ni_dhcp_config_t *);

static inline void
ni_opaque_set(ni_opaque_t *obj, const void *data, size_t len)
{
	if (len > sizeof(obj->data))
		len = sizeof(obj->data);
	memcpy(obj->data, data, len);
	obj->len = len;
}

#endif /* __WICKED_DHCP_PRIVATE_H__ */
