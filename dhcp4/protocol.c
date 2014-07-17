/*
 * Build and parse DHCP4 packets
 *
 * Copyright (C) 2010-2012, Olaf Kirch <okir@suse.de>
 *
 * Heavily inspired by dhcp4cd, which was written by Roy Marples <roy@marples.name>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <assert.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/if_arp.h>
#include <net/ethernet.h>

#include <arpa/inet.h>

#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <wicked/netinfo.h>
#include <wicked/route.h>
#include <wicked/logging.h>
#include <wicked/socket.h>
#include <wicked/resolver.h>
#include <wicked/nis.h>
#include <wicked/xml.h>
#include "dhcp4/dhcp.h"
#include "dhcp4/protocol.h"
#include "buffer.h"
#include "socket_priv.h"

static void	ni_dhcp4_socket_recv(ni_socket_t *);

/*
 * Open a DHCP4 socket for send and receive
 */
int
ni_dhcp4_socket_open(ni_dhcp4_device_t *dev)
{
	ni_capture_protinfo_t prot_info;
	ni_capture_t *capture;

	/* We need to bind to a port, otherwise Linux will generate
	 * ICMP_UNREACHABLE messages telling the server that there's
	 * no DHCP4 client listening at all.
	 *
	 * We don't actually use this fd at all, instead using our packet
	 * filter socket.
	 *
	 * (It would be nice if we did, at least in BOUND/RENEWING state
	 * where good manners would dictate unicast requests anyway).
	 */
	if (dev->listen_fd == -1) {
		struct sockaddr_in sin;
		struct ifreq ifr;
		int on = 1;
		int fd;

		if ((fd = socket (PF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
			ni_error("socket: %m");
			return -1;
		}

		if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == -1)
			ni_error("SO_REUSEADDR: %m");
		if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &on, sizeof(on)) == -1)
			ni_error("SO_RCVBUF: %m");

		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, dev->ifname, sizeof(ifr.ifr_name));
		if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) == -1)
			ni_error("SO_SOBINDTODEVICE: %m");

		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_port = htons(DHCP4_CLIENT_PORT);
		if (bind(fd, (struct sockaddr *) &sin, sizeof(sin)) == -1) {
			ni_error("bind: %m");
			close(fd);
		} else {
			dev->listen_fd = fd;
			fcntl(fd, F_SETFD, FD_CLOEXEC);
		}
	}

	memset(&prot_info, 0, sizeof(prot_info));
	prot_info.eth_protocol = ETHERTYPE_IP;
	prot_info.ip_protocol = IPPROTO_UDP;
	prot_info.ip_port = DHCP4_CLIENT_PORT;

	if ((capture = dev->capture) != NULL) {
		if (ni_capture_is_valid(capture, ETHERTYPE_IP))
			return 0;

		ni_capture_free(dev->capture);
		dev->capture = NULL;
	}

	dev->capture = ni_capture_open(&dev->system, &prot_info, ni_dhcp4_socket_recv);
	if (!dev->capture)
		return -1;

	ni_capture_set_user_data(dev->capture, dev);
	return 0;
}

/*
 * This callback is invoked from the socket code when we
 * detect an incoming DHCP4 packet on the raw socket.
 */
static void
ni_dhcp4_socket_recv(ni_socket_t *sock)
{
	ni_capture_t *capture = sock->user_data;
	ni_buffer_t buf;

	if (ni_capture_recv(capture, &buf) >= 0) {
		ni_dhcp4_device_t *dev = ni_capture_get_user_data(capture);

		ni_dhcp4_fsm_process_dhcp4_packet(dev, &buf);
	}
}

/*
 * Inline functions for setting/retrieving options from a buffer
 */
static inline void
ni_dhcp4_option_put(ni_buffer_t *bp, int code, const void *data, size_t len)
{
	ni_buffer_putc(bp, code);
	ni_buffer_putc(bp, len);
	ni_buffer_put(bp, data, len);
}

static inline void
ni_dhcp4_option_put_empty(ni_buffer_t *bp, int code)
{
	ni_dhcp4_option_put(bp, code, NULL, 0);
}

static inline void
ni_dhcp4_option_put8(ni_buffer_t *bp, int code, unsigned char value)
{
	ni_dhcp4_option_put(bp, code, &value, 1);
}

static inline void
ni_dhcp4_option_put16(ni_buffer_t *bp, int code, uint16_t value)
{
	value = htons(value);
	ni_dhcp4_option_put(bp, code, &value, 2);
}

static inline void
ni_dhcp4_option_put32(ni_buffer_t *bp, int code, uint32_t value)
{
	value = htonl(value);
	ni_dhcp4_option_put(bp, code, &value, 4);
}

static inline void
ni_dhcp4_option_put_ipv4(ni_buffer_t *bp, int code, struct in_addr addr)
{
	ni_dhcp4_option_put(bp, code, &addr, 4);
}

static inline void
ni_dhcp4_option_puts(ni_buffer_t *bp, int code, const char *string)
{
	ni_dhcp4_option_put(bp, code, string, strlen(string));
}

static inline unsigned int
ni_dhcp4_option_begin(ni_buffer_t *bp, int code)
{
	ni_buffer_putc(bp, code);
	ni_buffer_putc(bp, 0);
	return bp->tail;
}

static inline void
ni_dhcp4_option_end(ni_buffer_t *bp, unsigned int pos)
{
	if (pos == 0 || pos > bp->size) {
		ni_error("ni_dhcp4_option_end: bad offset!");
	} else {
		bp->base[pos-1] = bp->tail - pos;
	}
}

static int
ni_dhcp4_option_next(ni_buffer_t *bp, ni_buffer_t *optbuf)
{
	unsigned char code, count;

	if (bp->underflow)
		return -1;
	if (bp->head == bp->tail)
		return DHCP4_END;
	if (bp->tail - bp->head < 2)
		goto underflow;

	code = bp->base[bp->head++];
	if (code != DHCP4_PAD && code != DHCP4_END) {
		count = bp->base[bp->head++];
		if (bp->tail - bp->head < count)
			goto underflow;
		ni_buffer_init_reader(optbuf, bp->base + bp->head, count);
		bp->head += count;
	} else {
		memset(optbuf, 0, sizeof(*optbuf));
	}
	return code;

underflow:
	bp->underflow = 1;
	return -1;
}

static int
ni_dhcp4_option_get_sockaddr(ni_buffer_t *bp, ni_sockaddr_t *addr)
{
	struct sockaddr_in *sin = &addr->sin;

	memset(sin, 0, sizeof(*addr));
	sin->sin_family = AF_INET;
	return ni_buffer_get(bp, &sin->sin_addr, 4);
}

static int
ni_dhcp4_option_get_ipv4(ni_buffer_t *bp, struct in_addr *addr)
{
	return ni_buffer_get(bp, addr, 4);
}

static int
ni_dhcp4_option_get16(ni_buffer_t *bp, uint16_t *var)
{
	if (ni_buffer_get(bp, var, 2) < 0)
		return -1;
	*var = ntohs(*var);
	return 0;
}

static int
ni_dhcp4_option_get32(ni_buffer_t *bp, uint32_t *var)
{
	if (ni_buffer_get(bp, var, 4) < 0)
		return -1;
	*var = ntohl(*var);
	return 0;
}

static int
ni_dhcp4_option_get_string(ni_buffer_t *bp, char **var, unsigned int *lenp)
{
	unsigned int len = ni_buffer_count(bp);

	if (len == 0)
		return -1;

	if (lenp)
		*lenp = len;
	if (*var)
		free(*var);
	*var = malloc(len + 1);
	ni_buffer_get(bp, *var, len);
	(*var)[len] = '\0';
	return 0;
}

static int
__ni_dhcp4_build_msg_put_our_hostname(const ni_dhcp4_device_t *dev,
					ni_buffer_t *msgbuf)
{
	const ni_dhcp4_config_t *options = dev->config;
	size_t len = ni_string_len(options->hostname);

	if (!len)
		return 1; /* skipped hint */

	if (options->fqdn == FQDN_DISABLE) {
		char hname[64] = {'\0'}, *end;

		/*
		 * Truncate the domain part if fqdn to avoid attempts
		 * to update DNS with foo.bar + update-domain.
		 */
		strncat(hname, options->hostname, sizeof(hname)-1);
		if ((end = strchr(hname, '.')))
			*end = '\0';

		len = ni_string_len(hname);
		if (ni_check_domain_name(hname, len, 0)) {
			ni_dhcp4_option_puts(msgbuf, DHCP4_HOSTNAME, hname);
			ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_DHCP,
				"%s: using hostname: %s", dev->ifname, hname);
		} else {
			ni_info("%s: not sending suspect hostname: '%s'",
				dev->ifname, ni_print_suspect(hname, len));
			return 1;
		}
	} else
	if (ni_check_domain_name(options->hostname, len, 0)) {
		/* IETF DHC-FQDN option(81)
		 * http://tools.ietf.org/html/rfc4702#section-2.1
		 *
		 * Flags: 0000NEOS
		 * S: 1 => Client requests Server to update
		 *         a RR in DNS as well as PTR
		 * O: 1 => Server indicates to client that
		 *         DNS has been updated
		 * E: 1 => Name data is DNS format
		 * N: 1 => Client requests Server to not
		 *         update DNS
		 */
		ni_buffer_putc(msgbuf, DHCP4_FQDN);
		ni_buffer_putc(msgbuf, len + 3);
		ni_buffer_putc(msgbuf, options->fqdn & 0x9);
		ni_buffer_putc(msgbuf, 0);	/* from server for PTR RR */
		ni_buffer_putc(msgbuf, 0);	/* from server for A RR if S=1 */
		ni_buffer_put(msgbuf, options->hostname, len);
		ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_DHCP,
				"%s: using fqdn: %s", dev->ifname,
				options->hostname);
	} else {
		ni_info("%s: not sending suspect fqdn: '%s'",
			dev->ifname, ni_print_suspect(options->hostname, len));
		return 1;
	}

	return 0;
}

static int
__ni_dhcp4_build_msg_put_option_request(const ni_dhcp4_device_t *dev,
					unsigned int msg_code, ni_buffer_t *msgbuf)
{
	const ni_dhcp4_config_t *options = dev->config;
	unsigned int params_begin;

	switch (msg_code) {
	case DHCP4_DISCOVER:
	case DHCP4_REQUEST:
	case DHCP4_INFORM:
		break;
	default:
		return 1; /* skipped hint */
	}

	params_begin = ni_dhcp4_option_begin(msgbuf, DHCP4_PARAMETERREQUESTLIST);
	if (msg_code != DHCP4_INFORM) {
		ni_buffer_putc(msgbuf, DHCP4_RENEWALTIME);
		ni_buffer_putc(msgbuf, DHCP4_REBINDTIME);
	}
	ni_buffer_putc(msgbuf, DHCP4_NETMASK);
	ni_buffer_putc(msgbuf, DHCP4_BROADCAST);
	ni_buffer_putc(msgbuf, DHCP4_MTU);

	/*
	 * RFC 3442 states classless static routes override both,
	 * the (default) router and (class) static routes options.
	 * Keep them in front also on request... just in case.
	 */
	if (options->doflags & DHCP4_DO_CSR) {
		ni_buffer_putc(msgbuf, DHCP4_CSR);
	}
	if (options->doflags & DHCP4_DO_MSCSR) {
		ni_buffer_putc(msgbuf, DHCP4_MSCSR);
	}
	if (options->doflags & DHCP4_DO_GATEWAY) {
		ni_buffer_putc(msgbuf, DHCP4_STATICROUTE);
		ni_buffer_putc(msgbuf, DHCP4_ROUTERS);
	}
	if (options->doflags & DHCP4_DO_HOSTNAME) {
		if (options->fqdn == FQDN_DISABLE) {
			ni_buffer_putc(msgbuf, DHCP4_HOSTNAME);
		} else {
			ni_buffer_putc(msgbuf, DHCP4_FQDN);
		}
	}
	if (options->doflags & DHCP4_DO_DNS) {
		ni_buffer_putc(msgbuf, DHCP4_DNSSEARCH);
		ni_buffer_putc(msgbuf, DHCP4_DNSDOMAIN);
		ni_buffer_putc(msgbuf, DHCP4_DNSSERVER);
	}
	if (options->doflags & DHCP4_DO_NIS) {
		ni_buffer_putc(msgbuf, DHCP4_NISDOMAIN);
		ni_buffer_putc(msgbuf, DHCP4_NISSERVER);
	}
	if (options->doflags & DHCP4_DO_NTP) {
		ni_buffer_putc(msgbuf, DHCP4_NTPSERVER);
	}
	if (options->doflags & DHCP4_DO_ROOT) {
		ni_buffer_putc(msgbuf, DHCP4_ROOTPATH);
	}
	if (options->doflags & DHCP4_DO_LPR) {
		ni_buffer_putc(msgbuf, DHCP4_LPRSERVER);
	}
	if (options->doflags & DHCP4_DO_LOG) {
		ni_buffer_putc(msgbuf, DHCP4_LOGSERVER);
	}
	if (options->doflags & DHCP4_DO_NDS) {
		ni_buffer_putc(msgbuf, DHCP4_NDS_SERVER);
		ni_buffer_putc(msgbuf, DHCP4_NDS_TREE);
		ni_buffer_putc(msgbuf, DHCP4_NDS_CTX);
	}
	if (options->doflags & DHCP4_DO_SIP) {
		ni_buffer_putc(msgbuf, DHCP4_SIPSERVER);
	}
	if (options->doflags & DHCP4_DO_SMB) {
		ni_buffer_putc(msgbuf, DHCP4_NETBIOSNAMESERVER);
		ni_buffer_putc(msgbuf, DHCP4_NETBIOSDDSERVER);
		ni_buffer_putc(msgbuf, DHCP4_NETBIOSNODETYPE);
		ni_buffer_putc(msgbuf, DHCP4_NETBIOSSCOPE);
	}
	if (options->doflags & DHCP4_DO_POSIX_TZ) {
		ni_buffer_putc(msgbuf, DHCP4_POSIX_TZ_STRING);
		ni_buffer_putc(msgbuf, DHCP4_POSIX_TZ_DBNAME);
	}
	ni_dhcp4_option_end(msgbuf, params_begin);

	ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_DHCP,
			"%s: using an option request", dev->ifname);

	return 0;
}

static int
__ni_dhcp4_build_msg_put_client_id(const ni_dhcp4_device_t *dev, unsigned int msg_code,
				ni_dhcp4_message_t *message, ni_buffer_t *msgbuf)
{
	const ni_dhcp4_config_t *options = dev->config;

	if (options->client_id.len) {
		ni_dhcp4_option_put(msgbuf, DHCP4_CLIENTID,
				options->client_id.data,
				options->client_id.len);

		ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_DHCP,
				"%s: using client-id: %s", dev->ifname,
				ni_print_hex(options->client_id.data,
						options->client_id.len));
	} else
	if (!message->hwlen) {
		ni_error("%s: cannot construct %s without usable hw-addr and client-id",
				dev->ifname, ni_dhcp4_message_name(msg_code));
		return -1;
	} else {
		return 1; /* skipped client-id */
	}
	return 0;
}

static int
__ni_dhcp4_build_msg_put_server_id(const ni_dhcp4_device_t *dev,
				const ni_addrconf_lease_t *lease,
				unsigned int msg_code, ni_buffer_t *msgbuf)
{
	ni_sockaddr_t addr;

	ni_sockaddr_set_ipv4(&addr, lease->dhcp4.server_id, 0);
	if (!ni_sockaddr_is_ipv4_specified(&addr)) {
		ni_error("%s: cannot construct %s without server-id",
				dev->ifname, ni_dhcp4_message_name(msg_code));
		return -1;
	}

	ni_dhcp4_option_put_ipv4(msgbuf, DHCP4_SERVERIDENTIFIER, lease->dhcp4.server_id);
	ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_DHCP,
			"%s: using server-id: %s", dev->ifname,
			ni_sockaddr_print(&addr));
	return 0;
}


static int
__ni_dhcp4_build_msg_put_hwspec(const ni_dhcp4_device_t *dev, ni_dhcp4_message_t *message)
{
	switch (dev->system.hwaddr.type) {
	case ARPHRD_ETHER:
	case ARPHRD_IEEE802:
		if (dev->system.hwaddr.len && dev->system.hwaddr.len <= sizeof(message->chaddr)) {
			message->hwlen = dev->system.hwaddr.len;
			memcpy(&message->chaddr, dev->system.hwaddr.data, dev->system.hwaddr.len);
		}
		break;

	case ARPHRD_IEEE1394:
	case ARPHRD_INFINIBAND:
		/* See http://tools.ietf.org/html/rfc4390
		 *
		 * Note: set the ciaddr before if needed.
		 */
		message->hwlen = 0;
		if (message->ciaddr == 0)
			message->flags = htons(BROADCAST_FLAG);
		break;

	default:
		ni_error("%s: dhcp4 unsupported hardware type %s (0x%x)", dev->ifname,
				ni_arphrd_type_to_name(dev->system.hwaddr.type),
				dev->system.hwaddr.type);
		return -1;
	}
	if (message->hwlen) {
		ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_DHCP,
				"%s: using hw-address[%u]: %s", dev->ifname,
				message->hwtype, ni_print_hex(message->chaddr, message->hwlen));
	}
	if (message->flags & htons(BROADCAST_FLAG)) {
		ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_DHCP,
				"%s: using broadcast response flag", dev->ifname);
	}
	return 0;
}

static ni_dhcp4_message_t *
__ni_dhcp4_build_msg_init_head(const ni_dhcp4_device_t *dev,
				unsigned int msg_code, ni_buffer_t *msgbuf)
{
	ni_dhcp4_message_t *message;

	/* Build the main message (header) */
	if (!(message = ni_buffer_push_tail(msgbuf, sizeof(*message)))) {
		ni_error("%s: buffer too short for dhcp4 message", dev->ifname);
		return NULL;
	}

	memset(message, 0, sizeof(*message));
	message->op = DHCP4_BOOTREQUEST;
	message->xid = dev->dhcp4.xid;
	message->secs = htons(ni_dhcp4_device_uptime(dev, 0xFFFF));
	message->cookie = htonl(MAGIC_COOKIE);
	message->hwtype = dev->system.hwaddr.type;

	ni_dhcp4_option_put8(msgbuf, DHCP4_MESSAGETYPE, msg_code);
	ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_DHCP,
			"%s: using message type: %s", dev->ifname,
			ni_dhcp4_message_name(msg_code));

	return message;
}

static int
__ni_dhcp4_build_msg_discover(const ni_dhcp4_device_t *dev,
			const ni_addrconf_lease_t *lease,
			ni_buffer_t *msgbuf)
{
	const ni_dhcp4_config_t *options = dev->config;
	unsigned int msg_code = DHCP4_DISCOVER;
	ni_dhcp4_message_t *message;
	ni_sockaddr_t addr;

	/* Discover server able to provide usable offer */
	if (!(message = __ni_dhcp4_build_msg_init_head(dev, msg_code, msgbuf)))
		return -1;

	if (__ni_dhcp4_build_msg_put_hwspec(dev, message) < 0)
		return -1;

	if (__ni_dhcp4_build_msg_put_client_id(dev, msg_code, message, msgbuf) <  0)
		return -1;

	/* An optional hint that we've had this address in the past,
	 * so the server __may__ assign it again to us.
	 */
	ni_sockaddr_set_ipv4(&addr, lease->dhcp4.address, 0);
	if (ni_sockaddr_is_ipv4_specified(&addr)) {
		ni_dhcp4_option_put_ipv4(msgbuf, DHCP4_ADDRESS, lease->dhcp4.address);
		ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_DHCP,
				"%s: using ip-address hint: %s",
				dev->ifname, ni_sockaddr_print(&addr));
	}

	if (__ni_dhcp4_build_msg_put_option_request(dev, msg_code, msgbuf) <  0)
		return -1;

	ni_dhcp4_option_put16(msgbuf, DHCP4_MAXMESSAGESIZE, dev->system.mtu);

	if (lease->dhcp4.lease_time != 0) {
		ni_dhcp4_option_put32(msgbuf, DHCP4_LEASETIME,
					lease->dhcp4.lease_time);
	}

	if (options->userclass.len > 0) {
		ni_dhcp4_option_put(msgbuf, DHCP4_USERCLASS,
				options->userclass.data,
				options->userclass.len);
	}

	if (options->classid && options->classid[0]) {
		ni_dhcp4_option_puts(msgbuf, DHCP4_CLASSID, options->classid);
	}

	return 0;
}

static int
__ni_dhcp4_build_msg_decline(const ni_dhcp4_device_t *dev,
			const ni_addrconf_lease_t *lease,
			ni_buffer_t *msgbuf)
{
	unsigned int msg_code = DHCP4_DECLINE;
	ni_dhcp4_message_t *message;
	ni_sockaddr_t addr;

	/* Decline IP address the server offered to us;
	 * we've found another host using it already.
	 */
	ni_sockaddr_set_ipv4(&addr, lease->dhcp4.address, 0);
	if (!ni_sockaddr_is_ipv4_specified(&addr)) {
		ni_error("%s: cannot decline - no ip-address in lease", dev->ifname);
		return -1;
	}

	if (!(message = __ni_dhcp4_build_msg_init_head(dev, msg_code, msgbuf)))
		return -1;

	if (__ni_dhcp4_build_msg_put_hwspec(dev, message) < 0)
		return -1;

	if (__ni_dhcp4_build_msg_put_client_id(dev, msg_code, message, msgbuf) <  0)
		return -1;

	if (__ni_dhcp4_build_msg_put_server_id(dev, lease, msg_code, msgbuf) <  0)
		return -1;

	ni_dhcp4_option_put_ipv4(msgbuf, DHCP4_ADDRESS, lease->dhcp4.address);
	ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_DHCP,
			"%s: using decline ip-address: %s",
			dev->ifname, ni_sockaddr_print(&addr));
	return 0;
}

static int
__ni_dhcp4_build_msg_release(const ni_dhcp4_device_t *dev,
			const ni_addrconf_lease_t *lease,
			ni_buffer_t *msgbuf)
{
	unsigned int msg_code = DHCP4_RELEASE;
	ni_dhcp4_message_t *message;
	ni_sockaddr_t addr;

	/* Release an IP address from a lease we own */
	ni_sockaddr_set_ipv4(&addr, lease->dhcp4.address, 0);
	if (!ni_sockaddr_is_ipv4_specified(&addr)) {
		ni_error("%s: cannot release - no ip-address in lease", dev->ifname);
		return -1;
	}

	if (!(message = __ni_dhcp4_build_msg_init_head(dev, msg_code, msgbuf)))
		return -1;

	message->ciaddr = lease->dhcp4.address.s_addr;
	ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_DHCP,
			"%s: using release ip-address: %s",
			dev->ifname, ni_sockaddr_print(&addr));

	if (__ni_dhcp4_build_msg_put_hwspec(dev, message) < 0)
		return -1;

	if (__ni_dhcp4_build_msg_put_client_id(dev, msg_code, message, msgbuf) <  0)
		return -1;

	if (__ni_dhcp4_build_msg_put_server_id(dev, lease, msg_code, msgbuf) <  0)
		return -1;

	return 0;
}

int
__ni_dhcp4_build_msg_inform(const ni_dhcp4_device_t *dev,
			const ni_addrconf_lease_t *lease,
			ni_buffer_t *msgbuf)
{
	const ni_dhcp4_config_t *options = dev->config;
	unsigned int msg_code = DHCP4_INFORM;
	ni_dhcp4_message_t *message;
	ni_sockaddr_t addr;

	/* Inform server about IP address we use and request other config */
	ni_sockaddr_set_ipv4(&addr, lease->dhcp4.address, 0);
	if (!ni_sockaddr_is_ipv4_specified(&addr)) {
		ni_error("%s: cannot inform - no ip-address set", dev->ifname);
		return -1;
	}

	if (!(message = __ni_dhcp4_build_msg_init_head(dev, msg_code, msgbuf)))
		return -1;

	message->ciaddr = lease->dhcp4.address.s_addr;
	ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_DHCP,
			"%s: using inform ip-address: %s",
			dev->ifname, ni_sockaddr_print(&addr));

	if (__ni_dhcp4_build_msg_put_hwspec(dev, message) < 0)
		return -1;

	if (__ni_dhcp4_build_msg_put_client_id(dev, msg_code, message, msgbuf) <  0)
		return -1;

	if (__ni_dhcp4_build_msg_put_option_request(dev, msg_code, msgbuf) <  0)
		return -1;

	ni_dhcp4_option_put16(msgbuf, DHCP4_MAXMESSAGESIZE, dev->system.mtu);

	if (options->userclass.len > 0) {
		ni_dhcp4_option_put(msgbuf, DHCP4_USERCLASS,
				options->userclass.data,
				options->userclass.len);
	}

	if (options->classid && options->classid[0]) {
		ni_dhcp4_option_puts(msgbuf, DHCP4_CLASSID, options->classid);
	}

	return 0;
}

int
__ni_dhcp4_build_msg_request_offer(const ni_dhcp4_device_t *dev,
			const ni_addrconf_lease_t *lease,
			ni_buffer_t *msgbuf)
{
	const ni_dhcp4_config_t *options = dev->config;
	unsigned int msg_code = DHCP4_REQUEST;
	ni_dhcp4_message_t *message;
	ni_sockaddr_t addr;

	/* Request an offer provided by a server (id!) while discover */
	ni_sockaddr_set_ipv4(&addr, lease->dhcp4.address, 0);
	if (!ni_sockaddr_is_ipv4_specified(&addr)) {
		ni_error("%s: not requesting this offer - no ip-address in lease",
				dev->ifname);
		return -1;
	}

	if (!(message = __ni_dhcp4_build_msg_init_head(dev, msg_code, msgbuf)))
		return -1;

	if (__ni_dhcp4_build_msg_put_hwspec(dev, message) < 0)
		return -1;

	if (__ni_dhcp4_build_msg_put_client_id(dev, msg_code, message, msgbuf) <  0)
		return -1;

	if (__ni_dhcp4_build_msg_put_server_id(dev, lease, msg_code, msgbuf) <  0)
		return -1;

	ni_dhcp4_option_put_ipv4(msgbuf, DHCP4_ADDRESS, lease->dhcp4.address);
	ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_DHCP,
			"%s: using offered ip-address: %s",
			dev->ifname, ni_sockaddr_print(&addr));

	if (__ni_dhcp4_build_msg_put_our_hostname(dev, msgbuf) < 0)
		return -1;

	if (__ni_dhcp4_build_msg_put_option_request(dev, msg_code, msgbuf) <  0)
		return -1;

	ni_dhcp4_option_put16(msgbuf, DHCP4_MAXMESSAGESIZE, dev->system.mtu);

	if (lease->dhcp4.lease_time != 0) {
		ni_dhcp4_option_put32(msgbuf, DHCP4_LEASETIME,
					lease->dhcp4.lease_time);
	}

	if (options->userclass.len > 0) {
		ni_dhcp4_option_put(msgbuf, DHCP4_USERCLASS,
				options->userclass.data,
				options->userclass.len);
	}

	if (options->classid && options->classid[0]) {
		ni_dhcp4_option_puts(msgbuf, DHCP4_CLASSID, options->classid);
	}

	return 0;
}

int
__ni_dhcp4_build_msg_request_renew(const ni_dhcp4_device_t *dev,
			const ni_addrconf_lease_t *lease,
			ni_buffer_t *msgbuf)
{
	const ni_dhcp4_config_t *options = dev->config;
	unsigned int msg_code = DHCP4_REQUEST;
	ni_dhcp4_message_t *message;
	ni_sockaddr_t addr;

	/* Request a lease renewal (unicast to server, no id) */
	ni_sockaddr_set_ipv4(&addr, lease->dhcp4.address, 0);
	if (!ni_sockaddr_is_ipv4_specified(&addr)) {
		ni_error("%s: cannot renew - no ip-address in lease",
				dev->ifname);
		return -1;
	}

	if (!(message = __ni_dhcp4_build_msg_init_head(dev, msg_code, msgbuf)))
		return -1;

	message->ciaddr = lease->dhcp4.address.s_addr;
	ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_DHCP,
			"%s: using renew ip-address: %s",
			dev->ifname, ni_sockaddr_print(&addr));

	if (__ni_dhcp4_build_msg_put_hwspec(dev, message) < 0)
		return -1;

	if (__ni_dhcp4_build_msg_put_client_id(dev, msg_code, message, msgbuf) <  0)
		return -1;

	if (__ni_dhcp4_build_msg_put_our_hostname(dev, msgbuf) < 0)
		return -1;

	if (__ni_dhcp4_build_msg_put_option_request(dev, msg_code, msgbuf) <  0)
		return -1;

	ni_dhcp4_option_put16(msgbuf, DHCP4_MAXMESSAGESIZE, dev->system.mtu);

#if 0
	if (lease->dhcp4.lease_time != 0) {
		ni_dhcp4_option_put32(msgbuf, DHCP4_LEASETIME,
					lease->dhcp4.lease_time);
	}
#endif

	if (options->userclass.len > 0) {
		ni_dhcp4_option_put(msgbuf, DHCP4_USERCLASS,
				options->userclass.data,
				options->userclass.len);
	}

	if (options->classid && options->classid[0]) {
		ni_dhcp4_option_puts(msgbuf, DHCP4_CLASSID, options->classid);
	}

	return 0;
}

int
__ni_dhcp4_build_msg_request_rebind(const ni_dhcp4_device_t *dev,
			const ni_addrconf_lease_t *lease,
			ni_buffer_t *msgbuf)
{
	const ni_dhcp4_config_t *options = dev->config;
	unsigned int msg_code = DHCP4_REQUEST;
	ni_dhcp4_message_t *message;
	ni_sockaddr_t addr;

	/* Request a lease rebind from another server (no id) */
	ni_sockaddr_set_ipv4(&addr, lease->dhcp4.address, 0);
	if (!ni_sockaddr_is_ipv4_specified(&addr)) {
		ni_error("%s: cannot rebind - no ip-address in lease",
				dev->ifname);
		return -1;
	}

	if (!(message = __ni_dhcp4_build_msg_init_head(dev, msg_code, msgbuf)))
		return -1;

	message->ciaddr = lease->dhcp4.address.s_addr;
	ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_DHCP,
			"%s: using rebind ip-address: %s",
			dev->ifname, ni_sockaddr_print(&addr));

	if (__ni_dhcp4_build_msg_put_hwspec(dev, message) < 0)
		return -1;

	if (__ni_dhcp4_build_msg_put_client_id(dev, msg_code, message, msgbuf) <  0)
		return -1;

	if (__ni_dhcp4_build_msg_put_our_hostname(dev, msgbuf) < 0)
		return -1;

	if (__ni_dhcp4_build_msg_put_option_request(dev, msg_code, msgbuf) <  0)
		return -1;

	ni_dhcp4_option_put16(msgbuf, DHCP4_MAXMESSAGESIZE, dev->system.mtu);

#if 0
	if (lease->dhcp4.lease_time != 0) {
		ni_dhcp4_option_put32(msgbuf, DHCP4_LEASETIME,
					lease->dhcp4.lease_time);
	}
#endif

	if (options->userclass.len > 0) {
		ni_dhcp4_option_put(msgbuf, DHCP4_USERCLASS,
				options->userclass.data,
				options->userclass.len);
	}

	if (options->classid && options->classid[0]) {
		ni_dhcp4_option_puts(msgbuf, DHCP4_CLASSID, options->classid);
	}

	return 0;
}

int
__ni_dhcp4_build_msg_request_reboot(const ni_dhcp4_device_t *dev,
			const ni_addrconf_lease_t *lease,
			ni_buffer_t *msgbuf)
{
	const ni_dhcp4_config_t *options = dev->config;
	unsigned int msg_code = DHCP4_REQUEST;
	ni_dhcp4_message_t *message;
	ni_sockaddr_t addr;

	/* Request an lease after reboot to reuse old lease (no server id) */
	ni_sockaddr_set_ipv4(&addr, lease->dhcp4.address, 0);
	if (!ni_sockaddr_is_ipv4_specified(&addr)) {
		ni_error("%s: not reusing lease - no ip-address in lease",
				dev->ifname);
		return -1;
	}

	if (!(message = __ni_dhcp4_build_msg_init_head(dev, msg_code, msgbuf)))
		return -1;

	if (__ni_dhcp4_build_msg_put_hwspec(dev, message) < 0)
		return -1;

	if (__ni_dhcp4_build_msg_put_client_id(dev, msg_code, message, msgbuf) <  0)
		return -1;

	ni_dhcp4_option_put_ipv4(msgbuf, DHCP4_ADDRESS, lease->dhcp4.address);
	ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_DHCP,
			"%s: using reused ip-address: %s",
			dev->ifname, ni_sockaddr_print(&addr));

	if (__ni_dhcp4_build_msg_put_our_hostname(dev, msgbuf) < 0)
		return -1;

	if (__ni_dhcp4_build_msg_put_option_request(dev, msg_code, msgbuf) <  0)
		return -1;

	ni_dhcp4_option_put16(msgbuf, DHCP4_MAXMESSAGESIZE, dev->system.mtu);

#if 0
	if (lease->dhcp4.lease_time != 0) {
		ni_dhcp4_option_put32(msgbuf, DHCP4_LEASETIME,
					lease->dhcp4.lease_time);
	}
#endif

	if (options->userclass.len > 0) {
		ni_dhcp4_option_put(msgbuf, DHCP4_USERCLASS,
				options->userclass.data,
				options->userclass.len);
	}

	if (options->classid && options->classid[0]) {
		ni_dhcp4_option_puts(msgbuf, DHCP4_CLASSID, options->classid);
	}

	return 0;
}

int
ni_dhcp4_build_message(const ni_dhcp4_device_t *dev, unsigned int msg_code,
			const ni_addrconf_lease_t *lease, ni_buffer_t *msgbuf)
{
	const ni_dhcp4_config_t *options = dev->config;
	struct in_addr src_addr, dst_addr;
	int renew = dev->fsm.state == NI_DHCP4_STATE_RENEWING && msg_code == DHCP4_REQUEST;

	if (!options || !lease) {
		ni_error("%s: %s: %s: missing %s %s", __func__,
				dev->ifname, ni_dhcp4_message_name(msg_code),
				options? "" : "options", lease ? "" : "lease");
		return -1;
	}

	if (IN_LINKLOCAL(ntohl(lease->dhcp4.address.s_addr))) {
		ni_error("%s: cannot request a link local address", dev->ifname);
		goto failed;
	}

	/* Reserve some room for the IP and UDP header */
	if (!renew)
		ni_buffer_reserve_head(msgbuf, sizeof(struct ip) + sizeof(struct udphdr));

	src_addr.s_addr = dst_addr.s_addr = 0;
	switch (msg_code) {
	case DHCP4_INFORM:
		if (__ni_dhcp4_build_msg_inform(dev, lease, msgbuf) < 0)
			goto failed;
		break;

	case DHCP4_DISCOVER:
		if (__ni_dhcp4_build_msg_discover(dev, lease, msgbuf) < 0)
			goto failed;
		break;

	case DHCP4_DECLINE:
		if (__ni_dhcp4_build_msg_decline(dev, lease, msgbuf) < 0)
			goto failed;
		break;

	case DHCP4_RELEASE:
		if (__ni_dhcp4_build_msg_release(dev, lease, msgbuf) < 0)
			goto failed;
		break;

	case DHCP4_REQUEST:
		switch (dev->fsm.state) {
		case NI_DHCP4_STATE_REQUESTING:
			src_addr.s_addr = 0;
			dst_addr.s_addr = 0;

			if (__ni_dhcp4_build_msg_request_offer(dev, lease, msgbuf) < 0)
				goto failed;
			break;

		case NI_DHCP4_STATE_RENEWING:
			src_addr = lease->dhcp4.address;
			dst_addr = lease->dhcp4.server_id;

			if (__ni_dhcp4_build_msg_request_renew(dev, lease, msgbuf) < 0)
				goto failed;
			break;

		case NI_DHCP4_STATE_REBINDING:
			src_addr = lease->dhcp4.address;
			dst_addr.s_addr = 0;

			if (__ni_dhcp4_build_msg_request_rebind(dev, lease, msgbuf) < 0)
				goto failed;
			break;

		case NI_DHCP4_STATE_REBOOT:
			src_addr.s_addr = 0;
			dst_addr.s_addr = 0;

			if (__ni_dhcp4_build_msg_request_reboot(dev, lease, msgbuf) < 0)
				goto failed;
			break;

		default:
			goto failed;
		}
		break;

	default:
		goto failed;
	}

	ni_buffer_putc(msgbuf, DHCP4_END);

#ifdef BOOTP_MESSAGE_LENGTH_MIN
	ni_buffer_pad(msgbuf, BOOTP_MESSAGE_LENGTH_MIN, DHCP4_PAD);
#endif

	if (!renew && ni_capture_build_udp_header(msgbuf, src_addr,
			DHCP4_CLIENT_PORT, dst_addr, DHCP4_SERVER_PORT) < 0) {
		ni_error("%s: unable to build packet header", dev->ifname);
		goto failed;
	}

	return 0;
failed:
	return -1;
}

/*
 * Decode an RFC3397 DNS search order option.
 */
static int
ni_dhcp4_decode_dnssearch(ni_buffer_t *optbuf, ni_string_array_t *list, const char *what)
{
	ni_stringbuf_t namebuf = NI_STRINGBUF_INIT_DYNAMIC;
	unsigned char *base = ni_buffer_head(optbuf);
	unsigned int base_offset = optbuf->head;
	size_t len;

	ni_string_array_destroy(list);

	while (ni_buffer_count(optbuf) && !optbuf->underflow) {
		ni_buffer_t *bp = optbuf;
		ni_buffer_t jumpbuf;

		while (1) {
			unsigned int pos = bp->head - base_offset;
			unsigned int pointer;
			char label[64];
			int length;

			if ((length = ni_buffer_getc(bp)) < 0)
				goto failure; /* unexpected EOF */

			if (length == 0)
				break;	/* end of this name */

			switch (length & 0xC0) {
			case 0:
				/* Plain name component */
				if (ni_buffer_get(bp, label, length) < 0)
					goto failure;

				label[length] = '\0';
				if (!ni_stringbuf_empty(&namebuf))
					ni_stringbuf_putc(&namebuf, '.');
				ni_stringbuf_puts(&namebuf, label);
				break;

			case 0xC0:
				/* Pointer */
				pointer = (length & 0x3F) << 8;
				if ((length = ni_buffer_getc(bp)) < 0)
					goto failure;

				pointer |= length;
				if (pointer >= pos)
					goto failure;

				ni_buffer_init_reader(&jumpbuf, base, pos);
				jumpbuf.head = pointer;
				bp = &jumpbuf;
				break;

			default:
				goto failure;
			}

		}

		if (!ni_stringbuf_empty(&namebuf)) {

			len = ni_string_len(namebuf.string);
			if (ni_check_domain_name(namebuf.string, len, 0)) {
				ni_string_array_append(list, namebuf.string);
			} else {
				ni_warn("Discarded suspect %s: '%s'", what,
					ni_print_suspect(namebuf.string, len));
			}
		}
		ni_stringbuf_destroy(&namebuf);
	}

	return 0;

failure:
	ni_stringbuf_destroy(&namebuf);
	ni_string_array_destroy(list);
	return -1;
}

/*
 * Decode a CIDR list option.
 */
static int
ni_dhcp4_decode_csr(ni_buffer_t *bp, ni_route_array_t *routes)
{
	while (ni_buffer_count(bp) && !bp->underflow) {
		ni_sockaddr_t destination, gateway;
		struct in_addr prefix = { 0 };
		unsigned int prefix_len;
		ni_route_t *rp;

		prefix_len = ni_buffer_getc(bp);
		if (prefix_len > 32) {
			ni_error("invalid prefix len of %u in classless static route", prefix_len);
			return -1;
		}

		if (prefix_len)
			ni_buffer_get(bp, &prefix, (prefix_len + 7) / 8);
		ni_sockaddr_set_ipv4(&destination, prefix, 0);

		if (ni_dhcp4_option_get_sockaddr(bp, &gateway) < 0)
			return -1;

		rp = ni_route_create(prefix_len, &destination, &gateway, 0, NULL);
		ni_route_array_append(routes, rp);
	}

	if (bp->underflow)
		return -1;

	return 0;
}

static int
ni_dhcp4_decode_address_list(ni_buffer_t *bp, ni_string_array_t *list)
{
	while (ni_buffer_count(bp) && !bp->underflow) {
		struct in_addr addr;

		if (ni_dhcp4_option_get_ipv4(bp, &addr) < 0)
			return -1;
		ni_string_array_append(list, inet_ntoa(addr));
	}

	if (bp->underflow)
		return -1;

	return 0;
}

static int
ni_dhcp4_decode_sipservers(ni_buffer_t *bp, ni_string_array_t *list)
{
	int encoding;

	encoding = ni_buffer_getc(bp);
	switch (encoding) {
	case -1:
		ni_debug_dhcp("%s: missing data", __FUNCTION__);
		return -1;

	case 0:
		return ni_dhcp4_decode_dnssearch(bp, list, "sip-server name");

	case 1:
		return ni_dhcp4_decode_address_list(bp, list);

	default:
		ni_error("unknown sip encoding %d", encoding);
		return -1;
	}

	return 0;
}

/*
 * Given an IPv4 address, guess the netmask.
 */
static inline unsigned int
__count_net_bits(uint32_t prefix)
{
	unsigned int len = 0;

	while (prefix) {
		prefix <<= 1;
		len++;
	}
	return len;
}

static unsigned int
guess_prefix_len(struct in_addr addr)
{
	uint32_t prefix = ntohl(addr.s_addr);
	unsigned int len;

	/* At a minimum, use the prefix len for this IPv4 address class. */
	if (IN_CLASSA(prefix))
		len = 8;
	else if (IN_CLASSB(prefix))
		len = 16;
	else if (IN_CLASSC(prefix))
		len = 24;
	else
		len = 0;

	/* If the address has bits beyond the default class,
	 * extend the prefix until we've covered all of them. */
	return len + __count_net_bits(prefix << len);
}

static unsigned int
guess_prefix_len_sockaddr(const ni_sockaddr_t *ap)
{
	return guess_prefix_len(ap->sin.sin_addr);
}

/*
 * DHCP4_STATICROUTE
 * List of network/gateway pairs.
 */
static int
ni_dhcp4_decode_static_routes(ni_buffer_t *bp, ni_route_array_t *routes)
{
	while (ni_buffer_count(bp) && !bp->underflow) {
		ni_sockaddr_t destination, gateway;
		ni_route_t *rp;

		if (ni_dhcp4_option_get_sockaddr(bp, &destination) < 0
		 || ni_dhcp4_option_get_sockaddr(bp, &gateway) < 0)
			return -1;

		rp = ni_route_create(guess_prefix_len_sockaddr(&destination),
				&destination,
				&gateway,
				0, NULL);
		ni_route_array_append(routes, rp);
	}

	return 0;
}

/*
 * DHCP4_ROUTERS (3)
 * List of gateways for default route
 */
static int
ni_dhcp4_decode_routers(ni_buffer_t *bp, ni_route_array_t *routes)
{
	ni_sockaddr_t gateway;

	while (ni_buffer_count(bp) && !bp->underflow) {
		ni_route_t *rp;

		if (ni_dhcp4_option_get_sockaddr(bp, &gateway) < 0)
			return -1;

		rp = ni_route_create(0, NULL, &gateway, 0, NULL);
		ni_route_array_append(routes, rp);
	}

	return 0;
}

static int
ni_dhcp4_option_get_domain(ni_buffer_t *bp, char **var, const char *what)
{
	unsigned int len;
	char *tmp = NULL;

	if (ni_dhcp4_option_get_string(bp, &tmp, &len) < 0)
		return -1;

	if (!ni_check_domain_name(tmp, len, 0)) {
		ni_warn("Discarded suspect %s: '%s'", what,
			ni_print_suspect(tmp, len));
		free(tmp);
		return -1;
	}

	if (*var)
		free(*var);
	*var = tmp;
	return 0;
}

static int
ni_dhcp4_option_get_domain_list(ni_buffer_t *bp, ni_string_array_t *var,
					const char *what)
{
	ni_string_array_t list = NI_STRING_ARRAY_INIT;
	unsigned int len, i;
	char *tmp = NULL;

	if (ni_dhcp4_option_get_string(bp, &tmp, &len) < 0)
		return -1;

	/*
	 * Hack to accept "compatibility abuse" of dns domain name
	 * option containing multiple domains instead to send them
	 * using a dns-search option...
	 */
	if (!ni_string_split(&list, tmp, " ", 0)) {
		ni_warn("Discarded suspect %s: '%s'", what,
				ni_print_suspect(tmp, len));
		free(tmp);
		return -1;
	}
	for (i = 0; i < list.count; ++i) {
		const char *dom = list.data[i];
		if (!ni_check_domain_name(dom, ni_string_len(dom), 0)) {
			ni_warn("Discarded suspect %s: '%s'", what,
				ni_print_suspect(tmp, len));
			ni_string_array_destroy(&list);
			free(tmp);
			return -1;
		}
	}
	if (list.count != 1) {
		ni_warn("Abuse of %s option to provide a list: '%s'",
			what, tmp);
	}
	free(tmp);
	ni_string_array_move(var, &list);
	return 0;
}

static int
ni_dhcp4_option_get_pathname(ni_buffer_t *bp, char **var, const char *what)
{
	unsigned int len;
	char *tmp = NULL;

	if (ni_dhcp4_option_get_string(bp, &tmp, &len) < 0)
		return -1;

	if (!ni_check_pathname(tmp, len)) {
		ni_warn("Discarded suspect %s: '%s'", what,
			ni_print_suspect(tmp, len));
		free(tmp);
		return -1;
	}

	if (*var)
		free(*var);
	*var = tmp;
	return 0;
}

static int
ni_dhcp4_option_get_printable(ni_buffer_t *bp, char **var, const char *what)
{
	unsigned int len;
	char *tmp = NULL;

	if (ni_dhcp4_option_get_string(bp, &tmp, &len) < 0)
		return -1;

	if (!ni_check_printable(tmp, len)) {
		ni_warn("Discarded non-printable %s: '%s'", what,
			ni_print_suspect(tmp, len));
		free(tmp);
		return -1;
	}

	if (*var)
		free(*var);
	*var = tmp;
	return 0;
}

static int
ni_dhcp4_option_get_netbios_type(ni_buffer_t *bp, unsigned int *type)
{
	unsigned int len = ni_buffer_count(bp);

	if (len != 1)
		return -1;

	*type = (unsigned int)ni_buffer_getc(bp);
	switch (*type) {
		case 0x1:	/* B-node */
		case 0x2:	/* P-node */
		case 0x4:	/* M-node */
		case 0x8:	/* H-node */
			return 0;
		default:
			break;
	}
	*type = 0;
	return -1;
}

void
ni_dhcp4_apply_routes(ni_addrconf_lease_t *lease, ni_route_array_t *routes)
{
	ni_route_array_t temp = NI_ROUTE_ARRAY_INIT;
	ni_route_t *rp, *r;
	ni_address_t *ap;
	unsigned int i, j;

	if (!lease || !routes)
		return;

	/* apply device routes first (if any) */
	for (i = 0; i < routes->count; ++i) {
		if (!(rp = routes->data[i]))
			continue;
		if (ni_sockaddr_is_specified(&rp->nh.gateway))
			continue;
		ni_route_array_append(&temp, ni_route_ref(rp));
	}

	/* now the routes with a gateway - add a
	 * device routes as needed / when missed */
	for (i = 0; i < routes->count; ++i) {
		ni_bool_t added = FALSE;

		if (!(rp = routes->data[i]))
			continue;
		if (!ni_sockaddr_is_specified(&rp->nh.gateway))
			continue;

		/* just add, when gateway is on the same net as IP */
		for (ap = lease->addrs; !added && ap; ap = ap->next) {
			if (!ni_address_can_reach(ap, &rp->nh.gateway))
				continue;
			ni_route_array_append(&temp, ni_route_ref(rp));
			added = TRUE;
		}
		/* or there is a device route allowing to reach it */
		for (j = 0; !added && j < temp.count; ++j) {
			if (!(r = temp.data[j]))
				continue;
			if (ni_sockaddr_is_specified(&r->nh.gateway))
				continue;

			if (!ni_sockaddr_prefix_match(r->prefixlen,
						&r->destination,
						&rp->nh.gateway))
				continue;
			ni_route_array_append(&temp, ni_route_ref(rp));
			added = TRUE;
		}

		/* otherwise, automatically prepend a device route */
		if (!added) {
			unsigned int len = ni_af_address_length(rp->family);
			r = ni_route_create(len * 8, &rp->nh.gateway, NULL, 0, NULL);
			ni_route_array_append(&temp, r);
			ni_route_array_append(&temp, ni_route_ref(rp));
		}
	}
	ni_route_tables_add_routes(&lease->routes, &temp);
	ni_route_array_destroy(&temp);
}

/*
 * Parse a DHCP4 response.
 * FIXME: RFC2131 states that the server is allowed to split a DHCP4 option into
 * several (partial) options if the total length exceeds 255 octets. We don't
 * handle this yet.
 */
int
ni_dhcp4_parse_response(const ni_dhcp4_message_t *message, ni_buffer_t *options, ni_addrconf_lease_t **leasep)
{
	ni_buffer_t overload_buf;
	ni_addrconf_lease_t *lease;
	ni_route_array_t default_routes = NI_ROUTE_ARRAY_INIT;
	ni_route_array_t static_routes = NI_ROUTE_ARRAY_INIT;
	ni_route_array_t classless_routes = NI_ROUTE_ARRAY_INIT;
	ni_string_array_t dns_servers = NI_STRING_ARRAY_INIT;
	ni_string_array_t dns_search = NI_STRING_ARRAY_INIT;
	ni_string_array_t dns_domain = NI_STRING_ARRAY_INIT;
	ni_string_array_t nis_servers = NI_STRING_ARRAY_INIT;
	char *nisdomain = NULL;
	char *tmp = NULL;
	int opt_overload = 0;
	int msg_type = -1;
	int use_bootserver = 1;
	int use_bootfile = 1;
	unsigned int pfxlen;

	lease = ni_addrconf_lease_new(NI_ADDRCONF_DHCP, AF_INET);

	lease->state = NI_ADDRCONF_STATE_GRANTED;
	lease->type = NI_ADDRCONF_DHCP;
	lease->family = AF_INET;
	lease->time_acquired = time(NULL);

	lease->dhcp4.address.s_addr = message->yiaddr;
	lease->dhcp4.boot_saddr.s_addr = message->siaddr;
	lease->dhcp4.relay_addr.s_addr = message->giaddr;

parse_more:
	/* Loop as long as we still have data in the buffer. */
	while (ni_buffer_count(options) && !options->underflow) {
		ni_buffer_t buf;
		int option;

		option = ni_dhcp4_option_next(options, &buf);

		//ni_debug_dhcp("handle option %s (%d)", ni_dhcp4_option_name(option), option);
		if (option == DHCP4_PAD)
			continue;

		if (option == DHCP4_END)
			break;

		if (option < 0)
			goto error;

		if (ni_buffer_count(&buf) == 0) {
			ni_error("option %d has zero length", option);
			goto error;
		}

		switch (option) {
		case DHCP4_MESSAGETYPE:
			msg_type = ni_buffer_getc(&buf);
			if (msg_type < 0)
				goto error;
			continue;
		case DHCP4_ADDRESS:
			ni_dhcp4_option_get_ipv4(&buf, &lease->dhcp4.address);
			break;
		case DHCP4_NETMASK:
			ni_dhcp4_option_get_ipv4(&buf, &lease->dhcp4.netmask);
			break;
		case DHCP4_BROADCAST:
			ni_dhcp4_option_get_ipv4(&buf, &lease->dhcp4.broadcast);
			break;
		case DHCP4_SERVERIDENTIFIER:
			ni_dhcp4_option_get_ipv4(&buf, &lease->dhcp4.server_id);
			break;
		case DHCP4_LEASETIME:
			ni_dhcp4_option_get32(&buf, &lease->dhcp4.lease_time);
			break;
		case DHCP4_RENEWALTIME:
			ni_dhcp4_option_get32(&buf, &lease->dhcp4.renewal_time);
			break;
		case DHCP4_REBINDTIME:
			ni_dhcp4_option_get32(&buf, &lease->dhcp4.rebind_time);
			break;
		case DHCP4_MTU:
			ni_dhcp4_option_get16(&buf, &lease->dhcp4.mtu);
			/* Minimum legal mtu is 68 accoridng to
			 * RFC 2132. In practise it's 576 which is the
			 * minimum maximum message size. */
			if (lease->dhcp4.mtu < MTU_MIN) {
				ni_debug_dhcp("MTU %u is too low, minimum is %d; ignoring",
						lease->dhcp4.mtu, MTU_MIN);
				lease->dhcp4.mtu = 0;
			}
			break;
		case DHCP4_HOSTNAME:
			ni_dhcp4_option_get_domain(&buf, &lease->hostname,
							"hostname");
			break;
		case DHCP4_DNSDOMAIN:
			ni_dhcp4_option_get_domain_list(&buf, &dns_domain,
							"dns-domain");
			break;
		case DHCP4_MESSAGE:
			ni_dhcp4_option_get_printable(&buf, &lease->dhcp4.message,
							"dhcp4-message");
			break;
		case DHCP4_ROOTPATH:
			ni_dhcp4_option_get_pathname(&buf, &lease->dhcp4.root_path,
							"root-path");
			break;
		case DHCP4_NISDOMAIN:
			ni_dhcp4_option_get_domain(&buf, &nisdomain,
							"nis-domain");
			break;
		case DHCP4_NETBIOSNODETYPE:
			ni_dhcp4_option_get_netbios_type(&buf, &lease->netbios_type);
			break;
		case DHCP4_NETBIOSSCOPE:
			ni_dhcp4_option_get_domain(&buf, &lease->netbios_scope,
							"netbios-scope");
			break;
		case DHCP4_DNSSERVER:
			ni_dhcp4_decode_address_list(&buf, &dns_servers);
			break;
		case DHCP4_NTPSERVER:
			ni_dhcp4_decode_address_list(&buf, &lease->ntp_servers);
			break;
		case DHCP4_NISSERVER:
			ni_dhcp4_decode_address_list(&buf, &nis_servers);
			break;
		case DHCP4_LPRSERVER:
			ni_dhcp4_decode_address_list(&buf, &lease->lpr_servers);
			break;
		case DHCP4_LOGSERVER:
			ni_dhcp4_decode_address_list(&buf, &lease->log_servers);
			break;
		case DHCP4_NETBIOSNAMESERVER:
			ni_dhcp4_decode_address_list(&buf, &lease->netbios_name_servers);
			break;
		case DHCP4_NETBIOSDDSERVER:
			ni_dhcp4_decode_address_list(&buf, &lease->netbios_dd_servers);
			break;
		case DHCP4_DNSSEARCH:
			ni_dhcp4_decode_dnssearch(&buf, &dns_search, "dns-search domain");
			break;

		case DHCP4_NDS_SERVER:
			ni_dhcp4_decode_address_list(&buf, &lease->nds_servers);
			break;
		case DHCP4_NDS_CTX:
			if (!ni_dhcp4_option_get_printable(&buf, &tmp, "nds-context"))
				ni_string_array_append(&lease->nds_context, tmp);
			ni_string_free(&tmp);
			break;
		case DHCP4_NDS_TREE:
			ni_dhcp4_option_get_printable(&buf, &lease->nds_tree,
							"nds-tree");
			break;

		case DHCP4_CSR:
		case DHCP4_MSCSR:
			ni_route_array_destroy(&classless_routes);
			if (ni_dhcp4_decode_csr(&buf, &classless_routes) < 0)
				goto error;
			break;

		case DHCP4_SIPSERVER:
			ni_dhcp4_decode_sipservers(&buf, &lease->sip_servers);
			break;

		case DHCP4_STATICROUTE:
			ni_route_array_destroy(&static_routes);
			if (ni_dhcp4_decode_static_routes(&buf, &static_routes) < 0)
				goto error;
			break;

		case DHCP4_ROUTERS:
			ni_route_array_destroy(&default_routes);
			if (ni_dhcp4_decode_routers(&buf, &default_routes) < 0)
				goto error;
			break;

		case DHCP4_OPTIONSOVERLOADED:
			if (options != &overload_buf) {
				opt_overload = ni_buffer_getc(&buf);
			} else {
				ni_debug_dhcp("DHCP4: ignoring OVERLOAD option in overloaded data");
				(void) ni_buffer_getc(&buf);
			}
			break;

		case DHCP4_FQDN:
			/* We ignore replies about FQDN */
			break;

		case DHCP4_POSIX_TZ_STRING:
			ni_dhcp4_option_get_printable(&buf, &lease->posix_tz_string,
							"posix-tz-string");
			break;

		case DHCP4_POSIX_TZ_DBNAME:
			ni_dhcp4_option_get_printable(&buf, &lease->posix_tz_dbname,
							"posix-tz-dbname");
			break;

		default:
			ni_debug_dhcp("ignoring unsupported DHCP4 code %u", option);
			break;
		}

		if (buf.underflow) {
			ni_debug_dhcp("unable to parse DHCP4 option %s: too short",
					ni_dhcp4_option_name(option));
			goto error;
		} else if (ni_buffer_count(&buf)) {
			ni_debug_dhcp("excess data in DHCP4 option %s - %u bytes left",
					ni_dhcp4_option_name(option),
					ni_buffer_count(&buf));
		}

	}

	if (options->underflow) {
		ni_debug_dhcp("unable to parse DHCP4 response: truncated packet");
		goto error;
	}

	if (opt_overload) {
		const void *more_data = NULL;
		size_t size = 0;

		if (opt_overload & DHCP4_OVERLOAD_BOOTFILE) {
			use_bootfile = 0;
			more_data = message->bootfile;
			size = sizeof(message->bootfile);
			opt_overload &= ~DHCP4_OVERLOAD_BOOTFILE;
		} else
		if (opt_overload & DHCP4_OVERLOAD_SERVERNAME) {
			use_bootserver = 0;
			more_data = message->servername;
			size = sizeof(message->servername);
			opt_overload &= ~DHCP4_OVERLOAD_SERVERNAME;
		} else {
			opt_overload = 0;
		}
		if (more_data) {
			ni_buffer_init_reader(&overload_buf, (void *) more_data, size);
			options = &overload_buf;
			goto parse_more;
		}
	}

	if (use_bootserver && message->servername[0]) {
		char tmp[sizeof(message->servername)];
		size_t len;

		memcpy(tmp, message->servername, sizeof(tmp));
		tmp[sizeof(tmp)-1] = '\0';

		len = ni_string_len(tmp);
		if (ni_check_domain_name(tmp, len, 0)) {
			ni_string_dup(&lease->dhcp4.boot_sname, tmp);
		} else {
			ni_warn("Discarded suspect boot-server name: '%s'",
				ni_print_suspect(tmp, len));
		}
	}
	if (use_bootfile && message->bootfile[0]) {
		char tmp[sizeof(message->bootfile)];
		size_t len;

		memcpy(tmp, message->bootfile, sizeof(tmp));
		tmp[sizeof(tmp)-1] = '\0';
		len = ni_string_len(tmp);
		if (ni_check_pathname(tmp, len)) {
			ni_string_dup(&lease->dhcp4.boot_file, tmp);
		} else {
			ni_warn("Discarded suspect boot-file name: '%s'",
				ni_print_suspect(tmp, len));
		}
	}

	/* Fill in any missing fields */
	if (lease->dhcp4.netmask.s_addr) {
		ni_sockaddr_t mask;

		ni_sockaddr_set_ipv4(&mask, lease->dhcp4.netmask, 0);
		if (!(pfxlen = ni_sockaddr_netmask_bits(&mask)))
			pfxlen = 32;
	} else {
		uint32_t prefix = ntohl(lease->dhcp4.address.s_addr);

		if (IN_CLASSA(prefix))
			pfxlen = 8;
		else if (IN_CLASSB(prefix))
			pfxlen = 16;
		else if (IN_CLASSC(prefix))
			pfxlen = 24;
		else
			pfxlen = 32;
		lease->dhcp4.netmask.s_addr = htonl(~((1<<(32-pfxlen))-1));
		ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_DHCP,
				"guessed netmask: %s, cidr: %u",
				inet_ntoa(lease->dhcp4.netmask), pfxlen);
	}
	if (!lease->dhcp4.broadcast.s_addr) {
		lease->dhcp4.broadcast.s_addr = lease->dhcp4.address.s_addr |
						~lease->dhcp4.netmask.s_addr;
	}
	if (lease->dhcp4.address.s_addr) {
		ni_sockaddr_t local_addr;
		ni_address_t *ap;

		memset(&local_addr, 0, sizeof(local_addr));
		local_addr.sin.sin_family = AF_INET;
		local_addr.sin.sin_addr = lease->dhcp4.address;
		ap = ni_address_new(AF_INET, pfxlen, &local_addr, &lease->addrs);
		if (ap) {
			memset(&ap->bcast_addr, 0, sizeof(ap->bcast_addr));
			ap->bcast_addr.sin.sin_family = AF_INET;
			ap->bcast_addr.sin.sin_addr = lease->dhcp4.broadcast;
		}
	}

	if (classless_routes.count) {
		/* if CSR or MSCSR are available, ignore other routes */
		ni_dhcp4_apply_routes(lease, &classless_routes);
		ni_route_array_destroy(&classless_routes);
	} else {
		ni_dhcp4_apply_routes(lease, &static_routes);
		ni_route_array_destroy(&static_routes);
		ni_dhcp4_apply_routes(lease, &default_routes);
		ni_route_array_destroy(&default_routes);
	}

	if (dns_servers.count || dns_search.count || dns_domain.count) {
		ni_resolver_info_t *resolver = ni_resolver_info_new();

		if (dns_domain.count)
			ni_string_dup(&resolver->default_domain, dns_domain.data[0]);

		if (dns_search.count)
			ni_string_array_move(&resolver->dns_search, &dns_search);
		else
			ni_string_array_move(&resolver->dns_search, &dns_domain);

		ni_string_array_move(&resolver->dns_servers, &dns_servers);
		lease->resolver = resolver;
	}
	if (nisdomain != NULL) {
		ni_nis_info_t *nis = ni_nis_info_new();

		nis->domainname = nisdomain;
		nisdomain = NULL;

		if (nis_servers.count == 0)
			nis->default_binding = NI_NISCONF_BROADCAST;
		else
			ni_string_array_move(&nis->default_servers, &nis_servers);
		lease->nis = nis;
	}

	*leasep = lease;
	lease = NULL;

done:
	ni_route_array_destroy(&default_routes);
	ni_route_array_destroy(&static_routes);
	ni_route_array_destroy(&classless_routes);
	ni_string_array_destroy(&dns_servers);
	ni_string_array_destroy(&dns_search);
	ni_string_array_destroy(&dns_domain);
	ni_string_array_destroy(&nis_servers);
	ni_string_free(&nisdomain);

	return msg_type;

error:
	if (lease)
		ni_addrconf_lease_free(lease);
	msg_type = -1;
	goto done;
}

/*
 * Map DHCP4 options to names
 */
static const char *__dhcp4_option_names[256] = {
 [DHCP4_PAD]			= "DHCP4_PAD",
 [DHCP4_NETMASK]			= "DHCP4_NETMASK",
 [DHCP4_TIMEROFFSET]		= "DHCP4_TIMEROFFSET",
 [DHCP4_ROUTERS]			= "DHCP4_ROUTERS",
 [DHCP4_TIMESERVER]		= "DHCP4_TIMESERVER",
 [DHCP4_NAMESERVER]		= "DHCP4_NAMESERVER",
 [DHCP4_DNSSERVER]		= "DHCP4_DNSSERVER",
 [DHCP4_LOGSERVER]		= "DHCP4_LOGSERVER",
 [DHCP4_COOKIESERVER]		= "DHCP4_COOKIESERVER",
 [DHCP4_LPRSERVER]		= "DHCP4_LPRSERVER",
 [DHCP4_IMPRESSSERVER]		= "DHCP4_IMPRESSSERVER",
 [DHCP4_RLSSERVER]		= "DHCP4_RLSSERVER",
 [DHCP4_HOSTNAME]		= "DHCP4_HOSTNAME",
 [DHCP4_BOOTFILESIZE]		= "DHCP4_BOOTFILESIZE",
 [DHCP4_MERITDUMPFILE]		= "DHCP4_MERITDUMPFILE",
 [DHCP4_DNSDOMAIN]		= "DHCP4_DNSDOMAIN",
 [DHCP4_SWAPSERVER]		= "DHCP4_SWAPSERVER",
 [DHCP4_ROOTPATH]		= "DHCP4_ROOTPATH",
 [DHCP4_EXTENTIONSPATH]		= "DHCP4_EXTENTIONSPATH",
 [DHCP4_IPFORWARDING]		= "DHCP4_IPFORWARDING",
 [DHCP4_NONLOCALSOURCEROUTING]	= "DHCP4_NONLOCALSOURCEROUTING",
 [DHCP4_POLICYFILTER]		= "DHCP4_POLICYFILTER",
 [DHCP4_MAXDGRAMREASMSIZE]	= "DHCP4_MAXDGRAMREASMSIZE",
 [DHCP4_DEFAULTIPTTL]		= "DHCP4_DEFAULTIPTTL",
 [DHCP4_PATHMTUAGINGTIMEOUT]	= "DHCP4_PATHMTUAGINGTIMEOUT",
 [DHCP4_PATHMTUPLATEAUTABLE]	= "DHCP4_PATHMTUPLATEAUTABLE",
 [DHCP4_MTU]			= "DHCP4_MTU",
 [DHCP4_ALLSUBNETSLOCAL]		= "DHCP4_ALLSUBNETSLOCAL",
 [DHCP4_BROADCAST]		= "DHCP4_BROADCAST",
 [DHCP4_MASKDISCOVERY]		= "DHCP4_MASKDISCOVERY",
 [DHCP4_MASKSUPPLIER]		= "DHCP4_MASKSUPPLIER",
 [DHCP4_ROUTERDISCOVERY]		= "DHCP4_ROUTERDISCOVERY",
 [DHCP4_ROUTERSOLICITATIONADDR]	= "DHCP4_ROUTERSOLICITATIONADDR",
 [DHCP4_STATICROUTE]		= "DHCP4_STATICROUTE",
 [DHCP4_TRAILERENCAPSULATION]	= "DHCP4_TRAILERENCAPSULATION",
 [DHCP4_ARPCACHETIMEOUT]		= "DHCP4_ARPCACHETIMEOUT",
 [DHCP4_ETHERNETENCAPSULATION]	= "DHCP4_ETHERNETENCAPSULATION",
 [DHCP4_TCPDEFAULTTTL]		= "DHCP4_TCPDEFAULTTTL",
 [DHCP4_TCPKEEPALIVEINTERVAL]	= "DHCP4_TCPKEEPALIVEINTERVAL",
 [DHCP4_TCPKEEPALIVEGARBAGE]	= "DHCP4_TCPKEEPALIVEGARBAGE",
 [DHCP4_NISDOMAIN]		= "DHCP4_NISDOMAIN",
 [DHCP4_NISSERVER]		= "DHCP4_NISSERVER",
 [DHCP4_NTPSERVER]		= "DHCP4_NTPSERVER",
 [DHCP4_VENDORSPECIFICINFO]	= "DHCP4_VENDORSPECIFICINFO",
 [DHCP4_NETBIOSNAMESERVER]	= "DHCP4_NETBIOSNAMESERVER",
 [DHCP4_NETBIOSDDSERVER]		= "DHCP4_NETBIOSDDSERVER",
 [DHCP4_NETBIOSNODETYPE]		= "DHCP4_NETBIOSNODETYPE",
 [DHCP4_NETBIOSSCOPE]		= "DHCP4_NETBIOSSCOPE",
 [DHCP4_XFONTSERVER]		= "DHCP4_XFONTSERVER",
 [DHCP4_XDISPLAYMANAGER]		= "DHCP4_XDISPLAYMANAGER",
 [DHCP4_ADDRESS]			= "DHCP4_ADDRESS",
 [DHCP4_LEASETIME]		= "DHCP4_LEASETIME",
 [DHCP4_OPTIONSOVERLOADED]	= "DHCP4_OPTIONSOVERLOADED",
 [DHCP4_MESSAGETYPE]		= "DHCP4_MESSAGETYPE",
 [DHCP4_SERVERIDENTIFIER]	= "DHCP4_SERVERIDENTIFIER",
 [DHCP4_PARAMETERREQUESTLIST]	= "DHCP4_PARAMETERREQUESTLIST",
 [DHCP4_MESSAGE]			= "DHCP4_MESSAGE",
 [DHCP4_MAXMESSAGESIZE]		= "DHCP4_MAXMESSAGESIZE",
 [DHCP4_RENEWALTIME]		= "DHCP4_RENEWALTIME",
 [DHCP4_REBINDTIME]		= "DHCP4_REBINDTIME",
 [DHCP4_CLASSID]			= "DHCP4_CLASSID",
 [DHCP4_CLIENTID]		= "DHCP4_CLIENTID",
 [DHCP4_USERCLASS]		= "DHCP4_USERCLASS",
 [DHCP4_FQDN]			= "DHCP4_FQDN",
 [DHCP4_NDS_SERVER]		= "DHCP4_NDS_SERVER",
 [DHCP4_NDS_TREE]		= "DHCP4_NDS_TREE",
 [DHCP4_NDS_CTX]		= "DHCP4_NDS_CTX",
 [DHCP4_DNSSEARCH]		= "DHCP4_DNSSEARCH",
 [DHCP4_SIPSERVER]		= "DHCP4_SIPSERVER",
 [DHCP4_CSR]			= "DHCP4_CSR",
 [DHCP4_MSCSR]			= "DHCP4_MSCSR",
 [DHCP4_END]			= "DHCP4_END",
};

const char *
ni_dhcp4_option_name(unsigned int option)
{
	static char namebuf[64];
	const char *name = NULL;

	if (option < 256)
		name = __dhcp4_option_names[option];
	if (!name) {
		snprintf(namebuf, sizeof(namebuf), "DHCP4_OPTION_<%u>", option);
		name = namebuf;
	}
	return name;
}

static const char *	__dhcp4_message_names[16] = {
 [DHCP4_DISCOVER] =	"DHCP4_DISCOVER",
 [DHCP4_OFFER] =		"DHCP4_OFFER",
 [DHCP4_REQUEST] =	"DHCP4_REQUEST",
 [DHCP4_DECLINE] =	"DHCP4_DECLINE",
 [DHCP4_ACK] =		"DHCP4_ACK",
 [DHCP4_NAK] =		"DHCP4_NAK",
 [DHCP4_RELEASE] =	"DHCP4_RELEASE",
 [DHCP4_INFORM] =	"DHCP4_INFORM",
};

const char *
ni_dhcp4_message_name(unsigned int code)
{
	static char namebuf[64];
	const char *name = NULL;

	if (code < 16)
		name = __dhcp4_message_names[code];
	if (!name) {
		snprintf(namebuf, sizeof(namebuf), "DHCP4_MSG_<%u>", code);
		name = namebuf;
	}
	return name;
}
