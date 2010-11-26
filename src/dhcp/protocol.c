/*
 * Build and parse DHCP packets
 *
 * Copyright (C) 2010, Olaf Kirch <okir@suse.de>
 *
 * Heavily inspired by dhcpcd, which was written by Roy Marples <roy@marples.name>
 */

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

#include <wicked/logging.h>
#include <wicked/socket.h>
#include <wicked/resolver.h>
#include <wicked/nis.h>
#include "dhcp.h"
#include "protocol.h"
#include "buffer.h"

static void	ni_dhcp_socket_recv(ni_socket_t *);

/*
 * Open a DHCP socket for send and receive
 */
int
ni_dhcp_socket_open(ni_dhcp_device_t *dev)
{
	ni_capture_t *capture;

	/* We need to bind to a port, otherwise Linux will generate
	 * ICMP_UNREACHABLE messages telling the server that there's
	 * no DHCP client listening at all.
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
		sin.sin_port = htons(DHCP_CLIENT_PORT);
		if (bind(fd, (struct sockaddr *) &sin, sizeof(sin)) == -1) {
			ni_error("bind: %m");
			close(fd);
		} else {
			dev->listen_fd = fd;
			fcntl(fd, F_SETFD, FD_CLOEXEC);
		}
	}

	if ((capture = dev->capture) != NULL) {
		if (ni_capture_is_valid(capture, ETHERTYPE_IP))
			return 0;

		ni_capture_free(dev->capture);
		dev->capture = NULL;
	}

	dev->capture = ni_capture_open(&dev->system, ETHERTYPE_IP, ni_dhcp_socket_recv);
	if (!dev->capture)
		return -1;

	ni_capture_set_user_data(dev->capture, dev);
	return 0;
}

/*
 * This callback is invoked from the socket code when we
 * detect an incoming DHCP packet on the raw socket.
 */
static void
ni_dhcp_socket_recv(ni_socket_t *sock)
{
	ni_capture_t *capture = sock->user_data;
	ni_buffer_t buf;

	if (ni_capture_recv(capture, &buf) >= 0) {
		ni_dhcp_device_t *dev = ni_capture_get_user_data(capture);

		ni_dhcp_fsm_process_dhcp_packet(dev, &buf);
	}
}

/*
 * Inline functions for setting/retrieving options from a buffer
 */
static inline void
ni_dhcp_option_put(ni_buffer_t *bp, int code, const void *data, size_t len)
{
	ni_buffer_putc(bp, code);
	ni_buffer_putc(bp, len);
	ni_buffer_put(bp, data, len);
}

static inline void
ni_dhcp_option_put_empty(ni_buffer_t *bp, int code)
{
	ni_dhcp_option_put(bp, code, NULL, 0);
}

static inline void
ni_dhcp_option_put8(ni_buffer_t *bp, int code, unsigned char value)
{
	ni_dhcp_option_put(bp, code, &value, 1);
}

static inline void
ni_dhcp_option_put16(ni_buffer_t *bp, int code, uint16_t value)
{
	value = htons(value);
	ni_dhcp_option_put(bp, code, &value, 2);
}

static inline void
ni_dhcp_option_put32(ni_buffer_t *bp, int code, uint32_t value)
{
	value = htonl(value);
	ni_dhcp_option_put(bp, code, &value, 4);
}

static inline void
ni_dhcp_option_put_ipv4(ni_buffer_t *bp, int code, struct in_addr addr)
{
	ni_dhcp_option_put(bp, code, &addr, 4);
}

static inline void
ni_dhcp_option_puts(ni_buffer_t *bp, int code, const char *string)
{
	ni_dhcp_option_put(bp, code, string, strlen(string));
}

static inline unsigned int
ni_dhcp_option_begin(ni_buffer_t *bp, int code)
{
	ni_buffer_putc(bp, code);
	ni_buffer_putc(bp, 0);
	return bp->tail;
}

static inline void
ni_dhcp_option_end(ni_buffer_t *bp, unsigned int pos)
{
	if (pos == 0 || pos > bp->size) {
		ni_error("ni_dhcp_option_end: bad offset!");
	} else {
		bp->base[pos-1] = bp->tail - pos;
	}
}

static int
ni_dhcp_option_next(ni_buffer_t *bp, ni_buffer_t *optbuf)
{
	unsigned char code, count;

	if (bp->underflow)
		return -1;
	if (bp->head == bp->tail)
		return DHCP_END;
	if (bp->tail - bp->head < 2)
		goto underflow;

	code = bp->base[bp->head++];
	if (code != DHCP_PAD && code != DHCP_END) {
		count = bp->base[bp->head++];
		if (bp->tail - bp->head < count)
			goto underflow;
		ni_buffer_init_reader(optbuf, bp->base + bp->head, count);
		bp->head += count;
	} else {
		memset(optbuf, 0, sizeof(optbuf));
	}
	return code;

underflow:
	bp->underflow = 1;
	return -1;
}

static int
ni_dhcp_option_get_sockaddr(ni_buffer_t *bp, ni_sockaddr_t *addr)
{
	struct sockaddr_in *sin = (struct sockaddr_in *) addr;

	memset(sin, 0, sizeof(*addr));
	sin->sin_family = AF_INET;
	return ni_buffer_get(bp, &sin->sin_addr, 4);
}

static int
ni_dhcp_option_get_ipv4(ni_buffer_t *bp, struct in_addr *addr)
{
	return ni_buffer_get(bp, addr, 4);
}

static int
ni_dhcp_option_get16(ni_buffer_t *bp, uint16_t *var)
{
	if (ni_buffer_get(bp, var, 2) < 0)
		return -1;
	*var = ntohs(*var);
	return 0;
}

static int
ni_dhcp_option_get32(ni_buffer_t *bp, uint32_t *var)
{
	if (ni_buffer_get(bp, var, 4) < 0)
		return -1;
	*var = ntohl(*var);
	return 0;
}

static int
ni_dhcp_option_get_string(ni_buffer_t *bp, char **var)
{
	unsigned int len = ni_buffer_count(bp);

	if (len == 0)
		return -1;

	if (*var)
		free(*var);
	*var = malloc(len + 1);
	ni_buffer_get(bp, *var, len);
	(*var)[len] = '\0';
	return 0;
}

int
ni_dhcp_build_message(const ni_dhcp_device_t *dev,
			unsigned int msg_code,
			const ni_addrconf_lease_t *lease,
			ni_buffer_t *msgbuf)
{
	const ni_dhcp_config_t *options = dev->config;
	struct in_addr src_addr, dst_addr;
	ni_dhcp_message_t *message = NULL;

	if (!options || !lease)
		return -1;

	if (IN_LINKLOCAL(ntohl(lease->dhcp.address.s_addr))) {
		ni_error("cannot request a link local address");
		goto failed;
	}

	src_addr.s_addr = dst_addr.s_addr = 0;
	switch (msg_code) {
	case DHCP_DISCOVER:
		if (lease->dhcp.serveraddress.s_addr != 0)
			return -1;
		break;

	case DHCP_REQUEST:
	case DHCP_RELEASE:
	case DHCP_INFORM:
		if (lease->dhcp.address.s_addr == 0 || lease->dhcp.serveraddress.s_addr == 0)
			return -1;
		src_addr = lease->dhcp.address;
		dst_addr = lease->dhcp.serveraddress;
		break;
	}

	/* Reserve some room for the IP and UDP header */
	ni_buffer_reserve_head(msgbuf, sizeof(struct ip) + sizeof(struct udphdr));

	/* Build the message */
	message = ni_buffer_push_tail(msgbuf, sizeof(*message));

	message->op = DHCP_BOOTREQUEST;
	message->hwtype = dev->system.arp_type;
	message->xid = dev->dhcp.xid;
	message->cookie = htonl(MAGIC_COOKIE);
	message->secs = htons(ni_dhcp_device_uptime(dev, 0xFFFF));

	if (dev->fsm.state == NI_DHCP_STATE_BOUND
	 || dev->fsm.state == NI_DHCP_STATE_RENEWING
	 || dev->fsm.state == NI_DHCP_STATE_REBINDING)
		message->ciaddr = lease->dhcp.address.s_addr;

	switch (dev->system.arp_type) {
	case ARPHRD_ETHER:
	case ARPHRD_IEEE802:
		if (dev->system.hwaddr.len > sizeof(message->chaddr)) {
			ni_error("dhcp cannot handle hwaddress length %u",
					dev->system.hwaddr.len);
			goto failed;
		}
		message->hwlen = dev->system.hwaddr.len;
		memcpy(&message->chaddr, dev->system.hwaddr.data, dev->system.hwaddr.len);
		break;

	case ARPHRD_IEEE1394:
	case ARPHRD_INFINIBAND:
		message->hwlen = 0;
		if (message->ciaddr == 0)
			message->flags = htons(BROADCAST_FLAG);
		break;

	default:
		ni_error("dhcp: unknown hardware type %d", dev->system.arp_type);
	}

	ni_dhcp_option_put8(msgbuf, DHCP_MESSAGETYPE, msg_code);

	if (msg_code == DHCP_REQUEST)
		ni_dhcp_option_put16(msgbuf, DHCP_MAXMESSAGESIZE, dev->system.mtu);

	ni_dhcp_option_put(msgbuf, DHCP_CLIENTID,
			options->raw_client_id.data,
			options->raw_client_id.len);

	if (msg_code != DHCP_DECLINE && msg_code != DHCP_RELEASE) {
		if (options->userclass.len > 0)
			ni_dhcp_option_put(msgbuf, DHCP_USERCLASS,
					options->userclass.data,
					options->userclass.len);

		if (options->classid && options->classid[0])
			ni_dhcp_option_puts(msgbuf, DHCP_CLASSID, options->classid);
	}

	if (msg_code == DHCP_DISCOVER || msg_code == DHCP_REQUEST) {
		if (lease->dhcp.address.s_addr)
			ni_dhcp_option_put_ipv4(msgbuf, DHCP_ADDRESS, lease->dhcp.address);
		if (lease->dhcp.lease_time != 0)
			ni_dhcp_option_put32(msgbuf, DHCP_LEASETIME, lease->dhcp.lease_time);
	}

	if (msg_code == DHCP_REQUEST) {
		if (lease->dhcp.serveraddress.s_addr)
			ni_dhcp_option_put_ipv4(msgbuf, DHCP_SERVERIDENTIFIER, lease->dhcp.serveraddress);
	}

	if (msg_code == DHCP_DISCOVER || msg_code == DHCP_INFORM || msg_code == DHCP_REQUEST) {
		unsigned int params_begin;

		if (options->hostname && options->hostname[0]) {
			if (options->fqdn == FQDN_DISABLE) {
				ni_dhcp_option_puts(msgbuf, DHCP_HOSTNAME, options->hostname);
			} else {
				/* Draft IETF DHC-FQDN option(81)
				 * Flags: 0000NEOS
				 * S: 1 => Client requests Server to update
				 *         a RR in DNS as well as PTR
				 * O: 1 => Server indicates to client that
				 *         DNS has been updated
				 * E: 1 => Name data is DNS format
				 * N: 1 => Client requests Server to not
				 *         update DNS
				 */
				ni_buffer_putc(msgbuf, DHCP_FQDN);
				ni_buffer_putc(msgbuf, strlen(options->hostname) + 3);
				ni_buffer_putc(msgbuf, options->fqdn & 0x9);
				ni_buffer_putc(msgbuf, 0);	/* from server for PTR RR */
				ni_buffer_putc(msgbuf, 0);	/* from server for A RR if S=1 */
				ni_buffer_put(msgbuf, options->hostname, strlen(options->hostname));
			}
		}

		params_begin = ni_dhcp_option_begin(msgbuf, DHCP_PARAMETERREQUESTLIST);

		if (msg_code == DHCP_DISCOVER) {
			/* dhcpcd says we should include just a single option
			 * in discovery packets.
			 * I'm not convinced this is right, but let's do it
			 * this way.
			 */
			ni_buffer_putc(msgbuf, DHCP_DNSSERVER);
		} else {
			if (msg_code != DHCP_INFORM) {
				ni_buffer_putc(msgbuf, DHCP_RENEWALTIME);
				ni_buffer_putc(msgbuf, DHCP_REBINDTIME);
			}
			ni_buffer_putc(msgbuf, DHCP_NETMASK);
			ni_buffer_putc(msgbuf, DHCP_BROADCAST);

			if (options->flags & DHCP_DO_CSR)
				ni_buffer_putc(msgbuf, DHCP_CSR);
			if (options->flags & DHCP_DO_MSCSR)
				ni_buffer_putc(msgbuf, DHCP_MSCSR);

			/* RFC 3442 states classless static routes should be
			 * before routers and static routes as classless static
			 * routes override them both */
			ni_buffer_putc(msgbuf, DHCP_STATICROUTE);
			ni_buffer_putc(msgbuf, DHCP_ROUTERS);
			ni_buffer_putc(msgbuf, DHCP_HOSTNAME);
			ni_buffer_putc(msgbuf, DHCP_DNSSEARCH);
			ni_buffer_putc(msgbuf, DHCP_DNSDOMAIN);
			ni_buffer_putc(msgbuf, DHCP_DNSSERVER);

			if (options->flags & DHCP_DO_NIS) {
				ni_buffer_putc(msgbuf, DHCP_NISDOMAIN);
				ni_buffer_putc(msgbuf, DHCP_NISSERVER);
			}
			if (options->flags & DHCP_DO_NTP)
				ni_buffer_putc(msgbuf, DHCP_NTPSERVER);
			ni_buffer_putc(msgbuf, DHCP_MTU);
			ni_buffer_putc(msgbuf, DHCP_ROOTPATH);
			ni_buffer_putc(msgbuf, DHCP_SIPSERVER);
			ni_buffer_putc(msgbuf, DHCP_LPRSERVER);
			ni_buffer_putc(msgbuf, DHCP_LOGSERVER);
			ni_buffer_putc(msgbuf, DHCP_NETBIOSNAMESERVER);
			ni_buffer_putc(msgbuf, DHCP_NETBIOSDDSERVER);
			ni_buffer_putc(msgbuf, DHCP_NETBIOSSCOPE);
		}

		ni_dhcp_option_end(msgbuf, params_begin);
	}
	ni_buffer_putc(msgbuf, DHCP_END);

#ifdef BOOTP_MESSAGE_LENGTH_MIN
	ni_buffer_pad(msgbuf, BOOTP_MESSAGE_LENGTH_MIN, DHCP_PAD);
#endif

	if (ni_capture_build_udp_header(msgbuf, src_addr, DHCP_CLIENT_PORT, dst_addr, DHCP_SERVER_PORT) < 0) {
		ni_error("unable to build packet header");
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
ni_dhcp_decode_dnssearch(ni_buffer_t *optbuf, ni_string_array_t *list)
{
	unsigned char *base = ni_buffer_head(optbuf);
	unsigned int base_offset = optbuf->head;

	ni_string_array_destroy(list);

	while (ni_buffer_count(optbuf) && !optbuf->underflow) {
		ni_stringbuf_t namebuf = NI_STRINGBUF_INIT_DYNAMIC;
		ni_buffer_t *bp = optbuf;
		ni_buffer_t jumpbuf;

		while (1) {
			unsigned int pos = bp->head - base_offset;
			unsigned int pointer;
			char label[64];
			int length;

			if ((length = ni_buffer_getc(bp)) < 0)
				return -1; /* unexpected EOF */

			if (length == 0)
				break;	/* end of this name */

			switch (length & 0xC0) {
			case 0:
				/* Plain name component */
				if (ni_buffer_get(bp, label, length) < 0)
					return -1;
				label[length] = '\0';

				if (!ni_stringbuf_empty(&namebuf))
					ni_stringbuf_putc(&namebuf, '.');
				ni_stringbuf_puts(&namebuf, label);
				break;

			case 0xC0:
				/* Pointer */
				pointer = (length & 0x3F) << 8;
				if ((length = ni_buffer_getc(bp)) < 0)
					return -1;
				pointer |= length;
				if (pointer >= pos)
					return -1;

				ni_buffer_init_reader(&jumpbuf, base, pos);
				jumpbuf.head = pointer;
				bp = &jumpbuf;
				break;

			default:
				return -1;
			}

		}

		if (!ni_stringbuf_empty(&namebuf))
			ni_string_array_append(list, namebuf.string);
		ni_stringbuf_destroy(&namebuf);
	}

	return 0;
}

/*
 * Decode a CIDR list option.
 */
static int
ni_dhcp_decode_csr(ni_buffer_t *bp, ni_route_t **route_list)
{
	while (ni_buffer_count(bp) && !bp->underflow) {
		ni_sockaddr_t destination, gateway;
		unsigned int prefix_len;

		prefix_len = ni_buffer_getc(bp);
		if (prefix_len > 32) {
			ni_error("invalid prefix len of %u in classless static route", prefix_len);
			return -1;
		}

		memset(&destination, 0, sizeof(destination));
		destination.ss_family = AF_INET;

		if (prefix_len) {
			struct sockaddr_in *sin = (struct sockaddr_in *) &destination;

			ni_buffer_get(bp, &sin->sin_addr, (prefix_len + 7) / 8);
		}

		if (ni_dhcp_option_get_sockaddr(bp, &gateway) < 0)
			return -1;

		__ni_route_new(route_list, prefix_len, &destination, &gateway);
	}

	if (bp->underflow)
		return -1;

	return 0;
}

static int
ni_dhcp_decode_address_list(ni_buffer_t *bp, ni_string_array_t *list)
{
	while (ni_buffer_count(bp) && !bp->underflow) {
		struct in_addr addr;

		if (ni_dhcp_option_get_ipv4(bp, &addr) < 0)
			return -1;
		ni_string_array_append(list, inet_ntoa(addr));
	}

	if (bp->underflow)
		return -1;

	return 0;
}

static int
ni_dhcp_decode_sipservers(ni_buffer_t *bp, ni_string_array_t *list)
{
	int encoding;

	encoding = ni_buffer_getc(bp);
	switch (encoding) {
	case -1:
		ni_debug_dhcp("%s: missing data", __FUNCTION__);
		return -1;

	case 0:
		return ni_dhcp_decode_dnssearch(bp, list);

	case 1:
		return ni_dhcp_decode_address_list(bp, list);

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
 * DHCP_STATICROUTE
 * List of network/gateway pairs.
 */
static int
ni_dhcp_decode_static_routes(ni_buffer_t *bp, ni_route_t **route_list)
{
	ni_route_list_destroy(route_list);
	while (ni_buffer_count(bp) && !bp->underflow) {
		ni_sockaddr_t destination, gateway;

		if (ni_dhcp_option_get_sockaddr(bp, &destination) < 0
		 || ni_dhcp_option_get_sockaddr(bp, &gateway) < 0)
			return -1;

		__ni_route_new(route_list,
				guess_prefix_len_sockaddr(&destination),
				&destination,
				&gateway);
	}

	return 0;
}

/*
 * DHCP_ROUTERS (3)
 * List of gateways for default route
 */
static int
ni_dhcp_decode_routers(ni_buffer_t *bp, ni_route_t **route_list)
{
	ni_sockaddr_t destination, gateway;

	ni_route_list_destroy(route_list);

	destination.ss_family = AF_UNSPEC;
	while (ni_buffer_count(bp) && !bp->underflow) {
		if (ni_dhcp_option_get_sockaddr(bp, &gateway) < 0)
			return -1;

		__ni_route_new(route_list, 0, &destination, &gateway);
	}

	return 0;
}

/*
 * Parse a DHCP response.
 * FIXME: RFC2131 states that the server is allowed to split a DHCP option into
 * several (partial) options if the total length exceeds 255 octets. We don't
 * handle this yet.
 */
int
ni_dhcp_parse_response(const ni_dhcp_message_t *message, ni_buffer_t *options, ni_addrconf_lease_t **leasep)
{
	ni_buffer_t overload_buf;
	ni_addrconf_lease_t *lease;
	ni_route_t *default_routes = NULL;
	ni_route_t *static_routes = NULL;
	ni_route_t *classless_routes = NULL;
	ni_string_array_t dns_servers = NI_STRING_ARRAY_INIT;
	ni_string_array_t dns_search = NI_STRING_ARRAY_INIT;
	ni_string_array_t nis_servers = NI_STRING_ARRAY_INIT;
	char *nisdomain = NULL;
	char *dnsdomain = NULL;
	int opt_overload = 0;
	int msg_type = -1;
	int retval = -1;

	lease = ni_addrconf_lease_new(NI_ADDRCONF_DHCP, AF_INET);

	lease->state = NI_ADDRCONF_STATE_GRANTED;
	lease->type = NI_ADDRCONF_DHCP;
	lease->family = AF_INET;
	lease->time_acquired = time(NULL);

	lease->dhcp.address.s_addr = message->yiaddr;
	lease->dhcp.serveraddress.s_addr = message->siaddr;
	lease->dhcp.address.s_addr = message->yiaddr;

	assert(sizeof(lease->dhcp.servername) == sizeof(message->servername));
	memcpy(lease->dhcp.servername, message->servername, sizeof(lease->dhcp.servername));

parse_more:
	/* Loop as long as we still have data in the buffer. */
	while (ni_buffer_count(options) && !options->underflow) {
		ni_buffer_t buf;
		int option;

		option = ni_dhcp_option_next(options, &buf);

		//ni_debug_dhcp("handle option %s (%d)", ni_dhcp_option_name(option), option);
		if (option == DHCP_PAD)
			continue;

		if (option == DHCP_END)
			break;

		if (option < 0)
			goto error;

		if (ni_buffer_count(&buf) == 0) {
			ni_error("option %d has zero length", option);
			retval = -1;
			goto error;
		}

		switch (option) {
		case DHCP_MESSAGETYPE:
			msg_type = ni_buffer_getc(&buf);
			if (msg_type < 0)
				goto error;
			continue;
		case DHCP_ADDRESS:
			ni_dhcp_option_get_ipv4(&buf, &lease->dhcp.address);
			break;
		case DHCP_NETMASK:
			ni_dhcp_option_get_ipv4(&buf, &lease->dhcp.netmask);
			break;
		case DHCP_BROADCAST:
			ni_dhcp_option_get_ipv4(&buf, &lease->dhcp.broadcast);
			break;
		case DHCP_SERVERIDENTIFIER:
			ni_dhcp_option_get_ipv4(&buf, &lease->dhcp.serveraddress);
			break;
		case DHCP_LEASETIME:
			ni_dhcp_option_get32(&buf, &lease->dhcp.lease_time);
			break;
		case DHCP_RENEWALTIME:
			ni_dhcp_option_get32(&buf, &lease->dhcp.renewal_time);
			break;
		case DHCP_REBINDTIME:
			ni_dhcp_option_get32(&buf, &lease->dhcp.rebind_time);
			break;
		case DHCP_MTU:
			ni_dhcp_option_get16(&buf, &lease->dhcp.mtu);
			/* Minimum legal mtu is 68 accoridng to
			 * RFC 2132. In practise it's 576 which is the
			 * minimum maximum message size. */
			if (lease->dhcp.mtu < MTU_MIN) {
				ni_debug_dhcp("MTU %u is too low, minimum is %d; ignoring",
						lease->dhcp.mtu, MTU_MIN);
				lease->dhcp.mtu = 0;
			}
			break;
		case DHCP_HOSTNAME:
			ni_dhcp_option_get_string(&buf, &lease->hostname);
			break;
		case DHCP_DNSDOMAIN:
			ni_dhcp_option_get_string(&buf, &dnsdomain);
			break;
		case DHCP_MESSAGE:
			ni_dhcp_option_get_string(&buf, &lease->dhcp.message);
			break;
		case DHCP_ROOTPATH:
			ni_dhcp_option_get_string(&buf, &lease->dhcp.rootpath);
			break;
		case DHCP_NISDOMAIN:
			ni_dhcp_option_get_string(&buf, &nisdomain);
			break;
		case DHCP_NETBIOSNODETYPE:
			ni_dhcp_option_get_string(&buf, &lease->netbios_domain);
			break;
		case DHCP_NETBIOSSCOPE:
			ni_dhcp_option_get_string(&buf, &lease->netbios_scope);
			break;
		case DHCP_DNSSERVER:
			ni_dhcp_decode_address_list(&buf, &dns_servers);
			break;
		case DHCP_NTPSERVER:
			ni_dhcp_decode_address_list(&buf, &lease->ntp_servers);
			break;
		case DHCP_NISSERVER:
			ni_dhcp_decode_address_list(&buf, &nis_servers);
			break;
		case DHCP_LPRSERVER:
			ni_dhcp_decode_address_list(&buf, &lease->lpr_servers);
			break;
		case DHCP_LOGSERVER:
			ni_dhcp_decode_address_list(&buf, &lease->log_servers);
			break;
		case DHCP_NETBIOSNAMESERVER:
			ni_dhcp_decode_address_list(&buf, &lease->netbios_name_servers);
			break;
		case DHCP_NETBIOSDDSERVER:
			ni_dhcp_decode_address_list(&buf, &lease->netbios_dd_servers);
			break;
		case DHCP_DNSSEARCH:
			ni_dhcp_decode_dnssearch(&buf, &dns_search);
			break;

		case DHCP_CSR:
		case DHCP_MSCSR:
			ni_route_list_destroy(&classless_routes);
			if (ni_dhcp_decode_csr(&buf, &classless_routes) < 0)
				goto error;
			break;

		case DHCP_SIPSERVER:
			ni_dhcp_decode_sipservers(&buf, &lease->sip_servers);
			break;

		case DHCP_STATICROUTE:
			if (ni_dhcp_decode_static_routes(&buf, &static_routes) < 0)
				goto error;
			break;

		case DHCP_ROUTERS:
			if (ni_dhcp_decode_routers(&buf, &default_routes) < 0)
				goto error;
			break;

		case DHCP_OPTIONSOVERLOADED:
			if (options != &overload_buf) {
				opt_overload = ni_buffer_getc(&buf);
			} else {
				ni_debug_dhcp("DHCP: ignoring OVERLOAD option in overloaded data");
				(void) ni_buffer_getc(&buf);
			}
			break;

		case DHCP_FQDN:
			/* We ignore replies about FQDN */
			break;

		default:
			ni_debug_dhcp("ignoring unsupported DHCP code %u", option);
			break;
		}

		if (buf.underflow) {
			ni_debug_dhcp("unable to parse DHCP option %s: too short",
					ni_dhcp_option_name(option));
			goto error;
		} else if (ni_buffer_count(&buf)) {
			ni_debug_dhcp("excess data in DHCP option %s - %u bytes left",
					ni_dhcp_option_name(option),
					ni_buffer_count(&buf));
		}

	}

	if (options->underflow) {
		ni_debug_dhcp("unable to parse DHCP response: truncated packet");
		goto error;
	}

	if (opt_overload) {
		const void *more_data = NULL;
		size_t size = 0;

		if (opt_overload & DHCP_OVERLOAD_BOOTFILE) {
			more_data = message->bootfile;
			size = sizeof(message->bootfile);
			opt_overload &= ~DHCP_OVERLOAD_BOOTFILE;
		} else
		if (opt_overload & DHCP_OVERLOAD_SERVERNAME) {
			more_data = message->servername;
			size = sizeof(message->servername);
			opt_overload &= ~DHCP_OVERLOAD_SERVERNAME;
		} else {
			opt_overload = 0;
		}
		if (more_data) {
			ni_buffer_init_reader(&overload_buf, (void *) more_data, size);
			options = &overload_buf;
			goto parse_more;
		}
	}

	/* Fill in any missing fields */
	if (!lease->dhcp.netmask.s_addr) {
		unsigned int pfxlen = guess_prefix_len(lease->dhcp.address);

		lease->dhcp.netmask.s_addr = htonl(~(0xFFFFFFFF >> pfxlen));
	}
	if (!lease->dhcp.broadcast.s_addr) {
		lease->dhcp.broadcast.s_addr = lease->dhcp.address.s_addr | ~lease->dhcp.netmask.s_addr;
	}

	if (classless_routes) {
		/* CSR and MSCSR take precedence over static routes */
		lease->routes = classless_routes;
		classless_routes = NULL;
	} else {
		ni_route_t **tail = &lease->routes, *rp;

		if (static_routes) {
			*tail = static_routes;
			while ((rp = *tail) != NULL)
				tail = &rp->next;
			static_routes = NULL;
		}

		if (default_routes) {
			*tail = default_routes;
			default_routes = NULL;
		}
	}

	if (dns_servers.count != 0) {
		ni_resolver_info_t *resolver = ni_resolver_info_new();

		resolver->default_domain = dnsdomain;
		dnsdomain = NULL;

		ni_string_array_move(&resolver->dns_servers, &dns_servers);
		ni_string_array_move(&resolver->dns_search, &dns_search);
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

	if (lease->dhcp.address.s_addr) {
		ni_sockaddr_t local_addr;
		ni_address_t *ap;

		memset(&local_addr, 0, sizeof(local_addr));
		local_addr.sin.sin_family = AF_INET;
		local_addr.sin.sin_addr = lease->dhcp.address;
		ap = __ni_address_new(&lease->addrs, AF_INET,
				__count_net_bits(ntohl(lease->dhcp.netmask.s_addr)),
				&local_addr);

		memset(&ap->bcast_addr, 0, sizeof(ap->bcast_addr));
		ap->bcast_addr.sin.sin_family = AF_INET;
		ap->bcast_addr.sin.sin_addr = lease->dhcp.broadcast;
	}

	*leasep = lease;
	lease = NULL;

done:
	ni_route_list_destroy(&default_routes);
	ni_route_list_destroy(&static_routes);
	ni_route_list_destroy(&classless_routes);
	ni_string_array_destroy(&nis_servers);
	ni_string_array_destroy(&dns_servers);
	ni_string_array_destroy(&dns_search);
	ni_string_free(&dnsdomain);
	ni_string_free(&nisdomain);

	return msg_type;

error:
	if (lease)
		ni_addrconf_lease_free(lease);
	msg_type = -1;
	goto done;
}

/*
 * Map DHCP options to names
 */
static const char *__dhcp_option_names[256] = {
 [DHCP_PAD]			= "DHCP_PAD",
 [DHCP_NETMASK]			= "DHCP_NETMASK",
 [DHCP_TIMEROFFSET]		= "DHCP_TIMEROFFSET",
 [DHCP_ROUTERS]			= "DHCP_ROUTERS",
 [DHCP_TIMESERVER]		= "DHCP_TIMESERVER",
 [DHCP_NAMESERVER]		= "DHCP_NAMESERVER",
 [DHCP_DNSSERVER]		= "DHCP_DNSSERVER",
 [DHCP_LOGSERVER]		= "DHCP_LOGSERVER",
 [DHCP_COOKIESERVER]		= "DHCP_COOKIESERVER",
 [DHCP_LPRSERVER]		= "DHCP_LPRSERVER",
 [DHCP_IMPRESSSERVER]		= "DHCP_IMPRESSSERVER",
 [DHCP_RLSSERVER]		= "DHCP_RLSSERVER",
 [DHCP_HOSTNAME]		= "DHCP_HOSTNAME",
 [DHCP_BOOTFILESIZE]		= "DHCP_BOOTFILESIZE",
 [DHCP_MERITDUMPFILE]		= "DHCP_MERITDUMPFILE",
 [DHCP_DNSDOMAIN]		= "DHCP_DNSDOMAIN",
 [DHCP_SWAPSERVER]		= "DHCP_SWAPSERVER",
 [DHCP_ROOTPATH]		= "DHCP_ROOTPATH",
 [DHCP_EXTENTIONSPATH]		= "DHCP_EXTENTIONSPATH",
 [DHCP_IPFORWARDING]		= "DHCP_IPFORWARDING",
 [DHCP_NONLOCALSOURCEROUTING]	= "DHCP_NONLOCALSOURCEROUTING",
 [DHCP_POLICYFILTER]		= "DHCP_POLICYFILTER",
 [DHCP_MAXDGRAMREASMSIZE]	= "DHCP_MAXDGRAMREASMSIZE",
 [DHCP_DEFAULTIPTTL]		= "DHCP_DEFAULTIPTTL",
 [DHCP_PATHMTUAGINGTIMEOUT]	= "DHCP_PATHMTUAGINGTIMEOUT",
 [DHCP_PATHMTUPLATEAUTABLE]	= "DHCP_PATHMTUPLATEAUTABLE",
 [DHCP_MTU]			= "DHCP_MTU",
 [DHCP_ALLSUBNETSLOCAL]		= "DHCP_ALLSUBNETSLOCAL",
 [DHCP_BROADCAST]		= "DHCP_BROADCAST",
 [DHCP_MASKDISCOVERY]		= "DHCP_MASKDISCOVERY",
 [DHCP_MASKSUPPLIER]		= "DHCP_MASKSUPPLIER",
 [DHCP_ROUTERDISCOVERY]		= "DHCP_ROUTERDISCOVERY",
 [DHCP_ROUTERSOLICITATIONADDR]	= "DHCP_ROUTERSOLICITATIONADDR",
 [DHCP_STATICROUTE]		= "DHCP_STATICROUTE",
 [DHCP_TRAILERENCAPSULATION]	= "DHCP_TRAILERENCAPSULATION",
 [DHCP_ARPCACHETIMEOUT]		= "DHCP_ARPCACHETIMEOUT",
 [DHCP_ETHERNETENCAPSULATION]	= "DHCP_ETHERNETENCAPSULATION",
 [DHCP_TCPDEFAULTTTL]		= "DHCP_TCPDEFAULTTTL",
 [DHCP_TCPKEEPALIVEINTERVAL]	= "DHCP_TCPKEEPALIVEINTERVAL",
 [DHCP_TCPKEEPALIVEGARBAGE]	= "DHCP_TCPKEEPALIVEGARBAGE",
 [DHCP_NISDOMAIN]		= "DHCP_NISDOMAIN",
 [DHCP_NISSERVER]		= "DHCP_NISSERVER",
 [DHCP_NTPSERVER]		= "DHCP_NTPSERVER",
 [DHCP_VENDORSPECIFICINFO]	= "DHCP_VENDORSPECIFICINFO",
 [DHCP_NETBIOSNAMESERVER]	= "DHCP_NETBIOSNAMESERVER",
 [DHCP_NETBIOSDDSERVER]		= "DHCP_NETBIOSDDSERVER",
 [DHCP_NETBIOSNODETYPE]		= "DHCP_NETBIOSNODETYPE",
 [DHCP_NETBIOSSCOPE]		= "DHCP_NETBIOSSCOPE",
 [DHCP_XFONTSERVER]		= "DHCP_XFONTSERVER",
 [DHCP_XDISPLAYMANAGER]		= "DHCP_XDISPLAYMANAGER",
 [DHCP_ADDRESS]			= "DHCP_ADDRESS",
 [DHCP_LEASETIME]		= "DHCP_LEASETIME",
 [DHCP_OPTIONSOVERLOADED]	= "DHCP_OPTIONSOVERLOADED",
 [DHCP_MESSAGETYPE]		= "DHCP_MESSAGETYPE",
 [DHCP_SERVERIDENTIFIER]	= "DHCP_SERVERIDENTIFIER",
 [DHCP_PARAMETERREQUESTLIST]	= "DHCP_PARAMETERREQUESTLIST",
 [DHCP_MESSAGE]			= "DHCP_MESSAGE",
 [DHCP_MAXMESSAGESIZE]		= "DHCP_MAXMESSAGESIZE",
 [DHCP_RENEWALTIME]		= "DHCP_RENEWALTIME",
 [DHCP_REBINDTIME]		= "DHCP_REBINDTIME",
 [DHCP_CLASSID]			= "DHCP_CLASSID",
 [DHCP_CLIENTID]		= "DHCP_CLIENTID",
 [DHCP_USERCLASS]		= "DHCP_USERCLASS",
 [DHCP_FQDN]			= "DHCP_FQDN",
 [DHCP_DNSSEARCH]		= "DHCP_DNSSEARCH",
 [DHCP_SIPSERVER]		= "DHCP_SIPSERVER",
 [DHCP_CSR]			= "DHCP_CSR",
 [DHCP_MSCSR]			= "DHCP_MSCSR",
 [DHCP_END]			= "DHCP_END",
};

const char *
ni_dhcp_option_name(unsigned int option)
{
	static char namebuf[64];
	const char *name = NULL;

	if (option < 256)
		name = __dhcp_option_names[option];
	if (!name) {
		snprintf(namebuf, sizeof(namebuf), "DHCP_OPTION_<%u>", option);
		name = namebuf;
	}
	return name;
}

static const char *	__dhcp_message_names[16] = {
 [DHCP_DISCOVER] =	"DHCP_DISCOVER",
 [DHCP_OFFER] =		"DHCP_OFFER",
 [DHCP_REQUEST] =	"DHCP_REQUEST",
 [DHCP_DECLINE] =	"DHCP_DECLINE",
 [DHCP_ACK] =		"DHCP_ACK",
 [DHCP_NAK] =		"DHCP_NAK",
 [DHCP_RELEASE] =	"DHCP_RELEASE",
 [DHCP_INFORM] =	"DHCP_INFORM",
};

const char *
ni_dhcp_message_name(unsigned int code)
{
	static char namebuf[64];
	const char *name = NULL;

	if (code < 16)
		name = __dhcp_message_names[code];
	if (!name) {
		snprintf(namebuf, sizeof(namebuf), "DHCP_MSG_<%u>", code);
		name = namebuf;
	}
	return name;
}
