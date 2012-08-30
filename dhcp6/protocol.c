/*
 *	DHCP6 supplicant -- build and parse DHCP6 packets
 *
 *	Copyright (C) 2010-2012, Olaf Kirch <okir@suse.de>
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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <wicked/logging.h>
#include <wicked/netinfo.h>
#include <wicked/socket.h>
#include <wicked/resolver.h>
#if 0
#include <wicked/route.h>
#include <wicked/nis.h>
#include <wicked/xml.h>
#endif

#include "dhcp6/dhcp6.h"
#include "dhcp6/device.h"
#include "dhcp6/protocol.h"
#include "dhcp6/duid.h"
#include "dhcp6/fsm.h"

#include "buffer.h"
#include "socket_priv.h"
#include "netinfo_priv.h"


/*
 * IPV6_RECVPKTINFO is defined in rfc3542, that
 * obsoletes rfcC2292 that defines IPV6_PKTINFO.
 */
#if !defined(IPV6_RECVPKTINFO)
#define IPV6_RECVPKTINFO IPV6_PKTINFO
#endif

/*
 * Option request allocation chunk
 */
#define NI_DHCP6_OPTION_REQUEST_CHUNK	16


//extern int	ni_dhcp6_device_retransmit(ni_dhcp6_device_t *dev);

static void	ni_dhcp6_socket_recv		(ni_socket_t *);
static int	ni_dhcp6_process_packet		(ni_dhcp6_device_t *dev, ni_buffer_t *msgbuf,
						 const struct in6_addr *sender);

static int	ni_dhcp6_socket_get_timeout	(const ni_socket_t *sock, struct timeval *tv);
static void	ni_dhcp6_socket_check_timeout	(ni_socket_t *sock, const struct timeval *now);

static int	ni_dhcp6_client_parse_header (ni_buffer_t *, unsigned int *, unsigned int *);
static int	ni_dhcp6_client_parse_options(ni_dhcp6_device_t *, ni_buffer_t *, ni_addrconf_lease_t *);

static int	ni_dhcp6_option_next(ni_buffer_t *options, ni_buffer_t *optbuf);
static int	ni_dhcp6_option_get_duid(ni_buffer_t *bp, ni_opaque_t *duid);

/*
 * Open a socket bound to dhcp6 client port for sending unicasts.
 *
 */
static int
__ni_dhcp6_socket_open(ni_dhcp6_device_t *dev)
{
	ni_sockaddr_t saddr;
	int fd, on;

	/*
	 * FIXME: Error handling in case link-layer address is missed,
	 *        in tentative or even in dad-failed state, ....
	 *
	 * http://tools.ietf.org/html/rfc3315#section-13
	 *   13. Transmission of Messages by a Client
	 *   [...]
	 *   A client uses multicast to reach all servers or an individual server.
	 *   An individual server is indicated by specifying that server's DUID in
	 *   a Server Identifier option (see section 22.3) in the client's message
	 *   [...]
	 *
	 * http://tools.ietf.org/html/rfc3315#section-16
	 *   16. Client Source Address and Interface Selection
	 *   [...]
	 *   The client MUST use a link-local address assigned to the interface
	 *   for which it is requesting configuration information as the source
	 *   address in the header of the IP datagram.
	 *   [...]
	 *
	 * Further:
	 * Unicasts only after receiving the server unicast option from server.
	 */
	if (!dev->link.ifindex) {
		ni_error("interface index not set");
		return -1;
	}
	if (dev->config->client_addr.ss_family != AF_INET6 ||
	    !IN6_IS_ADDR_LINKLOCAL(&dev->config->client_addr.six.sin6_addr)) {
		ni_error("link layer address not (yet) available");
		return -1;
	}
	ni_trace("link local address is %s", ni_address_print(&dev->config->client_addr));

	if ((fd = socket (PF_INET6, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
		ni_error("socket(INET6, DGRAM, UDP): %m");
		return -1;
	}

	on = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == -1)
		ni_error("setsockopt(SO_REUSEADDR): %m");
#if defined(SO_REUSEPORT)
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) == -1)
		ni_error("setsockopt(SO_REUSEPORT): %m");
#endif
	if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &on, sizeof(on)) == -1)
		ni_error("setsockopt(SO_RCVBUF): %m");

	if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on)) != 0)
		ni_error("setsockopt(IPV6_RECVPKTINFO): %m");

	if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1)
		ni_error("fcntl(SETDF, CLOEXEC): %m");


	/*
	 * Should we use dev->config->client_addr directly?
	 */
	ni_sockaddr_set_ipv6(&saddr, dev->config->client_addr.six.sin6_addr,
					NI_DHCP6_CLIENT_PORT);
	saddr.six.sin6_scope_id = dev->link.ifindex;

	/*
	 * TODO: Tests needed.
	 *
	 *   When the interface has been just brought up, the kernel may
	 *   not yet finished DAD for the link-local address (tentative)
	 *   wicked has to wait until it powers up dhcpv6.
	 *
	 *   We should create open the dhcp6 socket _after_ NETLINK has
	 *   provided RA/managed net/prefix info to user space anyway,
	 *   so this should catch it ...
	 */
	if (bind(fd, &saddr.sa, sizeof(saddr.six)) == -1) {
		ni_error("bind(%s): %m", ni_address_print(&saddr));
		close(fd);
		return -1;
	}

	/*
	 * Set the device index for outgoing multicast packets on the socket.
	 */
	on = dev->link.ifindex;
	if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &on, sizeof(on)) != 0)
		ni_error("setsockopt(IPV6_MULTICAST_IF, %d: %m", on);

	ni_debug_dhcp("%s: bound DHCPv6 socket to [%s%%%u]:%u",
		dev->ifname, ni_address_print(&saddr), saddr.six.sin6_scope_id,
		ntohs(saddr.six.sin6_port));

	return fd;
}

/*
 * Open a DHCP6 socket for send and receive
 */
static int
ni_dhcp6_socket_open(ni_dhcp6_device_t *dev)
{
	int fd;

	if (dev->sock != NULL)
		return 0;

	if ((fd = __ni_dhcp6_socket_open(dev)) == -1)
		return -1;

	if ((dev->sock = ni_socket_wrap(fd, SOCK_DGRAM)) != NULL) {
		dev->sock->user_data = ni_dhcp6_device_get(dev);
		dev->sock->receive = ni_dhcp6_socket_recv;
		dev->sock->get_timeout = ni_dhcp6_socket_get_timeout;
		dev->sock->check_timeout = ni_dhcp6_socket_check_timeout;

		ni_buffer_init_dynamic(&dev->sock->rbuf, NI_DHCP6_RBUF_SIZE);

		ni_socket_activate(dev->sock);
	}
	return 0;
}

/*
 * This callback is invoked from the socket code when we
 * detect an incoming DHCP6 packet on the raw socket.
 */
static const char *
__ni_dhcp6_hexdump(ni_stringbuf_t *sbuf, const ni_buffer_t *packet)
{
	size_t plen = ni_buffer_count(packet);
	ni_stringbuf_grow(sbuf, plen * 3);
	return ni_format_hex(ni_buffer_head(packet), plen, sbuf->string, sbuf->size);
}

static void
ni_dhcp6_socket_recv(ni_socket_t *sock)
{
	ni_stringbuf_t hexbuf = NI_STRINGBUF_INIT_DYNAMIC;
	ni_dhcp6_device_t * dev = sock->user_data;
	ni_buffer_t * rbuf = &sock->rbuf;
	unsigned char cbuf[CMSG_SPACE(sizeof(struct in6_pktinfo))];
	ni_sockaddr_t saddr;
	struct iovec iov = {
		.iov_base = ni_buffer_tail(rbuf),
		.iov_len = ni_buffer_tailroom(rbuf),
	};
	struct msghdr msg = {
		.msg_name = &saddr,
		.msg_namelen = sizeof(saddr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = cbuf,
		.msg_controllen = sizeof(cbuf),
		.msg_flags = 0,
	};
	struct in6_pktinfo *pinfo = NULL;
	struct cmsghdr *cm;
	ssize_t bytes;

	memset(&saddr, 0, sizeof(saddr));
	memset(&cbuf, 0, sizeof(cbuf));

	bytes = recvmsg(sock->__fd, &msg, 0);
	if(bytes < 0) {
		if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
			ni_error("%s: recvmsg error on socket %d: %m",
				dev->ifname, sock->__fd);
			ni_socket_deactivate(sock);
		}
		return;
	} else if (bytes == 0) {
		ni_error("%s: recvmsg didn't returned any data on socket %d",
			dev->ifname, sock->__fd);
		return;
	}

	for (cm = CMSG_FIRSTHDR(&msg); cm; cm = CMSG_NXTHDR(&msg, cm)) {
		if (cm->cmsg_level == IPPROTO_IPV6 &&
		    cm->cmsg_type == IPV6_PKTINFO &&
		    cm->cmsg_len == CMSG_LEN(sizeof(struct in6_pktinfo))) {
			pinfo = (struct in6_pktinfo *)(CMSG_DATA(cm));
		}
	}

	if (pinfo == NULL) {
		ni_error("%s: failed to get packet info on socket %d",
			 dev->ifname, sock->__fd);
		return;
	}
	if(dev->link.ifindex != pinfo->ipi6_ifindex) {
		ni_error("%s: received packet with interface index %u instead of %u",
			dev->ifname, pinfo->ipi6_ifindex, dev->link.ifindex);
		return;
	}

	ni_buffer_push_tail(rbuf, bytes);

	ni_debug_socket("%s: received %zd byte packet from %s: %s",
			dev->ifname, bytes, ni_dhcp6_address_print(&pinfo->ipi6_addr),
			__ni_dhcp6_hexdump(&hexbuf, rbuf));
	ni_stringbuf_destroy(&hexbuf);

	ni_dhcp6_process_packet(dev, rbuf, &pinfo->ipi6_addr);

	ni_buffer_reset(rbuf);
}

static int
ni_dhcp6_process_packet(ni_dhcp6_device_t *dev, ni_buffer_t *msgbuf, const struct in6_addr *sender)
{
	ni_dhcp6_packet_header_t *header;
	int rv = -1;

	/*
	 * sanity check: verify we have at least the message type byte
	 *               [ni_dhcp6_socket_recv checked this already ...]
	 */
	if (!ni_buffer_count(msgbuf)) {
		ni_error("%s: discarding empty packet", dev->ifname);
		return rv;
	}

	/*
	 * peek header only
	 */
	header = ni_buffer_head(msgbuf);
	switch(header->type) {
		/* handle client response msgs */
		case NI_DHCP6_ADVERTISE:
		case NI_DHCP6_REPLY:
		case NI_DHCP6_RECONFIGURE:
			rv = ni_dhcp6_fsm_process_client_packet(dev, msgbuf, sender);
		break;

		/* and discard any other msgs  */
		default:
			ni_debug_dhcp("%s: received %s message in state %s from %s: discarding",
					dev->ifname, ni_dhcp6_message_name(header->type),
					ni_dhcp6_fsm_state_name(dev->fsm.state),
					ni_dhcp6_address_print(sender));
		break;
	}
	return rv;
}

const char *
ni_dhcp6_format_time(const struct timeval *tv)
{
	static char buf[64];
	struct tm tm;

	memset(buf, 0, sizeof(buf));
	memset(&tm, 0, sizeof(tm));

	localtime_r(&tv->tv_sec, &tm);
	strftime(buf, sizeof(buf), "%T", &tm);
	snprintf(buf + strlen(buf), sizeof(buf)-strlen(buf), ".%ld", tv->tv_usec);

	return buf;
}

const char *
ni_dhcp6_address_print(const struct in6_addr *ipv6)
{
	ni_sockaddr_t addr;

	addr.ss_family = AF_INET6;
	memcpy(&addr.six.sin6_addr, ipv6, sizeof(addr.six.sin6_addr));

	return ni_address_print(&addr);
}

static int
ni_dhcp6_socket_get_timeout(const ni_socket_t *sock, struct timeval *tv)
{
	ni_dhcp6_device_t * dev = sock->user_data;
	if( !(dev = sock->user_data)) {
		ni_error("check_timeout: socket without capture object?!");
		return -1;
	}

	timerclear(tv);
	if (timerisset(&dev->retrans.deadline)) {
		*tv = dev->retrans.deadline;
		ni_trace("%s: get socket timeout for socket [fd=%d]: %s",
				dev->ifname, sock->__fd, ni_dhcp6_format_time(tv));
#if 1
	} else {
		ni_trace("%s: get socket timeout for socket [fd=%d]: unset",
				dev->ifname, sock->__fd);
#endif
	}
	return timerisset(tv) ? 0 : -1;
}

static void
ni_dhcp6_socket_check_timeout(ni_socket_t *sock, const struct timeval *now)
{
	ni_dhcp6_device_t * dev;
	struct tm;

	if (!(dev = sock->user_data)) {
		ni_error("check_timeout: socket without device object?!");
		return;
	}

	if (timerisset(&dev->retrans.deadline) && timercmp(&dev->retrans.deadline, now, <)) {
#if 1
		ni_trace("%s: check socket timeout for socket [fd=%d]: %s",
				dev->ifname, sock->__fd,
				ni_dhcp6_format_time(&dev->retrans.deadline));
#endif
		ni_dhcp6_device_retransmit(dev);
#if 1
	} else {
		ni_trace("%s: check socket timeout for socket [fd=%d]: unset",
				dev->ifname, sock->__fd);
#endif
	}
}

/*
 * Inline functions for setting/retrieving options from a buffer
 */
static inline int
ni_dhcp6_option_put(ni_buffer_t *bp, int code, const void *data, size_t len)
{
	ni_dhcp6_option_header_t opt = {
		.code = htons(code),
		.len = htons(len),
	};
	/*ni_buffer_ensure_tailroom(bp, sizeof(opt) + len);*/
	if(ni_buffer_put(bp, &opt, sizeof(opt)) < 0)
		return -1;
	if(ni_buffer_put(bp, data, len) < 0)
		return -1;
	return 0;
}

static inline int
ni_dhcp6_option_put_empty(ni_buffer_t *bp, int code)
{
	return ni_dhcp6_option_put(bp, code, NULL, 0);
}

#if 0
static inline int
ni_dhcp6_option_put8(ni_buffer_t *bp, int code, uint8_t value)
{
	return ni_dhcp6_option_put(bp, code, &value, 1);
}
#endif

static inline int
ni_dhcp6_option_put16(ni_buffer_t *bp, int code, uint16_t value)
{
	value = htons(value);
	return ni_dhcp6_option_put(bp, code, &value, 2);
}

#if 0
static inline int
ni_dhcp6_option_put32(ni_buffer_t *bp, int code, uint32_t value)
{
	value = htonl(value);
	return ni_dhcp6_option_put(bp, code, &value, 4);
}

static inline int
ni_dhcp6_option_put_ipv4(ni_buffer_t *bp, int code, struct in_addr addr)
{
	return ni_dhcp6_option_put(bp, code, &addr, sizeof(addr));
}

static inline int
ni_dhcp6_option_put_ipv6(ni_buffer_t *bp, int code, struct in6_addr addr)
{
	return ni_dhcp6_option_put(bp, code, &addr, sizeof(addr));
}

static inline int
ni_dhcp6_option_puts(ni_buffer_t *bp, int code, const char *string)
{
	return ni_dhcp6_option_put(bp, code, string, strlen(string));
}
#endif

static int
ni_dhcp6_option_put_status(ni_buffer_t *bp, struct ni_dhcp6_status *status)
{
	ni_buffer_t data;
	uint16_t    code;
	size_t      len = ni_string_len(status->message);

	ni_buffer_init(&data, ni_buffer_tail(bp), ni_buffer_tailroom(bp));
	if (ni_buffer_reserve_head(&data, sizeof(ni_dhcp6_option_header_t)) < 0)
		goto failure;

	code = htons(status->code);
	ni_buffer_put(&data, &code, sizeof(code));
	ni_buffer_put(&data, status->message, len);

	if (ni_dhcp6_option_put(bp, NI_DHCP6_OPTION_STATUS_CODE, NULL, ni_buffer_count(&data)) < 0)
		goto failure;

	return 0;

failure:
	if (data.overflow)
		bp->overflow = 1;
	return -1;
}

static int
ni_dhcp6_option_put_ia_address(ni_buffer_t *bp, struct ni_dhcp6_ia_addr *iadr)
{
	ni_buffer_t data;
	uint32_t value32;
	uint16_t option;
	ni_sockaddr_t addr;

	ni_buffer_init(&data, ni_buffer_tail(bp), ni_buffer_tailroom(bp));
	if (ni_buffer_reserve_head(&data, sizeof(ni_dhcp6_option_header_t)) < 0)
		return -1;

	if (iadr->plen > 0) {
		addr.ss_family = AF_INET6;
		memcpy(&addr.six.sin6_addr, &iadr->addr, sizeof(addr.six.sin6_addr));
#if 0
		ni_trace("ia prefix: %s/%u, preferred_lft: %u, valid_lft: %u",
				ni_address_print(&addr), iadr->plen,
				iadr->preferred_lft, iadr->valid_lft);
#endif
		option = NI_DHCP6_OPTION_IA_PREFIX;
		value32 = htonl(iadr->preferred_lft);
		if (ni_buffer_put(&data, &value32, sizeof(value32)) < 0)
			goto failure;
		value32 = htonl(iadr->valid_lft);
		if (ni_buffer_put(&data, &value32, sizeof(value32)) < 0)
			goto failure;
		if (ni_buffer_put(&data, &iadr->plen, sizeof(iadr->plen)) < 0)
			goto failure;
		if (ni_buffer_put(&data, &iadr->addr, sizeof(iadr->addr)) < 0)
			goto failure;
	} else {
		addr.ss_family = AF_INET6;
		memcpy(&addr.six.sin6_addr, &iadr->addr, sizeof(addr.six.sin6_addr));
#if 0
		ni_trace("ia address: %s, preferred_lft: %u, valid_lft: %u",
				ni_address_print(&addr),
				iadr->preferred_lft, iadr->valid_lft);
#endif
		option = NI_DHCP6_OPTION_IAADDR;
		if (ni_buffer_put(&data, &iadr->addr, sizeof(iadr->addr)) < 0)
			goto failure;
		value32 = htonl(iadr->preferred_lft);
		if (ni_buffer_put(&data, &value32, sizeof(value32)) < 0)
			goto failure;
		value32 = htonl(iadr->valid_lft);
		if (ni_buffer_put(&data, &value32, sizeof(value32)) < 0)
			goto failure;
	}
	if (iadr->status && iadr->status->code != 0) {
		if (ni_dhcp6_option_put_status(&data, iadr->status) < 0)
			goto failure;
#if 0
	} else {
		struct ni_dhcp6_status s = { .code = 0, .message = "All fine" };
		if (ni_dhcp6_option_put_status(&data, &s) < 0)
			goto failure;
#endif
	}

	if (ni_dhcp6_option_put(bp, option, NULL, ni_buffer_count(&data)) < 0)
		goto failure;

	return 0;

failure:
	if (data.overflow)
		bp->overflow = 1;
	return -1;
}

static inline int
__ni_dhcp6_option_ia_type_to_option(uint16_t *option, uint16_t type)
{
	switch (type) {
	case NI_DHCP6_IA_PD_TYPE:
		*option = NI_DHCP6_OPTION_IA_PD;
		return 0;
	case NI_DHCP6_IA_NA_TYPE:
		*option = NI_DHCP6_OPTION_IA_NA;
		return 0;
	case NI_DHCP6_IA_TA_TYPE:
		*option = NI_DHCP6_OPTION_IA_TA;
		return 0;
	default:
		return -1;
	}
}

static int
ni_dhcp6_option_put_ia(ni_buffer_t *bp, struct ni_dhcp6_ia *ia)
{
	struct ni_dhcp6_ia_addr *iadr;
	ni_buffer_t data;
	uint16_t option;
	uint32_t value32;

	/*
	 * Hmm... perhaps we don't need a mask and should use option
	 * codes directly in ia->type?
	 */
	if(__ni_dhcp6_option_ia_type_to_option(&option, ia->type) < 0)
		return -1;

	ni_buffer_init(&data, ni_buffer_tail(bp), ni_buffer_tailroom(bp));
	if (ni_buffer_reserve_head(&data, sizeof(ni_dhcp6_option_header_t)) < 0)
		goto failure;
#if 0
	ni_trace("ia->iaid: %u", ia->iaid);
#endif
	value32 = htonl(ia->iaid);
	if (ni_buffer_put(&data, &value32, sizeof(value32)) < 0)
		goto failure;

	if (ia->type != NI_DHCP6_IA_TA_TYPE) {
		/*
		 * FIXME: this has to be done much earlier, not here!!
		 */
		if ((ia->renewal_time / 2) == 0)
			ia->renewal_time = 3600;

		if ( ia->rebind_time <= ia->renewal_time)
			ia->rebind_time = ia->renewal_time + (ia->renewal_time / 2);
#if 0
		ni_trace("ia->renewal_time: %u", ia->renewal_time);
#endif
		value32 = htonl(ia->renewal_time);
		if (ni_buffer_put(&data, &value32, sizeof(value32)) < 0)
			goto failure;
#if 0
		ni_trace("ia->rebind_time: %u", ia->rebind_time);
#endif
		value32 = htonl(ia->rebind_time);
		if (ni_buffer_put(&data, &value32, sizeof(value32)) < 0)
			goto failure;
	}

	for (iadr = ia->addrs; iadr; iadr = iadr->next) {
		if ((ia->type == NI_DHCP6_IA_PD_TYPE && iadr->plen == 0) ||
		    (ia->type != NI_DHCP6_IA_PD_TYPE && iadr->plen > 0))
			goto failure;

		if (ni_dhcp6_option_put_ia_address(&data, iadr) < 0)
			goto failure;
	}

	/* Hmm... do we ever set status? */
	if (ia->status && ia->status->code != 0) {
		if (ni_dhcp6_option_put_status(&data, ia->status) < 0)
			goto failure;
#if 0
	} else {
		struct ni_dhcp6_status s = { .code = 0, .message = "All fine" };
		if (ni_dhcp6_option_put_status(&data, &s) < 0)
			goto failure;
#endif
	}

	if (ni_dhcp6_option_put(bp, option, NULL, ni_buffer_count(&data)) < 0)
		goto failure;

	return 0;

failure:
	if (data.overflow)
		bp->overflow = 1;
	return -1;
}

int
ni_dhcp6_check_domain_name(const char *ptr, size_t len, int dots)
{
	const char *p;

	/* dots  < 0: no dots allowed at all
	   dots == 0: any number of dots allowed
	   dots  > 0: specified number of dots required at least  */

	/* not empty or complete length not over 255 characters
	   additionally, we allow a [.] at the end ('foo.bar.')   */
	if (!ptr || len == 0 || len >= 256)
		return -1;

	/* consists of [[:alnum:]-]+ labels separated by [.]      */
	/* a [_] is against RFC but seems to be "widely used"...  */
	for (p=ptr; *p && len-- > 0; p++) {
		if ( *p == '-' || *p == '_') {
			/* not allowed at begin or end of a label */
			if ((p - ptr) == 0 || len == 0 || p[1] == '.')
				return -1;
		} else if ( *p == '.') {
			/* each label has to be 1-63 characters;
			   we allow [.] at the end ('foo.bar.')   */
			ssize_t d = (ssize_t)(p - ptr);
			if( d <= 0 || d >= 64)
				return -1;
			ptr = p + 1; /* jump to the next label    */
			if(dots > 0 && len > 0)
				dots--;
		} else if ( !isalnum((unsigned char)*p)) {
			/* also numbers at the begin are fine     */
			return -1;
		}
	}
	return dots ? -1 : 0;
}

int
ni_dhcp6_check_domain_list(const char *ptr, size_t len, int dots)
{
	const char *p;
	int ret = -1; /* at least one needed */

	if (!ptr || len == 0)
		return ret;

	for (p=ptr; (*p != 0) && (len > 0); p++, len--) {
		if (*p != ' ')
			continue;
		if (p > ptr) {
			if (ni_dhcp6_check_domain_name(ptr, p - ptr, dots) != 0)
				return -1;
			ret = 0;
		}
		ptr = p + 1;
	}

	if (p > ptr)
		return ni_dhcp6_check_domain_name(ptr, p - ptr, dots);
	else
		return ret;
}

static int
ni_dhcp6_fqdn_encode(ni_buffer_t *bp, const char *fqdn)
{
	const char *end;
	size_t tot, len;
	uint8_t cc;

	if ((tot = ni_string_len(fqdn)) > 255)
		return -1;

	while (fqdn && *fqdn) {
		end = strchr(fqdn, '.');
		if( end) {
			len = (size_t)(end - fqdn);
			tot -= len + 1;
			end++;
		} else {
			len = tot;
		}

		if (len > 63)
			return -1;

		if (len == 0)
			break;

		cc = len;
		if (ni_buffer_put(bp, &cc, 1) < 0)
			return -1;

		if (ni_buffer_put(bp, fqdn, len) < 0)
			return -1;

		fqdn = end;
	}
	cc = 0;
	return ni_buffer_put(bp, &cc, 1);
}

static inline int
ni_dhcp6_option_put_fqdn(ni_buffer_t *bp, const char *hostname, ni_bool_t update_dns, ni_bool_t update_aaaa)
{
	/*
	 * http://tools.ietf.org/html/rfc4704#section-4.1
	 *
	 * The format of the Flags field is:
	 *
	 *      0 1 2 3 4 5 6 7
	 *     +-+-+-+-+-+-+-+-+
	 *     |  MBZ    |N|O|S|
	 *     +-+-+-+-+-+-+-+-+
	 *
	 * S: 1 ==> Client requests server to update AAAA RR (FQDN-to-address)
	 *      <== Server has taken responsibility for AAAA RR updates
	 * O: 0 ==> Client sets this bit to 0.
	 *      <== Whether the server has overridden the client's "S" bit.
	 * N: 0 ==> Client sets to 0 to request to update PTR RR (+ AAAA RR).
	 *      <== A server SHALL (0) or SHALL NOT (1) perform DNS updates.
	 *          If the "N" bit is 1, the "S" bit MUST be 0.
	 *
	 * Remaining MBZ bits are reserved and MUST be cleared and ignored.
	 */
	ni_buffer_t data;
	uint8_t flags = 4;

	if (update_dns) {
		flags = update_aaaa ? 1 : 0;
	}

	ni_buffer_init(&data, ni_buffer_tail(bp), ni_buffer_tailroom(bp));
	if (ni_buffer_reserve_head(&data, sizeof(ni_dhcp6_option_header_t)) < 0)
		goto failure;

	if (ni_buffer_put(&data, &flags, 1) < 0)
		goto failure;

	if (ni_string_len(hostname)) {
		if( ni_dhcp6_fqdn_encode(&data, hostname) < 0)
			goto failure;
	}

	if (ni_dhcp6_option_put(bp, NI_DHCP6_OPTION_FQDN, NULL, ni_buffer_count(&data)) < 0)
		goto failure;

	return 0;
failure:
	if (data.overflow)
		bp->overflow = 1;
	return -1;
}

static int
ni_dhcp6_option_next(ni_buffer_t *options, ni_buffer_t *optbuf)
{
	ni_dhcp6_option_header_t hdr;
	size_t len;
	void *ptr;

	if (options->underflow)
		return -1;

	if (ni_buffer_count(options) == 0)
		return 0;

	if (ni_buffer_get(options, &hdr, sizeof(hdr)) < 0)
		return -1;

	len = ntohs(hdr.len);
	if (len) {
		if (ni_buffer_count(options) < len)
			goto underflow;

		ptr = ni_buffer_pull_head(options, len);
		if (!ptr)
			goto underflow;

		ni_buffer_init_reader(optbuf, ptr, len);
	} else {
		ni_buffer_init(optbuf, NULL, 0);
	}
	return ntohs(hdr.code);

underflow:
	options->underflow = 1;
	return -1;
}

/*
static inline int
ni_dhcp6_option_get(ni_buffer_t *bp, void *var, size_t len)
{
	return ni_buffer_get(bp, var, len);
}
*/

static inline int
ni_dhcp6_option_get8(ni_buffer_t *bp, uint8_t *var)
{
	return ni_buffer_get(bp, var, 1);
}

static int
ni_dhcp6_option_get16(ni_buffer_t *bp, uint16_t *var)
{
	if (ni_buffer_get(bp, var, 2) < 0)
		return -1;
	*var = ntohs(*var);
	return 0;
}

static int
ni_dhcp6_option_get32(ni_buffer_t *bp, uint32_t *var)
{
	if (ni_buffer_get(bp, var, 4) < 0)
		return -1;
	*var = ntohl(*var);
	return 0;
}

static int
ni_dhcp6_option_gets(ni_buffer_t *bp, char **var)
{
	unsigned int len = ni_buffer_count(bp);
	int ret;

	if (len > 0) {
		ni_string_free(var);
		*var = xmalloc(len + 1);
		ret = ni_buffer_get(bp, *var, len);
		(*var)[len] = '\0';
		return ret;
	}
	bp->underflow = 1;
	return -1;
}

static int
ni_dhcp6_option_get_duid(ni_buffer_t *bp, ni_opaque_t *opaq)
{
	size_t len = ni_buffer_count(bp);

	if(len < sizeof(uint16_t)) {
		bp->underflow = 1;
	} else if (len > sizeof(opaq->data)) {
		bp->overflow = 1;
	} else {
		opaq->len = len;
		return ni_buffer_get(bp, &opaq->data, opaq->len);
	}
	return -1;
}

static int
ni_dhcp6_option_get_elapsed_time(ni_buffer_t *bp, struct timeval *tv)
{
	uint16_t csecs;

	if (ni_dhcp6_option_get16(bp, &csecs) < 0)
		return -1;

	if (csecs == 0xffff) {
		tv->tv_sec = ~(time_t)0L;
		tv->tv_usec = ~(suseconds_t)0L;
	} else {
		tv->tv_sec = csecs / 100;
		tv->tv_usec = (csecs -tv->tv_sec) * 10000;
	}
	return 0;
}

static int
ni_dhcp6_option_get_status(ni_buffer_t *bp, struct ni_dhcp6_status *status)
{
	status->code = 0;
	ni_string_free(&status->message);
	if (ni_dhcp6_option_get16(bp, &status->code) < 0)
		return -1;
	if (ni_dhcp6_option_gets(bp, &status->message) < 0)
		return -1;
	return 0;
}

static int
ni_dhcp6_option_get_ipv4(ni_buffer_t *bp, struct in_addr *addr)
{
	if( ni_buffer_get(bp, addr, 4) < 0)
		return -1;
	return 0;
}

static int
ni_dhcp6_option_get_ipv6(ni_buffer_t *bp, struct in6_addr *addr)
{
	if( ni_buffer_get(bp, addr, 16) < 0)
		return -1;
	return 0;
}

static int
ni_dhcp6_option_get_sockaddr(ni_buffer_t *bp, ni_sockaddr_t *addr)
{
	int rv = -1;
	switch (addr->ss_family) {
	case AF_INET:
		rv = ni_dhcp6_option_get_ipv4(bp, &addr->sin.sin_addr);
		break;
	case AF_INET6:
		rv = ni_dhcp6_option_get_ipv6(bp, &addr->six.sin6_addr);
		break;
	default:
		break;
	}
	return rv;
}

static int
ni_dhcp6_decode_address_list(ni_buffer_t *bp, ni_string_array_t *list)
{
	while (ni_buffer_count(bp) && !bp->underflow) {
		ni_sockaddr_t addr;

		memset(&addr, 0, sizeof(addr));
		addr.ss_family = AF_INET6;
		if (ni_dhcp6_option_get_sockaddr(bp, &addr) < 0)
			return -1;

		ni_string_array_append(list, ni_address_print(&addr));
	}

	if (bp->underflow)
		return -1;

	return 0;
}

/*
 * FIXME: See http://tools.ietf.org/html/rfc3315#section-8
 *
 * Decode an RFC3397 DNS search order option.
 */
static int
ni_dhcp6_decode_dnssearch(ni_buffer_t *optbuf, ni_string_array_t *list)
{
	unsigned char *base = ni_buffer_head(optbuf);
	unsigned int base_offset = optbuf->head;

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
 * Option request array
 */
void
ni_dhcp6_option_request_init(ni_dhcp6_option_request_t *ora)
{
	memset(ora, 0, sizeof(*ora));
}

void
ni_dhcp6_option_request_destroy(ni_dhcp6_option_request_t *ora)
{
	if (ora->options)
		free(ora->options);
	memset(ora, 0, sizeof(*ora));
}

static void
__ni_dhcp6_option_request_realloc(ni_dhcp6_option_request_t *ora, unsigned int newsize)
{
	unsigned int i;

	newsize += NI_DHCP6_OPTION_REQUEST_CHUNK;
	ora->options = xrealloc(ora->options, newsize * sizeof(uint16_t));

	for (i = ora->count; i < newsize; ++i)
		ora->options[i] = 0;
}

int
ni_dhcp6_option_request_append(ni_dhcp6_option_request_t *ora, uint16_t option)
{
	if ((ora->count % NI_DHCP6_OPTION_REQUEST_CHUNK) == 0)
		__ni_dhcp6_option_request_realloc(ora, ora->count);

	ora->options[ora->count++] = htons(option);
	return 0;
}

static inline int
ni_dhcp6_build_client_header(ni_buffer_t *bp, unsigned int msg_type, unsigned int msg_xid)
{
	ni_dhcp6_client_header_t header;

	header.type = msg_type;
	header.xid &= htonl(~NI_DHCP6_XID_MASK);
	header.xid |= htonl(msg_xid);

	ni_buffer_ensure_tailroom(bp, sizeof(header));
	if(ni_buffer_put(bp, &header, sizeof(header)) < 0)
		return -1;
	return 0;
}

static int
ni_dhcp6_build_reparse(ni_dhcp6_device_t *dev, void *data, size_t len)
{
	ni_addrconf_lease_t *lease;
	unsigned int         type;
	unsigned int         xid;
	ni_buffer_t          buf;
	int                  rv;

	ni_buffer_init_reader(&buf, data, len);
	if( (rv = ni_dhcp6_client_parse_header(&buf, &type, &xid)) < 0)
		return rv;

	lease = ni_addrconf_lease_new(NI_ADDRCONF_DHCP, AF_INET6);
	rv = ni_dhcp6_client_parse_options(dev, ni_buffer_head(&buf), lease);
	ni_addrconf_dhcp6_lease_free(lease);

	return rv;
}

int
ni_dhcp6_build_message(ni_dhcp6_device_t *dev,
			unsigned int msg_type,
			ni_buffer_t *msg_buf,
			const ni_addrconf_lease_t *lease)
{
	ni_dhcp6_option_request_t oreq;
	struct ni_dhcp6_ia *ia_list, *ia;
	uint16_t elapsed_time = 0;
	int rv = -1;

	ia_list = NULL;
	ni_dhcp6_option_request_init(&oreq);

	if (ni_dhcp6_build_client_header(msg_buf, msg_type, dev->dhcp6.xid) < 0)
		goto cleanup;

	if (ni_dhcp6_option_put(msg_buf, NI_DHCP6_OPTION_CLIENTID,
			&dev->config->client_duid.data, dev->config->client_duid.len) < 0)
		goto cleanup;

	if (lease->dhcp6.server_id.len) {
		if (ni_dhcp6_option_put(msg_buf, NI_DHCP6_OPTION_SERVERID,
				lease->dhcp6.server_id.data, lease->dhcp6.server_id.len) < 0)
			goto cleanup;
	}

	elapsed_time = ni_dhcp6_device_uptime(dev, 0xffff);
	if (ni_dhcp6_option_put16(msg_buf, NI_DHCP6_OPTION_ELAPSED_TIME, elapsed_time) < 0)
		goto cleanup;

	switch (msg_type) {
	case NI_DHCP6_INFO_REQUEST:
		/* it's just an info */
		ni_dhcp6_option_request_append(&oreq, NI_DHCP6_OPTION_UNICAST);
		ni_dhcp6_option_request_append(&oreq, NI_DHCP6_OPTION_FQDN);
	break;

	case NI_DHCP6_SOLICIT:
		// clientid, elapsed_time, oro	+ rapid commit (+ ia hint)
#if 0
		if (dev->config->try_unicast)
			ni_dhcp6_option_request_append(&oreq, NI_DHCP6_OPTION_UNICAST);
#endif

		if (dev->config->rapid_commit) {
			if (ni_dhcp6_option_put_empty(msg_buf, NI_DHCP6_OPTION_RAPID_COMMIT) < 0)
				goto cleanup;
		}

		if (dev->iaid == 0 && ni_dhcp6_device_iaid(dev, &dev->iaid) < 0)
			goto cleanup;

		ia = ia_list = xcalloc(1, sizeof(*ia));
		ia->type = NI_DHCP6_IA_NA_TYPE;
		ia->iaid = dev->iaid;
		if (dev->config->lease_time && dev->config->lease_time != ~0)
			ia->renewal_time = dev->config->lease_time / 2;
		else
			ia->renewal_time = 3600;
		ia->rebind_time = ia->renewal_time + (ia->renewal_time / 2);

		if (ni_dhcp6_option_put_ia(msg_buf, ia) < 0)
			goto cleanup;

		if (dev->config->hostname[0])
			ni_dhcp6_option_put_fqdn(msg_buf, dev->config->hostname, TRUE, TRUE);
	break;

	case NI_DHCP6_REQUEST:
		// clientid, elapsed_time, oro, serverid, ia_na,ia_ta,ia_pd
		for (ia = lease->dhcp6.ia_na; ia; ia = ia->next) {
			if (ia->type != NI_DHCP6_IA_NA_TYPE)
				return -1;
			if (ni_dhcp6_option_put_ia(msg_buf, ia) < 0)
				return -1;
		}
		for (ia = lease->dhcp6.ia_ta; ia; ia = ia->next) {
			if (ia->type != NI_DHCP6_IA_TA_TYPE)
				return -1;
			if (ni_dhcp6_option_put_ia(msg_buf, ia) < 0)
				return -1;
		}
		for (ia = lease->dhcp6.ia_pd; ia; ia = ia->next) {
			if (ia->type != NI_DHCP6_IA_PD_TYPE)
				return -1;
			if (ni_dhcp6_option_put_ia(msg_buf, ia) < 0)
				return -1;
		}

		if (dev->config->hostname[0])
			ni_dhcp6_option_put_fqdn(msg_buf, dev->config->hostname, TRUE, TRUE);
	break;

#if 0
	case NI_DHCP6_CONFIRM:
		// clientid, elapsed_time, oro, serverid, ia_na,ia_ta,ia_pd
	break;
#endif
	default:
		ni_error("Unable to construct %s messages", ni_dhcp6_message_name(msg_type));
		goto cleanup;
	break;
	}

	ni_dhcp6_option_request_append(&oreq, NI_DHCP6_OPTION_PREFERENCE);
	ni_dhcp6_option_request_append(&oreq, NI_DHCP6_OPTION_DNS_SERVERS);
	ni_dhcp6_option_request_append(&oreq, NI_DHCP6_OPTION_DNS_DOMAINS);
	ni_dhcp6_option_request_append(&oreq, NI_DHCP6_OPTION_SIP_SERVER_D);
	ni_dhcp6_option_request_append(&oreq, NI_DHCP6_OPTION_SIP_SERVER_A);
	if (oreq.count > 0) {
		if (ni_dhcp6_option_put(msg_buf, NI_DHCP6_OPTION_ORO, oreq.options,
					sizeof(uint16_t) * oreq.count) < 0)
			goto cleanup;
	}

#if 1
	if (ni_dhcp6_build_reparse(dev, ni_buffer_head(msg_buf), ni_buffer_count(msg_buf)) < 0) {
		ni_trace("unable to reparse dhcp6 %s message: %s", ni_dhcp6_message_name(msg_type),
			ni_print_hex(ni_buffer_head(msg_buf), ni_buffer_count(msg_buf)));
		goto cleanup;
	}
#endif

#if 1
	ni_trace("built dhcp6 %s message: %s", ni_dhcp6_message_name(msg_type),
		ni_print_hex(ni_buffer_head(msg_buf), ni_buffer_count(msg_buf)));
#endif

	rv = 0;

cleanup:
	if (ia_list)
		ni_dhcp6_ia_list_destroy(&ia_list);
	ni_dhcp6_option_request_destroy(&oreq);
	return rv;
}

int
ni_dhcp6_init_message(ni_dhcp6_device_t *dev, unsigned int msg_code, const ni_addrconf_lease_t *lease)
{
	int rv;

	if (ni_dhcp6_socket_open(dev) < 0) {
		ni_error("%s: unable to open DHCP6 socket", dev->ifname);
		goto transient_failure;
	}

	/* Assign a new XID to this message */
	while (dev->dhcp6.xid == 0) {
		dev->dhcp6.xid = random() & NI_DHCP6_XID_MASK;
	}

	ni_trace("%s: building %s with xid 0x%x", dev->ifname,
		ni_dhcp6_message_name(msg_code), dev->dhcp6.xid);

	rv = ni_dhcp6_build_message(dev, msg_code, &dev->message, lease);
	if (rv < 0) {
		ni_error("%s: unable to build %s message", dev->ifname,
			ni_dhcp6_message_name(msg_code));
		return -1;
	}

	memset(&dev->config->server_addr, 0, sizeof(dev->config->server_addr));
	dev->config->server_addr.six.sin6_family = AF_INET6;
	dev->config->server_addr.six.sin6_port = htons(NI_DHCP6_SERVER_PORT);
	dev->config->server_addr.six.sin6_scope_id = dev->link.ifindex;

#if 0
	if(ni_dhcp6_device_can_send_unicast(dev, msg_code, lease)) {
		memcpy(&dev->server_addr.six.sin6_addr, &lease->dhcp6.server_unicast,
			sizeof(dev->server_addr.six.sin6_addr));
	} else
#endif
	if(inet_pton(AF_INET6, NI_DHCP6_ALL_RAGENTS,
				&dev->config->server_addr.six.sin6_addr) != 1) {
		ni_error("%s: Unable to prepare DHCP6 destination address", dev->ifname);
		return -1;
	}

	if(!ni_dhcp6_set_message_timing(dev, msg_code))
		return -1;

	return 0;

transient_failure:
	/* We ran into a transient problem, such as being unable to open
	 * a raw socket. We should schedule a "short" timeout after which
	 * we should re-try the operation. */
	/* FIXME: Not done yet. */
	return 1;
}

void
ni_dhcp6_status_free(struct ni_dhcp6_status *status)
{
	if (status) {
		ni_string_free(&status->message);
		free(status);
	}
}

static void
ni_dhcp6_ia_addr_list_append(struct ni_dhcp6_ia_addr **list, struct ni_dhcp6_ia_addr *ap)
{
	while (*list)
		list = &(*list)->next;
	*list = ap;
}

static void
ni_dhcp6_ia_addr_list_destroy(struct ni_dhcp6_ia_addr **list)
{
	struct ni_dhcp6_ia_addr *addr;
	while ((addr = *list) != NULL) {
		*list = addr->next;
		ni_dhcp6_status_free(addr->status);
		free(addr);
	}
}

static void
ni_dhcp6_ia_list_append(struct ni_dhcp6_ia **list, struct ni_dhcp6_ia *ia)
{
	while (*list)
		list = &(*list)->next;
	*list = ia;
}

void
ni_dhcp6_ia_list_destroy(struct ni_dhcp6_ia **list)
{
	struct ni_dhcp6_ia *ia;
	while ((ia = *list) != NULL) {
		*list = ia->next;
		ni_dhcp6_status_free(ia->status);
		ni_dhcp6_ia_addr_list_destroy(&ia->addrs);
		free(ia);
	}
}

static int
ni_dhcp6_option_parse_ia_address(ni_buffer_t *bp, struct ni_dhcp6_ia *ia, uint16_t addr_type)
{
	struct ni_dhcp6_ia_addr *ap;
	ni_sockaddr_t addr;

	if ((ap = calloc(1, sizeof(*ap))) == NULL)
		goto failure;

	if (ia->type == NI_DHCP6_IA_PD_TYPE) {
		if (ni_dhcp6_option_get32(bp, &ap->preferred_lft) < 0)
			goto failure;

		if (ni_dhcp6_option_get32(bp, &ap->valid_lft) < 0)
			goto failure;

		if (ni_dhcp6_option_get8(bp, &ap->plen) < 0)
			goto failure;

		memset(&addr, 0, sizeof(addr));
		addr.ss_family = AF_INET6;
		if (ni_dhcp6_option_get_sockaddr(bp, &addr) < 0)
			goto failure;
		memcpy(&ap->addr, &addr.six.sin6_addr, sizeof(ap->addr));
#if 0
		ni_trace("%s.%s: %s/%u, pref-life: %u, valid_life: %u",
			ni_dhcp6_ia_type_name(ia->type),
			ni_dhcp6_option_name(addr_type),
			ni_address_print(&addr), ap->plen,
			ap->preferred_lft, ap->valid_lft);
#endif
	} else {
		memset(&addr, 0, sizeof(addr));
		addr.ss_family = AF_INET6;
		if (ni_dhcp6_option_get_sockaddr(bp, &addr) < 0)
			goto failure;
		memcpy(&ap->addr, &addr.six.sin6_addr, sizeof(ap->addr));

		if (ni_dhcp6_option_get32(bp, &ap->preferred_lft) < 0)
			goto failure;

		if (ni_dhcp6_option_get32(bp, &ap->valid_lft) < 0)
			goto failure;
#if 0
		ni_trace("%s.%s: %s, pref-life: %u, valid_life: %u",
			ni_dhcp6_ia_type_name(ia->type),
			ni_dhcp6_option_name(addr_type),
			ni_address_print(&addr),
			ap->preferred_lft, ap->valid_lft);
#endif
	}

	while( ni_buffer_count(bp) && !bp->underflow) {
#if 0
		ni_stringbuf_t	hexbuf = NI_STRINGBUF_INIT_DYNAMIC;
#endif
		ni_buffer_t	optbuf;
		int		option;

		option = ni_dhcp6_option_next(bp, &optbuf);
		if (option < 0)
			goto failure;

		if (option == 0)
			break;

#if 0
		__ni_dhcp6_hexdump(&hexbuf, &optbuf);
		ni_trace("ia-addr option %s: %s", ni_dhcp6_option_name(option), hexbuf.string);
		ni_stringbuf_destroy(&hexbuf);
#endif

		switch (option) {
		case NI_DHCP6_OPTION_STATUS_CODE:
			if (!ap->status)
				ap->status = calloc(1, sizeof(struct ni_dhcp6_status));
			if (!ap->status || ni_dhcp6_option_get_status(&optbuf, ap->status) < 0)
				goto failure;
		break;

		default:
#if 0
			ni_trace("ia-addr option %s: ignored", ni_dhcp6_option_name(option));
#endif
		break;
		}

		if (optbuf.underflow) {
			ni_trace("ia-addr option %s: %u byte of data is too short",
				ni_dhcp6_option_name(option), ni_buffer_count(&optbuf));
		} else if(ni_buffer_count(&optbuf)) {
			ni_trace("ia-addr option %s: is too long - %u bytes left",
				ni_dhcp6_option_name(option), ni_buffer_count(&optbuf));
		}
	}
	if (ap->preferred_lft > ap->valid_lft) {
		free(ap);
		return 1;
	} else {
		ni_dhcp6_ia_addr_list_append(&ia->addrs, ap);
		return 0;
	}

failure:
	if (ap)
		free(ap);
	return -1;
}

static int
ni_dhcp6_client_parse_ia_options(ni_buffer_t *bp,  struct ni_dhcp6_ia *ia)
{
#if 0
	ni_stringbuf_t	hexbuf = NI_STRINGBUF_INIT_DYNAMIC;
#endif

	while( ni_buffer_count(bp) && !bp->underflow) {
		ni_buffer_t	optbuf;
		int		option;

		option = ni_dhcp6_option_next(bp, &optbuf);
		if (option < 0)
			goto failure;

		if (option == 0)
			break;

#if 0
		__ni_dhcp6_hexdump(&hexbuf, &optbuf);
		ni_trace("%s option %s data: %s",
			ni_dhcp6_ia_type_name(ia->type),
			ni_dhcp6_option_name(option),
			hexbuf.string);
		ni_stringbuf_destroy(&hexbuf);
#endif

		switch (option) {
		case NI_DHCP6_OPTION_IAADDR:
			if (ia->type == NI_DHCP6_IA_PD_TYPE)
				goto failure;

			if (ni_dhcp6_option_parse_ia_address(&optbuf, ia, option) < 0)
				goto failure;
		break;

		case NI_DHCP6_OPTION_IA_PREFIX:
			if (ia->type != NI_DHCP6_IA_PD_TYPE)
				goto failure;

			if (ni_dhcp6_option_parse_ia_address(&optbuf, ia, option) < 0)
				goto failure;
		break;

		case NI_DHCP6_OPTION_STATUS_CODE:
			if (!ia->status)
				ia->status = calloc(1, sizeof(struct ni_dhcp6_status));
			if (!ia->status || ni_dhcp6_option_get_status(&optbuf, ia->status) < 0)
				goto failure;
		break;

		default:
#if 0
			ni_trace("%s option %s: ignored",
					ni_dhcp6_ia_type_name(ia->type),
					ni_dhcp6_option_name(option));
#endif
		break;
		}

		if (optbuf.underflow) {
			ni_trace("%s option %s: %u byte of data is too short",
				ni_dhcp6_ia_type_name(ia->type),
				ni_dhcp6_option_name(option),
				ni_buffer_count(&optbuf));
		} else if(ni_buffer_count(&optbuf)) {
			ni_trace("%s option %s: is too long - %u bytes left",
				ni_dhcp6_ia_type_name(ia->type),
				ni_dhcp6_option_name(option),
				ni_buffer_count(&optbuf));
		}
	}

	return 0;

failure:
	return -1;
}

static int
ni_dhcp6_client_parse_ia(ni_buffer_t *bp,  struct ni_dhcp6_ia **ia_na_list, uint16_t type)
{
	struct ni_dhcp6_ia *ia;

	if ((ia = calloc(1, sizeof(*ia))) == NULL)
		goto failure;

	ia->type = type;
	if (ia->type != NI_DHCP6_IA_TA_TYPE) {
		if (ni_dhcp6_option_get32(bp, &ia->iaid) < 0)
			goto failure;
		if (ni_dhcp6_option_get32(bp, &ia->renewal_time) < 0)
			goto failure;
		if (ni_dhcp6_option_get32(bp, &ia->rebind_time) < 0)
			goto failure;
		if (ia->rebind_time > ia->renewal_time)
			goto failure;
	} else {
		if (ni_dhcp6_option_get32(bp, &ia->iaid) < 0)
			goto failure;
	}
#if 0
	ni_trace("%s: iaid=%u, renew=%u, rebind=%u",
		ni_dhcp6_ia_type_name(ia->type),
		ia->iaid, ia->renewal_time, ia->rebind_time);
#endif
	if(ni_dhcp6_client_parse_ia_options(bp, ia) < 0)
		goto failure;

	ni_dhcp6_ia_list_append(ia_na_list, ia);
	return 0;

failure:
	if (ia) {
		ni_dhcp6_ia_addr_list_destroy(&ia->addrs);
		free(ia);
	}
	return -1;
}


static int
ni_dhcp6_client_parse_options(ni_dhcp6_device_t *dev, ni_buffer_t *buffer, ni_addrconf_lease_t *lease)
{
	ni_stringbuf_t hexbuf = NI_STRINGBUF_INIT_DYNAMIC;
#if 0
	unsigned int   i;
#endif
	struct timeval elapsed;

	while( ni_buffer_count(buffer) && !buffer->underflow) {
		ni_buffer_t	optbuf;
		int		option;

		ni_buffer_init(&optbuf, NULL, 0);
		option = ni_dhcp6_option_next(buffer, &optbuf);
		if (option < 0)
			goto failure;

		if (option == 0)
			break;

#if 0
		__ni_dhcp6_hexdump(&hexbuf, &optbuf);
		ni_trace("option %s data: %s", ni_dhcp6_option_name(option), hexbuf.string);
		ni_stringbuf_destroy(&hexbuf);
#endif

		switch(option) {
		case NI_DHCP6_OPTION_CLIENTID:
			ni_dhcp6_option_get_duid(&optbuf, &lease->dhcp6.client_id);
		break;
		case NI_DHCP6_OPTION_SERVERID:
			ni_dhcp6_option_get_duid(&optbuf, &lease->dhcp6.server_id);
		break;

		case NI_DHCP6_OPTION_PREFERENCE:
			ni_dhcp6_option_get8(&optbuf, &lease->dhcp6.server_pref);
		break;
		case NI_DHCP6_OPTION_UNICAST:
			ni_dhcp6_option_get_ipv6(&optbuf, &lease->dhcp6.server_addr);
		break;
		case NI_DHCP6_OPTION_STATUS_CODE:
			if (!lease->dhcp6.status)
				lease->dhcp6.status = calloc(1, sizeof(struct ni_dhcp6_status));
			if (!lease->dhcp6.status ||
			    ni_dhcp6_option_get_status(&optbuf, lease->dhcp6.status) < 0)
				goto failure;
		break;
		case NI_DHCP6_OPTION_ELAPSED_TIME:
			ni_dhcp6_option_get_elapsed_time(&optbuf, &elapsed);
		break;
		case NI_DHCP6_OPTION_RAPID_COMMIT:
			lease->dhcp6.rapid_commit = TRUE;
		break;

		case NI_DHCP6_OPTION_IA_NA:
			ni_dhcp6_client_parse_ia(&optbuf, &lease->dhcp6.ia_na, NI_DHCP6_IA_NA_TYPE);
		break;
		case NI_DHCP6_OPTION_IA_TA:
			ni_dhcp6_client_parse_ia(&optbuf, &lease->dhcp6.ia_ta, NI_DHCP6_IA_TA_TYPE);
		break;
		case NI_DHCP6_OPTION_IA_PD:
			ni_dhcp6_client_parse_ia(&optbuf, &lease->dhcp6.ia_pd, NI_DHCP6_IA_PD_TYPE);
		break;

		case NI_DHCP6_OPTION_DNS_SERVERS:
			if (lease->resolver == NULL)
				lease->resolver = ni_resolver_info_new();
			if (lease->resolver != NULL) {
				ni_dhcp6_decode_address_list(&optbuf, &lease->resolver->dns_servers);
#if 0
				for (i = 0; i < lease->resolver->dns_servers.count; ++i)
					ni_trace("option %s[%u]: %s", ni_dhcp6_option_name(option), i,
						lease->resolver->dns_servers.data[i]);
#endif
			}
		break;
		case NI_DHCP6_OPTION_DNS_DOMAINS:
			if (lease->resolver == NULL)
				lease->resolver = ni_resolver_info_new();
			if (lease->resolver != NULL) {
				ni_dhcp6_decode_dnssearch(&optbuf, &lease->resolver->dns_search);
#if 0
				for (i = 0; i < lease->resolver->dns_search.count; ++i)
					ni_trace("option %s[%u]: %s", ni_dhcp6_option_name(option), i,
						lease->resolver->dns_search.data[i]);
#endif
			}
		break;
		case NI_DHCP6_OPTION_SIP_SERVER_A:
			ni_dhcp6_decode_address_list(&optbuf, &lease->sip_servers);
#if 0
			for (i = 0; i < lease->sip_servers.count; ++i)
				ni_trace("option %s[%u]: %s", ni_dhcp6_option_name(option), i,
						lease->sip_servers.data[i]);
#endif
		break;
		case NI_DHCP6_OPTION_SIP_SERVER_D:
			ni_dhcp6_decode_dnssearch(&optbuf, &lease->sip_servers);
#if 0
			for (i = 0; i < lease->sip_servers.count; ++i)
				ni_trace("option %s[%u]: %s", ni_dhcp6_option_name(option), i,
						lease->sip_servers.data[i]);
#endif
		break;

		default:
#if 0
			ni_trace("%s: option %s: not supported - ignoring",
				dev->ifname, ni_dhcp6_option_name(option));
#endif
		break;
		}

		if (optbuf.underflow) {
			ni_trace("%s: option %s: %u byte data is too short: %s",
				dev->ifname, ni_dhcp6_option_name(option),
				ni_buffer_count(&optbuf), __ni_dhcp6_hexdump(&hexbuf, &optbuf));
			ni_stringbuf_destroy(&hexbuf);
		} else if(ni_buffer_count(&optbuf)) {
			ni_trace("%s: option %s: is too long - %u bytes left: %s",
				dev->ifname, ni_dhcp6_option_name(option),
				ni_buffer_count(&optbuf), __ni_dhcp6_hexdump(&hexbuf, &optbuf));
			ni_stringbuf_destroy(&hexbuf);
		}
	}

#if 1	/* too early here -- do it after parsing depending on the state */
	if (!lease->dhcp6.status || lease->dhcp6.status->code == NI_DHCP6_STATUS_SUCCESS) {
		ni_sockaddr_t            laddr;
		struct ni_dhcp6_ia_addr *iaddr;
		struct ni_dhcp6_ia *     ia;
		ni_address_t *           ap;

		ni_address_list_destroy(&lease->addrs);
		lease->addrs = NULL;
		for (ia = lease->dhcp6.ia_na; ia; ia = ia->next) {
			if (ia->type != NI_DHCP6_IA_NA_TYPE)
				continue; /* Hmm... */

			if (ia->status && ia->status->code != NI_DHCP6_STATUS_SUCCESS)
				continue;

			for (iaddr = ia->addrs; iaddr ; iaddr = iaddr->next) {
				if (iaddr->status &&  iaddr->status->code != NI_DHCP6_STATUS_SUCCESS)
					continue;

				ni_sockaddr_set_ipv6(&laddr, iaddr->addr, 0);
				/*
				 * FIXME: lookup if iadr matches some RA prefix for this interface
				 *        and use prefix lenght of the RA prefix...
				 */
				ap = ni_address_new(AF_INET6, 64, &laddr, &lease->addrs);
				ap->ipv6_cache_info.preferred_lft = iaddr->preferred_lft;
				ap->ipv6_cache_info.valid_lft = iaddr->valid_lft;

				ni_trace("%s: added IPv6 address %s/%u to lease candidate",
						dev->ifname,
						ni_address_print(&ap->local_addr), ap->prefixlen);
			}
		}
	}
#endif

	return 0;

failure:
	return -1;
}


static int
ni_dhcp6_client_parse_header(ni_buffer_t *msgbuf, unsigned int *msg_type, unsigned int *msg_xid)
{
	ni_dhcp6_client_header_t * header;

	header = ni_buffer_pull_head(msgbuf, sizeof(*header));
	if(header) {
		*msg_type = header->type;
		*msg_xid  = ntohl(header->xid) & NI_DHCP6_XID_MASK;
		return 0;
	}
	return -1;
}

int
ni_dhcp6_client_parse_response(ni_dhcp6_device_t *dev, ni_buffer_t *msgbuf,
				unsigned int *msg_type, unsigned int *msg_xid,
				ni_addrconf_lease_t **msg_lease)
{
	ni_addrconf_lease_t *lease;

	if (ni_dhcp6_client_parse_header(msgbuf, msg_type, msg_xid) < 0) {
		ni_error("%s: short DHCP6 client packet (%u bytes)", dev->ifname, ni_buffer_count(msgbuf));
		return -1;
	}

	switch (*msg_type) {
	case NI_DHCP6_REPLY:
	case NI_DHCP6_ADVERTISE:
		if (dev->dhcp6.xid == 0) {
			ni_error("%s: ignoring unexpected %s message xid 0x%06x",
				dev->ifname, ni_dhcp6_message_name(*msg_type), *msg_xid);
			return -1;
		}
		if (dev->dhcp6.xid != *msg_xid) {
			ni_error("%s: ignoring unexpected %s message xid 0x%06x (expecting 0x%06x)",
				dev->ifname, ni_dhcp6_message_name(*msg_type), *msg_xid, dev->dhcp6.xid);
			return -1;
		}
	break;
#if 0
	case NI_DHCP6_RECONFIGURE:
		if (dev->dhcp6.xid != 0) {
			ni_error("%s: ignoring unexpected %s message xid 0x%06x",
				dev->ifname, ni_dhcp6_message_name(*msg_type), *msg_xid);
			return -1;
		}
	break;
#endif
	default:
		ni_error("%s: ignoring unexpected %s message xid 0x%06x",
				dev->ifname, ni_dhcp6_message_name(*msg_type), *msg_xid);
	return -1;
	}

	lease = ni_addrconf_lease_new(NI_ADDRCONF_DHCP, AF_INET6);
	lease->state = NI_ADDRCONF_STATE_GRANTED;
	lease->type = NI_ADDRCONF_DHCP;
	lease->time_acquired = time(NULL);

	if (ni_dhcp6_client_parse_options(dev, msgbuf, lease) < 0) {
		ni_error("%s: unable to parse options in %s message xid 0x%06x",
			dev->ifname, ni_dhcp6_message_name(*msg_type), *msg_xid);
		goto failure;
	}

	if (lease->dhcp6.client_id.len == 0) {
		ni_error("%s: ignoring %s message xid 0x%06x: client-id missed",
			dev->ifname, ni_dhcp6_message_name(*msg_type), *msg_xid);
		goto failure;
	}
	if (lease->dhcp6.server_id.len == 0) {
		ni_error("%s: ignoring %s message xid 0x%06x: server-id missed",
			dev->ifname, ni_dhcp6_message_name(*msg_type), *msg_xid);
		goto failure;
	}
	if (!ni_opaque_eq(&dev->config->client_duid, &lease->dhcp6.client_id)) {
			ni_error("%s: ignoring %s message xid 0x%06x: client-id differs",
			dev->ifname, ni_dhcp6_message_name(*msg_type), *msg_xid);
		goto failure;
	}

	*msg_lease = lease;
	lease = NULL;
	return 0;

failure:
	ni_addrconf_dhcp6_lease_free(lease);
	return -1;
}

void
ni_addrconf_dhcp6_lease_free(ni_addrconf_lease_t *lease)
{
	if (lease) {
		ni_dhcp6_status_free(lease->dhcp6.status);
		lease->dhcp6.status = NULL;
		ni_dhcp6_ia_list_destroy(&lease->dhcp6.ia_na);
		ni_dhcp6_ia_list_destroy(&lease->dhcp6.ia_ta);
		ni_dhcp6_ia_list_destroy(&lease->dhcp6.ia_pd);
		ni_addrconf_lease_free(lease);
	}
}

/*
 * Map DHCP6 options to names
 */
static const char *__dhcp6_option_names[__NI_DHCP6_OPTION_MAX] = {
	[NI_DHCP6_OPTION_CLIENTID]          =	"client-id",
	[NI_DHCP6_OPTION_SERVERID]          =	"server-id",
	[NI_DHCP6_OPTION_IA_NA]             =	"ia-na",
	[NI_DHCP6_OPTION_IA_TA]             =	"ia-ta",
	[NI_DHCP6_OPTION_IAADDR]            =	"ia-addr",
	[NI_DHCP6_OPTION_ORO]               =	"oro",
	[NI_DHCP6_OPTION_PREFERENCE]        =	"preference",
	[NI_DHCP6_OPTION_ELAPSED_TIME]      =	"elapsed-time",
	[NI_DHCP6_OPTION_RELAY_MSG]         =	"relay-msg",
	[NI_DHCP6_OPTION_AUTH]              =	"auth",
	[NI_DHCP6_OPTION_UNICAST]           =	"unicast",
	[NI_DHCP6_OPTION_STATUS_CODE]       =	"status-code",
	[NI_DHCP6_OPTION_RAPID_COMMIT]      =	"rapid-commit",
	[NI_DHCP6_OPTION_USER_CLASS]        =	"user-class",
	[NI_DHCP6_OPTION_VENDOR_CLASS]      =	"vendor-class",
	[NI_DHCP6_OPTION_VENDOR_OPTS]       =	"vendor-opts",
	[NI_DHCP6_OPTION_INTERFACE_ID]      =	"interface-id",
	[NI_DHCP6_OPTION_RECONF_MSG]        =	"reconf-msg",
	[NI_DHCP6_OPTION_RECONF_ACCEPT]     =	"reconf-accept",
	[NI_DHCP6_OPTION_SIP_SERVER_D]      =	"sip-server-names",
	[NI_DHCP6_OPTION_SIP_SERVER_A]      =	"sip-server-addresses",
	[NI_DHCP6_OPTION_DNS_SERVERS]       =	"dns-servers",
	[NI_DHCP6_OPTION_DNS_DOMAINS]       =	"dns-domains",
	[NI_DHCP6_OPTION_IA_PD]             =	"ia-pd",
	[NI_DHCP6_OPTION_IA_PREFIX]         =	"ia-prefix",
	[NI_DHCP6_OPTION_NIS_SERVERS]       =	"nis-servers",
	[NI_DHCP6_OPTION_NISP_SERVERS]      =	"nisplus-servers",
	[NI_DHCP6_OPTION_NIS_DOMAIN_NAME]   =	"nis-domain",
	[NI_DHCP6_OPTION_NISP_DOMAIN_NAME]  =	"nisplus-domain",
	[NI_DHCP6_OPTION_SNTP_SERVERS]      =	"sntp-servers",
	[NI_DHCP6_OPTION_INFO_REFRESH_TIME] =	"info-refresh-time",
	[NI_DHCP6_OPTION_BCMCS_SERVER_D]    =	"bcms-domains",
	[NI_DHCP6_OPTION_BCMCS_SERVER_A]    =	"bcms-servers",
	[NI_DHCP6_OPTION_GEOCONF_CIVIC]     =	"geoconf-civic",
	[NI_DHCP6_OPTION_REMOTE_ID]         =	"remote-id",
	[NI_DHCP6_OPTION_SUBSCRIBER_ID]     =	"subscriber-id",
	[NI_DHCP6_OPTION_FQDN]              =	"fqdn",
	[NI_DHCP6_OPTION_PANA_AGENT]        =	"pana-agent",
	[NI_DHCP6_OPTION_POSIX_TIMEZONE]    =	"posix-timezone",
	[NI_DHCP6_OPTION_POSIX_TIMEZONEDB]  =	"posix-timezonedb",
	[NI_DHCP6_OPTION_ERO]               =	"ero",
	[NI_DHCP6_OPTION_LQ_QUERY]          =	"lq-query",
	[NI_DHCP6_OPTION_CLIENT_DATA]       =	"client-data",
	[NI_DHCP6_OPTION_CLT_TIME]          =	"clt-time",
	[NI_DHCP6_OPTION_LQ_RELAY_DATA]     =	"lq-relay-data",
	[NI_DHCP6_OPTION_LQ_CLIENT_LINK]    =	"lq-cient-link",
	[NI_DHCP6_OPTION_MIP6_HNINF]        =	"mip6-hninf",
	[NI_DHCP6_OPTION_MIP6_RELAY]        =	"mip6-relay",
	[NI_DHCP6_OPTION_V6_LOST]           =	"v6-lost",
	[NI_DHCP6_OPTION_CAPWAP_AC_V6]      =	"capwap-ac-v6",
	[NI_DHCP6_OPTION_RELAY_ID]          =	"relay-id",
	[NI_DHCP6_OPTION_MOS_ADDRESSES]     =	"mos-addresses",
	[NI_DHCP6_OPTION_MOS_DOMAINS]       =	"mos-domains",
	[NI_DHCP6_OPTION_NTP_SERVER]        =	"ntp-server",
	[NI_DHCP6_OPTION_V6_ACCESS_DOMAIN]  =	"v6-access-domain",
	[NI_DHCP6_OPTION_SIP_UA_CS_LIST]    =	"sip-ua-cs-list",
	[NI_DHCP6_OPTION_BOOTFILE_URL]      =	"bootfile-url",
	[NI_DHCP6_OPTION_BOOTFILE_PARAM]    =	"bootfile-param",
	[NI_DHCP6_OPTION_CLIENT_ARCH_TYPE]  =	"client-arch-type",
	[NI_DHCP6_OPTION_NII]               =	"nii",
	[NI_DHCP6_OPTION_GEOLOCATION]       =	"geolocation",
	[NI_DHCP6_OPTION_AFTR_NAME]         =	"aftr-name",
	[NI_DHCP6_OPTION_ERP_LOCAL_DOMAIN]  =	"erp-local-domain",
	[NI_DHCP6_OPTION_RSOO]              =	"rsoo",
	[NI_DHCP6_OPTION_PD_EXCLUDE]        =	"pd-exclude",
	[NI_DHCP6_OPTION_VSS]               =	"vss",
};

const char *
ni_dhcp6_option_name(unsigned int option)
{
	static char namebuf[64];
	const char *name = NULL;

	if (option < __NI_DHCP6_OPTION_MAX)
		name = __dhcp6_option_names[option];

	if (!name) {
		snprintf(namebuf, sizeof(namebuf), "[%u]", option);
		name = namebuf;
	}
	return name;
}

const char *
ni_dhcp6_ia_type_name(unsigned int ia_type)
{
	switch (ia_type) {
	case NI_DHCP6_IA_NA_TYPE:
		return ni_dhcp6_option_name(NI_DHCP6_OPTION_IA_NA);
	case NI_DHCP6_IA_TA_TYPE:
		return ni_dhcp6_option_name(NI_DHCP6_OPTION_IA_TA);
	case NI_DHCP6_IA_PD_TYPE:
		return ni_dhcp6_option_name(NI_DHCP6_OPTION_IA_PD);
	default:
		break;
	}
	return NULL;
}

static const char *	__dhcp6_message_names[__NI_DHCP6_MSG_TYPE_MAX] = {
	[NI_DHCP6_SOLICIT] =		"SOLICIT",
	[NI_DHCP6_ADVERTISE] =		"ADVERTISE",
	[NI_DHCP6_REQUEST] =		"REQUEST",
	[NI_DHCP6_CONFIRM] =		"CONFIRM",
	[NI_DHCP6_RENEW] =		"RENEW",
	[NI_DHCP6_REBIND] =		"REBIND",
	[NI_DHCP6_REPLY] =		"REPLY",
	[NI_DHCP6_RELEASE] =		"RELEASE",
	[NI_DHCP6_DECLINE] =		"DECLINE",
	[NI_DHCP6_RECONFIGURE] =	"RECONFIGURE",
	[NI_DHCP6_INFO_REQUEST] =	"INFO-REQUEST",
	[NI_DHCP6_RELAY_FORWARD] =	"RELAY-FORWARD",
	[NI_DHCP6_RELAY_REPLY] =	"RELAY-REPLY",
	[NI_DHCP6_LEASEQUERY] =		"LEASEQUERY",
	[NI_DHCP6_LEASEQUERY_REPLY] =	"LEASEQUERY-REPLY",
	[NI_DHCP6_LEASEQUERY_DONE] =	"LEASEQUERY-DONE",
	[NI_DHCP6_LEASEQUERY_DATA] = 	"LEASEQUERY-DATA",
};

const char *
ni_dhcp6_message_name(unsigned int type)
{
	static char namebuf[64];
	const char *name = NULL;

	if (type < __NI_DHCP6_MSG_TYPE_MAX)
		name = __dhcp6_message_names[type];

	if (!name) {
		snprintf(namebuf, sizeof(namebuf), "[%u]", type);
		name = namebuf;
	}
	return name;
}

static const char *	__dhcp6_status_codes[__NI_DHCP6_STATUS_MAX] = {
	[NI_DHCP6_STATUS_SUCCESS]	= "Success",
	[NI_DHCP6_STATUS_FAILURE]	= "UnspecFail",
	[NI_DHCP6_STATUS_NOADDRS]	= "NoAddrsAvail",
	[NI_DHCP6_STATUS_NOBINDING]	= "NoBinding",
	[NI_DHCP6_STATUS_NOTONLINK]	= "NotOnLink",
	[NI_DHCP6_STATUS_USEMULTICAST]	= "UseMulticast",
};

const char *
ni_dhcp6_status_name(unsigned int code)
{
	static char namebuf[64];
	const char *name = NULL;

	if (code < __NI_DHCP6_STATUS_MAX)
		name = __dhcp6_status_codes[code];

	if (!name) {
		snprintf(namebuf, sizeof(namebuf), "[%u]", code);
		name = namebuf;
	}
	return name;
}


/*
 * ni_timeout_t settings we're using in the timing table
 */
#define NI_DHCP6_EXP_BACKOFF	     -1 /* exponential increment type  */
#define NI_DHCP6_UNLIMITED	     -1 /* unlimited number of retries */

typedef struct ni_dhcp6_timing {
	unsigned int		delay;
	unsigned int		jitter;
	ni_timeout_param_t	params;
	unsigned int		duration;
} ni_dhcp6_timing_t;

static const ni_dhcp6_timing_t __dhcp6_msg_timings[__NI_DHCP6_MSG_TYPE_MAX] = {
	[NI_DHCP6_SOLICIT] = {
		.delay			= NI_DHCP6_SOL_MAX_DELAY,
		.jitter			= NI_DHCP6_MAX_JITTER,
		.params = {
			.increment	= NI_DHCP6_EXP_BACKOFF,
			.nretries	= NI_DHCP6_UNLIMITED,
			.timeout	= NI_DHCP6_SOL_TIMEOUT,
			.max_timeout	= NI_DHCP6_SOL_MAX_RT,
		},
	},
	[NI_DHCP6_REQUEST] = {
		.jitter			= NI_DHCP6_MAX_JITTER,
		.params = {
			.increment	= NI_DHCP6_EXP_BACKOFF,
			.nretries	= NI_DHCP6_REQ_MAX_RC,
			.timeout	= NI_DHCP6_REQ_TIMEOUT,
			.max_timeout	= NI_DHCP6_REQ_MAX_RT,
		},
	},
	[NI_DHCP6_CONFIRM] = {
		.delay			= NI_DHCP6_CNF_MAX_DELAY,
		.jitter			= NI_DHCP6_MAX_JITTER,
		.params = {
			.increment	= NI_DHCP6_EXP_BACKOFF,
			.nretries	= NI_DHCP6_UNLIMITED,
			.timeout	= NI_DHCP6_CNF_TIMEOUT,
			.max_timeout	= NI_DHCP6_CNF_MAX_RT,
		},
		.duration		= NI_DHCP6_CNF_MAX_RD,
	},
	[NI_DHCP6_RENEW] = {
		.jitter			= NI_DHCP6_MAX_JITTER,
		.params = {
			.increment	= NI_DHCP6_EXP_BACKOFF,
			.nretries	= NI_DHCP6_UNLIMITED,
			.timeout	= NI_DHCP6_REN_TIMEOUT,
			.max_timeout	= NI_DHCP6_REN_MAX_RT,
		},
	},
	[NI_DHCP6_REBIND] = {
		.jitter			= NI_DHCP6_MAX_JITTER,
		.params = {
			.increment	= NI_DHCP6_EXP_BACKOFF,
			.nretries	= NI_DHCP6_UNLIMITED,
			.timeout	= NI_DHCP6_REB_TIMEOUT,
			.max_timeout	= NI_DHCP6_REB_MAX_RT,
		},
	},
	[NI_DHCP6_RELEASE] = {
		.jitter			= NI_DHCP6_MAX_JITTER,
		.params = {
			.nretries	= NI_DHCP6_REL_MAX_RC,
			.timeout	= NI_DHCP6_REL_TIMEOUT,
			.max_timeout	= NI_DHCP6_UNLIMITED,
		},
	},
	[NI_DHCP6_DECLINE] = {
		.jitter			= NI_DHCP6_MAX_JITTER,
		.params = {
			.increment	= NI_DHCP6_EXP_BACKOFF,
			.nretries	= NI_DHCP6_DEC_MAX_RC,
			.timeout	= NI_DHCP6_DEC_TIMEOUT,
			.max_timeout	= NI_DHCP6_UNLIMITED,
		},
	},
	[NI_DHCP6_INFO_REQUEST] = {
		.delay			= NI_DHCP6_INF_MAX_DELAY,
		.jitter			= NI_DHCP6_MAX_JITTER,
		.params = {
			.increment	= NI_DHCP6_EXP_BACKOFF,
			.nretries	= NI_DHCP6_UNLIMITED,
			.timeout	= NI_DHCP6_INF_TIMEOUT,
			.max_timeout	= NI_DHCP6_INF_MAX_RT,
		},
	},
};

static inline int
__ni_dhcp6_jitter_rebase(unsigned int msec, int jitter)
{
	if (jitter < 0) {
		return 0 - ((msec * (0 - jitter)) / 1000);
	} else {
		return 0 + ((msec * (0 + jitter)) / 1000);
	}
}

ni_int_range_t
ni_dhcp6_jitter_rebase(unsigned int msec, int lower, int upper)
{
	ni_int_range_t jitter;
	jitter.min = __ni_dhcp6_jitter_rebase(msec, lower);
	jitter.max = __ni_dhcp6_jitter_rebase(msec, upper);
	return jitter;
}

ni_bool_t
ni_dhcp6_set_message_timing(ni_dhcp6_device_t *dev, unsigned int msg_type)
{
	memset(&dev->retrans, 0, sizeof(dev->retrans));

	if (msg_type < __NI_DHCP6_MSG_TYPE_MAX) {

		/* Each message has a timeout */
		if (!__dhcp6_msg_timings[msg_type].params.timeout)
			return FALSE;

		dev->retrans.delay    = __dhcp6_msg_timings[msg_type].delay;
		dev->retrans.jitter   = __dhcp6_msg_timings[msg_type].jitter;
		dev->retrans.params   = __dhcp6_msg_timings[msg_type].params;
		dev->retrans.duration = __dhcp6_msg_timings[msg_type].duration;

#if 0
		/*
		 * Note: MRD of 0 means unlimited in RFC, nretries 0 means no retries
		 *	 (one transmit attempt only) and nretries < 0 means unlimited.
		 */
		ni_trace("%s TIMING: IDT(%us), IRT(%us), MRT(%us), MRC(%u), MRD(%us), RND(%.3fs)\n",
			ni_dhcp6_message_name(msg_type),
			dev->retrans.delay/1000,
			dev->retrans.params.timeout/1000,
			dev->retrans.params.max_timeout/1000,
			(dev->retrans.params.nretries < 0 ? 0 : dev->retrans.params.nretries),
			dev->retrans.duration/1000,
			(double)dev->retrans.jitter/1000);
#endif
		return TRUE;
	}
	return FALSE;
}
