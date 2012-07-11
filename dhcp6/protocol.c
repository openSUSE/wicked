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


/*
 * IPV6_RECVPKTINFO is defined in rfc3542, that
 * obsoletes rfcC2292 that defines IPV6_PKTINFO.
 */
#if !defined(IPV6_RECVPKTINFO)
#define IPV6_RECVPKTINFO IPV6_PKTINFO
#endif

extern int	ni_dhcp6_device_retransmit(ni_dhcp6_device_t *dev);

static void	ni_dhcp6_socket_recv		(ni_socket_t *);
static int	ni_dhcp6_process_packet		(ni_dhcp6_device_t *dev, ni_buffer_t *msgbuf,
						 const struct in6_addr *sender);
extern int	ni_dhcp6_process_client_packet	(ni_dhcp6_device_t *dev, ni_buffer_t *msgbuf,
						 const struct in6_addr *sender);

static int	ni_dhcp6_socket_get_timeout	(const ni_socket_t *sock, struct timeval *tv);
static void	ni_dhcp6_socket_check_timeout	(ni_socket_t *sock, const struct timeval *now);

static int	ni_dhcp6_option_next(ni_buffer_t *options, ni_buffer_t *optbuf);
static int	ni_dhcp6_option_get_duid(ni_buffer_t *bp, ni_duid_t *duid);

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
	 * FIXME: Error handling in case link-layer address is missed, ....
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
	 * Unicasts only after receiving the Server Unicast option from server.
	 */
	if (!dev->link.ifindex) {
		ni_error("interface index not set");
		return -1;
	}
	if (!IN6_IS_ADDR_LINKLOCAL(&dev->client_addr.six.sin6_addr)) {
		ni_error("link layer address not (yet) available");
		return -1;
	}
	ni_trace("link local address is %s", ni_address_print(&dev->client_addr));

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


	memset(&saddr, 0, sizeof(saddr));
	saddr.six.sin6_family = AF_INET6;
	saddr.six.sin6_port = htons(NI_DHCP6_CLIENT_PORT);
	saddr.six.sin6_scope_id = dev->link.ifindex;
	/*
	 * Hmm... when we bind to the link local address, we're unable to
	 * send unicast (direct) messages to the sender any more ...
	 * So we bind to port+scope and set IPV6_MULTICAST_IF ???
	 *
	 */
	memcpy(&saddr.six.sin6_addr, &dev->client_addr.six.sin6_addr, sizeof(saddr.six.sin6_addr));

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

	ni_debug_dhcp("Bound DHCPv6 socket to [%s]:%u on %s[%u]",
		ni_address_print(&saddr), NI_DHCP6_CLIENT_PORT,
		dev->ifname, dev->link.ifindex);

	return fd;
}

/*
 * Open a DHCP6 socket for send and receive
 */
int
ni_dhcp6_socket_open(ni_dhcp6_device_t *dev)
{
	int fd;

	if (!(fd = __ni_dhcp6_socket_open(dev)))
		return -1;

	dev->sock = ni_socket_wrap(fd, SOCK_DGRAM);
	dev->sock->user_data = ni_dhcp6_device_get(dev);
	dev->sock->receive = ni_dhcp6_socket_recv;
	dev->sock->get_timeout = ni_dhcp6_socket_get_timeout;
	dev->sock->check_timeout = ni_dhcp6_socket_check_timeout;

	ni_buffer_init_dynamic(&dev->sock->rbuf, NI_DHCP6_RBUF_SIZE);

	ni_socket_activate(dev->sock);
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
	char abuf[INET6_ADDRSTRLEN] = { '\0' };
	char ibuf[IF_NAMESIZE] = { '\0' };
	struct in6_pktinfo *pinfo = NULL;
	struct cmsghdr *cm;
	ssize_t bytes;

	memset(&saddr, 0, sizeof(saddr));
	memset(&cbuf, 0, sizeof(cbuf));

	bytes = recvmsg(sock->__fd, &msg, 0);
	if(bytes < 0) {
		if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
			ni_error("recvmsg error on %s socket %d: %m",
				dev->ifname, sock->__fd);
			ni_socket_deactivate(sock);
		}
		return;
	}
	else if (bytes == 0) {
		ni_error("recvmsg didn't returned any data on %s socket %d",
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
		ni_error("DHCPv6 failed to get packet info on %s socket %d",
			 dev->ifname, sock->__fd);
		return;
	}

	ni_buffer_push_tail(rbuf, bytes);

	ni_trace("received %zd byte packet from %s%%%s: %s",
		bytes,
		inet_ntop(AF_INET6, &pinfo->ipi6_addr, abuf, sizeof(abuf)),
		if_indextoname(pinfo->ipi6_ifindex, ibuf),
		__ni_dhcp6_hexdump(&hexbuf, rbuf));
	ni_stringbuf_destroy(&hexbuf);

	if(dev->link.ifindex != pinfo->ipi6_ifindex) {
		ni_error("received packet with interface index %u instead of %u",
			pinfo->ipi6_ifindex, dev->link.ifindex);
		return;
	}

	ni_dhcp6_process_packet(dev, rbuf, &pinfo->ipi6_addr);
}

static int
ni_dhcp6_process_packet(ni_dhcp6_device_t *dev, ni_buffer_t *msgbuf, const struct in6_addr *sender)
{
	ni_dhcp6_packet_header_t *header;
	int rv = -1;

	/* sanity check: verify we have at least the message type byte */
	if (!ni_buffer_count(msgbuf)) {
		ni_error("discarding empty DHCPv6 message packet");
		return rv;
	}

	/*
	 * peek only
	 */
	header = ni_buffer_head(msgbuf);
	switch(header->type) {
		/* handle client response msgs */
		case NI_DHCP6_ADVERTISE:
		case NI_DHCP6_REPLY:
		case NI_DHCP6_RECONFIGURE:
			rv = ni_dhcp6_fsm_process_client_packet(dev, msgbuf, sender);
		break;

		/* and discard any any other */
		default:
			ni_trace("discarding unexpected %s message packet",
				ni_dhcp6_message_name(header->type));
		break;
	}
	return rv;
}

long
ni_dhcp6_timeout_jitter(unsigned int neg, unsigned int pos)
{
        long ret = 0;

        if (pos > 0) {
       		ret += (random() % (neg + pos)) - neg;
        } else if (neg > 0) {
        	ret -= (random() % (neg));
        }

        return ret;
}

unsigned long
ni_dhcp6_timeout_arm_msec(struct timeval *deadline, unsigned long timeout, unsigned int jitter_neg, unsigned int jitter_pos)
{
	long jitter = 0;

	if(timeout > jitter_neg && timeout > jitter_pos)
		jitter = ni_dhcp6_timeout_jitter(jitter_neg, jitter_pos);

	timeout += jitter;

	ni_trace("arming retransmit timer (timeout %lu msec [± %ld])", timeout, jitter);

	/* TODO: use monotonic clock? -> adopt src/timers.c */
	gettimeofday(deadline, NULL);
	deadline->tv_sec += timeout / 1000;
	deadline->tv_usec += (timeout % 1000) * 1000;
	if (deadline->tv_usec < 0) {
		deadline->tv_sec -= 1;
		deadline->tv_usec += 1000000;
	} else
	if (deadline->tv_usec > 1000000) {
		deadline->tv_sec += 1;
		deadline->tv_usec -= 1000000;
        }
	return timeout;
}

static int
ni_dhcp6_socket_get_timeout(const ni_socket_t *sock, struct timeval *tv)
{
	ni_dhcp6_device_t * dev = sock->user_data;
	if( !(dev = sock->user_data)) {
		ni_error("check_timeout: socket without capture object?!");
		return -1;
	}

	ni_trace("get timeout: deadline: %ld.%ld",
		dev->retrans.deadline.tv_sec,dev->retrans.deadline.tv_usec);

	timerclear(tv);
	if (timerisset(&dev->retrans.deadline)) {
		*tv = dev->retrans.deadline;
		ni_trace("%s: get socket timeout for socket [fd=%d]: %ld sec + %ld usec",
				dev->ifname, sock->__fd, tv->tv_sec, tv->tv_usec);
#if 1
	} else {
		ni_trace("%s: get socket timeout for socket [fd=%d]: none",
				dev->ifname, sock->__fd);
#endif
	}
	return timerisset(tv) ? 0 : -1;
}

static void
ni_dhcp6_socket_check_timeout(ni_socket_t *sock, const struct timeval *now)
{
	ni_dhcp6_device_t * dev;

	if (!(dev = sock->user_data)) {
		ni_error("check_timeout: socket without device object?!");
		return;
	}

	ni_trace("check timeout: deadline: %ld.%ld",
		dev->retrans.deadline.tv_sec,dev->retrans.deadline.tv_usec);

	if (timerisset(&dev->retrans.deadline) && timercmp(&dev->retrans.deadline, now, <)) {
		ni_trace("%s: check socket timeout for socket [fd=%d]: %ld sec + %ld usec",
				dev->ifname, sock->__fd,
				dev->retrans.deadline.tv_sec, dev->retrans.deadline.tv_usec);

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
	ni_buffer_ensure_tailroom(bp, sizeof(opt) + len);
	if(ni_buffer_put(bp, &opt, sizeof(opt)) < 0)
		return -1;
	if(ni_buffer_put(bp, data, len) < 0)
		return -1;
	return 0;
}

#if 0
static inline void
ni_dhcp6_option_put_empty(ni_buffer_t *bp, int code)
{
	ni_dhcp6_option_put(bp, code, NULL, 0);
}

static inline void
ni_dhcp6_option_put8(ni_buffer_t *bp, int code, uint8_t value)
{
	ni_dhcp6_option_put(bp, code, &value, 1);
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
ni_dhcp6_option_get_duid(ni_buffer_t *bp, ni_duid_t *duid)
{
	size_t len = ni_buffer_count(bp);

	if(len < sizeof(uint16_t)) {
		bp->underflow = 1;
	} else if (len > sizeof(duid->data)) {
		bp->overflow = 1;
	} else if(duid) {
		ni_duid_clear(duid);
		duid->len = len;
		return ni_buffer_get(bp, &duid->data, len);
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
ni_dhcp6_option_get_status(ni_buffer_t *bp, uint16_t *code, char **message)
{
	if (ni_dhcp6_option_get16(bp, code) < 0)
		return -1;
	if (ni_dhcp6_option_gets(bp, message) < 0)
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
ni_dhcp6_build_info_request_message(const ni_dhcp6_device_t *dev, ni_buffer_t *bp)
{
	uint16_t elapsed_time = 0;
	uint16_t request_opts[] = {
		htons(NI_DHCP6_OPTION_PREFERENCE),
		htons(NI_DHCP6_OPTION_ELAPSED_TIME),
		htons(NI_DHCP6_OPTION_UNICAST),
		htons(NI_DHCP6_OPTION_STATUS_CODE),
		htons(NI_DHCP6_OPTION_RAPID_COMMIT),
		htons(NI_DHCP6_OPTION_DNS_SERVERS),
		htons(NI_DHCP6_OPTION_DNS_DOMAINS),
	};

	if (ni_dhcp6_build_client_header(bp, NI_DHCP6_INFO_REQUEST, dev->dhcp6.xid) < 0)
		return -1;

	if (ni_dhcp6_option_put(bp, NI_DHCP6_OPTION_CLIENTID,
			&dev->config->client_duid.data, dev->config->client_duid.len) < 0)
		return -1;

#if 0
	if (dev->server_duid.len) {
		if(ni_dhcp6_option_put(bp, NI_DHCP6_OPTION_SERVERID,
			&dev->server_duid.data, dev->server_duid.len) < 0)
		return -1;
	}
#endif

	elapsed_time = ni_dhcp6_device_uptime(dev, 0xffff);
	if (ni_dhcp6_option_put16(bp, NI_DHCP6_OPTION_ELAPSED_TIME, elapsed_time) < 0)
		return -1;

	if (ni_dhcp6_option_put(bp, NI_DHCP6_OPTION_ORO, &request_opts, sizeof(request_opts)) < 0)
		return -1;

	return 0;
}

static int
ni_dhcp6_build_solicit_message(const ni_dhcp6_device_t *dev, ni_buffer_t *bp)
{
	uint16_t elapsed_time = 0;
	uint16_t request_opts[] = {
		htons(NI_DHCP6_OPTION_PREFERENCE),
		htons(NI_DHCP6_OPTION_ELAPSED_TIME),
		//htons(NI_DHCP6_OPTION_UNICAST),
		//htons(NI_DHCP6_OPTION_STATUS_CODE),
		//htons(NI_DHCP6_OPTION_RAPID_COMMIT),
		htons(NI_DHCP6_OPTION_DNS_SERVERS),
		htons(NI_DHCP6_OPTION_DNS_DOMAINS),
		htons(NI_DHCP6_OPTION_SIP_SERVER_D),
		htons(NI_DHCP6_OPTION_SIP_SERVER_A),
	};
	struct iaid_info {
		uint32_t iaid;
		uint32_t renew;
		uint32_t rebind;
	} ia;
	if (ni_dhcp6_build_client_header(bp, NI_DHCP6_SOLICIT, dev->dhcp6.xid) < 0)
		return -1;

	if (ni_dhcp6_option_put(bp, NI_DHCP6_OPTION_CLIENTID,
			&dev->config->client_duid.data, dev->config->client_duid.len) < 0)
		return -1;

	elapsed_time = ni_dhcp6_device_uptime(dev, 0xffff);
	if (ni_dhcp6_option_put16(bp, NI_DHCP6_OPTION_ELAPSED_TIME, elapsed_time) < 0)
		return -1;

	if (ni_dhcp6_option_put(bp, NI_DHCP6_OPTION_ORO, &request_opts, sizeof(request_opts)) < 0)
		return -1;

/*
	if (ni_dhcp6_option_put(bp, NI_DHCP6_OPTION_IA_NA, 0, sizeof()) < 0)
		return -1;
*/
	if (ni_dhcp6_device_iaid(dev, &ia.iaid) < 0)
		return -1;

	ia.iaid = htonl(ia.iaid);
	if (dev->config->lease_time && dev->config->lease_time != ~0)
		ia.renew = htonl(dev->config->lease_time / 2);
	else
		ia.renew = htonl(3600);
	ia.rebind = htonl(ia.renew + (ia.renew / 2));
	if (ni_dhcp6_option_put(bp, NI_DHCP6_OPTION_IA_NA, &ia, sizeof(ia)) < 0)
		return -1;

	return 0;
}

int
ni_dhcp6_build_message(const ni_dhcp6_device_t *dev,
			unsigned int msg_code,
			const ni_addrconf_lease_t *lease,
			ni_buffer_t *msgbuf)
{
	(void)dev;
	(void)msg_code;
	(void)lease;
	(void)msgbuf;

	switch(msg_code) {
		case NI_DHCP6_INFO_REQUEST:
			if(ni_dhcp6_build_info_request_message(dev, msgbuf) < 0)
				return -1;
		break;
		case NI_DHCP6_SOLICIT:
			if(ni_dhcp6_build_solicit_message(dev, msgbuf) < 0)
				return -1;
		break;
		default:
			return -1;
		break;
	}
	ni_trace("built dhcp6 packet: %s", ni_print_hex(msgbuf->base, ni_buffer_count(msgbuf)));

	return 0;
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

static int
ni_dhcp6_option_parse_ia_address(ni_buffer_t *bp, struct ni_dhcp6_ia *ia, uint16_t addr_type)
{
	const char *ia_type = ni_dhcp6_option_name(ia->type);
	const char *ap_type = ni_dhcp6_option_name(addr_type);
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

		ni_trace("%s.%s: %s/%u, pref-life: %u, valid_life: %u",
			ia_type, ap_type, ni_address_print(&addr), ap->plen,
			ap->preferred_lft, ap->valid_lft);
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

		ni_trace("%s.%s: %s, pref-life: %u, valid_life: %u",
			ia_type, ap_type, ni_address_print(&addr),
			ap->preferred_lft, ap->valid_lft);
	}

	while( ni_buffer_count(bp) && !bp->underflow) {
		ni_stringbuf_t	hexbuf = NI_STRINGBUF_INIT_DYNAMIC;
		ni_buffer_t	optbuf;
		int		option;

		option = ni_dhcp6_option_next(bp, &optbuf);
		if (option < 0)
			goto failure;

		if (option == 0)
			break;

		__ni_dhcp6_hexdump(&hexbuf, &optbuf);
		ni_trace("ia-addr option %s: %s", ni_dhcp6_option_name(option), hexbuf.string);
		ni_stringbuf_destroy(&hexbuf);

		switch (option) {
		case NI_DHCP6_OPTION_STATUS_CODE:
			ni_dhcp6_option_get_status(&optbuf, &ap->status.code, &ap->status.message);
		break;

		default:
			ni_trace("ia-addr option %s: ignored", ni_dhcp6_option_name(option));
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
	const char *type = ni_dhcp6_option_name(ia->type);

	while( ni_buffer_count(bp) && !bp->underflow) {
		ni_stringbuf_t	hexbuf = NI_STRINGBUF_INIT_DYNAMIC;
		ni_buffer_t	optbuf;
		int		option;

		option = ni_dhcp6_option_next(bp, &optbuf);
		if (option < 0)
			goto failure;

		if (option == 0)
			break;

		__ni_dhcp6_hexdump(&hexbuf, &optbuf);
		ni_trace("%s option %s data: %s", type, ni_dhcp6_option_name(option), hexbuf.string);
		ni_stringbuf_destroy(&hexbuf);

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
			if (ni_dhcp6_option_get_status(&optbuf, &ia->status.code,
								&ia->status.message) < 0)
				goto failure;
		break;

		default:
			ni_trace("%s option %s: ignored", type, ni_dhcp6_option_name(option));
		break;
		}

		if (optbuf.underflow) {
			ni_trace("%s option %s: %u byte of data is too short", type,
				ni_dhcp6_option_name(option), ni_buffer_count(&optbuf));
		} else if(ni_buffer_count(&optbuf)) {
			ni_trace("%s option %s: is too long - %u bytes left", type,
				ni_dhcp6_option_name(option), ni_buffer_count(&optbuf));
		}
	}

	return 0;

failure:
	return -1;
}

static int
ni_dhcp6_client_parse_ia(ni_buffer_t *bp,  struct ni_dhcp6_ia **ia_na_list, uint16_t iatype)
{
	struct ni_dhcp6_ia *ia;

	if ((ia = calloc(1, sizeof(*ia))) == NULL)
		goto failure;

	ia->type = iatype;
	if (iatype != NI_DHCP6_IA_TA_TYPE) {
		if (ni_dhcp6_option_get32(bp, &ia->iaid) < 0)
			goto failure;
		if (ni_dhcp6_option_get32(bp, &ia->renewal_time) < 0)
			goto failure;
		if (ni_dhcp6_option_get32(bp, &ia->rebind_time) < 0)
			goto failure;
	} else {
		if (ni_dhcp6_option_get32(bp, &ia->iaid) < 0)
			goto failure;
	}

	ni_trace("%s: iaid=%u, renew=%u, rebind=%u",
		ni_dhcp6_option_name(iatype),
		ia->iaid, ia->renewal_time, ia->rebind_time);

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
	struct timeval elapsed;

	while( ni_buffer_count(buffer) && !buffer->underflow) {
		ni_stringbuf_t	hexbuf = NI_STRINGBUF_INIT_DYNAMIC;
		ni_buffer_t	optbuf;
		int		option;
		unsigned int    i;

		memset(&optbuf, 0, sizeof(optbuf));
		option = ni_dhcp6_option_next(buffer, &optbuf);
		if (option < 0)
			goto failure;

		if (option == 0)
			break;

		__ni_dhcp6_hexdump(&hexbuf, &optbuf);
		ni_trace("option %s data: %s", ni_dhcp6_option_name(option), hexbuf.string);
		ni_stringbuf_destroy(&hexbuf);

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
				ni_dhcp6_option_get_ipv6(&optbuf, &lease->dhcp6.server_unicast);
			break;
			case NI_DHCP6_OPTION_STATUS_CODE:
				ni_dhcp6_option_get_status(&optbuf, &lease->dhcp6.status.code,
								&lease->dhcp6.status.message);
			break;
			case NI_DHCP6_OPTION_ELAPSED_TIME:
				ni_dhcp6_option_get_elapsed_time(&optbuf, &elapsed);
			break;
			case NI_DHCP6_OPTION_RAPID_COMMIT:
				lease->dhcp6.rapid_commit = TRUE;
			break;

			case NI_DHCP6_OPTION_IA_NA:
				ni_dhcp6_client_parse_ia(&optbuf, &lease->dhcp6.ia_na, option);
			break;
			case NI_DHCP6_OPTION_IA_TA:
				ni_dhcp6_client_parse_ia(&optbuf, &lease->dhcp6.ia_ta, option);
			break;
			case NI_DHCP6_OPTION_IA_PD:
				ni_dhcp6_client_parse_ia(&optbuf, &lease->dhcp6.ia_pd, option);
			break;

			case NI_DHCP6_OPTION_DNS_SERVERS:
				if (lease->resolver == NULL)
					lease->resolver = ni_resolver_info_new();
				if (lease->resolver != NULL) {
					ni_dhcp6_decode_address_list(&optbuf, &lease->resolver->dns_servers);
					for (i = 0; i < lease->resolver->dns_servers.count; ++i)
						ni_trace("option %s[%u]: %s", ni_dhcp6_option_name(option), i,
							lease->resolver->dns_servers.data[i]);
				}
			break;

			case NI_DHCP6_OPTION_DNS_DOMAINS:
				if (lease->resolver == NULL)
					lease->resolver = ni_resolver_info_new();
				if (lease->resolver != NULL) {
					ni_dhcp6_decode_dnssearch(&optbuf, &lease->resolver->dns_search);
					for (i = 0; i < lease->resolver->dns_search.count; ++i)
						ni_trace("option %s[%u]: %s", ni_dhcp6_option_name(option), i,
							lease->resolver->dns_search.data[i]);
				}
			break;
			case NI_DHCP6_OPTION_SIP_SERVER_A:
				ni_dhcp6_decode_address_list(&optbuf, &lease->sip_servers);
				for (i = 0; i < lease->sip_servers.count; ++i)
					ni_trace("option %s[%u]: %s", ni_dhcp6_option_name(option), i,
							lease->sip_servers.data[i]);
			break;
			case NI_DHCP6_OPTION_SIP_SERVER_D:
				ni_dhcp6_decode_dnssearch(&optbuf, &lease->sip_servers);
				for (i = 0; i < lease->sip_servers.count; ++i)
					ni_trace("option %s[%u]: %s", ni_dhcp6_option_name(option), i,
							lease->sip_servers.data[i]);
			break;
			default:
				ni_trace("%s: option %s: not supported - ignoring",
					dev->ifname, ni_dhcp6_option_name(option));
				ni_buffer_clear(&optbuf);
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

	return 0;

failure:
	return -1;
}

int
ni_dhcp6_client_parse_response(ni_dhcp6_device_t *dev, ni_buffer_t *buffer,  const struct in6_addr *sender, ni_addrconf_lease_t **leasep)
{
	ni_dhcp6_client_header_t *	header;
	ni_addrconf_lease_t *		lease = NULL;
	int				msg_type = -1;
	unsigned int			msg_xid;

	header = ni_buffer_pull_head(buffer, sizeof(*header));
	if(!header) {
		ni_error("short DHCP6 packet (%u bytes)", ni_buffer_count(buffer));
		return -1;
	}

	msg_type = header->type;
	msg_xid  = ntohl(header->xid) & NI_DHCP6_XID_MASK;
#if 0
	if (dev->fsm.state == NI_DHCP6_STATE_INIT) {
		ni_error("%s: ignoring unexpected %s message xid 0x%06x in state %s",
			dev->ifname, ni_dhcp6_message_name(msg_type), msg_xid,
			ni_dhcp6_fsm_state_name(dev->fsm.state));
		return -1;
	}
#endif
	if (dev->dhcp6.xid == 0) {
		ni_error("%s: ignoring unexpected %s message xid 0x%06x",
			dev->ifname, ni_dhcp6_message_name(msg_type), msg_xid);
		goto failure;
	}
	if (dev->dhcp6.xid != msg_xid) {
		ni_error("%s: ignoring unexpected %s message xid 0x%06x (expecting 0x%06x)",
			dev->ifname, ni_dhcp6_message_name(msg_type), msg_xid, dev->dhcp6.xid);
		goto failure;
	}

	lease = ni_addrconf_lease_new(NI_ADDRCONF_DHCP, AF_INET6);
	lease->time_acquired = time(NULL);

	if (ni_dhcp6_client_parse_options(dev, buffer, lease) < 0) {
		ni_error("%s: unable to parse options in %s message xid 0x%06x",
			dev->ifname, ni_dhcp6_message_name(msg_type), msg_xid);
		goto failure;
	}

	if (lease->dhcp6.client_id.len == 0) {
		ni_error("%s: ignoring %s message xid 0x%06x: client-id missed",
			dev->ifname, ni_dhcp6_message_name(msg_type), msg_xid);
		goto failure;
	}
	if (lease->dhcp6.server_id.len == 0) {
		ni_error("%s: ignoring %s message xid 0x%06x: server-id missed",
			dev->ifname, ni_dhcp6_message_name(msg_type), msg_xid);
		goto failure;
	}
	if (!ni_duid_eq(&dev->config->client_duid, &lease->dhcp6.client_id)) {
		ni_error("%s: ignoring %s message xid 0x%06x: client-id differs",
			dev->ifname, ni_dhcp6_message_name(msg_type), msg_xid);
		goto failure;
	}

	*leasep = lease;
	lease = NULL;

cleanup:
	return msg_type;

failure:
	if (lease)
		ni_addrconf_lease_free(lease);
	msg_type = -1;
	goto cleanup;
	return msg_type;
}

/*
 * Map DHCP6 options to names
 */
static const char *__dhcp6_option_names[__NI_DHCP6_OPTION_END] = {
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
	[NI_DHCP6_OPTION_CLIENT_FQDN]       =	"client-fqdn",
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

	if (option < (sizeof(__dhcp6_option_names)/sizeof(__dhcp6_option_names[0])))
		name = __dhcp6_option_names[option];

	if (!name) {
		snprintf(namebuf, sizeof(namebuf), "[%u]", option);
		name = namebuf;
	}
	return name;
}

static const char *	__dhcp6_message_names[__NI_DHCP6_MSG_TYPE_END] = {
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

	if (type < (sizeof(__dhcp6_message_names)/sizeof(__dhcp6_message_names[0])))
		name = __dhcp6_message_names[type];

	if (!name) {
		snprintf(namebuf, sizeof(namebuf), "DHCP6_MSG[%u]", type);
		name = namebuf;
	}
	return name;
}

static const ni_dhcp6_timeout_param_t __dhcp6_message_timings[__NI_DHCP6_MSG_TYPE_END] = {
	[NI_DHCP6_SOLICIT] = {
		.delay		= NI_DHCP6_SOL_MAX_DELAY,
		.timeout	= NI_DHCP6_SOL_TIMEOUT,
		.pos_jitter	= TRUE,
		.max_jitter	= NI_DHCP6_MAX_JITTER,
		.max_timeout	= NI_DHCP6_SOL_MAX_RT,
	},
	[NI_DHCP6_REQUEST] = {
		.timeout	= NI_DHCP6_REQ_TIMEOUT,
		.max_jitter	= NI_DHCP6_MAX_JITTER,
		.max_timeout	= NI_DHCP6_REQ_MAX_RT,
		.max_retransmits= NI_DHCP6_REQ_MAX_RC,
	},
	[NI_DHCP6_CONFIRM] = {
		.delay		= NI_DHCP6_CNF_MAX_DELAY,
		.timeout	= NI_DHCP6_CNF_TIMEOUT,
		.max_jitter	= NI_DHCP6_MAX_JITTER,
		.max_timeout	= NI_DHCP6_CNF_MAX_RT,
		.max_duration	= NI_DHCP6_CNF_MAX_RD,
	},
	[NI_DHCP6_RENEW] = {
		.timeout	= NI_DHCP6_REN_TIMEOUT,
		.max_jitter	= NI_DHCP6_MAX_JITTER,
		.max_timeout	= NI_DHCP6_REN_MAX_RT,
	},
	[NI_DHCP6_REBIND] = {
		.timeout	= NI_DHCP6_REB_TIMEOUT,
		.max_jitter	= NI_DHCP6_MAX_JITTER,
		.max_timeout	= NI_DHCP6_REB_MAX_RT,
	},
	[NI_DHCP6_RELEASE] = {
		.timeout	= NI_DHCP6_REL_TIMEOUT,
		.max_jitter	= NI_DHCP6_MAX_JITTER,
		.max_retransmits= NI_DHCP6_REL_MAX_RC,
	},
	[NI_DHCP6_DECLINE] = {
		.timeout	= NI_DHCP6_DEC_TIMEOUT,
		.max_jitter	= NI_DHCP6_MAX_JITTER,
		.max_retransmits= NI_DHCP6_DEC_MAX_RC,
	},
	[NI_DHCP6_INFO_REQUEST] = {
		.delay		= NI_DHCP6_INF_MAX_DELAY,
		.timeout	= NI_DHCP6_INF_TIMEOUT,
		.max_jitter	= NI_DHCP6_MAX_JITTER,
		.max_timeout	= NI_DHCP6_INF_MAX_RT,
	},
};

ni_bool_t
ni_dhcp6_set_message_timing(unsigned int code, ni_dhcp6_timeout_param_t *timeout)
{
	memset(timeout, 0, sizeof(*timeout));
	if (code < sizeof(__dhcp6_message_timings)/sizeof(__dhcp6_message_timings[0])) {

		/* Each message has a timeout */
		if (!__dhcp6_message_timings[code].timeout)
			return FALSE;

		*timeout = __dhcp6_message_timings[code];
#if 1
		ni_trace("%s TIMING: IDT(%lus), IRT(%lus), MRT(%lus), MRC(%u), MRD(%lus), RND(%.3fs)\n",
			 ni_dhcp6_message_name(code),
			 timeout->delay/1000,
			 timeout->timeout/1000,
			 timeout->max_timeout/1000,
			 timeout->max_retransmits,
			 timeout->max_duration/1000,
			 (double)timeout->max_jitter/1000);
#endif
		return TRUE;
	}
	return FALSE;
}
