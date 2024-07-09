#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>

#include <wicked/logging.h>
#include <wicked/netinfo.h>
#include <wicked/address.h>
#include <wicked/socket.h>
#include <wicked/ipv6.h>

#include "socket_priv.h"
#include "ipv6_priv.h"
#include "util_priv.h"
#include "buffer.h"

typedef struct ni_icmpv6_ra_socket ni_icmpv6_ra_socket_t;

struct ni_icmpv6_ra_socket {
	ni_netdev_ref_t	dev;
	ni_hwaddr_t	hwa;
	ni_socket_t *	sock;
};

static int
__ni_icmpv6_ra_sock_send_options(int fd)
{
	int val;

	/* set hop limit for sending (unicast) [do we need it?] */
	val = 255;
	if(setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &val, sizeof(val))) {
		ni_error("Unable to set unicast hop limit for icmpv6 socket: %m");
		return -1;
	}

	/* set hop limit for sending (multicast) */
	val = 255;
	if(setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &val, sizeof(val))) {
		ni_error("Unable to set multicast hop limit for icmpv6 socket: %m");
		return -1;
	}

	return 0;
}

#if 0
static int
__ni_icmpv6_ra_sock_recv_options(int fd)
{
	int val;

	/* Enable packet info ancillary data with the packet origin */
	val = 1;
	if(setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &val, sizeof(val))) {
		ni_error("Unable to enable receive packet info icmpv6 socket: %m");
		return -1;
	}

	/* Enable recv hop limit to ensure that the packet has not been forwarded */
	val = 1;
	if(setsockopt(fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &val, sizeof(val))) {
		ni_error("Unable to set receive hop limit for the socket: %m");
		return -1;
	}

	return 0;
}

static int
__ni_icmpv6_ra_sock_advert_filter(int fd)
{
	struct icmp6_filter filter;

	ICMP6_FILTER_SETBLOCKALL (&filter);
	ICMP6_FILTER_SETPASS (ND_ROUTER_ADVERT, &filter);
	if(setsockopt(fd, SOL_ICMPV6, ICMP6_FILTER, &filter, sizeof (filter)) < 0) {
		ni_error("Unable to apply router-advert filter: %m");
		close(fd);
		return -1;
	}
	return 0;
}
#endif

static int
__ni_icmpv6_ra_sock_open(void)
{
	int fd;

	fd = socket(PF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	if (fd < 0) {
		ni_error("Unable to create raw icmpv6 socket: %m");
		return -1;
	}
	return fd;
}

ni_icmpv6_ra_socket_t *
ni_icmpv6_ra_socket_new(const ni_netdev_ref_t *ref, const ni_hwaddr_t *hwa)
{
	ni_icmpv6_ra_socket_t  *ras;

	if (!ref || !ref->index || ni_string_empty(ref->name))
		return NULL;

	if (!(ras = calloc(1, sizeof(*ras))))
		return NULL;

	ni_netdev_ref_init(&ras->dev);
	ni_netdev_ref_set(&ras->dev, ref->name, ref->index);

	ni_link_address_init(&ras->hwa);
	if (hwa && hwa->len) {
		if (ni_link_address_set(&ras->hwa, hwa->type,
					hwa->data, hwa->len) < 0) {
			free(ras);
			return NULL;
		}
	}
	return ras;
}

void
ni_icmpv6_ra_socket_close(ni_icmpv6_ra_socket_t *ras)
{
	ni_socket_t *sock;

	if (ras && ras->sock) {
		sock = ras->sock;
		ras->sock = NULL;
		ni_socket_close(sock);
	}
}

void
ni_icmpv6_ra_socket_free(ni_icmpv6_ra_socket_t *ras)
{
	if (ras) {
		ni_icmpv6_ra_socket_close(ras);
		ni_netdev_ref_destroy(&ras->dev);
		free(ras);
	}
}

ni_bool_t
ni_icmpv6_ra_socket_open(ni_icmpv6_ra_socket_t *ras)
{
	int fd;

	if (!ras || ras->sock)
		return FALSE;

	if ((fd = __ni_icmpv6_ra_sock_open()) < 0)
		return FALSE;

	if (__ni_icmpv6_ra_sock_send_options(fd) < 0) {
		close(fd);
		return FALSE;
	}

	if (!(ras->sock = ni_socket_wrap(fd, SOCK_RAW))) {
		close(fd);
		return FALSE;
	}
	ras->sock->user_data = ras;
	return TRUE;
}

#if 0
static void
__ni_icmpv6_ra_receive(ni_socket_t *sock)
{
	/* Basically the parsing code is in ifevent.c
	 * (__ni_rtevent_newprefix) as the NEWPREFIX
	 * netlink message is almost same.
	 */
	(void)sock;
	ni_trace("%s", __func__);
}

ni_bool_t
ni_icmpv6_ra_monitor_open(ni_icmpv6_ra_socket_t *ras)
{
	if (!ni_icmpv6_ra_socket_open(ras))
		return FALSE;

	if (__ni_icmpv6_ra_sock_recv_options(ras->sock->__fd) < 0 ||
	    __ni_icmpv6_ra_sock_advert_filter(ras->sock->__fd) < 0) {
		ni_icmpv6_ra_socket_close(ras);
		return FALSE;
	}

	ras->sock->receive = __ni_icmpv6_ra_receive;
	ni_buffer_init_dynamic(&sock->rbuf, 8192);
	return TRUE;
}
#endif

ni_bool_t
ni_icmpv6_ra_solicit_build(ni_buffer_t *buf, ni_hwaddr_t *hwa)
{
	struct nd_router_solicit sol;
	struct nd_opt_hdr opt;
	size_t len = sizeof(sol) + sizeof(opt);

	ni_buffer_ensure_tailroom(buf, len + (hwa ? hwa->len : 0));

	memset(&sol, 0, sizeof(sol));
	sol.nd_rs_type = ND_ROUTER_SOLICIT;
	if (ni_buffer_put(buf, &sol, sizeof(sol)) < 0)
		return FALSE;

	if (hwa && hwa->len) {
		memset(&opt, 0, sizeof(opt));
		opt.nd_opt_type = ND_OPT_SOURCE_LINKADDR;
		opt.nd_opt_len = (sizeof(opt) + hwa->len) >> 3;
		if (ni_buffer_put(buf, &opt, sizeof(opt)) < 0)
			return FALSE;
		if (ni_buffer_put(buf, hwa->data, hwa->len) < 0)
			return FALSE;
	}
	return TRUE;
}

ni_bool_t
ni_icmpv6_ra_solicit_send(ni_icmpv6_ra_socket_t *ras)
{
	static const char *all_routers_mc = "ff02::2";
	struct in6_pktinfo *pinfo;
	unsigned char   cmsgbuf[CMSG_SPACE(sizeof(*pinfo))];
	struct cmsghdr *cmsg;
	struct iovec    iov;
	struct msghdr   msg;
	ni_sockaddr_t	addr;

	if (!ras || !ras->sock || !ras->dev.index)
		return FALSE;

	if (ni_sockaddr_parse(&addr, all_routers_mc, AF_INET6) < 0)
		return FALSE;

	ni_buffer_reset(&ras->sock->wbuf);
	if (!ni_icmpv6_ra_solicit_build(&ras->sock->wbuf, &ras->hwa)) {
		ni_buffer_reset(&ras->sock->wbuf);
		return FALSE;
	}

	memset(&cmsgbuf, 0, sizeof(cmsgbuf));
	cmsg = (struct cmsghdr *)cmsgbuf;
	cmsg->cmsg_len = CMSG_LEN(sizeof(*pinfo));
	cmsg->cmsg_level = SOL_IPV6;
	cmsg->cmsg_type = IPV6_PKTINFO;

	pinfo = (struct in6_pktinfo *)CMSG_DATA(cmsg);
	pinfo->ipi6_ifindex = ras->dev.index;

	iov.iov_base = ni_buffer_head(&ras->sock->wbuf);
	iov.iov_len  = ni_buffer_count(&ras->sock->wbuf);

	msg.msg_name = &addr.six;
	msg.msg_namelen = sizeof(addr.six);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = CMSG_SPACE(sizeof(*pinfo));

	if (sendmsg(ras->sock->__fd, &msg, 0) == -1)
		return FALSE;
	return TRUE;
}

ni_bool_t
ni_icmpv6_ra_solicit(const ni_netdev_ref_t *ref, const ni_hwaddr_t *hwa)
{
	ni_icmpv6_ra_socket_t *ras;
	ni_bool_t sent;

	ras = ni_icmpv6_ra_socket_new(ref, hwa);
	if (!ni_icmpv6_ra_socket_open(ras)) {
		ni_icmpv6_ra_socket_free(ras);
		return FALSE;
	}

	sent = ni_icmpv6_ra_solicit_send(ras);
	ni_icmpv6_ra_socket_free(ras);
	return sent;
}

