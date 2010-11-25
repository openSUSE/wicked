/*
 * Addrconf stubs for IPv6 autoconf
 *
 * This is supposed to do two things:
 *
 *  -	discover route prefixes announced on this network via
 *	IPv6 router announcements
 *
 *  -	Inspect these RAs to see whether the router suggests we
 *	should obtain additional configuration through ipv6.
 *	In which case we should enable DHCP address configuration
 *	on this device.
 *	(Note we could also do this by doing a netlink RTM_GETLINK
 *	with an address family of AF_INET6; there's an INET6_FLAGS
 *	field in there that has MANAGED and OTHER flags.
 *
 * Copyright (C) 2010 Olaf Kirch <okir@suse.de>
 */

#include <arpa/inet.h>
#include <netinet/icmp6.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include <wicked/netinfo.h>
#include <wicked/addrconf.h>
#include <wicked/logging.h>
#include <wicked/wicked.h>
#include <wicked/socket.h>
#include "netinfo_priv.h"
#include "buffer.h"
#include "kernel.h"

static void		ni_ipv6_process_packet(ni_socket_t *);
static void		ni_ipv6_add_router(ni_interface_t *, struct sockaddr_storage *, unsigned int);
static void		ni_ipv6_add_prefix(ni_interface_t *, const struct nd_opt_prefix_info *, unsigned int);

/*
 * Start listening for IPv6 router advertisements
 * FIXME: we should really do this _before_ the interface is brought UP,
 * because we rely on catching the RAs sent in response to the kernel's
 * initial router solicitation.
 */
static int
ni_ipv6_addrconf_request(const ni_addrconf_t *acm, ni_interface_t *ifp, const xml_node_t *cfg_xml)
{
	static int complained = 0;
	ni_socket_t *sock;
	struct ipv6_mreq mreq;
	int fd = -1;

	if (!ni_interface_network_is_up(ifp)) {
		ni_error("ipv6: unexpected links flags - link is not up");
		return -1;
	}
	if (ifp->ifindex == 0) {
		ni_error("ipv6: interface index is 0!");
		return -1;
	}

	if (ifp->ipv6ra_listener != NULL)
		return 0;

	fd = socket(PF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	if (fd < 0) {
		/* FIXME: check errno */
		if (!complained++)
			ni_error("unable to create IPv6 socket - protocol disabled?");
		return -1;
	}

	/* FIXME: we may want to install a filter that only accepts RAs */

	memset(&mreq, 0, sizeof(mreq));
	inet_pton(AF_INET6, "ff02::1", &mreq.ipv6mr_multiaddr);
	mreq.ipv6mr_interface = ifp->ifindex;
	if (setsockopt(fd, SOL_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq)) < 0) {
		ni_error("ipv6: unable to join all-nodes multicast group: %m");
		goto failed;
	}

	sock = ni_socket_wrap(fd, SOCK_DGRAM);
	sock->data_ready = ni_ipv6_process_packet;
	sock->user_data = ifp;
	ni_socket_activate(sock);
	ifp->ipv6ra_listener = sock;

	ifp->ipv6.lease[NI_ADDRCONF_AUTOCONF] = ni_addrconf_lease_new(NI_ADDRCONF_AUTOCONF, AF_INET6);

	return 0;

failed:
	if (fd >= 0)
		close(fd);
	return -1;
}

/*
 * We stop listening for IPv6 RAs on one interface.
 */
static int
ni_ipv6_addrconf_release(const ni_addrconf_t *acm, ni_interface_t *ifp, ni_addrconf_lease_t *lease)
{
	if (ifp->ipv6ra_listener) {
		ni_socket_close(ifp->ipv6ra_listener);
		ifp->ipv6ra_listener = NULL;
	}
	ni_addrconf_lease_free(ifp->ipv6.lease[NI_ADDRCONF_AUTOCONF]);
	ifp->ipv6.lease[NI_ADDRCONF_AUTOCONF] = NULL;
	return 0;
}

ni_addrconf_t ni_ipv6_addrconf = {
	.type = NI_ADDRCONF_AUTOCONF,
	.supported_af = NI_AF_MASK_IPV6,

	.request = ni_ipv6_addrconf_request,
	.release = ni_ipv6_addrconf_release,
};

/*
 * Process all-nodes multicast packet
 */
void
ni_ipv6_process_packet(ni_socket_t *sock)
{
	struct sockaddr_storage router_addr;
	ni_interface_t *ifp = sock->user_data;
	unsigned char buffer[256 * 1024];
	struct nd_router_advert *ra;
	uint16_t lifetime;
	socklen_t alen;
	ni_buffer_t rbuf;
	int count;

	alen = sizeof(router_addr);
	count = recvfrom(sock->__fd, buffer, sizeof(buffer), 0,
			(struct sockaddr *) &router_addr, &alen);
	if (count < 0) {
		ni_error("datagram recv failed: %m");
		return;
	}

	if (ifp->ipv6.lease[NI_ADDRCONF_AUTOCONF] == NULL)
		return;

	ni_debug_ipv6("%s: received ipv6 multicast", ifp->name);
	ni_buffer_init_reader(&rbuf, buffer, count);
	ra = ni_buffer_pull_head(&rbuf, sizeof(*ra));
	if (ra == NULL) {
		/* Whatever it is, it's too short to be a RA */
		return;
	}

	/* FIXME: verify ICMP checksum */

	if (ra->nd_ra_type != ND_ROUTER_ADVERT || ra->nd_ra_code != 0) {
		/* Some other type of ICMP packet */
		return;
	}

	if (ra->nd_ra_flags_reserved & ND_RA_FLAG_MANAGED) {
		ni_warn("%s: router suggests DHCP6 configuration", ifp->name);
		/* ni_ipv6_enable_dhcp6(ifp); */
	}
	if (ra->nd_ra_flags_reserved & ND_RA_FLAG_OTHER) {
		ni_warn("%s: ignoring ipv6 router adv marked OTHER", ifp->name);
		return;
	}
	if (ra->nd_ra_flags_reserved & ND_RA_FLAG_HOME_AGENT) {
		ni_warn("%s: ignoring ipv6 router adv marked HOME_AGENT", ifp->name);
		return;
	}

	lifetime = ntohs(ra->nd_ra_router_lifetime);

	/* Add default router */
	ni_ipv6_add_router(ifp, &router_addr, lifetime);

	/* Process all options. For now we only check prefix info */
	while (ni_buffer_count(&rbuf) && !rbuf.underflow) {
		const void *data;
		int opt, len;

		if ((opt = ni_buffer_getc(&rbuf)) < 0
		 || (len = ni_buffer_getc(&rbuf)) < 0)
			goto short_packet;
		len <<= 3;

		data = ni_buffer_pull_head(&rbuf, len);
		if (!data)
			goto short_packet;

		ni_debug_ipv6("RA option %d, len %d", opt, len);
		if (opt == ND_OPT_PREFIX_INFORMATION) {
			const struct nd_opt_prefix_info *pi = data;

			if (len >= sizeof(*pi))
				ni_ipv6_add_prefix(ifp, pi, lifetime);
		}
	}

	return;

short_packet:
	ni_error("%s: short ICMPv6 packet", ifp->name);
}

void
ni_ipv6_add_router(ni_interface_t *ifp, struct sockaddr_storage *router_addr, unsigned int lifetime)
{
	ni_addrconf_lease_t *lease = ifp->ipv6.lease[NI_ADDRCONF_AUTOCONF];
	ni_route_t **pos, *rp;

	pos = &lease->routes;
	while ((rp = *pos) != NULL && !ni_address_equal(&rp->nh.gateway, router_addr))
		pos = &rp->next;

	if (lifetime != 0 && rp == NULL) {
		/* Add a new default route */
		rp = __ni_route_new(&lease->routes, 0, NULL, router_addr);
	} else
	if (lifetime == 0 && rp != NULL) {
		*pos = rp->next;
		ni_route_free(rp);
		rp = NULL;
	}
	if (rp)
		rp->expires = time(NULL) + lifetime + 1;
}

void
ni_ipv6_add_prefix(ni_interface_t *ifp, const struct nd_opt_prefix_info *pi, unsigned int lifetime)
{
	ni_addrconf_lease_t *lease = ifp->ipv6.lease[NI_ADDRCONF_AUTOCONF];
	struct sockaddr_storage prefix;
	ni_address_t *ap;
	uint8_t flags;

	flags = pi->nd_opt_pi_flags_reserved;
	/* Handle AUTO, RADDR flags */

	memset(&prefix, 0, sizeof(prefix));
	if (pi->nd_opt_pi_prefix_len) {
		struct sockaddr_in6 *six = (struct sockaddr_in6 *) &prefix;

		six->sin6_family = AF_INET6;
		six->sin6_addr = pi->nd_opt_pi_prefix;
		six->sin6_scope_id = ifp->ifindex;
	}

	for (ap = lease->addrs; ap; ap = ap->next) {
		if (ap->prefixlen == pi->nd_opt_pi_prefix_len
		 && ni_address_prefix_match(ap->prefixlen, &ap->local_addr, &prefix))
			break;
	}
	if (ap == NULL)
		ap = __ni_address_new(&lease->addrs, AF_INET6,
				pi->nd_opt_pi_prefix_len,
				&prefix);
	// ap->expires = time(NULL) + lifetime + 1;

#if 0
	struct sockaddr_storage *gw = NULL;
	ni_route_t *rp, *nrp;

	/* Add link-local routes */
	if (!(flags & ND_OPT_PI_FLAG_ONLINK))
		gw = &router_addr;

	nrp = ni_route_new(NULL, pi->nd_opt_pi_prefix_len, &prefix, gw);
	for (rp = ifp->routes; rp; rp = rp->next) {
		if (ni_route_equal(rp, nrp))
			break;
	}

	if (rp != NULL) {
		ni_route_free(nrp);
	} else {
		__ni_route_list_append(&lease->routes, nrp);
		rp = nrp;
	}
#endif
}
