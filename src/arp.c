/*
 * ARP support - needed for DHCP, IPv4LL, and maybe others
 *
 * Copyright (C) 2010-2012, Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/time.h>
#include <errno.h>

#include <wicked/netinfo.h>
#include <wicked/socket.h>
#include "netinfo_priv.h"
#include "socket_priv.h"
#include "array_priv.h"
#include "buffer.h"

static void	ni_arp_socket_recv(ni_socket_t *);
static int	ni_arp_parse(ni_arp_socket_t *, ni_buffer_t *, ni_arp_packet_t *);

/*
 * Open ARP socket
 */
ni_arp_socket_t *
ni_arp_socket_open(const ni_capture_devinfo_t *dev_info, ni_arp_callback_t *callback, void *calldata)
{
	ni_capture_protinfo_t prot_info;
	ni_arp_socket_t *arph;

	arph = calloc(1, sizeof(*arph));
	ni_capture_devinfo_copy(&arph->dev_info, dev_info);
	arph->callback = callback;
	arph->user_data = calldata;

	memset(&prot_info, 0, sizeof(prot_info));
	prot_info.eth_protocol = ETHERTYPE_ARP;

	arph->capture = ni_capture_open(dev_info, &prot_info, ni_arp_socket_recv, "arp");
	if (!arph->capture) {
		ni_arp_socket_close(arph);
		return NULL;
	}

	ni_capture_set_user_data(arph->capture, arph);
	return arph;
}

void
ni_arp_socket_close(ni_arp_socket_t *arph)
{
	ni_capture_free(arph->capture);
	ni_capture_devinfo_destroy(&arph->dev_info);
	free(arph);
}

/*
 * This callback is invoked from the socket code when we
 * detect an incoming ARP packet on the raw socket.
 */
static void
ni_arp_socket_recv(ni_socket_t *sock)
{
	ni_capture_t *capture = sock->user_data;
	ni_buffer_t buf;

	if (ni_capture_recv(capture, &buf, NULL) >= 0) {
		ni_arp_socket_t *arph = ni_capture_get_user_data(capture);
		ni_arp_packet_t packet;

		if (ni_arp_parse(arph, &buf, &packet) >= 0)
			arph->callback(arph, &packet, arph->user_data);
	}
}

int
ni_arp_send_request(ni_arp_socket_t *arph, struct in_addr sip, struct in_addr tip)
{
	ni_arp_packet_t packet;

	memset(&packet, 0, sizeof(packet));
	packet.op = ARPOP_REQUEST;
	packet.sip = sip;
	packet.sha = arph->dev_info.hwaddr;
	packet.tip = tip;
	return ni_arp_send(arph, &packet);
}

int
ni_arp_send_reply(ni_arp_socket_t *arph, struct in_addr sip,
		const ni_hwaddr_t *tha, struct in_addr tip)
{
	ni_arp_packet_t packet;

	memset(&packet, 0, sizeof(packet));
	packet.op = ARPOP_REPLY;
	packet.sip = sip;
	packet.sha = arph->dev_info.hwaddr;
	packet.tip = tip;
	if (tha)
		packet.tha = *tha;
	return ni_arp_send(arph, &packet);
}

int
ni_arp_send_grat_reply(ni_arp_socket_t *arph, struct in_addr sip)
{
	ni_arp_packet_t packet;

	memset(&packet, 0, sizeof(packet));
	packet.op = ARPOP_REPLY;
	packet.sip = sip;
	packet.sha = arph->dev_info.hwaddr;
	packet.tip = sip;
	packet.tha = arph->dev_info.hwaddr;
	return ni_arp_send(arph, &packet);
}

/*
 * See e.g. https://tools.ietf.org/html/rfc5227#section-3:
 * Gratuitous ARP request are more likely to work correctly as
 * requests are always broadcasts and replies may be expected
 * to be unicasts only and dropped by incorrect implementations.
 */
int
ni_arp_send_grat_request(ni_arp_socket_t *arph, struct in_addr sip)
{
	ni_arp_packet_t packet;
	memset(&packet, 0, sizeof(packet));
	packet.op = ARPOP_REQUEST;
	packet.sip = sip;
	packet.sha = arph->dev_info.hwaddr;
	packet.tip = sip;
	ni_link_address_get_broadcast(arph->dev_info.hwaddr.type, &packet.tha);
	return ni_arp_send(arph, &packet);
}

int
ni_arp_send(ni_arp_socket_t *arph, const ni_arp_packet_t *packet)
{
	unsigned int hwlen, pktlen;
	struct arphdr *arp;
	ni_buffer_t buf;
	int rv;

	hwlen = ni_link_address_length(arph->dev_info.hwaddr.type);
	pktlen = sizeof(*arp) + 2 * hwlen + 2 * 4;

	arp = calloc(1, pktlen);
	ni_buffer_init(&buf, arp, pktlen);

	arp = ni_buffer_push_tail(&buf, sizeof(*arp));
	arp->ar_hrd = htons(arph->dev_info.hwaddr.type);
	arp->ar_pro = htons(ETHERTYPE_IP);
	arp->ar_hln = hwlen;
	arp->ar_pln = 4;
	arp->ar_op = htons(packet->op);

	if (packet->sha.len == hwlen) {
		ni_buffer_put(&buf, packet->sha.data, packet->sha.len);
	} else {
		ni_buffer_put(&buf, NULL, hwlen);
	}
	ni_buffer_put(&buf, &packet->sip, 4);
	if (packet->tha.len == hwlen) {
		ni_buffer_put(&buf, packet->tha.data, packet->tha.len);
	} else {
		ni_buffer_put(&buf, NULL, hwlen);
	}
	ni_buffer_put(&buf, &packet->tip, 4);

	rv = ni_capture_send(arph->capture, &buf, NULL);
	free(buf.base);
	return rv;
}

int
ni_arp_parse(ni_arp_socket_t *arph, ni_buffer_t *bp, ni_arp_packet_t *p)
{
	struct arphdr *arp;

	if (!(arp = ni_buffer_pull_head(bp, sizeof(*arp))))
		return -1;

	if (arp->ar_pro != htons(ETHERTYPE_IP)
	 || arp->ar_pln != 4)
		return -1;

	p->op = ntohs(arp->ar_op);
	p->sha.type = arph->dev_info.hwaddr.type;
	p->sha.len = ni_link_address_length(arph->dev_info.hwaddr.type);
	p->tha = p->sha;

	if (ni_buffer_get(bp, p->sha.data, p->sha.len) < 0 || ni_buffer_get(bp, &p->sip, 4) < 0
	 || ni_buffer_get(bp, p->tha.data, p->tha.len) < 0 || ni_buffer_get(bp, &p->tip, 4) < 0)
		return -1;

	return 0;
}

unsigned long
ni_arp_timeout_left(struct timeval *started, const struct timeval *current, unsigned long msec)
{
	struct timeval dif, end;
	unsigned long left = 0;

	if (timerisset(started) && timercmp(current, started, >)) {
		dif.tv_sec  = msec / 1000;
		dif.tv_usec = (msec % 1000) * 1000;
		timeradd(started, &dif, &end);
		if (timercmp(&end, current, >)) {
			timersub(&end, current, &dif);
			left = dif.tv_sec * 1000 + dif.tv_usec / 1000;
		}
	}
	return left;
}

static void
ni_arp_address_free(ni_arp_address_t *aa)
{
	ni_address_free(aa->address);
	free(aa);
}

static ni_define_ptr_array_init(ni_arp_address);
static ni_define_ptr_array_destroy(ni_arp_address);
static ni_define_ptr_array_realloc(ni_arp_address, NI_ARP_ADDRESS_ARRAY_CHUNK);
static ni_define_ptr_array_append(ni_arp_address);
static ni_define_ptr_array_delete_at(ni_arp_address);

static ni_bool_t
ni_arp_address_array_append_addr(ni_arp_address_array_t *arr, ni_address_t *addr)
{
	ni_arp_address_t *e;

	if (!(e = calloc(1, sizeof(*e))))
		return FALSE;

	e->address = ni_address_ref(addr);
	if (e->address && ni_arp_address_array_append(arr, e))
		return TRUE;

	ni_arp_address_free(e);
	return FALSE;
}

static ni_arp_address_t *
ni_arp_address_array_find_match_addr(ni_arp_address_array_t *array, ni_address_t *ap,
			unsigned int *index, ni_bool_t (*match)(const ni_address_t *, const ni_address_t *))
{
	ni_arp_address_t *a;
	unsigned int i;

	if (array) {
		match = match ?: ni_address_equal_ref;

		for (i = index ? *index : 0; i < array->count; ++i) {
			a = array->data[i];
			if (match(a->address, ap)) {
				if (index)
					*index = i;
				return a;
			}
		}
	}
	if (index)
		*index = -1U;
	return NULL;
}

void
ni_arp_verify_init(ni_arp_verify_t *vfy, const ni_config_arp_verify_t *cfg)
{
	memset(vfy, 0, sizeof(*vfy));
	vfy->nprobes = cfg->count;
	vfy->nretry = cfg->retries;
	vfy->probe_min_ms = cfg->interval.min;
	vfy->probe_max_ms = cfg->interval.max;
}

void
ni_arp_verify_reset(ni_arp_verify_t *vfy, const ni_config_arp_verify_t *cfg)
{
	vfy->nprobes = cfg->count;
	vfy->nretry = cfg->retries;
	vfy->probe_min_ms = cfg->interval.min;
	vfy->probe_max_ms = cfg->interval.max;
	timerclear(&vfy->started);
	vfy->last_timeout = 0;
	ni_arp_address_array_destroy(&vfy->ipaddrs);
}

void
ni_arp_verify_destroy(ni_arp_verify_t *vfy)
{
	ni_arp_address_array_destroy(&vfy->ipaddrs);
	memset(vfy, 0, sizeof(*vfy));
}

unsigned int
ni_arp_verify_add_address(ni_arp_verify_t *vfy,  ni_address_t *ap)
{
	if (!vfy || !ap || !vfy->nprobes)
		return 0;

	if (ap->family != AF_INET || !ni_sockaddr_is_ipv4_specified(&ap->local_addr))
		return 0;

	if (ni_arp_address_array_find_match_addr(&vfy->ipaddrs, ap, NULL, ni_address_equal_local_addr))
		return 0;	/* already have it */

	if (!ni_arp_address_array_append_addr(&vfy->ipaddrs, ap))
		return 0;

	return vfy->ipaddrs.count;
}

ni_bool_t
ni_arp_verify_remove_address(ni_arp_verify_t *vfy,  ni_address_t *ap)
{
	unsigned int index = 0;

	if (!vfy || !ap)
		return FALSE;

	if (ap->family != AF_INET || !ni_sockaddr_is_ipv4_specified(&ap->local_addr))
		return FALSE;

	if (!ni_arp_address_array_find_match_addr(&vfy->ipaddrs, ap, &index,
				ni_address_equal_local_addr))
		return FALSE;

	return ni_arp_address_array_delete_at(&vfy->ipaddrs, index);
}

unsigned int
ni_arp_verify_add_in_addr(ni_arp_verify_t * vfy, struct in_addr addr)
{
	unsigned int ret;
	ni_sockaddr_t sockaddr;
	ni_address_t *address;

	memset(&sockaddr, 0, sizeof(sockaddr));
	ni_sockaddr_set_ipv4(&sockaddr, addr, 0);

	if (!(address = ni_address_create(AF_INET, 32, &sockaddr, NULL)))
		return 0;

	ni_address_set_tentative(address, TRUE);

	ret = ni_arp_verify_add_address(vfy, address);
	ni_address_free(address);

	return ret;
}

ni_arp_address_t *
ni_arp_reply_match_address(ni_arp_socket_t *sock, ni_arp_address_array_t *ipaddrs,
		const ni_arp_packet_t *pkt)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	const ni_netdev_t *dev;
	ni_bool_t false_alarm = FALSE;
	ni_bool_t found_addr = FALSE;
	ni_arp_address_t *vap;
	ni_address_t sip;

	if (!sock || !pkt || pkt->op != ARPOP_REPLY || !ipaddrs)
		return NULL;

	memset(&sip, 0, sizeof(sip));
	ni_sockaddr_set_ipv4(&sip.local_addr, pkt->sip, 0);
	vap = ni_arp_address_array_find_match_addr(ipaddrs, &sip, NULL, ni_address_equal_local_addr);
	if (!vap) {
		ni_debug_application("%s: ignore report about unrelated address %s from  %s",
				sock->dev_info.ifname, ni_sockaddr_print(&sip.local_addr),
				ni_link_address_print(&pkt->sha));
		return NULL;
	}
	if (ni_address_is_duplicate(vap->address))
		return vap;

	/* Ignore any ARP replies that seem to come from our own MAC
	 * address. Some helpful switches seem to generate them.
	 */
	if (ni_link_address_equal(&sock->dev_info.hwaddr, &pkt->sha)) {
		ni_debug_application("%s: ignore address %s in use by our own mac address %s",
				sock->dev_info.ifname, ni_sockaddr_print(&sip.local_addr),
				ni_link_address_print(&pkt->sha));
		return NULL;
	}

	/* As well as ARP replies that seem to come from our own host:
	 * dup if same address, not a dup if there are two interfaces
	 * connected to the same broadcast domain.
	 */
	for (dev = ni_netconfig_devlist(nc); dev; dev = dev->next) {
		if (dev->link.ifindex == sock->dev_info.ifindex)
			continue;

		if (!ni_netdev_link_is_up(dev))
			continue;

		if (!ni_link_address_equal(&dev->link.hwaddr, &pkt->sha))
			continue;

		/* OK, we have an interface matching the hwaddr,
		 * which will answer arp requests when it is on
		 * the same broadcast domain and causes a false
		 * alarm, except it really has the IP assigned.
		 */
		false_alarm = TRUE;
		found_addr = !!ni_address_list_find(dev->addrs, &vap->address->local_addr);
	}
	if (false_alarm && !found_addr) {
		ni_debug_application("%s: reply from one of our interfaces",
				sock->dev_info.ifname);
		return NULL;
	}

	return vap;
}

ni_arp_send_status_t
ni_arp_verify_send(ni_arp_socket_t *sock, ni_arp_verify_t *vfy, ni_timeout_t *timeout)
{
	static struct in_addr null = { 0 };
	const struct in_addr *ip;
	unsigned int i;
	struct timeval now;
	ni_address_t *ap;
	ni_arp_address_t *vap;
	ni_bool_t need_wait;

	if (!sock || !vfy || !timeout)
		return NI_ARP_SEND_FAILURE;

	ni_timer_get_time(&now);
	if ((*timeout = ni_arp_timeout_left(&vfy->started, &now, vfy->last_timeout)))
		return NI_ARP_SEND_PROGRESS;

	for (i = 0; i < vfy->ipaddrs.count; ++i) {
		vap = vfy->ipaddrs.data[i];
		ap  = vap->address;

		if (ni_address_is_duplicate(ap))
			continue;
		if (!ni_address_is_tentative(ap))
			continue;

		if (vap->nattempts >= vfy->nprobes)
			ni_address_set_tentative(ap, FALSE);
	}

	need_wait = FALSE;
	for (i = 0; i < vfy->ipaddrs.count; ++i) {
		vap = vfy->ipaddrs.data[i];
		ap  = vap->address;

		if (ni_address_is_duplicate(ap))
			continue;
		if (!ni_address_is_tentative(ap))
			continue;

		ni_debug_application("%s: sending arp verify for IP %s (%u/%u)",
				sock->dev_info.ifname, ni_sockaddr_print(&ap->local_addr),
				vap->nattempts + 1, vfy->nprobes);

		ip = &ap->local_addr.sin.sin_addr;
		if (ni_arp_send_request(sock, null, *ip) > 0) {
			vap->nattempts++;
			need_wait = TRUE;
		} else {
			if (errno == ENOBUFS) {
				vap->nerrors++;
				if (vap->nerrors >= vfy->nretry) {
					ni_error("%s: ARP verify failed for %s - max (%u) retry!",
							sock->dev_info.ifname,
							ni_sockaddr_print(&ap->local_addr),
							vfy->nretry);
					ni_address_set_duplicate(ap, TRUE);
				} else {
					need_wait = TRUE;
					ni_debug_application("%s: ARP verify failed for %s -"
							" ENOBUFS, probes:%u/%u errors:%u/%u",
							sock->dev_info.ifname,
							ni_sockaddr_print(&ap->local_addr),
							vap->nattempts, vfy->nprobes,
							vap->nerrors, vfy->nretry);
				}
			} else {
				ni_error("%s: ARP verify send failed for %s - unexpected error!",
						sock->dev_info.ifname,
						ni_sockaddr_print(&ap->local_addr));
				ni_address_set_duplicate(ap, TRUE);
			}
		}
	}
	if (need_wait) {
		ni_timer_get_time(&vfy->started);
		vfy->last_timeout = ni_timeout_random_range(vfy->probe_min_ms, vfy->probe_max_ms);
		*timeout = vfy->last_timeout;
		return NI_ARP_SEND_PROGRESS;
	}
	for (i = 0; i < vfy->ipaddrs.count; ++i) {
		vap = vfy->ipaddrs.data[i];
		if (vap->nattempts > 0)
			return NI_ARP_SEND_COMPLETE;
	}

	return NI_ARP_SEND_FAILURE;
}


void
ni_arp_notify_init(ni_arp_notify_t *nfy, const ni_config_arp_notify_t *cfg)
{
	memset(nfy, 0, sizeof(*nfy));
	nfy->nclaims = cfg->count;
	nfy->nretry = cfg->retries;
	nfy->wait_ms = cfg->interval;
}

void
ni_arp_notify_reset(ni_arp_notify_t *nfy, const ni_config_arp_notify_t *cfg)
{
	nfy->nclaims = cfg->count;
	nfy->nretry = cfg->retries;
	nfy->wait_ms = cfg->interval;
	timerclear(&nfy->started);
	ni_arp_address_array_destroy(&nfy->ipaddrs);
}

void
ni_arp_notify_destroy(ni_arp_notify_t *nfy)
{
	ni_arp_address_array_destroy(&nfy->ipaddrs);
	memset(nfy, 0, sizeof(*nfy));
}

unsigned int
ni_arp_notify_add_address(ni_arp_notify_t *nfy,  ni_address_t *ap)
{
	if (!nfy || !ap || !nfy->nclaims)
		return 0;

	if (ap->family != AF_INET || !ni_sockaddr_is_ipv4_specified(&ap->local_addr))
		return 0;

	if (ni_arp_address_array_find_match_addr(&nfy->ipaddrs, ap, NULL, ni_address_equal_local_addr))
		return 0;	/* already have it */

	if (!ni_arp_address_array_append_addr(&nfy->ipaddrs, ap))
		return 0;

	return nfy->ipaddrs.count;
}

ni_bool_t
ni_arp_notify_send(ni_arp_socket_t *sock, ni_arp_notify_t *nfy, ni_timeout_t *timeout)
{
	const struct in_addr *ip;
	unsigned int i;
	struct timeval now;
	ni_arp_address_t *aa;
	ni_address_t *ap;
	ni_bool_t need_wait;

	if (!sock || !nfy || !timeout)
		return FALSE;

	ni_timer_get_time(&now);
	if ((*timeout = ni_arp_timeout_left(&nfy->started, &now, nfy->wait_ms)))
		return TRUE;

	if (nfy->nclaims && nfy->ipaddrs.count) {
		need_wait = FALSE;

		for (i = 0; i < nfy->ipaddrs.count; ++i) {
			aa = nfy->ipaddrs.data[i];
			ap = aa->address;

			if (ni_address_is_duplicate(ap))
				continue;

			if (ni_address_is_tentative(ap))
				continue;

			if ((nfy->nretry && aa->nerrors >= nfy->nretry) ||
				aa->nattempts >= nfy->nclaims)
				continue;

			ni_debug_application("%s: sending arp notify for IP %s (%u/%u)",
					sock->dev_info.ifname, ni_sockaddr_print(&ap->local_addr),
					aa->nattempts + 1, nfy->nclaims);

			ip = &ap->local_addr.sin.sin_addr;
			if (ni_arp_send_grat_request(sock, *ip) > 0) {
				aa->nattempts++;
				if (nfy->nclaims > aa->nattempts)
					need_wait = TRUE;
			} else {
				if (errno == ENOBUFS) {
					aa->nerrors++;
					if (aa->nerrors >= nfy->nretry) {
						ni_error("%s: ARP notify failed for %s - max (%u) retry!",
								sock->dev_info.ifname,
								ni_sockaddr_print(&ap->local_addr),
								nfy->nretry);
					} else {
						need_wait = TRUE;
					}
				} else {
					ni_error("%s: ARP notify send failed for %s - unexpected error!",
						sock->dev_info.ifname,
						ni_sockaddr_print(&ap->local_addr));
						ni_address_set_duplicate(ap, TRUE);
				}
			}
		}
		if (need_wait) {
			ni_timer_get_time(&nfy->started);
			*timeout = nfy->wait_ms;
			return TRUE;
		}
	}

	return FALSE;
}

