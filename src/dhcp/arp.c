/*
 * Sending ARP probes before we acquire addresses
 *
 * Copyright (C) 2010, Olaf Kirch <okir@suse.de>
 */

#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <stdlib.h>

#include <wicked/netinfo.h>
#include <wicked/socket.h>
#include "dhcp.h"
#include "arp.h"

static void	ni_arp_socket_recv(ni_socket_t *);
static int	ni_arp_send(ni_dhcp_device_t *dev, unsigned int arpop,
				const ni_hwaddr_t *sha, struct in_addr sip,
				const ni_hwaddr_t *tha, struct in_addr tip);

/*
 * Open ARP socket
 */
int
ni_arp_socket_open(ni_dhcp_device_t *dev)
{
	ni_capture_t *capture;

	if ((capture = dev->capture) != NULL) {
		if (ni_capture_is_valid(capture, ETHERTYPE_ARP))
			return 0;

		ni_capture_free(dev->capture);
		dev->capture = NULL;
	}

	dev->capture = ni_capture_open(&dev->system, ETHERTYPE_ARP, ni_arp_socket_recv);
	if (!dev->capture)
		return -1;

	ni_capture_set_user_data(capture, dev);
	return 0;
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

	if (ni_capture_recv(capture, &buf) >= 0) {
		ni_dhcp_device_t *dev = ni_capture_get_user_data(capture);

		ni_dhcp_fsm_process_arp_packet(dev, &buf);
	}
}

int
ni_arp_send_request(ni_dhcp_device_t *dev, struct in_addr sip,
			const ni_hwaddr_t *tha, struct in_addr tip)
{
	return ni_arp_send(dev, ARPOP_REQUEST, &dev->system.hwaddr, sip, tha, tip);
}

int
ni_arp_send(ni_dhcp_device_t *dev, unsigned int arpop,
		const ni_hwaddr_t *sha, struct in_addr sip,
		const ni_hwaddr_t *tha, struct in_addr tip)
{
	unsigned int hwlen, pktlen;
	struct arphdr *arp;
	ni_buffer_t buf;
	int rv;

	if (ni_arp_socket_open(dev) < 0)
		return -1;

	hwlen = ni_link_address_length(dev->system.iftype);
	pktlen = sizeof(*arp) + 2 * hwlen + 2 * 4;

	arp = calloc(1, pktlen);
	ni_buffer_init(&buf, arp, pktlen);

	arp = ni_buffer_push_tail(&buf, sizeof(*arp));
	arp->ar_hrd = htons(dev->system.arp_type);
	arp->ar_pro = htons(ETHERTYPE_IP);
	arp->ar_hln = hwlen;
	arp->ar_pln = 4;
	arp->ar_op = htons(arpop);

	if (sha && sha->len == hwlen) {
		ni_buffer_put(&buf, sha->data, sha->len);
	} else {
		ni_buffer_put(&buf, NULL, hwlen);
	}
	ni_buffer_put(&buf, &sip, 4);
	if (tha && tha->len == hwlen) {
		ni_buffer_put(&buf, tha->data, tha->len);
	} else {
		ni_buffer_put(&buf, NULL, hwlen);
	}
	ni_buffer_put(&buf, &tip, 4);

	rv = ni_capture_broadcast(dev->capture, &buf, NULL);
	free(buf.base);
	return rv;
}

int
ni_arp_parse_reply(ni_dhcp_device_t *dev, ni_buffer_t *bp, struct in_addr *sip, ni_hwaddr_t *sha)
{
	struct arphdr *arp;

	if (!(arp = ni_buffer_pull_head(bp, sizeof(*arp))))
		return -1;

	if (arp->ar_op != htons(ARPOP_REPLY)
	 || arp->ar_pro != htons(ETHERTYPE_IP)
	 || arp->ar_pln != 4)
		return -1;

	sha->type = dev->system.iftype;
	sha->len = ni_link_address_length(dev->system.iftype);
	if (ni_buffer_get(bp, sha->data, sha->len) < 0
	 || ni_buffer_get(bp, sip, 4) < 0)
		return -1;

	if (ni_buffer_count(bp) < sha->len + 4)
		return -1;

	return 0;
}
