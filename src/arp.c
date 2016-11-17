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

#include <wicked/netinfo.h>
#include <wicked/socket.h>
#include "netinfo_priv.h"
#include "socket_priv.h"
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
	arph->dev_info = *dev_info;
	arph->callback = callback;
	arph->user_data = calldata;

	memset(&prot_info, 0, sizeof(prot_info));
	prot_info.eth_protocol = ETHERTYPE_ARP;

	arph->capture = ni_capture_open(dev_info, &prot_info, ni_arp_socket_recv);
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

	if (ni_capture_recv(capture, &buf, NULL, "arp") >= 0) {
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

