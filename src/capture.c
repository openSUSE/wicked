/*
 * Raw socket handling code
 *
 * Copyright (C) 2010, Olaf Kirch <okir@suse.de>
 *
 * Heavily inspired by dhcpcd, which was written by Roy Marples <roy@marples.name>
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#define __FAVOR_BSD
#include <netinet/udp.h>
#undef __FAVOR_BSD

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <linux/filter.h>
#include <netpacket/packet.h>
#define bpf_insn sock_filter

#include <wicked/logging.h>
#include <wicked/socket.h>
#include "netinfo_priv.h"
#include "buffer.h"

#define MTU_MAX			1500
#define DHCP_CLIENT_PORT	68

/*
 * Credit where credit is due :)
 * The below BPF filter is taken from ISC DHCP
 */
static struct bpf_insn dhcp_bpf_filter [] = {
	/* Make sure this is an IP packet... */
	BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 12),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_IP, 0, 8),

	/* Make sure it's a UDP packet... */
	BPF_STMT(BPF_LD + BPF_B + BPF_ABS, 23),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_UDP, 0, 6),

	/* Make sure this isn't a fragment... */
	BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 20),
	BPF_JUMP(BPF_JMP + BPF_JSET + BPF_K, 0x1fff, 4, 0),

	/* Get the IP header length... */
	BPF_STMT(BPF_LDX + BPF_B + BPF_MSH, 14),

	/* Make sure it's to the right port... */
	BPF_STMT(BPF_LD + BPF_H + BPF_IND, 16),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, DHCP_CLIENT_PORT, 0, 1),

	/* If we passed all the tests, ask for the whole packet. */
	BPF_STMT(BPF_RET + BPF_K, ~0U),

	/* Otherwise, drop it. */
	BPF_STMT(BPF_RET + BPF_K, 0),
};

static struct bpf_insn arp_bpf_filter [] = {
	/* Make sure this is an ARP packet... */
	BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 12),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_ARP, 0, 1),

	/* If we passed all the tests, ask for the whole packet. */
	BPF_STMT(BPF_RET + BPF_K, ~0U),

	/* Otherwise, drop it. */
	BPF_STMT(BPF_RET + BPF_K, 0),
};

/*
 * Platform specific
 */
struct ni_capture {
	ni_socket_t *		sock;
	int			protocol;
	struct sockaddr_ll	sll;

	const char *		ifname;

	void *			buffer;
	size_t			mtu;

	struct {
		struct timeval		deadline;
		const ni_buffer_t *	buffer;
		ni_timeout_param_t	timeout;
	} retrans;

	void *			user_data;
};

ni_capture_t *		ni_capture_open(const ni_capture_devinfo_t *, int, void (*)(ni_socket_t *));
static int		ni_capture_set_filter(ni_capture_t *, int);
static ssize_t		__ni_capture_broadcast(const ni_capture_t *, const ni_buffer_t *);

static uint32_t
checksum_partial(uint32_t sum, const void *data, uint16_t len)
{
	while (len > 1) {
		sum += *(uint16_t *) data;
		data += 2;
		len -= 2;
	}

	if (len == 1) {
		uint16_t a = *(unsigned char *) data;

		sum += htons(a << 8);
	}
	return sum;
}

static inline uint16_t
checksum_fold(uint32_t sum)
{
	sum = (sum >> 16) + (sum & 0xffff);
	sum +=(sum >> 16);

	return ~sum;
}

static uint16_t
checksum(const void *data, uint16_t length)
{
	uint32_t sum;

	sum = checksum_partial(0, data, length);
	return checksum_fold(sum);
}

static uint16_t
ipudp_checksum(const struct ip *iph, const struct udphdr *uh,
		const unsigned char *data, size_t length)
{
	struct {
		struct in_addr src, dst;
		uint8_t mbz, proto;
		uint16_t length;
	} fake_header;
	uint32_t csum;

	memset(&fake_header, 0, sizeof(fake_header));
	fake_header.src = iph->ip_src;
	fake_header.dst = iph->ip_dst;
	fake_header.proto = iph->ip_p;
	fake_header.length = uh->uh_ulen;
	fake_header.mbz = 0;

	csum = checksum_partial(0, &fake_header, sizeof(fake_header));
	csum = checksum_partial(csum, uh, sizeof(*uh));
	csum = checksum_partial(csum, data, length);

	return checksum_fold(csum);
}

int
ni_capture_build_udp_header(ni_buffer_t *bp,
		struct in_addr src_addr, uint16_t src_port,
		struct in_addr dst_addr, uint16_t dst_port)
{
	const unsigned char *payload;
	unsigned int payload_len;
	unsigned int udp_len;
	struct ip *ip;
	struct udphdr *udp;

	payload = ni_buffer_head(bp);
	payload_len = ni_buffer_count(bp);

	/* Build the UDP header */
	udp = ni_buffer_push_head(bp, sizeof(struct udphdr));
	if (udp == NULL) {
		ni_error("not enough headroom for UDP header");
		return -1;
	}
	udp_len = ni_buffer_count(bp);
	udp->uh_sport = htons(src_port);
	udp->uh_dport = htons(dst_port);
	udp->uh_ulen = htons(udp_len);
	udp->uh_sum = 0;

	/* Build the IP header */
	ip = ni_buffer_push_head(bp, sizeof(struct ip));
	if (ip == NULL) {
		ni_error("not enough headroom for IP header");
		return -1;
	}
	ip->ip_v = 4;
	ip->ip_hl = 5;
	ip->ip_id = 0;
	ip->ip_tos = IPTOS_LOWDELAY;
	ip->ip_len = htons(sizeof(*ip) + udp_len);
	ip->ip_id = 0;
	ip->ip_off = htons(IP_DF);
	ip->ip_ttl = IPDEFTTL;
	ip->ip_p = IPPROTO_UDP;
	ip->ip_src = src_addr;
	ip->ip_dst = dst_addr;
	if (ip->ip_dst.s_addr == 0)
		ip->ip_dst.s_addr = INADDR_BROADCAST;
	ip->ip_sum = 0;

	/* Finally, do the checksums */
	ip->ip_sum = checksum((unsigned char *) ip, sizeof(*ip));
	udp->uh_sum = ipudp_checksum(ip, udp, payload, payload_len);

	return 0;
}

static void *
ni_capture_inspect_udp_header(unsigned char *data, size_t bytes, size_t *payload_len)
{
	struct ip *iph = (struct ip *) data;
	struct udphdr *uh;
	unsigned int ihl;

	ihl = iph->ip_hl << 2;
	if (iph->ip_v != 4 || ihl < 20) {
		ni_debug_socket("bad IP header, ignoring");
		return NULL;
	}

	if (bytes < ihl) {
		ni_debug_socket("truncated IP header, ignoring");
		return NULL;
	}

	if (checksum(iph, ihl) != 0) {
		ni_debug_socket("bad IP header checksum, ignoring");
		return NULL;
	}

	if (bytes < ntohs(iph->ip_len)) {
		ni_debug_socket("truncated IP packet, ignoring");
		return NULL;
	}

	data += ihl;
	bytes -= ihl;

	if (iph->ip_p != IPPROTO_UDP) {
		ni_debug_socket("unexpected IP protocol, ignoring");
		return NULL;
	}

	if (bytes < sizeof(*uh)) {
		ni_debug_socket("truncated IP packet, ignoring");
		return NULL;
	}

	uh = (struct udphdr *) data;
	data += sizeof(*uh);
	bytes -= sizeof(*uh);

	if (ipudp_checksum(iph, uh, data, bytes) != 0) {
		ni_debug_socket("bad UDP checksum, ignoring");
		return NULL;
	}

	*payload_len = ntohs(iph->ip_len);
	return data;
}

/*
 * Timeout handling
 */
void
ni_timeout_increase(ni_timeout_param_t *tmo)
{
	if (tmo->increment)
		tmo->timeout += tmo->increment;
	else
		tmo->timeout <<= 1;
	if (tmo->timeout > tmo->max_timeout)
		tmo->timeout = tmo->max_timeout;
}

int
ni_timeout_arm(struct timeval *deadline, unsigned long timeout, unsigned int jitter)
{
	timeout *= 1000;
	if (jitter) {
		jitter *= 1000;
		timeout += (random() % (2 * jitter)) - jitter;
	}

	ni_debug_socket("arming retransmit timer (%lu msec)", timeout);
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
	return 0;
}

void
ni_capture_arm_retransmit(ni_capture_t *capture)
{
	ni_timeout_arm(&capture->retrans.deadline,
			capture->retrans.timeout.timeout,
			capture->retrans.timeout.max_jitter);
}

void
ni_capture_disarm_retransmit(ni_capture_t *capture)
{
	/* Clear retransmit timer, buffer, and everything else */
	memset(&capture->retrans, 0, sizeof(capture->retrans));
}

void
ni_capture_force_retransmit(ni_capture_t *capture, unsigned int delay)
{
	if (timerisset(&capture->retrans.deadline))
		ni_timeout_arm(&capture->retrans.deadline, delay, 0);
}

/*
 * Retransmit handling
 */
void
ni_capture_retransmit(ni_capture_t *capture)
{
	int rv;

	ni_debug_socket("%s: retransmit request", capture->ifname);

	if (capture->retrans.buffer == NULL) {
		ni_error("ni_capture_retransmit: no message!?");
		ni_capture_disarm_retransmit(capture);
		return;
	}

	ni_timeout_increase(&capture->retrans.timeout);
	rv = __ni_capture_broadcast(capture, capture->retrans.buffer);

	/* We don't care whether sending failed or not. Quite possibly
	 * it's a temporary condition, so continue */
	if (rv < 0)
		ni_warn("%s: sending message failed", capture->ifname);
	ni_capture_arm_retransmit(capture);
}

/*
 * Common functions for handling timeouts
 * (Common as in: working for DHCP and ARP)
 * These are a bit of a layering violation, but I don't like too many
 * callbacks nested in callbacks...
 */
static int
__ni_capture_socket_get_timeout(const ni_socket_t *sock, struct timeval *tv)
{
	ni_capture_t *capture;

	if (!(capture = sock->user_data)) {
		ni_error("capture socket without capture object?!");
		return -1;
	}

	timerclear(tv);
	if (timerisset(&capture->retrans.deadline))
		*tv = capture->retrans.deadline;
	return timerisset(tv)? 0 : -1;
}

static void
__ni_capture_socket_check_timeout(ni_socket_t *sock, const struct timeval *now)
{
	ni_capture_t *capture;

	if (!(capture = sock->user_data)) {
		ni_error("capture socket without capture object?!");
		return;
	}

	if (timerisset(&capture->retrans.deadline) && timercmp(&capture->retrans.deadline, now, <))
		ni_capture_retransmit(capture);
}

/*
 * Capture receive handling
 */
int
ni_capture_recv(ni_capture_t *capture, ni_buffer_t *bp)
{
	void *payload;
	size_t payload_len;
	ssize_t bytes;

	ni_debug_socket("%s: incoming packet", capture->ifname);
	bytes = read(capture->sock->__fd, capture->buffer, capture->mtu);
	if (bytes < 0) {
		ni_error("%s: cannot read from socket: %m", __FUNCTION__);
		return -1;
	}

	switch (capture->protocol) {
	case ETHERTYPE_IP:
		/* Make sure IP and UDP header are sane */
		payload = ni_capture_inspect_udp_header(capture->buffer, bytes, &payload_len);
		if (payload == NULL) {
			ni_debug_socket("bad IP/UDP packet header");
			return -1;
		}
		break;

	case ETHERTYPE_ARP:
		payload = capture->buffer;
		payload_len = bytes;
		break;

	default:
		ni_error("%s: cannot handle ethertype %u", __FUNCTION__, capture->protocol);
		return -1;
	}

	ni_buffer_init_reader(bp, payload, payload_len);
	return payload_len;
}

/*
 * Get/set user data
 */
void
ni_capture_set_user_data(ni_capture_t *capture, void *user_data)
{
	capture->user_data = user_data;
}

void *
ni_capture_get_user_data(const ni_capture_t *capture)
{
	return capture->user_data;
}

/*
 * Check if the capture is valid, and has the desired protocol
 */
int
ni_capture_is_valid(const ni_capture_t *capture, int protocol)
{
	ni_socket_t *sock = capture->sock;

	return (sock && !sock->error && capture->protocol == protocol);
}

/*
 * Open capture socket
 *
 * Dirty little secret: when opening an ETHERTYPE_IP socket, we will always
 * install a packet filter for DHCP. We need to get this out of the system at
 * some point.
 */
ni_capture_t *
ni_capture_open(const ni_capture_devinfo_t *devinfo, int protocol, void (*data_ready)(ni_socket_t *))
{
	struct sockaddr_ll sll;
	ni_capture_t *capture = NULL;
	ni_hwaddr_t brdaddr;
	int fd = -1;

	if (devinfo->ifindex == 0) {
		ni_error("no ifindex for interface `%s'", devinfo->ifname);
		return NULL;
	}

	if (ni_link_address_get_broadcast(devinfo->iftype, &brdaddr) < 0) {
		ni_error("cannot get broadcast address for %s (bad iftype)", devinfo->ifname);
		return NULL;
	}

	if ((fd = socket (PF_PACKET, SOCK_DGRAM, htons(protocol))) < 0) {
		ni_error("socket: %m");
		return NULL;
	}
	fcntl(fd, F_SETFD, FD_CLOEXEC);

	capture = calloc(1, sizeof(*capture));
	capture->ifname = devinfo->ifname;
	capture->sock = ni_socket_wrap(fd, SOCK_DGRAM);
	capture->protocol = protocol;

	capture->sll.sll_family = AF_PACKET;
	capture->sll.sll_protocol = htons(protocol);
	capture->sll.sll_ifindex = devinfo->ifindex;
	capture->sll.sll_hatype = htons(devinfo->arp_type);
	capture->sll.sll_halen = brdaddr.len;
	memcpy(&capture->sll.sll_addr, brdaddr.data, brdaddr.len);

	if (ni_capture_set_filter(capture, protocol) < 0)
		goto failed;

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = PF_PACKET;
	sll.sll_protocol = htons(protocol);
	sll.sll_ifindex = devinfo->ifindex;

	if (bind(fd, (struct sockaddr *) &sll, sizeof(sll)) == -1) {
		ni_error("bind: %m");
		goto failed;
	}

	capture->mtu = devinfo->mtu;
	if (capture->mtu == 0)
		capture->mtu = MTU_MAX;
	capture->buffer = malloc(capture->mtu);

	capture->sock->data_ready = data_ready;
	capture->sock->get_timeout = __ni_capture_socket_get_timeout;
	capture->sock->check_timeout = __ni_capture_socket_check_timeout;
	capture->sock->user_data = capture;
	ni_socket_activate(capture->sock);
	return capture;

failed:
	if (capture)
		ni_capture_free(capture);
	else if (fd >= 0)
		close(fd);
	return NULL;
}

static int
ni_capture_set_filter(ni_capture_t *cap, int protocol)
{
	struct sock_fprog pf;
	static int done = 0;

	/* Initialize packet filters if we haven't done so */
	if (!done) {
		/* We need to massage the filters for Linux cooked packets */
		dhcp_bpf_filter[1].jf = 0; /* skip the IP packet type check */
		dhcp_bpf_filter[2].k -= ETH_HLEN;
		dhcp_bpf_filter[4].k -= ETH_HLEN;
		dhcp_bpf_filter[6].k -= ETH_HLEN;
		dhcp_bpf_filter[7].k -= ETH_HLEN;

		arp_bpf_filter[1].jf = 0; /* skip the IP packet type check */
		arp_bpf_filter[2].k -= ETH_HLEN;

		done = 1;
	}

	/* Install the DHCP filter */
	memset(&pf, 0, sizeof(pf));
	if (protocol == ETHERTYPE_ARP) {
		pf.filter = arp_bpf_filter;
		pf.len = sizeof(arp_bpf_filter) / sizeof(arp_bpf_filter[0]);
	} else {
		pf.filter = dhcp_bpf_filter;
		pf.len = sizeof(dhcp_bpf_filter) / sizeof(dhcp_bpf_filter[0]);
	}

	if (setsockopt(cap->sock->__fd, SOL_SOCKET, SO_ATTACH_FILTER, &pf, sizeof(pf)) < 0) {
		ni_error("SO_ATTACH_FILTER: %m");
		return -1;
	}

	return 0;
}

ssize_t
__ni_capture_broadcast(const ni_capture_t *capture, const ni_buffer_t *buf)
{
	ssize_t rv;

	if (capture == NULL) {
		ni_error("%s: no capture handle", __FUNCTION__);
		return -1;
	}

	rv = sendto(capture->sock->__fd, ni_buffer_head(buf), ni_buffer_count(buf), 0,
			(struct sockaddr *) &capture->sll, sizeof(capture->sll));
	if (rv < 0)
		ni_error("unable to send dhcp packet: %m");

	return rv;
}

ssize_t
ni_capture_broadcast(ni_capture_t *capture, const ni_buffer_t *buf, const ni_timeout_param_t *tmo)
{
	ssize_t rv;

	rv = __ni_capture_broadcast(capture, buf);
	if (tmo) {
		capture->retrans.buffer = buf;
		capture->retrans.timeout = *tmo;
		ni_capture_arm_retransmit(capture);
	} else {
		ni_capture_disarm_retransmit(capture);
	}
	return rv;
}

void
ni_capture_free(ni_capture_t *capture)
{
	if (capture->sock)
		ni_socket_close(capture->sock);
	if (capture->buffer)
		free(capture->buffer);
	free(capture);
}

