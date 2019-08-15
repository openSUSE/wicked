/*
 * Raw socket handling code
 *
 * Copyright (C) 2010-2012, Olaf Kirch <okir@suse.de>
 *
 * Heavily inspired by dhcpcd, which was written by Roy Marples <roy@marples.name>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

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
#define bpf_insn sock_filter

#if defined(HAVE_LINUX_IF_PACKET_H)
#include <linux/if_packet.h>
#else
#include <netpacket/packet.h>
#endif

#include <wicked/logging.h>
#include <wicked/socket.h>
#include "netinfo_priv.h"
#include "socket_priv.h"
#include "modprobe.h"
#include "buffer.h"

#define MTU_MAX			1500
#define DHCP_CLIENT_PORT	68

#ifndef ETHERTYPE_LLDP
# define ETHERTYPE_LLDP		0x88CC
#endif

#define	AFPACKET_MODULE_NAME	"af_packet"
#define AFPACKET_MODULE_OPTS	NULL

/* in case we have old headers files */
#if defined(PACKET_AUXDATA) && !defined(HAVE_STRUCT_TPACKET_AUXDATA)
struct tpacket_auxdata {
	__u32	tp_status;
	__u32	tp_len;
	__u32	tp_snaplen;
	__u16	tp_mac;
	__u16	tp_net;
	__u16	tp_vlan_tci;
	__u16	tp_padding;
};
#endif

/*
 * Credit where credit is due :)
 * The below BPF filter is taken from ISC DHCP
 */
static struct bpf_insn std_ipv4_bpf_filter [] = {
	/* Make sure it's a UDP packet... */
	BPF_STMT(BPF_LD + BPF_B + BPF_ABS, 9),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_UDP, 0, 6),

	/* Make sure this isn't a fragment... */
	BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 6),
	BPF_JUMP(BPF_JMP + BPF_JSET + BPF_K, 0x1fff, 4, 0),

	/* Get the IP header length... */
	BPF_STMT(BPF_LDX + BPF_B + BPF_MSH, 0),

	/* Make sure it's to the right port... */
	BPF_STMT(BPF_LD + BPF_H + BPF_IND, 2),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, DHCP_CLIENT_PORT, 0, 1),

	/* If we passed all the tests, ask for the whole packet. */
	BPF_STMT(BPF_RET + BPF_K, ~0U),

	/* Otherwise, drop it. */
	BPF_STMT(BPF_RET + BPF_K, 0),
};

/*
 * Wrap sockaddr_ll same to ni_sockaddr_t,
 * just for link-layer packets only
 *
 * sll_addr[8] is not enough for infiniband.
 */
typedef union ni_packetaddr {
	sa_family_t		ss_family;
	struct sockaddr_storage	ss;
	struct sockaddr		sa;
	struct sockaddr_ll	sll;
} ni_packetaddr_t;

/*
 * Platform specific
 */
struct ni_capture {
	ni_socket_t *		sock;
	ni_packetaddr_t		addr;
	int			protocol;

	char *			ifname;

	void *			buffer;
	size_t			mtu;

	struct {
		struct timeval		deadline;
		const ni_buffer_t *	buffer;
		ni_timeout_param_t	timeout;
	} retrans;

	void *			user_data;
};

static int		ni_capture_set_filter(ni_capture_t *, const ni_capture_protinfo_t *);
static ssize_t		__ni_capture_send(const ni_capture_t *, const ni_buffer_t *);

static uint32_t
checksum_partial(uint32_t sum, const void *data, uint16_t len)
{
	union {
		const uint16_t *s;
		const uint8_t *c;
	} u;

	u.s = data;
	while (len > 1) {
		sum += *u.s++;
		len -= 2;
	}

	if (len == 1) {
		union {
			uint8_t c[2];
			uint16_t s;
		} bs;
		bs.c[0] = u.c[0];
		bs.c[1] = 0;
		sum += bs.s;
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
ipudp_checksum(const struct ip *iph, const struct udphdr *uhp,
		const void *data, size_t length)
{
	struct udphdr uh;
	uint32_t csum;
	union {
		uint8_t c[2];
		uint16_t s;
	} bs;

	uh.uh_sport = uhp->uh_sport;
	uh.uh_dport = uhp->uh_dport;
	uh.uh_ulen = uhp->uh_ulen;
	uh.uh_sum = 0;

	bs.c[0] = 0;
	bs.c[1] = IPPROTO_UDP;

	csum = checksum_partial(bs.s + uh.uh_ulen, &iph->ip_src, 2* sizeof(iph->ip_src));
	csum = checksum_partial(csum, data, length);
	csum = checksum_partial(csum, &uh, sizeof(uh));

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
	ip->ip_sum = checksum( ip, sizeof(*ip));
	udp->uh_sum = ipudp_checksum(ip, udp, payload, payload_len);

	return 0;
}

static void *
ni_capture_inspect_udp_header(void *data, size_t bytes, size_t *payload_len,
				ni_bool_t partial_checksum)
{
	struct ip *iph = data;
	struct udphdr *uh;
	unsigned int ihl;
	unsigned int ip_len = ntohs(iph->ip_len);

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

	if (bytes < ip_len) {
		ni_debug_socket("truncated IP packet, ignoring");
		return NULL;
	}

	if (bytes > ip_len) {
		ni_debug_socket("Received %x bytes, but ip_len is %x. Adjusting.", (int)bytes, ip_len);
		bytes = ip_len;
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

	uh = data;
	data += sizeof(*uh);
	bytes -= sizeof(*uh);

	if (!partial_checksum && uh->uh_sum &&
		ipudp_checksum(iph, uh, data, bytes) != uh->uh_sum) {
		ni_debug_socket("bad UDP checksum, ignoring");
		return NULL;
	}

	*payload_len = ip_len;
	return data;
}

/*
 * Timeout handling
 */
void
ni_capture_arm_retransmit(ni_capture_t *capture)
{
	ni_timeout_arm(&capture->retrans.deadline, &capture->retrans.timeout);
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
	if (timerisset(&capture->retrans.deadline)) {
		struct timeval *deadline = &capture->retrans.deadline;

		ni_timer_get_time(deadline);
		deadline->tv_sec += delay;
	}
}

/*
 * Retransmit handling
 */
static void
ni_capture_retransmit(ni_capture_t *capture)
{
	int rv;

	ni_debug_socket("%s: retransmit request", capture->ifname);

	if (capture->retrans.buffer == NULL) {
		ni_error("ni_capture_retransmit: no message!?");
		ni_capture_disarm_retransmit(capture);
		return;
	}

	if (!ni_timeout_recompute(&capture->retrans.timeout))
		return;

	if (capture->retrans.timeout.timeout_callback)
		capture->retrans.timeout.timeout_callback(capture->retrans.timeout.timeout_data);

	rv = __ni_capture_send(capture, capture->retrans.buffer);

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
__ni_capture_recv(int fd, void *buf, size_t len, ni_bool_t *partial_csum, ni_sockaddr_t *from)
{
#if defined(PACKET_AUXDATA)
	/* use 2 times bigger buffer to catch possible additions... */
	unsigned char cbuf[CMSG_SPACE(sizeof(struct tpacket_auxdata)*2)];
	struct iovec iov = {
		.iov_base = buf,
		.iov_len  = len,
	};
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = cbuf,
		.msg_controllen = sizeof(cbuf),
		.msg_name = from ? from : NULL,
		.msg_namelen = from ? sizeof(from->ss) : 0,
	};
	struct cmsghdr *cmsg;
	struct tpacket_auxdata *aux;
	ssize_t bytes;

	*partial_csum = FALSE;
	memset(cbuf, 0, sizeof(cbuf));
	if (from)
		memset(from, 0, sizeof(*from));

	if ((bytes = recvmsg (fd, &msg, 0)) < 0)
		return bytes;

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level == SOL_PACKET &&
		    cmsg->cmsg_type == PACKET_AUXDATA &&
		    cmsg->cmsg_len >= CMSG_LEN(sizeof(struct tpacket_auxdata))) {
			aux = (void *)CMSG_DATA(cmsg);
			if (aux->tp_status & TP_STATUS_CSUMNOTREADY)
				*partial_csum = TRUE;
			break;
		}
	}

	return bytes;
#else
	*partial_csum = FALSE;

	return read(fd, buf, len);
#endif
}

ni_bool_t
ni_capture_from_hwaddr_set(ni_hwaddr_t *hwaddr, const ni_sockaddr_t *from)
{
	struct sockaddr_ll *ll;

	if (!hwaddr || !from || from->ss_family != AF_PACKET)
		return FALSE;

	ll = (struct sockaddr_ll *)&from->ss;
	if (ll->sll_halen != ni_link_address_length(ll->sll_hatype))
		return FALSE;

	if (ni_link_address_set(hwaddr, ll->sll_hatype, ll->sll_addr, ll->sll_halen))
		return FALSE;
	return TRUE;
}

const char *
ni_capture_from_hwaddr_print(const ni_sockaddr_t *from)
{
	ni_hwaddr_t hwaddr;

	if (!ni_capture_from_hwaddr_set(&hwaddr, from))
		return NULL;
	return ni_link_address_print(&hwaddr);
}

int
ni_capture_recv(ni_capture_t *capture, ni_buffer_t *bp, ni_sockaddr_t *from, const char *hint)
{
	void *payload;
	size_t payload_len;
	ssize_t bytes;
	ni_bool_t partial_checksum = FALSE;
	const char *lladdr;

	bytes = __ni_capture_recv(capture->sock->__fd, capture->buffer,
				  capture->mtu, &partial_checksum, from);

	if (bytes < 0) {
		ni_error("%s: %s cannot read %s%spacket from socket: %m",
				capture->ifname, __FUNCTION__,
				hint ? hint : "", hint ? " " : "");
		return -1;
	}

	lladdr = ni_capture_from_hwaddr_print(from);
	ni_debug_socket("%s: incoming %s%spacket%s%s%s", capture->ifname,
			hint ? hint : "", hint ? " " : "",
			(partial_checksum ? " with partial checksum" : ""),
			lladdr ? " from " : "", lladdr ? lladdr : "");

	switch (capture->protocol) {
	case ETHERTYPE_IP:
		/* Make sure IP and UDP header are sane */
		payload = ni_capture_inspect_udp_header(capture->buffer, bytes,
						&payload_len, partial_checksum);
		if (payload == NULL) {
			ni_debug_socket("%s: bad IP/UDP %s%spacket header",
					capture->ifname,
					hint ? hint : "", hint ? " " : "");
			return -1;
		}
		break;

	case ETHERTYPE_ARP:
	case ETHERTYPE_LLDP:
		payload = capture->buffer;
		payload_len = bytes;
		break;

	default:
		ni_error("%s: %s cannot handle ethertype %u", capture->ifname,
				__FUNCTION__, capture->protocol);
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
 * Initialize capture device info
 */
int
ni_capture_devinfo_init(ni_capture_devinfo_t *devinfo, const char *ifname, const ni_linkinfo_t *link)
{
	memset(devinfo, 0, sizeof(*devinfo));
	ni_string_dup(&devinfo->ifname, ifname);
	devinfo->iftype = link->type;
	devinfo->ifindex = link->ifindex;
	devinfo->mtu = link->mtu ? link->mtu : MTU_MAX;
	devinfo->hwaddr = link->hwaddr;

	if (devinfo->hwaddr.len == 0) {
		ni_error("%s: empty MAC address, cannot do packet level networking yet",
			ifname);
		return -1;
	}
	if (devinfo->hwaddr.type == ARPHRD_VOID) {
		ni_error("%s: void arp type, cannot do packet level networking yet",
			ifname);
		return -1;
	}

	if (devinfo->hwaddr.type == ARPHRD_NONE) {
		ni_warn("%s: no arp type, trying to use ether for capturing", ifname);
		devinfo->hwaddr.type = ARPHRD_ETHER;
	}

	return 0;
}

int
ni_capture_devinfo_refresh(ni_capture_devinfo_t *devinfo, const char *ifname, const ni_linkinfo_t *link)
{
	if (!ni_string_eq(devinfo->ifname, ifname)) {
		ni_string_dup(&devinfo->ifname, ifname);
	}

	devinfo->mtu = link->mtu ? link->mtu : MTU_MAX;
	devinfo->hwaddr = link->hwaddr;

	if (devinfo->iftype != link->type) {
		ni_debug_socket("%s: reconfig changes device type from %s(%u) to %s(%u)",
				devinfo->ifname,
				ni_linktype_type_to_name(devinfo->iftype), devinfo->iftype,
				ni_linktype_type_to_name(link->type), link->type);
	}
	if (devinfo->ifindex != link->ifindex) {
		ni_error("%s: reconfig changes device index from %u to %u",
				devinfo->ifname, devinfo->ifindex, link->ifindex);
		return -1;
	}

	if (devinfo->hwaddr.len == 0) {
		ni_error("%s: empty MAC address, cannot do packet level networking yet",
			ifname);
		return -1;
	}
	if (devinfo->hwaddr.type == ARPHRD_VOID) {
		ni_error("%s: void arp type, cannot do packet level networking yet",
			ifname);
		return -1;
	}

	return 0;
}

/*
 * Open capture socket
 *
 * Dirty little secret: when opening an ETHERTYPE_IP socket, we will always
 * install a packet filter for DHCP. We need to get this out of the system at
 * some point.
 */
static void
__ni_capture_enable_packet_auxdata(int fd)
{
#if defined(PACKET_AUXDATA)
	int on = 1;

	if (setsockopt (fd, SOL_PACKET, PACKET_AUXDATA, &on, sizeof(on)) < 0) {
		if (errno != ENOPROTOOPT) {
			ni_error("cannot enable packet auxdata: %m");
		}
	}
#endif
}

static void
__ni_capture_init_once(void)
{
	static ni_bool_t done = FALSE;

	if (done)
		return;
	done = TRUE;

	/* load af_packet module we need for capturing */
	ni_modprobe(AFPACKET_MODULE_NAME, AFPACKET_MODULE_OPTS);
}

ni_capture_t *
ni_capture_open(const ni_capture_devinfo_t *devinfo, const ni_capture_protinfo_t *protinfo, void (*receive)(ni_socket_t *))
{
	ni_packetaddr_t	addr;
	ni_capture_t *capture = NULL;
	ni_hwaddr_t destaddr;
	int fd = -1;

	if (devinfo->ifindex == 0) {
		ni_error("no ifindex for interface `%s'", devinfo->ifname);
		return NULL;
	}
	if (protinfo->eth_protocol == 0) {
		ni_error("%s: bad ethernet protocol for dev %s", __func__, devinfo->ifname);
		return NULL;
	}

	/* Destination address defaults to broadcast */
	destaddr = protinfo->eth_destaddr;

	if (destaddr.len == 0
	 && ni_link_address_get_broadcast(devinfo->hwaddr.type, &destaddr) < 0) {
		ni_error("cannot get broadcast address for %s (bad iftype)", devinfo->ifname);
		return NULL;
	}

	__ni_capture_init_once();

	if ((fd = socket (PF_PACKET, SOCK_DGRAM, htons(protinfo->eth_protocol))) < 0) {
		ni_error("socket: %m");
		return NULL;
	}
	fcntl(fd, F_SETFD, FD_CLOEXEC);

	capture = calloc(1, sizeof(*capture));
	if (!capture)
		goto failed;
	ni_string_dup(&capture->ifname, devinfo->ifname);
	capture->sock = ni_socket_wrap(fd, SOCK_DGRAM);
	capture->protocol = protinfo->eth_protocol;

	capture->addr.sll.sll_family = AF_PACKET;
	capture->addr.sll.sll_protocol = htons(protinfo->eth_protocol);
	capture->addr.sll.sll_ifindex = devinfo->ifindex;
	capture->addr.sll.sll_hatype = htons(devinfo->hwaddr.type);
	capture->addr.sll.sll_halen = destaddr.len;
	memcpy(&capture->addr.sll.sll_addr, destaddr.data, destaddr.len);

	if (ni_capture_set_filter(capture, protinfo) < 0)
		goto failed;

	memset(&addr, 0, sizeof(addr));
	addr.sll.sll_family = PF_PACKET;
	addr.sll.sll_protocol = htons(protinfo->eth_protocol);
	addr.sll.sll_ifindex = devinfo->ifindex;

	if (bind(fd, &addr.sa, sizeof(addr)) == -1) {
		ni_error("bind: %m");
		goto failed;
	}

	__ni_capture_enable_packet_auxdata(fd);

	capture->mtu = devinfo->mtu;
	if (capture->mtu == 0)
		capture->mtu = MTU_MAX;
	capture->buffer = xmalloc(capture->mtu);

	capture->sock->receive = receive;
	capture->sock->get_timeout = __ni_capture_socket_get_timeout;
	capture->sock->check_timeout = __ni_capture_socket_check_timeout;
	capture->sock->user_data = capture;
	ni_socket_activate(capture->sock);
	return capture;

failed:
	ni_capture_free(capture);
	if (fd >= 0)
		close(fd);
	return NULL;
}

static int
ni_capture_set_filter(ni_capture_t *cap, const ni_capture_protinfo_t *protinfo)
{
	struct sock_fprog pf;

	/* Install the DHCP filter */
	memset(&pf, 0, sizeof(pf));

	switch (protinfo->eth_protocol) {
	case ETHERTYPE_ARP:
	case ETHERTYPE_LLDP:
		/* For pure link layer protocols, we do not need to install a
		 * filter, as we've already bound to a sll address where
		 * sll_protocol is set to the ethertype we want to match */
		return 0;

	case ETHERTYPE_IP:
		if (protinfo->ip_protocol != IPPROTO_UDP && protinfo->ip_protocol != IPPROTO_TCP) {
			ni_error("cannot build capture filter for IP proto %d, port %d: not supported",
					protinfo->ip_protocol, protinfo->ip_port);
			return -1;
		}

		std_ipv4_bpf_filter[1].k = protinfo->ip_protocol;
		std_ipv4_bpf_filter[6].k = protinfo->ip_port;

		pf.filter = std_ipv4_bpf_filter;
		pf.len = sizeof(std_ipv4_bpf_filter) / sizeof(std_ipv4_bpf_filter[0]);
		break;

	default:
		ni_error("cannot build capture filter for ether type 0x%04x: not supported", protinfo->eth_protocol);
		return -1;
	}

	if (setsockopt(cap->sock->__fd, SOL_SOCKET, SO_ATTACH_FILTER, &pf, sizeof(pf)) < 0) {
		ni_error("SO_ATTACH_FILTER: %m");
		return -1;
	}

	return 0;
}

ssize_t
__ni_capture_send(const ni_capture_t *capture, const ni_buffer_t *buf)
{
	ssize_t rv;

	if (capture == NULL) {
		ni_error("%s: no capture handle", __FUNCTION__);
		return -1;
	}

	rv = sendto(capture->sock->__fd, ni_buffer_head(buf), ni_buffer_count(buf), 0,
			&capture->addr.sa, sizeof(capture->addr));
	if (rv < 0)
		ni_error("unable to send dhcp packet: %m");

	return rv;
}

ssize_t
ni_capture_send(ni_capture_t *capture, const ni_buffer_t *buf, const ni_timeout_param_t *tmo)
{
	ssize_t rv;

	rv = __ni_capture_send(capture, buf);
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
	if (!capture)
		return;
	if (capture->sock)
		ni_socket_close(capture->sock);
	if (capture->buffer)
		free(capture->buffer);
	ni_string_free(&capture->ifname);
	free(capture);
}

