/*
 * General kernel functions for network config and discovery
 *
 * Copyright (C) 2009-2010 Olaf Kirch <okir@suse.de>
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <errno.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>

#include "netinfo_priv.h"
#include "sysfs.h"
#include "kernel.h"

#ifndef SIOCETHTOOL
# define SIOCETHTOOL	0x8946
#endif

/*
 * Helpers for SIOC* ioctls
 */
static int
__ni_ioctl(ni_handle_t *nih, int ioc, void *arg)
{
	if (nih->iocfd < 0) {
		nih->iocfd = socket(PF_INET, SOCK_DGRAM, 0);
		if (nih->iocfd < 0) {
			error("cannot create UDP socket: %m");
			return -1;
		}
	}

	return ioctl(nih->iocfd, ioc, arg);
}

/*
 * Query an ethernet type interface for ethtool information
 */
int
__ni_ethtool(ni_handle_t *nih, const ni_interface_t *ifp, int cmd, void *data)
{
	struct ifreq ifr;

	strncpy(ifr.ifr_name, ifp->name, IFNAMSIZ);
	((struct ethtool_cmd *) data)->cmd = cmd;
	ifr.ifr_data = data;

	if (__ni_ioctl(nih, SIOCETHTOOL, &ifr) < 0)
		return -1;
	return 0;
}

/*
 * Bridge helper functions
 */
int
__ni_brioctl_add_bridge(ni_handle_t *nih, const char *ifname)
{
	return __ni_ioctl(nih, SIOCBRADDBR, (char *) ifname);
}

int
__ni_brioctl_del_bridge(ni_handle_t *nih, const char *ifname)
{
	return __ni_ioctl(nih, SIOCBRDELBR, (char *) ifname);
}

int
__ni_brioctl_add_port(ni_handle_t *nih, const char *ifname, unsigned int port_index)
{
	struct ifreq ifr;

	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_ifindex = port_index;
	return __ni_ioctl(nih, SIOCBRADDIF, &ifr);
}

int
__ni_brioctl_del_port(ni_handle_t *nih, const char *ifname, unsigned int port_index)
{
	struct ifreq ifr;

	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_ifindex = port_index;
	return __ni_ioctl(nih, SIOCBRDELIF, &ifr);
}

int
__ni_rta_get_addr(int af, struct sockaddr_storage *ss, struct rtattr *rta)
{
	unsigned int alen, maxlen;
	void *dst;

	memset(ss, 0, sizeof(*ss));
	ss->ss_family = AF_UNSPEC;

	if (!rta)
		return 0;

	alen = RTA_PAYLOAD(rta);
	if (alen > sizeof(*ss))
		alen = sizeof(*ss);

	switch (af) {
	case AF_INET:
		dst = &((struct sockaddr_in *) ss)->sin_addr;
		maxlen = 4;
		break;

	case AF_INET6:
		dst = &((struct sockaddr_in6 *) ss)->sin6_addr;
		maxlen = 16;
		break;

	/* FIXME: support IPX and DECnet */

	default:
		return 0;
	}

	if (alen != maxlen)
		return 0;
	memcpy(dst, RTA_DATA(rta), alen);
	ss->ss_family = af;
	return 0;
}

int
__ni_rta_get_string(char **val, struct rtattr *rta)
{
	char *s = NULL;

	if (*val) {
		free(*val);
		*val = NULL;
	}
	if (rta) {
		unsigned int len = RTA_PAYLOAD(rta);

		if (len > 128)
			return -1;
		*val = s = malloc(len + 1);
		if (!s)
			return -1;
		memcpy(s, RTA_DATA(rta), len);
		s[len] = '\0';
	}
	return 0;
}

struct rtattr *
__ni_rta_begin_nested(struct nlmsghdr *nh, size_t size, int type)
{
	struct rtattr *rtattr = NLMSG_TAIL(nh);

	if (addattr_l(nh, size, type, NULL, 0) < 0)
		return NULL;
	return rtattr;
}

void
__ni_rta_end_nested(struct nlmsghdr *nh, struct rtattr *rtattr)
{
	rtattr->rta_len = (void *) NLMSG_TAIL(nh) - (void *) rtattr;
}

struct rtattr *
__ni_rta_begin_linkinfo(struct nlmsghdr *nh, size_t size, const char *kind)
{
	struct rtattr *linkinfo;

	if (!(linkinfo = __ni_rta_begin_nested(nh, size, IFLA_LINKINFO)))
		return NULL;

	if (kind) {
		int len = strlen(kind);

		if (addattr_l(nh, size, IFLA_INFO_KIND, kind, len) < 0)
			return NULL;
	}

	return linkinfo;
}

struct rtattr *
__ni_rta_find(struct rtattr *rta, size_t len, int type)
{
	while (RTA_OK(rta, len)) {
		if (rta->rta_type == type)
			return rta;
		rta = RTA_NEXT(rta, len);
	}
	return NULL;
}

/*
 * Handle a message exchange with the netlink layer.
 */
static int
__ni_rtnl_junk_handler(const struct sockaddr_nl *nladdr, struct nlmsghdr *nh, ni_handle_t *nih)
{
	warn("ni_rtnl_talk: received junk message of type=%d, flags=0x%x\n",
			nh->nlmsg_type, nh->nlmsg_flags);
	return 0;
}


int
ni_rtnl_talk(ni_handle_t *nih, struct nlmsghdr *nh)
{
	return rtnl_talk(&nih->rth, nh, 0, 0, NULL, (rtnl_filter_t) __ni_rtnl_junk_handler, nih);
}

struct __ni_rtnl_dump_state {
	ni_handle_t *	nih;
	void *			user_data;
	ni_rtnl_callback_t *	junk;
	ni_rtnl_callback_t *	filter;
};

static int
__ni_rtnl_dump_junk(const struct sockaddr_nl *nla,
		struct nlmsghdr *h,
		void *p)
{
	struct __ni_rtnl_dump_state *data = p;

	if (data->junk)
		return data->junk(data->nih, nla, h, data->user_data);
	return 0;
}

static int
__ni_rtnl_dump_filter(const struct sockaddr_nl *nla,
		struct nlmsghdr *h,
		void *p)
{
	struct __ni_rtnl_dump_state *data = p;

	if (data->filter)
		return data->filter(data->nih, nla, h, data->user_data);
	return 0;
}

int
ni_rtnl_dump(ni_handle_t *nih, int type,
		ni_rtnl_callback_t *junk_cb,
		ni_rtnl_callback_t *filter_cb,
		void *user_data)
{
	struct __ni_rtnl_dump_state data = {
		.nih = nih,
		.filter = filter_cb,
		.junk = junk_cb,
		.user_data = user_data,
	};
	int err;

	err = rtnl_wilddump_request(&nih->rth, AF_UNSPEC, type);
	if (err < 0) {
		perror("cannot send RTNL dump request");
		return -1;
	}

	err = rtnl_dump_filter(&nih->rth,
			__ni_rtnl_dump_filter, &data,
			__ni_rtnl_dump_junk, &data);
	if (err < 0)
		return err;

	return 0;
}

void
ni_nlmsg_list_init(struct ni_nlmsg_list *nll)
{
	nll->tail = &nll->head;
	nll->head = NULL;
}

void
ni_nlmsg_list_destroy(struct ni_nlmsg_list *nll)
{
	struct ni_nlmsg *entry;

	while ((entry = nll->head) != NULL) {
		nll->head = entry->next;
		free(entry);
	}
	nll->tail = &nll->head;
}

struct nlmsghdr *
ni_nlmsg_list_append(struct ni_nlmsg_list *nll, struct nlmsghdr *h)
{
	struct ni_nlmsg *entry;

	entry = malloc(sizeof(*entry) + h->nlmsg_len - sizeof(entry->h));
	if (!entry)
		return NULL;

	memcpy(&entry->h, h, h->nlmsg_len);

	*(nll->tail) = entry;
	nll->tail = &entry->next;
	entry->next = NULL;

	return &entry->h;
}

static int
__ni_rtnl_store_nlmsg(const struct sockaddr_nl *nla,
		struct nlmsghdr *h,
		void *p)
{
	struct ni_nlmsg_list *nll = p;

	/* FIXME: look at sender addr to prevent rtnetlink spoofing */

	if (!ni_nlmsg_list_append(nll, h))
		return -1;
	return 0;
}

int
ni_rtnl_dump_store(ni_handle_t *nih, int type,
			struct ni_nlmsg_list *list)
{
	int err;

	err = rtnl_wilddump_request(&nih->rth, AF_UNSPEC, type);
	if (err < 0) {
		perror("cannot send RTNL dump request");
		return -1;
	}

	err = rtnl_dump_filter(&nih->rth,
			__ni_rtnl_store_nlmsg, list,
			NULL, NULL);
	if (err < 0)
		return err;

	return 0;
}
