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
#include <net/if_arp.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <netlink/msg.h>
#include <netlink/route/rtnl.h>

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
 * Call a wireless extension
 */
int
__ni_wireless_ext(ni_handle_t *nih, const ni_interface_t *ifp, int cmd,
			void *data, size_t data_len, unsigned int flags)
{
	struct iwreq iwr;

	strncpy(iwr.ifr_name, ifp->name, IFNAMSIZ);
	iwr.u.data.pointer = data;
	iwr.u.data.length = data_len;
	iwr.u.data.flags = flags;

	if (__ni_ioctl(nih, cmd, &iwr) < 0)
		return -1;
	/* Not optimal yet */
	return iwr.u.data.length;
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

/*
 * Wireless extension ioctls
 */
int
__ni_wireless_get_name(ni_handle_t *nih, const ni_interface_t *ifp, char *result, size_t size)
{
	struct iwreq iwreq;

	memset(&iwreq, 0, sizeof(iwreq));
	strncpy(iwreq.ifr_name, ifp->name, IFNAMSIZ);
	if (__ni_ioctl(nih, SIOCGIWNAME, &iwreq) < 0)
		return -1;

	if (size) {
		strncpy(result, iwreq.ifr_name, size-1);
		result[size-1] = '\0';
	}
	return 0;
}

int
__ni_wireless_get_essid(ni_handle_t *nih, const ni_interface_t *ifp, char *result, size_t size)
{
	char buffer[IW_ESSID_MAX_SIZE];
	struct iwreq iwreq;

	memset(&iwreq, 0, sizeof(iwreq));
	strncpy(iwreq.ifr_name, ifp->name, IFNAMSIZ);
	iwreq.u.essid.pointer = buffer;
	iwreq.u.essid.length = sizeof(buffer);
	if (__ni_ioctl(nih, SIOCGIWESSID, &iwreq) < 0)
		return -1;

	if (size) {
		strncpy(result, buffer, size-1);
		result[size-1] = '\0';
	}
	return 0;
}

/*
 * rtnetlink attribute handling
 */
int
__ni_nla_get_addr(int af, ni_sockaddr_t *ss, struct nlattr *nla)
{
	unsigned int alen, maxlen;
	void *dst;

	memset(ss, 0, sizeof(*ss));
	ss->ss_family = AF_UNSPEC;

	if (!nla)
		return 0;

	alen = nla_len(nla);
	if (alen > sizeof(*ss))
		alen = sizeof(*ss);

	switch (af) {
	case AF_INET:
		dst = &ss->sin.sin_addr;
		maxlen = 4;
		break;

	case AF_INET6:
		dst = &ss->six.sin6_addr;
		maxlen = 16;
		break;

	/* FIXME: support IPX and DECnet */

	default:
		return 0;
	}

	if (alen != maxlen)
		return 0;
	memcpy(dst, nla_data(nla), alen);
	ss->ss_family = af;
	return 0;
}

static int
__ni_nl_ack_handler(struct nl_msg *msg, void *arg)
{
	*(int *) arg = 0;
	return NL_STOP;
}

static int
__ni_nl_error_handler(struct sockaddr_nl *sender, struct nlmsgerr *err, void *arg)
{
	ni_debug_ifconfig("netlink reports error %d", err->error);
	*(int *) arg = - err->error;
	return NL_STOP;
}

/*
 * Handle a message exchange with the netlink layer.
 */
int
ni_nl_talk(ni_handle_t *nih, struct nl_msg *msg)
{
	struct nl_handle *handle;
	struct nl_cb *cb, *ocb;
	int err = 0;

	if (!(handle = nih->nlh)) {
		ni_error("%s: no netlink handle", __func__);
		return -1;
	}

	if (nl_send_auto_complete(handle, msg) < 0) {
		ni_error("%s: unable to send", __func__);
		return -1;
	}

	ocb = nl_socket_get_cb(handle);
	cb = nl_cb_clone(ocb);
	nl_cb_put(ocb);

	if (!cb)
		return -1;

	nl_cb_err(cb, NL_CB_CUSTOM, __ni_nl_error_handler, &err);
	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, __ni_nl_ack_handler, &err);
#if 0
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);

	if (valid_handler)
		nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, valid_handler, valid_data);
#endif

	if ((err = nl_recvmsgs(handle, cb)) < 0) {
		ni_error("%s: recv failed: %s", __func__, nl_geterror());
		nl_cb_put(cb);
		return -1;
	}

	nl_cb_put(cb);
	return err;
}

struct __ni_nl_dump_state {
	ni_handle_t *		nih;
	int			msg_type;
	unsigned int		hdrlen;
	struct ni_nlmsg_list *	list;
};

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
__ni_nl_dump_valid(struct nl_msg *msg, void *p)
{
	const struct sockaddr_nl *sender = nlmsg_get_src(msg);
	struct __ni_nl_dump_state *data = p;
	struct nlmsghdr *nlh;

	if (sender->nl_pid) {
		ni_warn("received netlink message from %d - spoof", sender->nl_pid);
		return -1;
	}

	if (data->list == NULL)
		return 0;

	nlh = nlmsg_hdr(msg);
	if (data->hdrlen && !nlmsg_valid_hdr(nlh, data->hdrlen)) {
		ni_error("netlink message too short");
		return -EINVAL;
	}

	if (data->msg_type >= 0 && nlh->nlmsg_type != data->msg_type) {
		ni_error("netlink has unexpected message type %d; expected %d",
				nlh->nlmsg_type, data->msg_type);
		return -EINVAL;
	}


	if (!ni_nlmsg_list_append(data->list, nlh))
		return -1;

	return 0;
}

int
ni_nl_dump_store(ni_handle_t *nih, int af, int type,
			struct ni_nlmsg_list *list)
{
	struct nl_handle *handle;
	struct nl_cb *cb, *ocb;
	struct __ni_nl_dump_state data = {
		.nih = nih,
		.msg_type = -1,
		.list = list,
	};

	if (!(handle = nih->nlh)) {
		ni_error("%s: no netlink handle", __func__);
		return -1;
	}

	if (nl_rtgen_request(handle, type, af, NLM_F_DUMP) < 0) {
		ni_error("%s: failed to send request", __func__);
		return -1;
	}

	ocb = nl_socket_get_cb(handle);
	cb = nl_cb_clone(ocb);
	nl_cb_put(ocb);

	if (!cb)
		return -1;

	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, __ni_nl_dump_valid, &data);

	if (nl_recvmsgs(handle, cb) < 0) {
		ni_error("%s: failed to receive response", __func__);
		nl_cb_put(cb);
		return -1;
	}

	nl_cb_put(cb);
	return 0;
}

