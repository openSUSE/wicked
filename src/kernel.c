/*
 * General kernel functions for network config and discovery
 *
 * Copyright (C) 2009-2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <linux/if_tun.h>
#include <linux/ppp_defs.h>
#define aligned_u64 uint64_t
#include <linux/if_ppp.h>
#include <netlink/msg.h>
#include <netlink/route/rtnl.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/family.h>

#include "netinfo_priv.h"
#include "util_priv.h"
#include "sysfs.h"
#include "kernel.h"
#include <wicked/ppp.h>

/* FIXME: we should really make this configurable */
#ifndef CONFIG_TUNTAP_CHRDEV_PATH
# define CONFIG_TUNTAP_CHRDEV_PATH	"/dev/net/tun"
#endif
#ifndef CONFIG_PPP_CHRDEV_PATH
# define CONFIG_PPP_CHRDEV_PATH		"/dev/ppp"
#endif

#ifndef SIOCETHTOOL
# define SIOCETHTOOL	0x8946
#endif

ni_netlink_t *		__ni_global_netlink;
int			__ni_global_iocfd = -1;

/*
 * Helpers for SIOC* ioctls
 */
static int
__ni_ioctl(int ioc, void *arg)
{
	if (__ni_global_iocfd < 0) {
		__ni_global_iocfd = socket(PF_INET, SOCK_DGRAM, 0);
		if (__ni_global_iocfd < 0) {
			ni_error("cannot create UDP socket: %m");
			return -1;
		}
	}

	return ioctl(__ni_global_iocfd, ioc, arg);
}

/*
 * Rename a network interface
 */
int
__ni_netdev_rename(const char *old_name, const char *new_name)
{
	struct ifreq ifr;

	if (ni_string_eq(old_name, new_name))
		return 0;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, old_name, sizeof(ifr.ifr_name));
	strncpy(ifr.ifr_newname, new_name, sizeof(ifr.ifr_newname));

	if (__ni_ioctl(SIOCSIFNAME, &ifr) < 0) {
		ni_error("unable to rename network device %s to %s: %m",
				old_name, new_name);
		return -1;
	}

	return 0;
}

/*
 * Query an ethernet type interface for ethtool information
 */
int
__ni_ethtool(const char *ifname, int cmd, void *data)
{
	struct ifreq ifr;

	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	((struct ethtool_cmd *) data)->cmd = cmd;
	ifr.ifr_data = data;

	if (__ni_ioctl(SIOCETHTOOL, &ifr) < 0)
		return -1;
	return 0;
}

/*
 * Call a wireless extension
 */
int
__ni_wireless_ext(const ni_netdev_t *dev, int cmd,
			void *data, size_t data_len, unsigned int flags)
{
	struct iwreq iwr;

	strncpy(iwr.ifr_name, dev->name, IFNAMSIZ);
	iwr.u.data.pointer = data;
	iwr.u.data.length = data_len;
	iwr.u.data.flags = flags;

	if (__ni_ioctl(cmd, &iwr) < 0)
		return -1;
	/* Not optimal yet */
	return iwr.u.data.length;
}

/*
 * Bridge helper functions
 */
int
__ni_brioctl_add_bridge(const char *ifname)
{
	return __ni_ioctl(SIOCBRADDBR, (char *) ifname);
}

int
__ni_brioctl_del_bridge(const char *ifname)
{
	return __ni_ioctl(SIOCBRDELBR, (char *) ifname);
}

int
__ni_brioctl_add_port(const char *ifname, unsigned int port_index)
{
	struct ifreq ifr;

	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_ifindex = port_index;
	return __ni_ioctl(SIOCBRADDIF, &ifr);
}

int
__ni_brioctl_del_port(const char *ifname, unsigned int port_index)
{
	struct ifreq ifr;

	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_ifindex = port_index;
	return __ni_ioctl(SIOCBRDELIF, &ifr);
}

/*
 * Wireless extension ioctls
 */
int
__ni_wireless_get_name(const char *name, char *result, size_t size)
{
	struct iwreq iwreq;

	memset(&iwreq, 0, sizeof(iwreq));
	strncpy(iwreq.ifr_name, name, IFNAMSIZ);
	if (__ni_ioctl(SIOCGIWNAME, &iwreq) < 0)
		return -1;

	if (size) {
		strncpy(result, iwreq.ifr_name, size-1);
		result[size-1] = '\0';
	}
	return 0;
}

int
__ni_wireless_get_essid(const char *name, char *result, size_t size)
{
	char buffer[IW_ESSID_MAX_SIZE];
	struct iwreq iwreq;

	memset(&iwreq, 0, sizeof(iwreq));
	strncpy(iwreq.ifr_name, name, IFNAMSIZ);
	iwreq.u.essid.pointer = buffer;
	iwreq.u.essid.length = sizeof(buffer);
	if (__ni_ioctl(SIOCGIWESSID, &iwreq) < 0)
		return -1;

	if (size) {
		strncpy(result, buffer, size-1);
		result[size-1] = '\0';
	}
	return 0;
}

/*
 * Create/delete a tun/tap device
 * Yet another API variant for interface creation...
 */
static int
__ni_tuntap_open_dev(void)
{
	int devfd;

	if ((devfd = open(CONFIG_TUNTAP_CHRDEV_PATH, O_RDWR)) < 0)
		ni_error("unable to open %s: %m", CONFIG_TUNTAP_CHRDEV_PATH);

	return devfd;
}

char *
__ni_tuntap_create_tun(const char *ifname)
{
	unsigned int index = 0;
	struct ifreq ifr;
	int devfd;
	char *retname = NULL;

	if ((devfd = __ni_tuntap_open_dev()) < 0)
		return NULL;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_TUN_EXCL;

	while (1) {
		/* If the caller didn't specify an interface name, we try
		 * all tunX names in turn until we find a free one.
		 */
		if (ifname != NULL)
			strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
		else
			snprintf(ifr.ifr_name, IFNAMSIZ, "tun%u", index++);

		if (ioctl(devfd, TUNSETIFF, &ifr) >= 0) {
			retname = xstrdup(ifr.ifr_name);

			(void) ioctl(devfd, TUNSETPERSIST, 1);
			break;
		}

		if (errno != EBUSY || ifname) {
			ni_error("failed to create tun device: %m");
			goto done;
		}
	}

done:
	close(devfd);
	return retname;
}

int
__ni_tuntap_delete(const char *ifname)
{
	struct ifreq ifr;
	int devfd, rv = -1;

	ni_trace("%s(%s)", __func__, ifname);
	if ((devfd = __ni_tuntap_open_dev()) < 0)
		return -1;

	/* To destroy the interface, attach it to the chrdev, unset the
	 * PERSIST flag, and close the chrdev. */
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_flags = IFF_TUN;

	if (ioctl(devfd, TUNSETIFF, &ifr) < 0) {
		ni_error("%s: cannot attach tun device: %m", ifname);
	} else
	if (ioctl(devfd, TUNSETPERSIST, 0) < 0) {
		ni_error("%s: unable to unset persist flag: %m", ifname);
	} else {
		rv = 0;
	}

	close(devfd);
	return rv;
}

/*
 * Create a ppp device
 */
char *
__ni_ppp_create_device(ni_ppp_t *ppp, const char *ifname)
{
	int devfd, ifunit = -1;

	if (ppp->devfd >= 0) {
		ni_error("%s: this ppp handle already has a devfd?", __func__);
		return NULL;
	}

	if ((devfd = open(CONFIG_PPP_CHRDEV_PATH, O_RDWR)) < 0) {
		ni_error("unable to open %s: %m", CONFIG_PPP_CHRDEV_PATH);
		return NULL;
	}

	/* If we're asked to create a device named pppN, assume we should be
	 * creating the device with the specified ppp unit N */
	if (ifname && !strncmp(ifname, "ppp", 3)) {
		if(ni_parse_int(ifname + 3, &ifunit, 10) >= 0 && ifunit >= 0)
			ifname = NULL;
		else
			ifunit = -1;
	}

	if (ioctl(devfd, PPPIOCNEWUNIT, &ifunit) < 0) {
		ni_error("unable to create new PPP network device: %m");
		close(devfd);
		return NULL;
	}

	snprintf(ppp->devname, sizeof(ppp->devname), "ppp%u", ifunit);
	if (ifname != NULL) {
		if (__ni_netdev_rename(ppp->devname, ifname) < 0) {
			close(devfd);
			return NULL;
		}
		strncpy(ppp->devname, ifname, sizeof(ppp->devname));
	}

	ppp->devfd = devfd;
	ppp->unit = ifunit;
	return ppp->devname;
}

/*
 * rtnetlink attribute handling
 */
const void *
__ni_nla_get_data(size_t minlen, const struct nlattr *nla)
{
	int len;

	if (!nla || (len = nla_len(nla)) < 0 || (size_t)len < minlen)
		return NULL;

	return nla_data(nla);
}

int
__ni_nla_get_addr(int af, ni_sockaddr_t *ss, const struct nlattr *nla)
{
	size_t alen, maxlen;
	void *dst;

	memset(ss, 0, sizeof(*ss));
	ss->ss_family = AF_UNSPEC;

	if (!nla || nla_len(nla) < 0)
		return 1; /* empty attr */

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

	/* TODO: support IPX and DECnet */
	default:
		return -1;
	}

	if (alen != maxlen)
		return -1;

	memcpy(dst, nla_data(nla), alen);
	ss->ss_family = af;
	return 0;
}

/*
 * Open netlink handle; usually for rtnetlink
 */
ni_netlink_t *
__ni_netlink_open(int protocol)
{
	ni_netlink_t *nl;

	nl = xcalloc(1, sizeof(*nl));
	nl->nl_cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (nl->nl_cb == NULL) {
		ni_error("nl_cb_alloc failed");
		goto failed;
	}

	nl->nl_handle = nl_handle_alloc_cb(nl->nl_cb);
	if (nl_connect(nl->nl_handle, protocol) < 0) {
		ni_error("nl_connect failed: %m");
		goto failed;
	}

	return nl;

failed:
	__ni_netlink_close(nl);
	return NULL;
}

void
__ni_netlink_close(ni_netlink_t *nl)
{
	if (nl->nl_family)
		genl_family_put(nl->nl_family);
	if (nl->nl_cache)
		nl_cache_free(nl->nl_cache);
	if (nl->nl_handle)
		nl_handle_destroy(nl->nl_handle);
	if (nl->nl_cb)
		nl_cb_put(nl->nl_cb);

	free(nl);
}

static int
__ni_nl_ack_handler(struct nl_msg *msg, void *arg)
{
	int *p = arg;
	*p = 1;
	return NL_STOP;
}

static int
__ni_nl_error_handler(struct sockaddr_nl *sender, struct nlmsgerr *err, void *arg)
{
	ni_debug_ifconfig("netlink reports error %d", err->error);
	*(int *) arg = - err->error;
	return NL_STOP;
}

static struct nl_cb *
__ni_nl_cb_clone(ni_netlink_t *nl)
{
	struct nl_cb *cb, *ocb;

	if ((cb = nl->nl_cb) != NULL) {
		cb = nl_cb_clone(cb);
	} else {
		ocb = nl_socket_get_cb(nl->nl_handle);
		cb = nl_cb_clone(ocb);
		nl_cb_put(ocb);
	}
	return cb;
}

/*
 * Handle a message exchange with the netlink layer.
 */
int
__ni_nl_talk(ni_netlink_t *nl, struct nl_msg *msg,
		int (*valid_handler)(struct nl_msg *, void *), void *user_data)
{
	struct nl_handle *handle;
	struct nl_cb *cb;
	int err = 0, ack = 0;

	if (!(handle = nl->nl_handle)) {
		ni_error("%s: no netlink handle", __func__);
		return -1;
	}

	if (nl_send_auto_complete(handle, msg) < 0) {
		ni_error("%s: unable to send", __func__);
		return -1;
	}

	if (!(cb = __ni_nl_cb_clone(nl)))
		return -1;

	nl_cb_err(cb, NL_CB_CUSTOM, __ni_nl_error_handler, &err);
	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, __ni_nl_ack_handler, &ack);
#if 0
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
#endif

	if (valid_handler)
		nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, valid_handler, user_data);

	/* libnl sets NLM_F_ACK per default, wait for ack before proceeding */
	do {
		if ((err = nl_recvmsgs(handle, cb)) < 0) {
			ni_error("%s: recv failed: %s", __func__, nl_geterror());
			if (err == -EEXIST)
				err = 0;
			break;
		}
	} while (ack == 0);

	nl_cb_put(cb);
	return err;
}

/*
 * Helper functions for storing all netlink responses in a list
 */
struct __ni_nl_dump_state {
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
		return NL_SKIP;
	}

	if (data->list == NULL)
		return NL_OK;

	nlh = nlmsg_hdr(msg);
	if (data->hdrlen && !nlmsg_valid_hdr(nlh, data->hdrlen)) {
		ni_error("netlink message too short");
		return NL_SKIP;
	}

	if (data->msg_type >= 0 && nlh->nlmsg_type != data->msg_type) {
		ni_error("netlink has unexpected message type %d; expected %d",
				nlh->nlmsg_type, data->msg_type);
		return NL_SKIP;
	}


	if (!ni_nlmsg_list_append(data->list, nlh))
		return NL_SKIP;

	return NL_OK;
}

/*
 * Issue a DUMP request and store all replies in list
 */
int
ni_nl_dump_store(int af, int type, struct ni_nlmsg_list *list)
{
	struct nl_handle *handle;
	struct __ni_nl_dump_state data = {
		.msg_type = -1,
		.list = list,
	};
	struct nl_cb *cb;

	if (!__ni_global_netlink || !(handle = __ni_global_netlink->nl_handle)) {
		ni_error("%s: no netlink handle", __func__);
		return -1;
	}

	if (nl_rtgen_request(handle, type, af, NLM_F_DUMP) < 0) {
		ni_error("%s: failed to send request", __func__);
		return -1;
	}

	if (!(cb = __ni_nl_cb_clone(__ni_global_netlink)))
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

/*
 * Send a message and capture the response message(s)
 */
int
ni_nl_talk(struct nl_msg *msg, struct ni_nlmsg_list *list)
{

	if (!__ni_global_netlink) {
		ni_error("%s: no netlink handle", __func__);
		return -1;
	}

	if (list == NULL) {
		return __ni_nl_talk(__ni_global_netlink, msg, NULL, NULL);
	} else {
		struct __ni_nl_dump_state data = {
			.msg_type = -1,
			.list = list,
		};

		return __ni_nl_talk(__ni_global_netlink, msg, __ni_nl_dump_valid, &data);
	}
}

