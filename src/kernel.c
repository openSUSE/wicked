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
#include <wicked/tuntap.h>

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

	memset(&ifr, 0, sizeof(ifr));
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

	memset(&iwr, 0, sizeof(iwr));
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

int
__ni_tuntap_create(const ni_netdev_t *cfg)
{
	const char *iftype;
	struct ifreq ifr;
	int devfd = -1;
	uid_t owner;
	gid_t group;
	int rv = -1;

	if (!cfg || !cfg->tuntap || ni_string_empty(cfg->name))
		goto error;

	if ((NI_IFTYPE_TUN != cfg->link.type && NI_IFTYPE_TAP != cfg->link.type) ||
			!(iftype = ni_linktype_type_to_name(cfg->link.type)))
		goto error;

	if ((devfd = __ni_tuntap_open_dev()) < 0)
		goto error;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_NO_PI;
	ifr.ifr_flags |= (NI_IFTYPE_TUN == cfg->link.type ? IFF_TUN : IFF_TAP);
	strncpy(ifr.ifr_name, cfg->name, sizeof(ifr.ifr_name) - 1);

	if ((rv = ioctl(devfd, TUNSETIFF, (void *) &ifr)) < 0) {
		ni_error("%s: failed to create %s device: %m", cfg->name, iftype);
		goto error;
	}

	if ((rv = ioctl(devfd, TUNSETPERSIST, 1)) < 0) {
		ni_error("%s: failed to set %s device persistent: %m", cfg->name, iftype);
		goto error;
	}

	owner = cfg->tuntap->owner;
	group = cfg->tuntap->group;

	if (owner == -1U && group == -1U)
		owner = geteuid();

	if (owner != -1U) {
		if ((rv = ioctl(devfd, TUNSETOWNER, owner)) < 0) {
			ni_warn("%s: cannot set %s device owner to %d",
					cfg->name, iftype, owner);
			/* do not fail ? */
		}
	}

	if (group != -1U) {
		if ((rv = ioctl(devfd, TUNSETGROUP, group)) < 0) {
			ni_warn("%s: cannot set %s device group to %d",
					cfg->name, iftype, group);
			/* do not fail ? */
		}
	}

	rv = 0;
error:
	if (devfd >= 0)
		close(devfd);
	return rv;
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

	nl->nl_sock = nl_socket_alloc_cb(nl->nl_cb);
	if (nl_connect(nl->nl_sock, protocol) < 0) {
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
	if (nl->nl_sock)
		nl_socket_free(nl->nl_sock);
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
		ocb = nl_socket_get_cb(nl->nl_sock);
		cb = nl_cb_clone(ocb);
		nl_cb_put(ocb);
	}
	return cb;
}

/*
 * Handle a message exchange with the netlink layer.
 */
static int
__ni_nl_talk(ni_netlink_t *nl, struct nl_msg *msg,
		int (*valid_handler)(struct nl_msg *, void *), void *user_data)
{
	struct nl_sock *nl_sock;
	struct nl_cb *cb;
	int err = 0, ack = 0;

	if (!(nl_sock = nl->nl_sock)) {
		ni_error("%s: no netlink socket", __func__);
		return -NLE_BAD_SOCK;
	}

	if ((err = nl_send_auto(nl_sock, msg)) < 0) {
		ni_error("%s: unable to send: %s", __func__, nl_geterror(err));
		return err;
	}

	if (!(cb = __ni_nl_cb_clone(nl)))
		return -NLE_NOMEM;

	nl_cb_err(cb, NL_CB_CUSTOM, __ni_nl_error_handler, &err);
	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, __ni_nl_ack_handler, &ack);
#if 0
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
#endif

	if (valid_handler)
		nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, valid_handler, user_data);

	/* libnl sets NLM_F_ACK per default, wait for ack before proceeding */
	do {
		if ((err = nl_recvmsgs(nl_sock, cb)) < 0) {
			ni_debug_socket("%s: recv failed: %s", __func__, nl_geterror(err));
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
	struct nl_sock *nl_sock;
	struct __ni_nl_dump_state data = {
		.msg_type = -1,
		.list = list,
	};
	struct nl_cb *cb;
	const char *name;
	int rv;

	name = ni_rtnl_msg_type_to_name(type, __func__);
	if (!__ni_global_netlink || !(nl_sock = __ni_global_netlink->nl_sock)) {
		ni_error("%s: no netlink socket", name);
		return -NLE_BAD_SOCK;
	}

	if ((rv = nl_rtgen_request(nl_sock, type, af, NLM_F_DUMP)) < 0) {
		ni_error("%s: failed to send request", name);
		return rv;
	}

	if (!(cb = __ni_nl_cb_clone(__ni_global_netlink)))
		return -NLE_NOMEM;

	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, __ni_nl_dump_valid, &data);

retry:
	rv = nl_recvmsgs(nl_sock, cb);
	switch (rv) {
	case NLE_SUCCESS:
		break;
	case -NLE_AGAIN:
		/* debug only, we retry to receive */
		ni_debug_socket("%s: failed to receive response: %s",
				name, nl_geterror(rv));
		goto retry;
	case -NLE_DUMP_INTR:
		/* debug only, we repeat the query */
		ni_debug_socket("%s: failed to receive response: %s",
				name, nl_geterror(rv));
		break;
	default:
		ni_error("%s: failed to receive response: %s",
				name, nl_geterror(rv));
		break;
	}
	nl_cb_put(cb);
	return rv;
}

/*
 * Send a message and capture the response message(s)
 */
int
ni_nl_talk(struct nl_msg *msg, struct ni_nlmsg_list *list)
{

	if (!__ni_global_netlink) {
		ni_error("%s: no netlink socket", __func__);
		return -NLE_BAD_SOCK;
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

#define ni_t2n(x)	[x] = #x
static const char *	ni_rtnl_msg_type_names[RTM_MAX] = {
#ifdef	RTM_NEWLINK
	ni_t2n(RTM_NEWLINK),
	ni_t2n(RTM_DELLINK),
	ni_t2n(RTM_GETLINK),
	ni_t2n(RTM_SETLINK),
#endif
#ifdef	RTM_NEWADDR
	ni_t2n(RTM_NEWADDR),
	ni_t2n(RTM_DELADDR),
	ni_t2n(RTM_GETADDR),
#endif
#ifdef	RTM_NEWROUTE
	ni_t2n(RTM_NEWROUTE),
	ni_t2n(RTM_DELROUTE),
	ni_t2n(RTM_GETROUTE),
#endif
#ifdef	RTM_NEWNEIGH
	ni_t2n(RTM_NEWNEIGH),
	ni_t2n(RTM_DELNEIGH),
	ni_t2n(RTM_GETNEIGH),
#endif
#ifdef	RTM_NEWRULE
	ni_t2n(RTM_NEWRULE),
	ni_t2n(RTM_DELRULE),
	ni_t2n(RTM_GETRULE),
#endif
#ifdef	RTM_NEWQDISC
	ni_t2n(RTM_NEWQDISC),
	ni_t2n(RTM_DELQDISC),
	ni_t2n(RTM_GETQDISC),
#endif
#ifdef	RTM_NEWTCLASS
	ni_t2n(RTM_NEWTCLASS),
	ni_t2n(RTM_DELTCLASS),
	ni_t2n(RTM_GETTCLASS),
#endif
#ifdef	RTM_NEWTFILTER
	ni_t2n(RTM_NEWTFILTER),
	ni_t2n(RTM_DELTFILTER),
	ni_t2n(RTM_GETTFILTER),
#endif
#ifdef	RTM_NEWACTION
	ni_t2n(RTM_NEWACTION),
	ni_t2n(RTM_DELACTION),
	ni_t2n(RTM_GETACTION),
#endif
#ifdef	RTM_NEWPREFIX
	ni_t2n(RTM_NEWPREFIX),
#endif
#ifdef	RTM_GETMULTICAST
	ni_t2n(RTM_GETMULTICAST),
#endif
#ifdef	RTM_GETANYCAST
	ni_t2n(RTM_GETANYCAST),
#endif
#ifdef	RTM_NEWNEIGHTBL
	ni_t2n(RTM_NEWNEIGHTBL),
	ni_t2n(RTM_GETNEIGHTBL),
	ni_t2n(RTM_SETNEIGHTBL),
#endif
#ifdef	RTM_NEWNDUSEROPT
	ni_t2n(RTM_NEWNDUSEROPT),
#endif
#ifdef	RTM_NEWADDRLABEL
	ni_t2n(RTM_NEWADDRLABEL),
	ni_t2n(RTM_DELADDRLABEL),
	ni_t2n(RTM_GETADDRLABEL),
#endif
#ifdef	RTM_GETDCB
	ni_t2n(RTM_GETDCB),
	ni_t2n(RTM_SETDCB),
#endif
#ifdef	RTM_NEWNETCONF
	ni_t2n(RTM_NEWNETCONF),
	ni_t2n(RTM_GETNETCONF),
#endif
#ifdef	RTM_NEWMDB
	ni_t2n(RTM_NEWMDB),
	ni_t2n(RTM_DELMDB),
	ni_t2n(RTM_GETMDB),
#endif
#ifdef	RTM_NEWNSID
	ni_t2n(RTM_NEWNSID),
	ni_t2n(RTM_DELNSID),
	ni_t2n(RTM_GETNSID),
#endif
};
#undef	ni_t2n

const char *
ni_rtnl_msg_type_to_name(unsigned int type, const char *unknown)
{
	if (type > RTM_BASE && type < RTM_MAX)
		return ni_rtnl_msg_type_names[type];
	else
		return unknown;
}

