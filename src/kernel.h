/*
 * General kernel functions for network config and discovery
 *
 * Copyright (C) 2009-2010 Olaf Kirch <okir@suse.de>
 */

#ifndef __NETINFO_KERNEL_H__
#define __NETINFO_KERNEL_H__

#include <net/if.h>
#include <netlink/netlink.h>

#define __user /* unclean header file */
#include <wireless.h>

struct __ni_netlink {
	struct nl_handle *	nl_handle;
	struct nl_cache *	nl_cache;
	struct nl_cb *		nl_cb;
	struct genl_family *	nl_family;
};

static inline int
__ni_rta_get_uint(uint *val, struct rtattr *rta)
{
	if (rta)
		*val = *(uint *) RTA_DATA(rta);
	return 0;
}

static inline int
__ni_rta_get_uint16(uint16_t *val, struct rtattr *rta)
{
	if (rta)
		*val = *(uint16_t *) RTA_DATA(rta);
	return 0;
}

extern int		__ni_ethtool(const char *, int, void *);
extern int		__ni_wireless_ext(const ni_interface_t *ifp, int cmd,
				void *data, size_t data_len, unsigned int flags);
extern int		__ni_brioctl_add_bridge(const char *);
extern int		__ni_brioctl_del_bridge(const char *);
extern int		__ni_brioctl_add_port(const char *, unsigned int);
extern int		__ni_brioctl_del_port(const char *, unsigned int);

extern int		__ni_wireless_get_name(ni_handle_t *, const char *, char *, size_t);
extern int		__ni_wireless_get_essid(ni_handle_t *, const char *, char *, size_t);

extern int		__ni_nla_get_addr(int, ni_sockaddr_t *, struct nlattr *);
extern struct nlattr *	__ni_nla_find(struct nlattr *, size_t len, int type);

/*
 * Chain nlmsghdrs together.
 */
struct ni_nlmsg {
	struct ni_nlmsg *	next;
	struct nlmsghdr		h;
};

struct ni_nlmsg_list {
	struct ni_nlmsg *	head;
	struct ni_nlmsg **	tail;
};

extern int	ni_nl_talk(struct nl_msg *);
extern int	ni_nl_dump_store(int af, int type, struct ni_nlmsg_list *list);

extern void	ni_nlmsg_list_init(struct ni_nlmsg_list *);
extern void	ni_nlmsg_list_destroy(struct ni_nlmsg_list *);

static inline void *
__ni_rtnl_msgdata(struct nlmsghdr *h, int expected_type, size_t min_size)
{
	if (expected_type >= 0 && h->nlmsg_type != expected_type)
		return NULL;
	if (h->nlmsg_len < min_size)
		return NULL;
	return NLMSG_DATA(h);
}

static inline struct ifinfomsg *
ni_rtnl_ifinfomsg(struct nlmsghdr *h, int expected_type)
{
	return __ni_rtnl_msgdata(h, expected_type, sizeof(struct ifinfomsg));
}

static inline struct ifaddrmsg *
ni_rtnl_ifaddrmsg(struct nlmsghdr *h, int expected_type)
{
	return __ni_rtnl_msgdata(h, expected_type, sizeof(struct ifaddrmsg));
}

static inline struct rtmsg *
ni_rtnl_rtmsg(struct nlmsghdr *h, int expected_type)
{
	return __ni_rtnl_msgdata(h, expected_type, sizeof(struct rtmsg));
}

static inline struct prefixmsg *
ni_rtnl_prefixmsg(struct nlmsghdr *h, int expected_type)
{
	return __ni_rtnl_msgdata(h, expected_type, sizeof(struct prefixmsg));
}

extern int	__ni_interface_process_newlink(ni_interface_t *, struct nlmsghdr *,
				struct ifinfomsg *, ni_handle_t *);
extern int	__ni_interface_process_newlink_ipv6(ni_interface_t *, struct nlmsghdr *,
				struct ifinfomsg *, ni_handle_t *);
extern int	__ni_interface_process_newprefix(ni_interface_t *, struct nlmsghdr *,
				struct prefixmsg *, ni_handle_t *);

#ifndef IFF_LOWER_UP
# define IFF_LOWER_UP	0x10000
#endif

/* prefixmsg flags */
#ifndef IF_PREFIX_ONLINK
# define IF_PREFIX_ONLINK	0x01
#endif
#ifndef IF_PREFIX_AUTOCONF
# define IF_PREFIX_AUTOCONF	0x02
#endif

/*
 * Copied from linux/ipv6.h (which doesn't include cleanly in user space code)
 *
 * Index values for the variables in ipv6_devconf:
 */
enum {
	DEVCONF_FORWARDING = 0,
	DEVCONF_HOPLIMIT,
	DEVCONF_MTU6,
	DEVCONF_ACCEPT_RA,
	DEVCONF_ACCEPT_REDIRECTS,
	DEVCONF_AUTOCONF,
	DEVCONF_DAD_TRANSMITS,
	DEVCONF_RTR_SOLICITS,
	DEVCONF_RTR_SOLICIT_INTERVAL,
	DEVCONF_RTR_SOLICIT_DELAY,
	DEVCONF_USE_TEMPADDR,
	DEVCONF_TEMP_VALID_LFT,
	DEVCONF_TEMP_PREFERED_LFT,
	DEVCONF_REGEN_MAX_RETRY,
	DEVCONF_MAX_DESYNC_FACTOR,
	DEVCONF_MAX_ADDRESSES,
	DEVCONF_FORCE_MLD_VERSION,
	DEVCONF_ACCEPT_RA_DEFRTR,
	DEVCONF_ACCEPT_RA_PINFO,
	DEVCONF_ACCEPT_RA_RTR_PREF,
	DEVCONF_RTR_PROBE_INTERVAL,
	DEVCONF_ACCEPT_RA_RT_INFO_MAX_PLEN,
	DEVCONF_PROXY_NDP,
	DEVCONF_OPTIMISTIC_DAD,
	DEVCONF_ACCEPT_SOURCE_ROUTE,
	DEVCONF_MC_FORWARDING,
	DEVCONF_DISABLE_IPV6,
	DEVCONF_ACCEPT_DAD,
	DEVCONF_MAX
};

#ifndef IF_RA_OTHERCONF
#define IF_RA_OTHERCONF 0x80
#define IF_RA_MANAGED   0x40
#endif

#endif /* __NETINFO_KERNEL_H__ */
