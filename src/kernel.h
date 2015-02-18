/*
 * General kernel functions for network config and discovery
 *
 * Copyright (C) 2009-2012 Olaf Kirch <okir@suse.de>
 */

#ifndef __NETINFO_KERNEL_H__
#define __NETINFO_KERNEL_H__

#include <net/if.h>
#include <netlink/netlink.h>
#include <netlink/netlink.h>
#include <linux/ethtool.h>

#define __user /* unclean header file */
#include <wireless.h>

#include <wicked/types.h>

struct __ni_netlink {
	struct nl_sock *	nl_sock;
	struct nl_cb *		nl_cb;
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

struct ni_ethtool_counter {
	char *		name;
	uint64_t	value;
};
struct ni_ethtool_stats {
	unsigned int	count;
	struct ni_ethtool_counter *data;
};

extern int		__ni_ethtool(const char *, int, void *);
extern ni_ethtool_stats_t *__ni_ethtool_stats_init(const char *, const struct ethtool_drvinfo *);
extern int		__ni_ethtool_stats_refresh(const char *, ni_ethtool_stats_t *);
extern void		__ni_ethtool_stats_free(ni_ethtool_stats_t *);
extern int		__ni_wireless_ext(const ni_netdev_t *dev, int cmd,
				void *data, size_t data_len, unsigned int flags);
extern int		__ni_brioctl_add_bridge(const char *);
extern int		__ni_brioctl_del_bridge(const char *);
extern int		__ni_brioctl_add_port(const char *, unsigned int);
extern int		__ni_brioctl_del_port(const char *, unsigned int);

extern int		__ni_wireless_get_name(const char *, char *, size_t);
extern int		__ni_wireless_get_essid(const char *, char *, size_t);

extern int		__ni_tuntap_create(const ni_netdev_t *);

extern char *		__ni_ppp_create_device(ni_ppp_t *, const char *);

extern int		__ni_netdev_rename(const char *old_name, const char *new_name);
extern int		__ni_rtnl_link_rename(unsigned int ifindex, const char *oldname, const char *newname);

extern const void *	__ni_nla_get_data(size_t, const struct nlattr *);
extern int		__ni_nla_get_addr(int, ni_sockaddr_t *, const struct nlattr *);
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

extern int	ni_nl_talk(struct nl_msg *, struct ni_nlmsg_list *);
extern int	ni_nl_dump_store(int af, int type, struct ni_nlmsg_list *list);

extern void	ni_nlmsg_list_init(struct ni_nlmsg_list *);
extern void	ni_nlmsg_list_destroy(struct ni_nlmsg_list *);

static inline void *
__ni_rtnl_msgdata(struct nlmsghdr *h, int expected_type, size_t min_size)
{
	if (expected_type >= 0 && h->nlmsg_type != expected_type)
		return NULL;
	if (h->nlmsg_len < NLMSG_LENGTH(min_size))
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

static inline struct nduseroptmsg *
ni_rtnl_nduseroptmsg(struct nlmsghdr *h, int expected_type)
{
	return __ni_rtnl_msgdata(h, expected_type, sizeof(struct nduseroptmsg));
}

extern int	__ni_rtnl_parse_newaddr(unsigned, struct nlmsghdr *, struct ifaddrmsg *, ni_address_t *);
extern int	__ni_rtnl_parse_newprefix(const char *, struct nlmsghdr *, struct prefixmsg *, ni_ipv6_ra_pinfo_t *);

extern int	__ni_netdev_process_newlink(ni_netdev_t *, struct nlmsghdr *, struct ifinfomsg *, ni_netconfig_t *);
extern int	__ni_netdev_process_newlink_ipv6(ni_netdev_t *, struct nlmsghdr *, struct ifinfomsg *);
extern int	__ni_netdev_process_newprefix(ni_netdev_t *, struct nlmsghdr *, struct prefixmsg *);
extern int	__ni_netdev_process_newaddr_event(ni_netdev_t *dev, struct nlmsghdr *h, struct ifaddrmsg *ifa, const ni_address_t **);

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
 * RFC 2863 operational status.
 * Declared in linux/if.h, but that's one of those contaminated
 * files that you can't really use :(
 */
enum {
	IF_OPER_UNKNOWN,
	IF_OPER_NOTPRESENT,
	IF_OPER_DOWN,
	IF_OPER_LOWERLAYERDOWN,
	IF_OPER_TESTING,
	IF_OPER_DORMANT,
	IF_OPER_UP,
};

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
