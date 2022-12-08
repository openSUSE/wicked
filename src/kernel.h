/*
 * General kernel functions for network config and discovery
 *
 * Copyright (C) 2009-2012 Olaf Kirch <okir@suse.de>
 */

#ifndef NI_WICKED_KERNEL_H
#define NI_WICKED_KERNEL_H

#include <netlink/netlink.h>
#include <linux/ethtool.h>
#include <linux/fib_rules.h>

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

extern int		__ni_ethtool(const char *, int, void *);
extern int		__ni_brioctl_add_bridge(const char *);
extern int		__ni_brioctl_del_bridge(const char *);
extern int		__ni_brioctl_add_port(const char *, unsigned int);
extern int		__ni_brioctl_del_port(const char *, unsigned int);

extern int		__ni_tuntap_create(const ni_netdev_t *);

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

extern const char *	ni_rtnl_msg_type_to_name(unsigned int, const char *);

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

static inline struct fib_rule_hdr *
ni_rtnl_fibrulemsg(struct nlmsghdr *h, int expected_type)
{
	return __ni_rtnl_msgdata(h, expected_type, sizeof(struct fib_rule_hdr));
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

extern ni_bool_t	ni_rtnl_route_filter_msg(struct rtmsg *);
extern int	ni_rtnl_route_parse_msg(struct nlmsghdr *, struct rtmsg *, ni_route_t *);
extern int	ni_rtnl_rule_parse_msg(struct nlmsghdr *, struct fib_rule_hdr *, ni_rule_t *);

extern int	__ni_rtnl_parse_newaddr(unsigned, struct nlmsghdr *, struct ifaddrmsg *, ni_address_t *);
extern int	__ni_rtnl_parse_newprefix(const char *, struct nlmsghdr *, struct prefixmsg *, ni_ipv6_ra_pinfo_t *);

extern int	__ni_netdev_process_newlink(ni_netdev_t *, struct nlmsghdr *, struct ifinfomsg *, ni_netconfig_t *);
extern int	__ni_netdev_process_newlink_ipv6(ni_netdev_t *, struct nlmsghdr *, struct ifinfomsg *);
extern int	__ni_netdev_process_newprefix(ni_netdev_t *, struct nlmsghdr *, struct prefixmsg *);
extern int	__ni_netdev_process_newaddr_event(ni_netdev_t *dev, struct nlmsghdr *h, struct ifaddrmsg *ifa, const ni_address_t **);

/* IPv6 Ready & RA flags in RTM_NEWLINK events (kernel net/if_inet6.h) */
#ifndef IF_RA_OTHERCONF
#define IF_RA_OTHERCONF 0x80
#endif
#ifndef IF_RA_MANAGED
#define IF_RA_MANAGED   0x40
#endif
#ifndef IF_RA_RCVD
#define IF_RA_RCVD	0x20
#endif
#ifndef IF_RS_SENT
#define IF_RS_SENT	0x10
#endif
#ifndef IF_READY
#define IF_READY	0x80000000
#endif

/* IPv6 RA prefix in RTM_NEWPREFIX events (kernel net/if_inet6.h)      */
#ifndef IF_PREFIX_ONLINK
# define IF_PREFIX_ONLINK	0x01
#endif
#ifndef IF_PREFIX_AUTOCONF
# define IF_PREFIX_AUTOCONF	0x02
#endif

#endif /* NI_WICKED_KERNEL_H */
