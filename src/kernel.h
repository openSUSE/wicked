/*
 * General kernel functions for network config and discovery
 *
 * Copyright (C) 2009-2010 Olaf Kirch <okir@suse.de>
 */

#ifndef __NETINFO_KERNEL_H__
#define __NETINFO_KERNEL_H__

#include <net/if.h>

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

extern int		__ni_ethtool(ni_handle_t *, const ni_interface_t *, int, void *);
extern int		__ni_brioctl_add_bridge(ni_handle_t *, const char *);
extern int		__ni_brioctl_del_bridge(ni_handle_t *, const char *);
extern int		__ni_brioctl_add_port(ni_handle_t *, const char *, unsigned int);
extern int		__ni_brioctl_del_port(ni_handle_t *, const char *, unsigned int);

extern int		__ni_rta_get_addr(int, struct sockaddr_storage *, struct rtattr *);
extern int		__ni_rta_get_string(char **, struct rtattr *);
extern struct rtattr *	__ni_rta_find(struct rtattr *, size_t len, int type);
extern struct rtattr *	__ni_rta_begin_nested(struct nlmsghdr *, size_t, int);
extern struct rtattr *	__ni_rta_begin_linkinfo(struct nlmsghdr *, size_t, const char *);
extern void		__ni_rta_end_nested(struct nlmsghdr *, struct rtattr *);

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

typedef int	ni_rtnl_callback_t(ni_handle_t *,
			const struct sockaddr_nl *,
			const struct nlmsghdr *,
			void *arg);


extern int	ni_rtnl_talk(ni_handle_t *, struct nlmsghdr *);
extern int	ni_rtnl_dump(struct ni_handle *nih, int type,
			ni_rtnl_callback_t *junk_cb,
			ni_rtnl_callback_t *filter_cb,
			void *user_data);
extern int	ni_rtnl_dump_store(struct ni_handle *nih, int type,
			struct ni_nlmsg_list *list);

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

extern int	__ni_interface_process_newlink(ni_interface_t *, struct nlmsghdr *,
				struct ifinfomsg *, ni_handle_t *);

#ifndef IFF_LOWER_UP
# define IFF_LOWER_UP	0x10000
#endif

#endif /* __NETINFO_KERNEL_H__ */
