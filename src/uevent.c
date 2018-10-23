/*
 *	wicked uevent event listener
 *
 *	Copyright (C) 2014 SUSE LINUX Products GmbH, Nuernberg, Germany.
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License along
 *	with this program; if not, see <http://www.gnu.org/licenses/> or write
 *	to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 *	Boston, MA 02110-1301 USA.
 *
 * 	Authors:
 *		Marius Tomaschewski <mt@suse.de>
 *
 *	A lot of the code has its origin in udevmonitor, because udev is using
 *	netlink as transport in a way we can't parse it using libnl library.
 *	We don't want to link against libudev, but use own wicked structures.
 *
 *	The libudev-monitor.c has been released under the GNU Lesser General
 *	Public License and Copyright (C) 2008-2012 Kay Sievers <kay@vrfy.org>.
 *
 *	MurmurHash2 was written by Austin Appleby, and is placed in the public
 *	domain. The author hereby disclaims copyright to this source code.
 *
 * 	We have the code from systemd-udev 210, so we can calculate the same
 * 	hashes as udev is using while sending and apply the socket filters
 * 	to filter out unwanted events as soon as possible (in the kernel).
 *
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>

#include <netlink/netlink.h>
#include <linux/filter.h>
#define bpf_insn sock_filter
#include <net/if.h>

#include <wicked/logging.h>
#include <wicked/socket.h>
#include <wicked/netinfo.h>

#include "netinfo_priv.h"
#include "socket_priv.h"
#include "uevent.h"
#include "appconfig.h"


/*
 * Udev definitions
 */
#ifndef NI_UEVENT_UDEV_TAG
#define NI_UEVENT_UDEV_TAG		"libudev"
#endif
#ifndef NI_UEVENT_UDEV_MAGIC
#define NI_UEVENT_UDEV_MAGIC		0xfeedcafe
#endif
#ifndef NI_UEVENT_UDEV_QUEUE
#define NI_UEVENT_UDEV_QUEUE		"/var/run/udev/queue.bin"
#endif
#ifndef NI_UEVENT_NLGRP_NONE
#define NI_UEVENT_NLGRP_NONE		0
#endif
#ifndef NI_UEVENT_NLGRP_KERN
#define NI_UEVENT_NLGRP_KERN		1
#endif
#ifndef NI_UEVENT_NLGRP_UDEV
#define NI_UEVENT_NLGRP_UDEV		2
#endif

/*
 * Our udev monitor structure
 */
struct ni_uevent_monitor {
	unsigned int		users;

	ni_socket_t *		sock;
	struct sockaddr_nl	addr;
	ni_bool_t		bound;

	ni_uevent_callback_t *	ucb_func;
	void *			ucb_data;

	ni_var_array_t		sub_filter;
	ni_string_array_t	tag_filter;
};

/*
 * libudev event netlink header
 * The following data is formated in key=value\0,
 * the subsystem and device type is MurmurHash2.
 */
struct __ni_uevent_nlhdr {
	char prefix[8];
	unsigned int magic;
	unsigned int header_size;
	unsigned int properties_off;
	unsigned int properties_len;
	unsigned int filter_subsystem_hash;
	unsigned int filter_devtype_hash;
	unsigned int filter_tag_bloom_hi;
	unsigned int filter_tag_bloom_lo;
};


static inline ni_uevent_monitor_t *
__ni_uevent_monitor_new(void)
{
	ni_uevent_monitor_t *mon;

	if ((mon = calloc(1, sizeof(*mon))))
		mon->users = 1;

	return mon;
}

static void
__ni_uevent_monitor_receive(ni_socket_t *sock)
{
	ni_uevent_monitor_t *mon = sock ? sock->user_data : NULL;
	unsigned char mbuf[8192];
	unsigned char cbuf[CMSG_SPACE(sizeof(struct ucred))];
	struct iovec iov = {
		.iov_base = mbuf,
		.iov_len  = sizeof(mbuf)-1,
	};
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = cbuf,
		.msg_controllen = sizeof(cbuf),
	};
	struct ucred *cred;
	struct cmsghdr *cmsg;
	ssize_t mlen;
	ssize_t mpos;
	ni_var_array_t vars = NI_VAR_ARRAY_INIT;

	if (!mon || mon->sock != sock)
		return;

	mlen = recvmsg(mon->sock->__fd, &msg, 0);
	ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_SOCKET,
			"received uevent netlink message with length %zd", mlen);
	if (mlen < 0) {
		if (errno != EINTR && errno != EAGAIN)
			ni_debug_socket("unable to receive uevent netlink message: %m");
		return;
	}
	if (mlen < 32 || (size_t)mlen >= sizeof(mbuf)-1) {
		ni_debug_socket("invalid uevent netlink message length");
		return;
	}
	mbuf[mlen] = '\0';

	if (mon->addr.nl_groups	== NI_UEVENT_NLGRP_KERN) {
		if (mon->addr.nl_pid > 0) {
			ni_debug_socket("multicast kernel netlink uevent from pid %d ignored",
					mon->addr.nl_pid);
			return;
		}
	}

	cmsg = CMSG_FIRSTHDR(&msg);
	if (cmsg == NULL || cmsg->cmsg_type != SCM_CREDENTIALS) {
		ni_debug_socket("no sender credentials received, ignoring uevent message");
		return;
	}
	cred = (struct ucred *)CMSG_DATA(cmsg);
	if (cred->uid != 0) {
		ni_debug_socket("ignoring uevent message from sender uid=%d", cred->uid);
		return;
	}

	if (memcmp(mbuf, NI_UEVENT_UDEV_TAG, sizeof(NI_UEVENT_UDEV_TAG)) == 0) {
		struct __ni_uevent_nlhdr *uhdr;

		/* udev message needs magic (checked via filter too) */
		uhdr = (struct __ni_uevent_nlhdr *)mbuf;
		if (uhdr->magic != htonl(NI_UEVENT_UDEV_MAGIC)) {
			ni_error("unrecognized udev uevent message signature (%x vs %x)",
					ntohl(uhdr->magic), NI_UEVENT_UDEV_MAGIC);
			return;
		}
		if (uhdr->properties_off+32 > (size_t)mlen) {
			ni_debug_socket("invalid udev uevent message property offset %u",
					uhdr->properties_off);
			return;
		}
		mpos = uhdr->properties_off;
	} else {
		/* kernel message with header */
		mpos = strlen((const char *)mbuf) + 1;
		if ((size_t)mpos< sizeof("a@/d") || mpos >= mlen) {
			ni_debug_socket("invalid kernel uevent message length");
			return;
		}

		/* check message header */
		if (strstr((const char *)mbuf, "@/") == NULL) {
			ni_debug_socket("unrecognized kernel uevent message header");
			return;
		}
	}

	while (mpos < mlen) {
		size_t klen;
		char * kptr;
		char * vptr;

		kptr = (char *)&mbuf[mpos];
		klen = strlen(kptr);
		if (klen == 0)
			break;

		mpos += klen + 1;
		vptr = strchr(kptr, '=');
		if (!vptr)
			continue;
		*vptr++ = '\0';

		ni_var_array_set(&vars, kptr, vptr);
	}

	if (mon->ucb_func) {
		mon->ucb_func(&vars, mon->ucb_data);
	}
	ni_var_array_destroy(&vars);
}

/*
 * MurmurHash2 was written by Austin Appleby, and is placed in the public
 * domain. The author hereby disclaims copyright to this source code.
 */
static uint32_t
__ni_uevent_MurmurHash2(const void * key, int len, uint32_t seed)
{
	/*
	 * 'm' and 'r' are mixing constants generated offline.
	 * They're not really 'magic', they just happen to work well.
	 */
	const uint32_t m = 0x5bd1e995;
	const int r = 24;

	/* Initialize the hash to a 'random' value */
	uint32_t h = seed ^ len;

	/* Mix 4 bytes at a time into the hash */
	const unsigned char *data = (const unsigned char *)key;

	while(len >= 4) {
		uint32_t k = *(uint32_t*)data;

		k *= m;
		k ^= k >> r;
		k *= m;

		h *= m;
		h ^= k;

		data += 4;
		len -= 4;
	}

	/* Handle the last few bytes of the input array */
	switch (len) {
		case 3: h ^= data[2] << 16;
			/* fall through */
		case 2: h ^= data[1] << 8;
			/* fall through */
		case 1: h ^= data[0];
			/* fall through */
		default:
			h *= m;
			break;
	}

	/*
	 * Do a few final mixes of the hash to ensure the last few
	 * bytes are well-incorporated.
	 */
	h ^= h >> 13;
	h *= m;
	h ^= h >> 15;

	return h;
}

static uint32_t
__ni_uevent_string_hash32(const char *str)
{
	return __ni_uevent_MurmurHash2(str, ni_string_len(str), 0);
}

static uint64_t
__ni_uevent_string_bloom64(const char *str)
{
	uint32_t hash = __ni_uevent_string_hash32(str);
	uint64_t bits = 0;

	bits |= 1LLU << (hash & 63);
	bits |= 1LLU << ((hash >> 6) & 63);
	bits |= 1LLU << ((hash >> 12) & 63);
	bits |= 1LLU << ((hash >> 18) & 63);
	return bits;
}


static inline void
bpf_stmt(struct sock_filter *inss, unsigned int *pos,
		unsigned short code, unsigned int data)
{
	struct sock_filter *ins = &inss[*pos];
	ins->code = code;
	ins->k = data;
	(*pos)++;
}

static inline void
bpf_jump(struct sock_filter *inss, unsigned int *pos,
		unsigned short code, unsigned int data,
		unsigned short jt, unsigned short jf)
{
	struct sock_filter *ins = &inss[*pos];
	ins->code = code;
	ins->jt = jt;
	ins->jf = jf;
	ins->k = data;
	(*pos)++;
}

int
ni_uevent_monitor_enable(ni_uevent_monitor_t *mon)
{
	struct sockaddr *sa;
	socklen_t salen;
	const int on = 1;
	int ret = 0;

	if (!mon || !mon->sock) {
		errno = EINVAL;
		return -1;
	}

	sa = (struct sockaddr *)&mon->addr;
	salen = sizeof(mon->addr);
	if (!mon->bound) {
		ret = bind(mon->sock->__fd, sa, salen);
		if (ret != 0) {
			ni_error("Cannot bind uevent netlink socket: %m");
			return ret;
		}
		mon->bound = TRUE;
	}

	ret = getsockname(mon->sock->__fd, sa, &salen);
	if (ret != 0) {
		ni_error("Cannot read uevent netlink sockname: %m");
		return ret;
	}

	ret = setsockopt(mon->sock->__fd, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on));
	if (ret != 0) {
		ni_error("Cannot enable passing credentials on socket: %m");
		return ret;
	}

	ni_socket_activate(mon->sock);
	return 0;
}

int
ni_uevent_monitor_filter_apply(ni_uevent_monitor_t *mon)
{
	struct sock_filter ins[512];
	struct sock_fprog filter;
	unsigned int i, at;

	/*
	if (!mon->sub_filter.count && !mon->tag_filter.count)
		return 0;
	*/

	at = 0;
	memset(&ins, 0, sizeof(ins));

	/* load magic in A */
	bpf_stmt(ins, &at, BPF_LD|BPF_W|BPF_ABS,
			offsetof(struct __ni_uevent_nlhdr, magic));
	/* jump if magic matches */
	bpf_jump(ins, &at, BPF_JMP|BPF_JEQ|BPF_K, NI_UEVENT_UDEV_MAGIC, 1, 0);
	/* wrong magic, pass packet -- this allows us to complain in receive */
	bpf_stmt(ins, &at, BPF_RET|BPF_K, 0xffffffff);

	i = at + 2;
	i = (mon->tag_filter.count * 6) + 1;
	i = (mon->sub_filter.count * 5) + 1;
	if (i >= sizeof(ins)/sizeof(ins[0]))
		return -1;

	if (mon->tag_filter.count) {
		unsigned int tag_matches = mon->tag_filter.count;

		for (i = 0; i < mon->tag_filter.count; ++i) {
			const char *tag = mon->tag_filter.data[i];
			uint64_t tag_bloom_bits = __ni_uevent_string_bloom64(tag);
			uint32_t tag_bloom_hi = tag_bloom_bits >> 32;
			uint32_t tag_bloom_lo = tag_bloom_bits & 0xffffffff;

			/* load device bloom bits in A */
			bpf_stmt(ins, &at, BPF_LD|BPF_W|BPF_ABS,
					offsetof(struct __ni_uevent_nlhdr,
							filter_tag_bloom_hi));
			/* clear bits (tag bits & bloom bits) */
			bpf_stmt(ins, &at, BPF_ALU|BPF_AND|BPF_K, tag_bloom_hi);
			/* jump to next tag if it does not match */
			bpf_jump(ins, &at, BPF_JMP|BPF_JEQ|BPF_K, tag_bloom_hi, 0, 3);

			/* load device bloom bits in A */
			bpf_stmt(ins, &at, BPF_LD|BPF_W|BPF_ABS,
					offsetof(struct __ni_uevent_nlhdr,
							filter_tag_bloom_lo));
			/* clear bits (tag bits & bloom bits) */
			bpf_stmt(ins, &at, BPF_ALU|BPF_AND|BPF_K, tag_bloom_lo);
			/* jump behind end of tag match block if tag matches */
			tag_matches--;
			bpf_jump(ins, &at, BPF_JMP|BPF_JEQ|BPF_K, tag_bloom_lo,
						1 + (tag_matches * 6), 0);
		}

		/* nothing matched, drop packet */
		bpf_stmt(ins, &at, BPF_RET|BPF_K, 0);
	}

	if (mon->sub_filter.count) {
		for (i = 0; i < mon->sub_filter.count; ++i) {
			const ni_var_t * var = &mon->sub_filter.data[i];
			unsigned int hash = __ni_uevent_string_hash32(var->name);

			/* load device subsystem value in A */
			bpf_stmt(ins, &at, BPF_LD|BPF_W|BPF_ABS,
					offsetof(struct __ni_uevent_nlhdr,
						filter_subsystem_hash));

			if (ni_string_empty(var->value)) {
				/* jump if subsystem does not match */
				bpf_jump(ins, &at, BPF_JMP|BPF_JEQ|BPF_K, hash, 0, 1);
			} else {
				/* jump if subsystem does not match */
				bpf_jump(ins, &at, BPF_JMP|BPF_JEQ|BPF_K, hash, 0, 3);

				/* load device devtype value in A */
				bpf_stmt(ins, &at, BPF_LD|BPF_W|BPF_ABS,
						offsetof(struct __ni_uevent_nlhdr,
							filter_devtype_hash));
				/* jump if value does not match */
				hash = __ni_uevent_string_hash32(var->value);
				bpf_jump(ins, &at, BPF_JMP|BPF_JEQ|BPF_K, hash, 0, 1);
			}
			/* matched, pass packet */
			bpf_stmt(ins, &at, BPF_RET|BPF_K, 0xffffffff);
		}

		/* nothing matched, drop packet */
		bpf_stmt(ins, &at, BPF_RET|BPF_K, 0);
	}

	/* matched, pass packet */
	bpf_stmt(ins, &at, BPF_RET|BPF_K, 0xffffffff);

	memset(&filter, 0, sizeof(filter));
	filter.len = at;
	filter.filter = ins;
	return setsockopt(mon->sock->__fd, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter));
}

void
ni_uevent_monitor_free(ni_uevent_monitor_t *mon)
{
	if (mon) {
		ni_assert(mon->users);
		mon->users--;
		if (mon->users)
			return;

		if (mon->sock) {
			mon->sock->user_data = NULL;
			ni_socket_release(mon->sock);
			mon->sock = NULL;
		}
		ni_var_array_destroy(&mon->sub_filter);
		ni_string_array_destroy(&mon->tag_filter);
		free(mon);
	}
}

ni_uevent_monitor_t *
ni_uevent_monitor_ref(ni_uevent_monitor_t *mon)
{
	if (mon) {
		ni_assert(mon->users);
		mon->users++;
		return mon;
	}
	return NULL;
}

ni_uevent_monitor_t *
ni_uevent_monitor_new(unsigned int group, ni_uevent_callback_t *user_func, void *user_data)
{
	ni_uevent_monitor_t *mon;
	int fd;

	if (!user_func) {
		errno = EINVAL;
		return NULL;
	}

	fd = socket(PF_NETLINK, SOCK_RAW|SOCK_CLOEXEC|SOCK_NONBLOCK,
			NETLINK_KOBJECT_UEVENT);
	if (fd < 0) {
		ni_error("Cannot open uevent netlink socket: %m");
		return NULL;
	}

	mon = __ni_uevent_monitor_new();
	if (!mon) {
		close(fd);
		ni_error("Cannot allocate uevent monitor: %m");
		return NULL;
	}

	if (!(mon->sock = ni_socket_wrap(fd, SOCK_RAW))) {
		close(fd);
		ni_uevent_monitor_free(mon);
		ni_error("Cannot wrap uevent netlink socket: %m");
		return NULL;
	}

	mon->sock->user_data	= mon;
	mon->sock->receive	= __ni_uevent_monitor_receive;
	mon->addr.nl_family	= AF_NETLINK;
	mon->addr.nl_groups	= group;
	mon->ucb_func		= user_func;
	mon->ucb_data		= user_data;

	return mon;
}

void
ni_uevent_trace_callback(const ni_var_array_t *vars, void *user_data)
{
	const ni_var_t *var;
	unsigned int i;

	if (!vars)
		return;

	(void)user_data;

	ni_trace("* Received uevent via netlink:");
	for (i = 0; i < vars->count; ++i) {
		var = &vars->data[i];
		ni_trace("%s='%s'", var->name, var->value);
	}
	ni_trace("* End.");
}

void
__ni_uevent_ifevent_forwarder(const ni_var_array_t *vars, void *user_data)
{
	ni_netconfig_t *nc;
	ni_netdev_t *dev;
	unsigned int i;
	const ni_var_t *var;
	enum {
		UDEV_ACTION_SKIP = 0,
		UDEV_ACTION_ADD  = 1,
		UDEV_ACTION_MOVE = 2,
	};
	static ni_intmap_t      __action_map[] = {
		{ "add",	UDEV_ACTION_ADD  },
		{ "move",	UDEV_ACTION_MOVE },
		{ NULL,		UDEV_ACTION_SKIP }
	};
	struct {
		ni_bool_t       subsystem;
		unsigned int    action;
		unsigned int    ifindex;
		const char *    interface;
		const char *    interface_old;
		const char *    tags;
	} uinfo;

	(void)user_data;
	if (!vars)
		return;

	if ((nc = ni_global_state_handle(0)) == NULL)
		return;

	memset(&uinfo, 0, sizeof(uinfo));
	for (i = 0; i < vars->count; ++i) {
		var = &vars->data[i];

		ni_debug_verbose(NI_LOG_DEBUG3, NI_TRACE_EVENTS,
			"UEVENT: %s='%s'", var->name, var->value);

		if (ni_string_eq("SUBSYSTEM", var->name)) {
			uinfo.subsystem = ni_string_eq("net", var->value);
		} else
		if (ni_string_eq("ACTION", var->name)) {
			if (ni_parse_uint_mapped(var->value, __action_map, &uinfo.action))
				uinfo.action = UDEV_ACTION_SKIP;
		} else
		if (ni_string_eq("IFINDEX", var->name)) {
			if (ni_parse_uint(var->value, &uinfo.ifindex, 10))
				uinfo.ifindex = 0;
		} else
		if (ni_string_eq("INTERFACE_OLD", var->name)) {
			if (!ni_string_empty(var->value))
				uinfo.interface_old = var->value;
		} else
		if (ni_string_eq("INTERFACE", var->name)) {
			if (!ni_string_empty(var->value))
				uinfo.interface = var->value;
		} else
		if (ni_string_eq("TAGS", var->name)) {
			if (!ni_string_empty(var->value))
				uinfo.tags = var->value;
		}
	}

	if (!uinfo.subsystem || uinfo.action == UDEV_ACTION_SKIP || !uinfo.ifindex)
		return;

	dev = ni_netdev_by_index(nc, uinfo.ifindex);
	ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_EVENTS,
			"UEVENT(%s) ACTION: %s, IFINDEX=%u, NAME=%s, PREV=%s, TAGS=%s",
			dev ? dev->name : NULL,
			ni_format_uint_mapped(uinfo.action, __action_map),
			uinfo.ifindex,
			uinfo.interface, uinfo.interface_old, uinfo.tags);

	if (dev && !(dev->link.ifflags & NI_IFF_DEVICE_READY)) {
		unsigned int old_flags = dev->link.ifflags;
		char namebuf[IF_NAMESIZE+1] = {'\0'};
		const char *ifname;

		if (!ni_string_empty(uinfo.interface_old))
			return;

		if (!uinfo.tags || !strstr(uinfo.tags, ":systemd:"))
			return;

		if (!(ifname = if_indextoname(dev->link.ifindex, namebuf)))
			return; /* device gone in the meantime */

		if (!ni_string_eq(dev->name, ifname))
			ni_string_dup(&dev->name, ifname);

		dev->link.ifflags |= NI_IFF_DEVICE_READY;
		__ni_netdev_process_events(nc, dev, old_flags);
	}
}

static ni_uevent_monitor_t *	__ni_global_uevent_monitor = NULL;
static ni_bool_t		__ni_global_uevent_disabled = FALSE;

int
ni_server_enable_interface_uevents()
{
	ni_uevent_monitor_t *mon;

	if (__ni_global_uevent_monitor) {
		ni_error("uevent monitor handler is already set");
		return -1;
	}

	/* Monitor udev, kernel events we get via rtnetlink */
	mon = ni_uevent_monitor_new(NI_UEVENT_NLGRP_UDEV,
			__ni_uevent_ifevent_forwarder, NULL);
	if (!mon)
		return -1;

	/* Here, we want to only SUBSYSTEM=net events */
	ni_var_array_set(&mon->sub_filter, "net", NULL);
	if (ni_uevent_monitor_filter_apply(mon) < 0) {
		ni_uevent_monitor_free(mon);
		ni_error("Cannot set uevent netlink message filter: %m");
		return -1;
	}

	__ni_global_uevent_monitor = mon;
	__ni_global_uevent_disabled = FALSE;

	return ni_uevent_monitor_enable(mon);
}

ni_bool_t
ni_server_listens_uevents(void)
{
	return __ni_global_uevent_monitor != NULL;
}

void
ni_server_deactivate_interface_uevents(void)
{
	if (__ni_global_uevent_monitor) {
		ni_uevent_monitor_t *mon;

		mon = __ni_global_uevent_monitor;
		__ni_global_uevent_monitor = NULL;

		ni_uevent_monitor_free(mon);
	}
}

void
ni_server_disable_interface_uevents(void)
{
	ni_server_deactivate_interface_uevents();
	__ni_global_uevent_disabled = TRUE;
}

ni_bool_t
ni_server_disabled_uevents(void)
{
	return __ni_global_uevent_disabled;
}

