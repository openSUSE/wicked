/*
 * This file implements a netcf interface to wicked
 *
 * Copyright (C) 2010 Olaf Kirch <okir@suse.de>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 */


#include <sys/time.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include <netcf.h>
#include <wicked/netinfo.h>
#include <wicked/xml.h>
#include "util_priv.h"

typedef struct netcf_ifinfo {
	ni_handle_t *		handle;		/* netinfo handle */
	struct timeval		valid;		/* until when it's valid */
	unsigned int		cache_lft;	/* cache lifetime */
} netcf_ifinfo_t;

typedef struct netcf {
	unsigned int		users;
	netcf_ifinfo_t		state;
	netcf_ifinfo_t		config;
	int			error;
	ni_syntax_t *		xmlsyntax;
} netcf_t;

struct netcf_if {
	netcf_t *		netcf;
	ni_interface_t *	handle;
};

/* Cached interface state expires after a certain period of time.
 * Default to 1 second for interface state, 5 sec for config */
#define __NETCF_STATE_CACHE_LFT		1
#define __NETCF_CONFIG_CACHE_LFT	5

static const char *	__ncf_strerror(int);

/*
 * Initialize a netcf object.
 * For now, we use handles to talk to the kernel directly,
 * rather than going through wickedd. In a later version, we
 * should probably go through the REST interface.
 */
int
ncf_init(struct netcf **ncfp, const char *root)
{
	netcf_t *ncf;

	*ncfp = NULL;

	ncf = calloc(1, sizeof(netcf_t));
	ncf->users = 1;

	ncf->state.cache_lft = __NETCF_STATE_CACHE_LFT;
	ncf->state.handle = ni_indirect_open("/system");
	if (!ncf->state.handle)
		goto failed;

	ncf->config.cache_lft = __NETCF_CONFIG_CACHE_LFT;
	ncf->config.handle = ni_indirect_open("/config");
	if (!ncf->config.handle)
		goto failed;

	ni_indirect_set_root(ncf->config.handle, root);

	ncf->xmlsyntax = ni_syntax_new("netcf-strict", NULL);
	if (!ncf->xmlsyntax)
		goto failed;

	/* original netcf code also evaluates
	 * NETCF_DATADIR and NETCF_DEBUG env vars
	 */

	*ncfp = ncf;
	return 0;

failed:
	ncf_close(ncf);
	return -1;
}

int
ncf_close(struct netcf *ncf)
{
	if (ncf) {
		if (ncf->users != 1) {
			ncf->error = NETCF_EINUSE;
			return -1;
		}

		if (ncf->state.handle)
			ni_close(ncf->state.handle);
		if (ncf->config.handle)
			ni_close(ncf->config.handle);
		if (ncf->xmlsyntax)
			ni_syntax_free(ncf->xmlsyntax);
		memset(ncf, 0, sizeof(*ncf));
		free(ncf);
	}
	return 0;
}

/*
 * Retrieve error code and messages
 */
int
ncf_error(struct netcf *ncf, const char **errmsg, const char **details)
{
	int error = ncf->error;

	if (errmsg)
		*errmsg = __ncf_strerror(error);
	if (details)
		*details = NULL;

	ncf->error = 0;
	return error;
}

/*
 * Maybe refresh interface data
 */
static int
__ncf_maybe_refresh(netcf_ifinfo_t *nif)
{
	if (timerisset(&nif->valid)) {
		struct timeval now, delta;

		gettimeofday(&now, NULL);
		timersub(&nif->valid, &now, &delta);
		if (delta.tv_sec >= 0)
			return 0;
		timerclear(&nif->valid);
	}

	if (ni_refresh(nif->handle) < 0)
		return -1;

	if (nif->cache_lft) {
		gettimeofday(&nif->valid, NULL);
		nif->valid.tv_sec += nif->cache_lft;
	}
	return 0;
}

/*
 * Get the list of interfaces with a state matching @flags,
 * which is a bitfield made up of
 *  NETCF_IFACE_INACTIVE     - match inactive interfaces only
 *  NETCF_IFACE_ACTIVE       - match active interfaces only
 */
int
__ncf_list_interfaces(struct netcf *ncf, unsigned int flags,
			char **result, unsigned int maxnames)
{
	static const unsigned int match_any = (NETCF_IFACE_ACTIVE|NETCF_IFACE_INACTIVE);
	unsigned int count = 0;
	ni_interface_t *ifp, *pos;

	if (__ncf_maybe_refresh(&ncf->config) < 0)
		goto internal_error;

	/* If we're asking for either active or inactive, we
	 * also need to refresh the state */
	if ((flags & match_any) != match_any) {
		ni_handle_t *nih = ncf->config.handle;

		if (__ncf_maybe_refresh(&ncf->state) < 0)
			goto internal_error;

		for (ifp = ni_interface_first(nih, &pos); ifp; ifp = ni_interface_next(nih, &pos)) {
			ni_interface_t *cur;
			int state;

			/* Really use __ni_interface_for_config */
			cur = ni_interface_by_name(ncf->state.handle, ifp->name);
			if (!cur)
				continue;

			state = ni_interface_network_is_up(cur)? NETCF_IFACE_ACTIVE : NETCF_IFACE_INACTIVE;
			if (count < maxnames && (flags & state))
				result[count++] = xstrdup(cur->name);
		}
	} else {
		ni_handle_t *nih = ncf->config.handle;

		for (ifp = ni_interface_first(nih, &pos); ifp; ifp = ni_interface_next(nih, &pos)) {
			if (count < maxnames)
				result[count++] = xstrdup(ifp->name);
		}
	}

	return 0;

internal_error:
	while (count--)
		free(result[count]);
	ncf->error = NETCF_EOTHER;
	return -1;
}

/*
 * Get the number of interfaces with a state matching @flags,
 * which is a bitfield made up of
 *  NETCF_IFACE_INACTIVE     - match inactive interfaces only
 *  NETCF_IFACE_ACTIVE       - match active interfaces only
 */
int
ncf_num_of_interfaces(struct netcf *ncf, unsigned int flags)
{
	return __ncf_list_interfaces(ncf, flags, NULL, 0);
}

/*
 * Get the lost of interfaces with a state matching @flags,
 * which is a bitfield made up of
 *  NETCF_IFACE_INACTIVE     - match inactive interfaces only
 *  NETCF_IFACE_ACTIVE       - match active interfaces only
 */
int
ncf_list_interfaces(struct netcf *ncf, int maxnames, char **names, unsigned int flags)
{
	return __ncf_list_interfaces(ncf, flags, names, maxnames);
}

/*
 * Constructor and destructor for netcf_if objects
 */
static struct netcf_if *
__ncf_if_new(netcf_t *ncf, ni_interface_t *ifp)
{
	struct netcf_if *nif;

	if (!ifp)
		return NULL;
	nif = calloc(1, sizeof(*nif));
	nif->netcf = ncf;
	nif->handle = ni_interface_get(ifp);
	ncf->users++;
	return nif;
}

/*
 * Release any resources used by this NETCF_IF; the pointer is invalid
 * after this call
 */
void
ncf_if_free(struct netcf_if *nif)
{
	assert(nif->netcf && nif->netcf->users > 1);
	nif->netcf->users--;

	if (nif->handle)
		ni_interface_put(nif->handle);
	nif->handle = NULL;
	free(nif);
}

/*
 * Look interface up by name.
 *
 * Returns the interface, which must later be freed with a call to
 * NCF_IF_FREE, or NULL on error.
 */
struct netcf_if *
ncf_lookup_by_name(struct netcf *ncf, const char *name)
{
	ni_interface_t *ifp;

	if (__ncf_maybe_refresh(&ncf->config) < 0) {
		ncf->error = NETCF_EOTHER;
		return NULL;
	}

	ifp = ni_interface_by_name(ncf->config.handle, name);
	if (!ifp)
		return NULL;

	return __ncf_if_new(ncf, ifp);
}

/*
 * Find all interfaces with the given hardware address MAC. Generally, MAC
 * should be in hex notation aa:bb:cc:dd:ee:ff.
 *
 * Up to MAXIFACES interfaces are returned in the array IFACES, which must
 * be allocated by the caller to hold at least MAXIFACES pointers to struct
 * netcf_if. It is permissible to pass in MAXIFACES == 0, in which case
 * IFACES is ignored. If there are more than MAXIFACES interfaces with the
 * given MAC, only MAXIFACES many will be returned.
 *
 * The function returns -1 on error, or a nonnegative number indicating the
 * number of interfaces with the given MAC, which can be larger than
 * MAXIFACES.
 */
int
ncf_lookup_by_mac_string(struct netcf *ncf, const char *mac, int maxifaces, struct netcf_if **ifaces)
{
	ni_handle_t *nih = ncf->config.handle;
	ni_interface_t *ifp, *pos;
	unsigned int count = 0;
	ni_hwaddr_t hwa;

	if (ni_link_address_parse(&hwa, NI_IFTYPE_ETHERNET, mac) < 0) {
		ncf->error = NETCF_EOTHER;
		return -1;
	}

	if (__ncf_maybe_refresh(&ncf->config) < 0) {
		ncf->error = NETCF_EOTHER;
		return -1;
	}

	memset(ifaces, 0, maxifaces * sizeof(ifaces[0]));
	for (ifp = ni_interface_first(nih, &pos); ifp; ifp = ni_interface_next(nih, &pos)) {
		if (ifp->type != NI_IFTYPE_ETHERNET)
			continue;

		/* FIXME: ignore slave interfaces */
		if (!ni_link_address_equal(&ifp->hwaddr, &hwa))
			continue;

		if (count < maxifaces)
			ifaces[count++] = __ncf_if_new(ncf, ifp);
	}

	return count;
}

/*
 * Define a new interface
 */
struct netcf_if *
ncf_define(struct netcf *ncf, const char *data)
{
	FILE *memstream;
	ni_interface_t *ifp;
	xml_node_t *xml;

	memstream = fmemopen((char *) data, strlen(data), "r");
	if (memstream == NULL) {
		/* ni_error("Unable to open memstream for data: %m"); */
		ncf->error = NETCF_EINTERNAL;
		return NULL;
	}

	xml = xml_node_scan(memstream);
	fclose(memstream);

	if (xml == NULL) {
		ncf->error = NETCF_EXMLPARSER;
		return NULL;
	}

	ifp = ni_syntax_xml_to_interface(ncf->xmlsyntax, ncf->config.handle, xml);
	xml_node_free(xml);

	if (ifp == NULL) {
		ncf->error = NETCF_EXMLINVALID;
		return NULL;
	}

	return __ncf_if_new(ncf, ifp);
}

/*
 * Get the state information associated with the interface
 */
static ni_interface_t *
__ncf_if_state(struct netcf_if *nif)
{
	struct netcf *ncf = nif->netcf;
	ni_interface_t *ifp;

	if (__ncf_maybe_refresh(&ncf->state) < 0) {
		ncf->error = NETCF_EINTERNAL;
		return NULL;
	}

	/* FIXME: lookup by name _or_ hwaddr _or_ other stuff */
	ifp = ni_interface_by_name(ncf->state.handle, nif->handle->name);
	if (!ifp) {
		/* Interface is currently down */
		ncf->error = NETCF_EOTHER;
		return NULL;
	}

	return ifp;
}

/* Return the name of the interface. The string can be used up until the
 * next call to a function that takes this NETCF_IF as argument
 */
const char *
ncf_if_name(struct netcf_if *nif)
{
	ni_interface_t *ifp;

	if (!(ifp = nif->handle))
		return NULL;

	/* The interface definition may not specify a name, but just
	 * a HWADDR */
	if (!ifp->name) {
		ifp = __ncf_if_state(nif);
		if (!ifp)
			return NULL;
	}

	return ifp->name;
}

/*
 * Return the MAC address of an interface.
 */
const char *
ncf_if_mac_string(struct netcf_if *nif)
{
	ni_interface_t *ifp;

	if (!(ifp = nif->handle))
		return NULL;

	/* The interface definition may not specify a HWADDR, so get
	 * it from the kernel. 
	 */
	if (ifp->hwaddr.type == NI_IFTYPE_UNKNOWN) {
		ifp = __ncf_if_state(nif);
		if (!ifp)
			return NULL;
	}

	return ni_link_address_print(&ifp->hwaddr);
}

/*
 * Bring the interface up
 */
int
ncf_if_up(struct netcf_if *nif)
{
	nif->netcf->error = NETCF_EINTERNAL;
	return -1;
}

/*
 * Take the interface down
 */
int
ncf_if_down(struct netcf_if *nif)
{
	nif->netcf->error = NETCF_EINTERNAL;
	return -1;
}

/*
 * Delete the interface definition
 */
int
ncf_if_undefine(struct netcf_if *nif)
{
	nif->netcf->error = NETCF_EINTERNAL;
	return -1;
}

/*
 * Create XML description of a netinfo interface object
 */
static char *
__ncf_if_xml(struct netcf *ncf, ni_handle_t *nih, ni_interface_t *ifp)
{
	xml_node_t *xml = NULL;
	FILE *memstream = NULL;
	char *out_string = NULL;
	size_t out_size;

	/* FIXME: add slave interfaces as well? */
	xml = ni_syntax_xml_from_interface(ncf->xmlsyntax, nih, ifp);
	if (!xml)
		goto error;

	memstream = open_memstream(&out_string, &out_size);
	if (xml_node_print(xml, memstream) < 0)
		goto error;
	fclose(memstream);

	xml_node_free(xml);
	return out_string;

error:
	if (memstream);
		fclose(memstream);
	if (xml)
		xml_node_free(xml);
	return NULL;
}

/*
 * Produce an XML description for the static (stored) interface
 * config, in the same format that NCF_DEFINE expects
 */
char *
ncf_if_xml_desc(struct netcf_if *nif)
{
	return __ncf_if_xml(nif->netcf, nif->netcf->config.handle, nif->handle);
}

/*
 * Produce an XML description of the current live state of the
 * interface, in the same format that NCF_DEFINE expects, but
 * potentially with extra info not contained in the static config (ie
 * the current IP address of an interface that uses DHCP)
 */
char *
ncf_if_xml_state(struct netcf_if *nif)
{
	struct netcf *ncf = nif->netcf;
	ni_interface_t *ifp;

	if (!(ifp = __ncf_if_state(nif)))
		return NULL;

	return __ncf_if_xml(ncf, ncf->state.handle, ifp);
}

/* Report various status info about the interface as bits in
 * "flags". The meaning of the bits is in the enum type netcf_if_flag_t.
 * Returns 0 on success, -1 on failure
 */
int
ncf_if_status(struct netcf_if *nif, unsigned int *flags)
{
	struct netcf *ncf = nif->netcf;
	ni_interface_t *ifp;

	*flags = NETCF_IFACE_INACTIVE;
	if (!(ifp = __ncf_if_state(nif))) {
		/* No error, just consider it down */
		ncf->error = 0;
	} else if (ni_interface_network_is_up(ifp))
		*flags = NETCF_IFACE_ACTIVE;

	return 0;
}

/*
 * Helper function mapping error codes to messages
 */
static const char *
__ncf_strerror(int error)
{
	switch (error) {
	case NETCF_NOERROR:
		return "no error";
	case NETCF_EINTERNAL:
		return "internal error";
	case NETCF_EOTHER:
		return "other error";
	case NETCF_ENOMEM:
		return "allocation failed";
	case NETCF_EXMLPARSER:
		return "XML parser choked";
	case NETCF_EXMLINVALID:
		return "XML invalid in some form";
	case NETCF_ENOENT:
		return "Required entry in a tree is missing";
	case NETCF_EEXEC:
		return "external program execution failed";
	case NETCF_EINUSE:
		return "cannot close netcf, instances still in use";
	case NETCF_EXSLTFAILED:
		return "XSLT transformation failed";
	case NETCF_EFILE:
		return "some file access failed";
	case NETCF_EIOCTL:
		return "an ioctl call failed";
	case NETCF_ENETLINK:
		return "netlink error";
	default:
		return "error code not handled";
	}
}

