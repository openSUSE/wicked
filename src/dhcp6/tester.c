/*
 *	wicked dhcp6 in test (request offer/lease) mode
 *
 *	Copyright (C) 2013-2014 SUSE LINUX Products GmbH, Nuernberg, Germany.
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
 *	Authors:
 *		Marius Tomaschewski <mt@suse.de>
 *
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <unistd.h>
#include <net/if_arp.h>

#include <wicked/types.h>
#include <wicked/logging.h>
#include <wicked/leaseinfo.h>
#include <wicked/system.h>
#include <wicked/xml.h>

#include "dhcp6/dhcp6.h"
#include "dhcp6/device.h"
#include "dhcp6/tester.h"
#include "duid.h"
#include "appconfig.h"
#include "netinfo_priv.h"

/* TODO: get rid of these static things */
static ni_dhcp6_tester_t	dhcp6_tester_opts;
static int			dhcp6_tester_status;

ni_dhcp6_tester_t *
ni_dhcp6_tester_init(void)
{
	memset(&dhcp6_tester_opts, 0, sizeof(dhcp6_tester_opts));
	dhcp6_tester_opts.outfmt  = NI_DHCP6_TESTER_OUT_LEASE_INFO;
	dhcp6_tester_opts.mode    = NI_BIT(NI_DHCP6_MODE_AUTO);
	dhcp6_tester_opts.timeout = 0;
	dhcp6_tester_status = NI_WICKED_RC_NOT_RUNNING;
	return &dhcp6_tester_opts;
}

ni_bool_t
ni_dhcp6_tester_set_outfmt(const char *outfmt, unsigned int *type)
{
	static const ni_intmap_t __outfmt_map[] = {
		{ "lease-xml",	NI_DHCP6_TESTER_OUT_LEASE_XML  },
		{ "leaseinfo",	NI_DHCP6_TESTER_OUT_LEASE_INFO },
		{ "info",	NI_DHCP6_TESTER_OUT_LEASE_INFO },
		{ NULL,		NI_DHCP6_TESTER_OUT_LEASE_INFO },
	};
	return ni_parse_uint_mapped(outfmt, __outfmt_map, type) == 0;
}

static void
ni_dhcp6_tester_protocol_event(enum ni_dhcp6_event ev, const ni_dhcp6_device_t *dev,
				ni_addrconf_lease_t *lease)
{
	ni_debug_dhcp("%s(ev=%u, dev=%s[%u], config-uuid=%s)", __func__, ev,
			dev->ifname, dev->link.ifindex,
			dev->config ? ni_uuid_print(&dev->config->uuid) : "<none>");

	switch (ev) {
	case NI_DHCP6_EVENT_ACQUIRED:
		if (lease && lease->state == NI_ADDRCONF_STATE_GRANTED) {
			FILE *fp = stdout;

			if (dhcp6_tester_opts.output != NULL) {
				fp = fopen(dhcp6_tester_opts.output, "w");
				if (!fp) {
					ni_error("Cannot open %s for output",
							dhcp6_tester_opts.output);
					dhcp6_tester_status = NI_WICKED_RC_ERROR;
					return;
				}
			}
			if (dhcp6_tester_opts.outfmt == NI_DHCP6_TESTER_OUT_LEASE_XML) {
				xml_node_t *xml = NULL;

				if (ni_addrconf_lease_to_xml(lease, &xml, dev->ifname) != 0) {
					if (dhcp6_tester_opts.output)
						fclose(fp);
					dhcp6_tester_status = NI_WICKED_RC_ERROR;
					return;
				}
				xml_node_print(xml, fp);
				xml_node_free(xml);
			} else {
				ni_leaseinfo_dump(fp, lease, dev->ifname, NULL);
			}
			fflush(fp);
			if (dhcp6_tester_opts.output)
				fclose(fp);
			dhcp6_tester_status = NI_WICKED_RC_SUCCESS;
		}
		break;
	default:
		break;
	}
}

static ni_bool_t
ni_dhcp6_tester_parse_pd_req(ni_dhcp6_request_t *req, const xml_node_t *prefix)
{
	ni_dhcp6_prefix_req_t *pr;
	ni_dhcp6_ia_addr_t *hint;
	ni_sockaddr_t addr;
	unsigned int plen;
	xml_node_t *ptr;

	if (!req || !(ptr = xml_node_get_child(prefix, "hint")) || ni_string_empty(ptr->cdata))
		return FALSE;

	if (!ni_sockaddr_prefix_parse(ptr->cdata, &addr, &plen))
		return FALSE;

	if (addr.ss_family != AF_INET6 || !plen || plen >= ni_af_address_prefixlen(AF_INET6))
		return FALSE;

	if (!(pr = ni_dhcp6_prefix_req_new()))
		return FALSE;

	if (!(hint = ni_dhcp6_ia_prefix_new(addr.six.sin6_addr, plen))) {
		ni_dhcp6_prefix_req_free(pr);
		return FALSE;
	}

	if (!ni_dhcp6_ia_addr_list_append(&pr->hints, hint)) {
		ni_dhcp6_ia_addr_free(hint);
		ni_dhcp6_prefix_req_free(pr);
		return FALSE;
	}
	if (!ni_dhcp6_prefix_req_list_append(&req->prefix_reqs, pr)) {
		ni_dhcp6_prefix_req_free(pr);
		return FALSE;
	}
	return TRUE;
}

static ni_bool_t
ni_dhcp6_tester_req_xml_init(ni_dhcp6_request_t *req, xml_document_t *doc)
{
	xml_node_t *xml, *child;
	const char *type;

	xml = xml_document_root(doc);
	if (xml && !xml->name && xml->children)
		xml = xml->children;

	/* TODO: parse using /ipv6:dhcp/request xml schema */
	if (!xml || !ni_string_eq(xml->name, "request")) {
		ni_error("Invalid dhcp6 request xml '%s'",
			xml ? xml_node_location(xml) : NULL);
		return FALSE;
	}

	type = xml_node_get_attr(xml, "type");
	if (ni_string_eq(type, "offer")) {
		req->dry_run = NI_DHCP6_RUN_OFFER;
	} else
	if (ni_string_eq(type, "lease")) {
		req->dry_run = NI_DHCP6_RUN_LEASE;
	}

	for (child = xml->children; child; child = child->next) {
		if (ni_string_eq(child->name, "uuid")) {
			if (ni_uuid_parse(&req->uuid, child->cdata) != 0)
				goto failure;
		} else
		if (ni_string_eq(child->name, "mode")) {
			if (!ni_dhcp6_mode_parse(&req->mode, child->cdata))
				goto failure;
		} else
		if (ni_string_eq(child->name, "acquire-timeout")) {
			if (ni_parse_uint(child->cdata, &req->acquire_timeout, 10) != 0)
				goto failure;
		} else
		if (ni_string_eq(child->name, "hostname")) {
			if (!ni_check_domain_name(child->cdata, ni_string_len(child->cdata), 0))
				goto failure;
			ni_string_dup(&req->hostname, child->cdata);
		} else
		if (ni_string_eq(child->name, "fqdn")) {
			const xml_node_t *ptr;

			for (ptr = child->children; ptr; ptr = ptr->next) {
				if (ni_string_eq(ptr->name, "enabled")) {
					ni_bool_t b;
					if (ni_parse_boolean(ptr->cdata, &b) == 0)
						ni_tristate_set(&req->fqdn.enabled, b);
					else
					if (ni_string_eq(ptr->cdata, "default"))
						req->fqdn.enabled = NI_TRISTATE_DEFAULT;
					else
						goto failure;
				} else
				if (ni_string_eq(ptr->name, "update")) {
					if (!ni_dhcp_fqdn_update_name_to_mode(ptr->cdata, &req->fqdn.update))
						goto failure;
				} else
				if (ni_string_eq(ptr->name, "qualify")) {
					if (ni_parse_boolean(ptr->cdata, &req->fqdn.qualify) != 0)
						goto failure;
				}
			}
		} else
		if (ni_string_eq(child->name, "client-id")) {
			ni_opaque_t duid;

			ni_duid_clear(&duid);
			if (!ni_duid_parse_hex(&duid, child->cdata))
				goto failure;
			ni_string_dup(&req->clientid, child->cdata);
		} else
		if (ni_string_eq(child->name, "prefix")) {
			if (!ni_dhcp6_tester_parse_pd_req(req, child))
				goto failure;
		} else
		if (ni_string_eq(child->name, "request-options")) {
			xml_node_t *opt;
			for (opt = child->children; opt; opt = opt->next) {
				if (ni_string_empty(opt->cdata))
					continue;
				ni_string_array_append(&req->request_options, opt->cdata);
			}
		}
	}

	return TRUE;
failure:
	if (child) {
		ni_error("Cannot parse dhcp6 request '%s' at %s: %s",
			child->name, xml_node_location(child), child->cdata);
	}
	return FALSE;
}

static ni_bool_t
ni_dhcp6_tester_req_init(ni_dhcp6_request_t *req, const char *request)
{
	/* Apply some defaults */
	req->dry_run = NI_DHCP6_RUN_OFFER;
	req->acquire_timeout = 10;
	req->mode = NI_BIT(NI_DHCP6_MODE_AUTO);

	if (!ni_string_empty(request)) {
		xml_document_t *doc;

		if (!(doc = xml_document_read(request))) {
			ni_error("Cannot parse dhcp6 request xml '%s'", request);
			return FALSE;
		}

		if (!ni_dhcp6_tester_req_xml_init(req, doc)) {
			xml_document_free(doc);
			return FALSE;
		}
		xml_document_free(doc);
	}

	/* Always enter dry run mode & disable rapid-commit */
	req->rapid_commit = FALSE;
	if (ni_uuid_is_null(&req->uuid))
		ni_uuid_generate(&req->uuid);

	return TRUE;
}

int
ni_dhcp6_tester_run(ni_dhcp6_tester_t *opts)
{
	ni_netconfig_t *nc;
	ni_netdev_t *ifp = NULL;
	ni_dhcp6_device_t *dev = NULL;
	ni_dhcp6_request_t *req = NULL;
	unsigned int link_timeout = 20;
	struct timeval start_time;
	char *errdetail = NULL;
	int rv;

	ni_timer_get_time(&start_time);
	if (opts->timeout && opts->timeout != -1U) {
		link_timeout = (opts->timeout * 2) / 3;
	}

	if (!opts || ni_string_empty(opts->ifname))
		ni_fatal("Invalid start parameters!");

	dhcp6_tester_opts   = *opts;
	dhcp6_tester_status = NI_WICKED_RC_ERROR;

	if (!(nc = ni_global_state_handle(1)))
		ni_fatal("Cannot refresh interface list!");

	if (!(ifp = ni_netdev_by_name(nc, opts->ifname)))
		ni_fatal("Cannot find interface with name '%s'", opts->ifname);

	if (!ni_dhcp6_supported(ifp))
		ni_fatal("DHCPv6 not supported on '%s'", opts->ifname);

	if (!(dev = ni_dhcp6_device_new(ifp->name, &ifp->link)))
		ni_fatal("Cannot allocate dhcp6 client for '%s'", ifp->name);

	ni_dhcp6_set_event_handler(ni_dhcp6_tester_protocol_event);

	if (!(req = ni_dhcp6_request_new())) {
		ni_error("Cannot allocate dhcp6 request for '%s'", opts->ifname);
		goto failure;
	}

	req->update = ni_config_addrconf_update(ifp->name, NI_ADDRCONF_DHCP, AF_INET6);
	req->update |= NI_BIT(NI_ADDRCONF_UPDATE_HOSTNAME);

	if (!ni_dhcp6_tester_req_init(req, opts->request))
		goto failure;

	if (opts->mode != req->mode)
		req->mode = opts->mode;

	if (!ni_dhcp6_device_check_ready(dev)) {

		if (!ni_netdev_link_is_up(ifp)) {
			ni_netdev_req_t *ifreq;

			ni_debug_dhcp("%s: Trying to bring link up", ifp->name);
			ifreq = ni_netdev_req_new();
			ifreq->ifflags = NI_IFF_LINK_UP | NI_IFF_NETWORK_UP;
			if ((rv = ni_system_interface_link_change(ifp, ifreq)) < 0) {
				ni_error("%s: Unable to set up link", ifp->name);
				ni_netdev_req_free(ifreq);
				goto failure;
			}
			ni_netdev_req_free(ifreq);
		} else {
			ni_debug_dhcp("%s: Waiting for IPv6 to become ready",
					ifp->name);
		}

		do {
			sleep(1);

			if (!(ifp = ni_netdev_by_index(nc, dev->link.ifindex)))
				break;
			if (__ni_system_refresh_interface(nc, ifp))
				break;
			if (!(ifp = ni_netdev_by_index(nc, dev->link.ifindex)))
				break;
			if (!ni_netdev_device_is_up(ifp))
				break;

			if (ni_dhcp6_device_check_ready(dev))
				break;
		} while (ni_lifetime_left(link_timeout, &start_time, NULL) > 1);

		if (!ifp || !ni_dhcp6_device_check_ready(dev) || !link_timeout) {
			ni_error("%s: Unable to bring IPv6 link up",
				ifp && ifp->name ? ifp->name : dev->ifname);
			goto failure;
		}
	}

	if (opts->timeout && opts->timeout != -1U)
		req->acquire_timeout = ni_lifetime_left(opts->timeout, &start_time, NULL);

	if ((rv = ni_dhcp6_acquire(dev, req, &errdetail)) < 0) {
		ni_error("%s: DHCPv6 acquire request %s failed: %s%s[%s]",
				dev->ifname, ni_uuid_print(&req->uuid),
				(errdetail ? errdetail : ""),
				(errdetail ? " " : ""),
				ni_strerror(rv));
		ni_string_free(&errdetail);
		goto failure;
	}

	dhcp6_tester_status = NI_WICKED_RC_IN_PROGRESS;
	while (!ni_caught_terminal_signal()) {
		ni_timeout_t timeout;

		timeout = ni_timer_next_timeout();
		if (dev->config && (dev->config->mode & NI_BIT(NI_DHCP6_MODE_AUTO))) {
			ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_DHCP,
					"%s: DHCPv6 mode is auto", dev->ifname);

			if (!(ifp = ni_netdev_by_index(nc, dev->link.ifindex)))
				break;
			if (__ni_system_refresh_interface(nc, ifp))
				break;

			ni_dhcp6_device_update_mode(dev, ifp);
			if (dev->config->mode & NI_BIT(NI_DHCP6_MODE_AUTO)) {
				if (timeout > 1000)
					timeout = 1000;
			}
		}
		if (ni_socket_wait(timeout) != 0)
			break;
	}
	ni_server_deactivate_interface_events();
	ni_socket_deactivate_all();

failure:
	if (dev)
		ni_dhcp6_device_put(dev);
	if (req)
		ni_dhcp6_request_free(req);
	return dhcp6_tester_status;
}
