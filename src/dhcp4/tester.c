/*
 *	wicked dhcp4 in test (request offer/lease) mode
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
#include <wicked/leaseinfo.h>
#include <wicked/socket.h>
#include <wicked/system.h>
#include <wicked/xml.h>

#include "appconfig.h"
#include "dhcp4/dhcp4.h"
#include "dhcp4/tester.h"


/* TODO: get rid of these static things */
static ni_dhcp4_tester_t	dhcp4_tester_opts;
static int			dhcp4_tester_status;

ni_dhcp4_tester_t *
ni_dhcp4_tester_init(void)
{
	memset(&dhcp4_tester_opts, 0, sizeof(dhcp4_tester_opts));
	dhcp4_tester_opts.outfmt  = NI_DHCP4_TESTER_OUT_LEASE_INFO;
	dhcp4_tester_opts.timeout = 0;
	dhcp4_tester_opts.broadcast = NI_TRISTATE_DEFAULT;
	dhcp4_tester_status = NI_WICKED_RC_NOT_RUNNING;
	return &dhcp4_tester_opts;
}

ni_bool_t
ni_dhcp4_tester_set_outfmt(const char *outfmt, unsigned int *type)
{
	static const ni_intmap_t __outfmt_map[] = {
		{ "lease-xml",	NI_DHCP4_TESTER_OUT_LEASE_XML  },
		{ "leaseinfo",	NI_DHCP4_TESTER_OUT_LEASE_INFO },
		{ "info",	NI_DHCP4_TESTER_OUT_LEASE_INFO },
		{ NULL,		NI_DHCP4_TESTER_OUT_LEASE_INFO },
	};
	return ni_parse_uint_mapped(outfmt, __outfmt_map, type) == 0;
}

static void
ni_dhcp4_tester_protocol_event(enum ni_dhcp4_event ev, const ni_dhcp4_device_t *dev,
		ni_addrconf_lease_t *lease)
{
	ni_debug_dhcp("%s(ev=%u, dev=%s[%u], config-uuid=%s)", __func__, ev,
			dev->ifname, dev->link.ifindex,
			dev->config ? ni_uuid_print(&dev->config->uuid) : "<none>");

	switch (ev) {
	case NI_DHCP4_EVENT_ACQUIRED:
		if (lease && lease->state == NI_ADDRCONF_STATE_GRANTED) {
			FILE *fp = stdout;

			if (dhcp4_tester_opts.output != NULL) {
				fp = fopen(dhcp4_tester_opts.output, "w");
				if (!fp) {
					ni_error("Cannot open %s for output",
						dhcp4_tester_opts.output);
					dhcp4_tester_status = NI_WICKED_RC_ERROR;
					return;
				}
			}
			if (dhcp4_tester_opts.outfmt == NI_DHCP4_TESTER_OUT_LEASE_XML) {
				xml_node_t *xml = NULL;

				if (ni_addrconf_lease_to_xml(lease, &xml, dev->ifname) != 0) {
					if (dhcp4_tester_opts.output)
						fclose(fp);
					dhcp4_tester_status = NI_WICKED_RC_ERROR;
					return;
				}
				xml_node_print(xml, fp);
				xml_node_free(xml);
			} else {
				ni_leaseinfo_dump(fp, lease, dev->ifname, NULL);
			}
			fflush(fp);
			if (dhcp4_tester_opts.output)
				fclose(fp);
			dhcp4_tester_status = NI_WICKED_RC_SUCCESS;
		}
		break;
	default:
		break;
	}
}

static ni_bool_t
ni_dhcp4_tester_req_xml_init(ni_dhcp4_request_t *req, xml_document_t *doc)
{
	xml_node_t *xml, *child;
	const char *type;

	xml = xml_document_root(doc);
	if (xml && !xml->name && xml->children)
		xml = xml->children;

	if (!xml || !ni_string_eq(xml->name, "request")) {
		ni_error("Invalid dhcp4 request xml '%s'",
				xml ? xml_node_location(xml) : NULL);
		return FALSE;
	}

	type = xml_node_get_attr(xml, "type");
	if (ni_string_eq(type, "offer")) {
		req->dry_run = NI_DHCP4_RUN_OFFER;
	} else
	if (ni_string_eq(type, "lease")) {
		req->dry_run = NI_DHCP4_RUN_LEASE;
	}

	for (child = xml->children; child; child = child->next) {
		if (ni_string_eq(child->name, "uuid")) {
			if (ni_uuid_parse(&req->uuid, child->cdata) != 0)
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
				if (ni_string_eq(ptr->name, "encode")) {
					if (ni_parse_boolean(ptr->cdata, &req->fqdn.encode) != 0)
						goto failure;
				} else
				if (ni_string_eq(ptr->name, "qualify")) {
					if (ni_parse_boolean(ptr->cdata, &req->fqdn.qualify) != 0)
						goto failure;
				}
			}
		} else
		if (ni_string_eq(child->name, "clientid")) {
			ni_opaque_t duid;

			if (ni_parse_hex(child->cdata, duid.data, sizeof(duid.data)) <= 0)
				goto failure;
			ni_string_dup(&req->clientid, child->cdata);
		} else
		if(ni_string_eq(child->name, "start-delay")) {
			if (ni_parse_uint(child->cdata, &req->start_delay, 10) != 0)
				goto failure;
		} else
		if (ni_string_eq(child->name, "lease-time")) {
			if (ni_parse_uint(child->cdata, &req->lease_time, 10) != 0)
				goto failure;
		} else
		if (ni_string_eq(child->name, "recover-lease")) {
			if (ni_parse_boolean(child->cdata, &req->recover_lease) != 0)
				goto failure;
		} else
		if (ni_string_eq(child->name, "release-lease")) {
			if (ni_parse_boolean(child->cdata, &req->release_lease) != 0)
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
		ni_error("Cannot parse dhcp4 request '%s': %s",
				child->name, xml_node_location(child));
	}
	return FALSE;
}

static ni_bool_t
ni_dhcp4_tester_req_init(ni_dhcp4_request_t *req, const char *request)
{
	/* Apply some defaults */
	req->dry_run = NI_DHCP4_RUN_OFFER;
	req->acquire_timeout = 10;

	if (!ni_string_empty(request)) {
		xml_document_t *doc;

		if (!(doc = xml_document_read(request))) {
			ni_error("Cannot parse dhcp4 request xml '%s'", request);
			return FALSE;
		}

		if (!ni_dhcp4_tester_req_xml_init(req, doc)) {
			xml_document_free(doc);
			return FALSE;
		}
		xml_document_free(doc);
	}

	/* Always enter dry run mode */
	if (ni_uuid_is_null(&req->uuid))
		ni_uuid_generate(&req->uuid);

	return TRUE;
}

int
ni_dhcp4_tester_run(ni_dhcp4_tester_t *opts)
{
	ni_netconfig_t *nc;
	ni_netdev_t *ifp = NULL;
	ni_dhcp4_device_t *dev = NULL;
	ni_dhcp4_request_t *req = NULL;
	unsigned int link_timeout = 20;
	int rv;

	if (opts->timeout && opts->timeout != -1U) {
		link_timeout = (opts->timeout * 2) / 3;
		opts->timeout -= link_timeout;
	}

	if (!opts || ni_string_empty(opts->ifname))
		ni_fatal("Invalid start parameters!");

	dhcp4_tester_opts   = *opts;
	dhcp4_tester_status = NI_WICKED_RC_ERROR;

	if (!(nc = ni_global_state_handle(1)))
		ni_fatal("Cannot refresh interface list!");

	if (!(ifp = ni_netdev_by_name(nc, opts->ifname)))
		ni_fatal("Cannot find interface with name '%s'", opts->ifname);

	if (!ni_dhcp4_supported(ifp))
		ni_fatal("DHCPv4 not supported on '%s'", opts->ifname);

	if (!(dev = ni_dhcp4_device_new(ifp->name, &ifp->link)))
		ni_fatal("Cannot allocate dhcp4 client for '%s'", opts->ifname);

	ni_dhcp4_set_event_handler(ni_dhcp4_tester_protocol_event);

	if (!(req = ni_dhcp4_request_new())) {
		ni_error("Cannot allocate dhcp4 request");
		goto failure;
	}

	req->update = ni_config_addrconf_update(ifp->name, NI_ADDRCONF_DHCP, AF_INET);
	req->update |= NI_BIT(NI_ADDRCONF_UPDATE_HOSTNAME);

	if (!ni_dhcp4_tester_req_init(req, opts->request))
		goto failure;

	if (!ni_netdev_link_is_up(ifp)) {
		ni_netdev_req_t *ifreq;
		ni_debug_dhcp("%s: Link is not up, trying to bring it up",
				ifp->name);

		ifreq = ni_netdev_req_new();
		ifreq->ifflags = NI_IFF_LINK_UP | NI_IFF_NETWORK_UP;
		if ((rv = ni_system_interface_link_change(ifp, ifreq)) < 0) {
			ni_error("%s: Unable to set up link", ifp->name);
			ni_netdev_req_free(ifreq);
			goto failure;
		}
		ni_netdev_req_free(ifreq);

		do {
			sleep(1);

			if (!(nc = ni_global_state_handle(1)))
				goto failure;

			if (!(ifp = ni_netdev_by_index(nc, dev->link.ifindex)))
				break;

			if (ni_netdev_link_is_up(ifp))
				break;

			ni_debug_dhcp("%s: Link is not (yet) up", ifp->name);
		} while (link_timeout-- > 1);

		if (!ifp || !ni_netdev_link_is_up(ifp) || !link_timeout) {
			ni_error("%s: Unable to bring link up",
				ifp && ifp->name ? ifp->name : dev->ifname);
			goto failure;
		}

		/* Do not try to send too early, even link is reported up now */
		sleep(1);
	}

	if (opts->timeout && opts->timeout != -1U)
		req->acquire_timeout = opts->timeout;

	req->broadcast = opts->broadcast;

	if ((rv = ni_dhcp4_acquire(dev, req)) < 0) {
		ni_error("%s: DHCP4v6 acquire request %s failed: %s",
				dev->ifname, ni_uuid_print(&req->uuid),
				ni_strerror(rv));
		goto failure;
	}

	dhcp4_tester_status = NI_WICKED_RC_IN_PROGRESS;
	while (!ni_caught_terminal_signal()) {
		long timeout;

		timeout = ni_timer_next_timeout();

		if (ni_socket_wait(timeout) != 0)
			break;
	}
	ni_server_deactivate_interface_events();
	ni_socket_deactivate_all();

failure:
	if (dev)
		ni_dhcp4_device_put(dev);
	if (req)
		ni_dhcp4_request_free(req);
	return dhcp4_tester_status;
}
