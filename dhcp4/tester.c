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
#include <net/if_arp.h>

#include <wicked/types.h>
#include <wicked/leaseinfo.h>
#include <wicked/socket.h>
#include <wicked/xml.h>

#include "dhcp4/dhcp.h"
#include "dhcp4/tester.h"


static dhcp4_tester_t	dhcp4_tester_opts;
static int		dhcp4_tester_status;

dhcp4_tester_t *
dhcp4_tester_init(void)
{
	memset(&dhcp4_tester_opts, 0, sizeof(dhcp4_tester_opts));
	dhcp4_tester_opts.outfmt  = DHCP4_TESTER_OUT_LEASE_INFO;
	dhcp4_tester_opts.timeout = 10;	/* 10 seconds */
	return &dhcp4_tester_opts;
}

ni_bool_t
dhcp4_tester_set_outfmt(const char *outfmt, unsigned int *type)
{
	static const ni_intmap_t __outfmt_map[] = {
		{ "lease-xml",	DHCP4_TESTER_OUT_LEASE_XML  },
		{ "leaseinfo",	DHCP4_TESTER_OUT_LEASE_INFO },
		{ "info",	DHCP4_TESTER_OUT_LEASE_INFO },
		{ NULL,		DHCP4_TESTER_OUT_LEASE_INFO },
	};
	return ni_parse_uint_mapped(outfmt, __outfmt_map, type) == 0;
}

static void
dhcp4_tester_protocol_event(enum ni_dhcp4_event ev, const ni_dhcp4_device_t *dev,
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
			if (dhcp4_tester_opts.outfmt == DHCP4_TESTER_OUT_LEASE_XML) {
				xml_node_t *xml = NULL;

				if (ni_addrconf_lease_to_xml(lease, &xml) != 0) {
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
			dhcp4_tester_status = 0;
		}
		break;
	default:
		break;
	}
}

static ni_bool_t
dhcp4_tester_req_xml_init(ni_dhcp4_request_t *req, xml_document_t *doc)
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
dhcp4_tester_req_init(ni_dhcp4_request_t *req, const char *request)
{
	/* Apply some defaults */
	req->dry_run = NI_DHCP4_RUN_OFFER;
	req->update = ~0;

	if (!ni_string_empty(request)) {
		xml_document_t *doc;

		if (!(doc = xml_document_read(request))) {
			ni_error("Cannot parse dhcp4 request xml '%s'", request);
			return FALSE;
		}

		if (!dhcp4_tester_req_xml_init(req, doc)) {
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
dhcp4_tester_run(dhcp4_tester_t *opts)
{
	ni_netconfig_t *nc;
	ni_netdev_t *ifp;
	ni_dhcp4_device_t *dev;
	ni_dhcp4_request_t *req;
	int rv;

	if (!opts || ni_string_empty(opts->ifname))
		ni_fatal("Invalid start parameters!");

	dhcp4_tester_opts   = *opts;
	dhcp4_tester_status = NI_WICKED_RC_ERROR;

	if (!(nc = ni_global_state_handle(1)))
		ni_fatal("Cannot refresh interface list!");

	if (!(ifp = ni_netdev_by_name(nc, opts->ifname)))
		ni_fatal("Cannot find interface with name '%s'", opts->ifname);

	switch (ifp->link.hwaddr.type) {
	case ARPHRD_ETHER:
		break;
	default:
		ni_fatal("Interface type not supported yet");
		break;
	}

	if (!(dev = ni_dhcp4_device_new(ifp->name, &ifp->link)))
		ni_fatal("Cannot allocate dhcp4 client for '%s'", opts->ifname);

	ni_dhcp4_set_event_handler(dhcp4_tester_protocol_event);

	if (!(req = ni_dhcp4_request_new())) {
		ni_error("Cannot allocate dhcp4 request");
		goto failure;
	}

	if (!dhcp4_tester_req_init(req, opts->request))
		goto failure;

	if (opts->timeout && opts->timeout != -1U)
		req->acquire_timeout = opts->timeout;

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
	ni_dhcp4_device_put(dev);
	ni_dhcp4_request_free(req);
	return dhcp4_tester_status;
}
