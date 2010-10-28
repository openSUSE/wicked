/*
 * Addrconf stubs for the DHCP helper
 *
 * Copyright (C) 2010 Olaf Kirch <okir@suse.de>
 */

#include <sys/poll.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/wicked.h>
#include <wicked/xml.h>
#include <wicked/socket.h>
#include "netinfo_priv.h"
#include "kernel.h"
#include "dhcp.h"
#include "protocol.h"

static void		ni_dhcp_process_event(ni_socket_t *);

/*
 * Netinfo side of DHCP addrconf mechanism
 */
static int
__ni_dhcp_addrconf_do(const ni_addrconf_t *acm, ni_interface_t *ifp, const xml_node_t *cfg_xml)
{
	ni_handle_t *dummy = NULL;
	ni_wicked_request_t req;
	xml_node_t *tmp_xml = NULL;
	ni_proxy_t *proxy;
	char pathbuf[128];
	int rv = -1;

	if (!(proxy = ni_proxy_find("dhcp"))) {
		proxy = ni_proxy_fork_subprocess("dhcp", ni_dhcp_run);
		proxy->sock->data_ready = ni_dhcp_process_event;
	}

	snprintf(pathbuf, sizeof(pathbuf), "/interface/%s", ifp->name);
	ni_wicked_request_init(&req);
	req.cmd = NI_REST_OP_PUT;
	req.path = strdup(pathbuf);

	req.xml_in = cfg_xml;
	if (req.xml_in == NULL) {
		dummy = ni_dummy_open();
		req.xml_in = tmp_xml = ni_syntax_xml_from_interface(ni_default_xml_syntax(), dummy, ifp);
	}

	if (req.xml_in == NULL) {
		ni_error("%s: unable to create XML representation", ifp->name);
		goto out;
	}

	rv = ni_wicked_send_event(proxy->sock, &req);
	if (rv < 0) {
		ni_error("dhcp: notify failed: %s", req.error_msg);
	}

out:
	ni_wicked_request_destroy(&req);
	if (tmp_xml)
		xml_node_free(tmp_xml);
	if (dummy)
		ni_close(dummy);
	return rv;
}

static int
ni_dhcp_addrconf_request(const ni_addrconf_t *acm, ni_interface_t *ifp, const xml_node_t *cfg_xml)
{
	if ((ifp->flags & IFF_UP) == 0) {
		ni_error("dhcp: unexpected links flags - link is not up");
		return -1;
	}

	return __ni_dhcp_addrconf_do(acm, ifp, cfg_xml);
}

static int
ni_dhcp_addrconf_release(const ni_addrconf_t *acm, ni_interface_t *ifp, ni_addrconf_lease_t *lease)
{
	return __ni_dhcp_addrconf_do(acm, ifp, 0);
}

static int
ni_dhcp_is_valid(const ni_addrconf_t *acm, const ni_addrconf_lease_t *lease)
{
	time_t now = time(NULL);

	if (lease->state != NI_ADDRCONF_STATE_GRANTED)
		return 0;
	if (lease->time_acquired + lease->dhcp.lease_time <= now)
		return 0;
	return 1;
}

static void
ni_dhcp_interface_event(const ni_addrconf_t *acm, ni_interface_t *ifp, ni_event_t ev)
{
	xml_node_t *evnode;

	if (ev != NI_EVENT_LINK_DELETE
	 && ev != NI_EVENT_LINK_UP
	 && ev != NI_EVENT_LINK_DOWN)
		return;

	ni_debug_dhcp("%s(%s, %s)", __FUNCTION__, ifp->name, ni_event_type_to_name(ev));
	evnode = xml_node_new("event", NULL);
	xml_node_add_attr(evnode, "type", ni_event_type_to_name(ev));
	__ni_dhcp_addrconf_do(acm, ifp, evnode);
	xml_node_free(evnode);
}

ni_addrconf_t ni_dhcp_addrconf = {
	.type = NI_ADDRCONF_DHCP,
	.supported_af = NI_AF_MASK_IPV4,

	.request = ni_dhcp_addrconf_request,
	.release = ni_dhcp_addrconf_release,
	.interface_event = ni_dhcp_interface_event,
	.is_valid = ni_dhcp_is_valid,
	.xml_from_lease = ni_dhcp_xml_from_lease,
	.xml_to_lease = ni_dhcp_xml_to_lease,
};

/*
 * netinfo side - handle event sent by dhcp supplicant
 */
static void
ni_dhcp_process_event(ni_socket_t *sock)
{
	ni_wicked_request_t req;

	ni_trace("ni_dhcp_process_event(%p)", sock);
	/* Read the request coming in from the socket. */
	ni_wicked_request_init(&req);

	ni_socket_pull(sock);
	if (ni_wicked_request_parse(sock, &req) < 0)
		ni_error("cannot parse dhcp event");
	else if (ni_wicked_call_direct(&req) < 0)
		ni_error("failed to process dhcp event");

	ni_wicked_request_destroy(&req);
}
