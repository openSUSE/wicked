/*
 * Addrconf stubs for the IPv4LL helper
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
#include <wicked/addrconf.h>
#include <wicked/logging.h>
#include <wicked/wicked.h>
#include <wicked/xml.h>
#include <wicked/socket.h>
#include <wicked/ipv4ll.h>
#include "netinfo_priv.h"
#include "socket_priv.h"
#include "kernel.h"
#include "autoip.h"

static int		ni_autoip_process_event(ni_socket_t *);

/*
 * Netinfo side of IPv4LL addrconf mechanism
 */
static int
__ni_autoip_addrconf_do(const ni_addrconf_t *acm, ni_interface_t *ifp, const xml_node_t *cfg_xml)
{
	ni_handle_t *dummy = NULL;
	ni_wicked_request_t req;
	xml_node_t *tmp_xml = NULL;
	ni_proxy_t *proxy;
	char pathbuf[128];
	int rv = -1;

	if (!(proxy = ni_proxy_find("autoip"))) {
		proxy = ni_proxy_fork_subprocess("autoip", ni_autoip_run);
		ni_socket_set_request_callback(proxy->sock, ni_autoip_process_event);
	}

	snprintf(pathbuf, sizeof(pathbuf), "/interface/%s", ifp->name);
	ni_wicked_request_init(&req);
	req.cmd = NI_REST_OP_PUT;
	req.path = xstrdup(pathbuf);

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
	if (rv < 0)
		ni_error("autoip: notify failed: %s", req.error_msg);

out:
	ni_wicked_request_destroy(&req);
	if (tmp_xml)
		xml_node_free(tmp_xml);
	if (dummy)
		ni_close(dummy);
	return rv;
}

static int
ni_autoip_addrconf_request(const ni_addrconf_t *acm, ni_interface_t *ifp, const xml_node_t *cfg_xml)
{
	if (!ni_interface_network_is_up(ifp)) {
		ni_error("autoip: unexpected links flags - link is not up");
		return -1;
	}
	if (!(ifp->link.ifflags & NI_IFF_ARP_ENABLED)) {
		ni_error("%s: device does not support ARP, cannot configure for IPv4LL", ifp->name);
		return -1;
	}
	if (!ni_afinfo_addrconf_test(&ifp->ipv4, NI_ADDRCONF_AUTOCONF)) {
		ni_error("%s: interface %s doesn't have autoip enabled", __FUNCTION__, ifp->name);
		return -1;
	}

	return __ni_autoip_addrconf_do(acm, ifp, cfg_xml);
}

static int
ni_autoip_addrconf_release(const ni_addrconf_t *acm, ni_interface_t *ifp, ni_addrconf_lease_t *lease)
{
	return __ni_autoip_addrconf_do(acm, ifp, 0);
}

static void
ni_autoip_interface_event(const ni_addrconf_t *acm, ni_interface_t *ifp, ni_event_t ev)
{
	xml_node_t *evnode;

	if (ev != NI_EVENT_LINK_DELETE
	 && ev != NI_EVENT_LINK_UP
	 && ev != NI_EVENT_LINK_DOWN)
		return;

	ni_debug_autoip("%s(%s, %s)", __FUNCTION__, ifp->name, ni_event_type_to_name(ev));
	evnode = xml_node_new("event", NULL);
	xml_node_add_attr(evnode, "type", ni_event_type_to_name(ev));
	__ni_autoip_addrconf_do(acm, ifp, evnode);
	xml_node_free(evnode);
}

ni_addrconf_t ni_autoip_addrconf = {
	.type = NI_ADDRCONF_AUTOCONF,
	.supported_af = NI_AF_MASK_IPV4,

	.request = ni_autoip_addrconf_request,
	.release = ni_autoip_addrconf_release,
	.interface_event = ni_autoip_interface_event,
};

/*
 * netinfo side - handle event sent by autoip supplicant
 */
static int
ni_autoip_process_event(ni_socket_t *sock)
{
	ni_wicked_request_t req;

	ni_trace("ni_autoip_process_event(%p)", sock);
	/* Read the request coming in from the socket. */
	ni_wicked_request_init(&req);

	if (ni_wicked_request_parse(sock, &req) < 0)
		ni_error("cannot parse autoip event");
	else if (ni_wicked_call_direct(&req) < 0)
		ni_error("failed to process autoip event");

	ni_wicked_request_destroy(&req);
	return -1;
}
