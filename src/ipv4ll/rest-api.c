/*
 * IPv4LL and autoip client for wicked.
 * Note, this REST interface is used for both autoip and IPv4LL,
 *
 * Copyright (C) 2010 Olaf Kirch <okir@suse.de>
 */

#include <sys/poll.h>
#include <sys/time.h>
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
#include "netinfo_priv.h"
#include "socket_priv.h"
#include "kernel.h"
#include "autoip.h"

static ni_rest_node_t	ni_autoip_root_node;

static void		ni_autoip_process_request(ni_socket_t *);
static void		ni_autoip_send_device_event(ni_socket_t *, const ni_autoip_device_t *);
static xml_node_t *	autoip_device_xml(const ni_autoip_device_t *);

/*
 * Handle terminal signals
 */
static int	ni_autoip_stop = 0;

static void
catch_fatal_signals(int sig)
{
	ni_autoip_stop = sig;
}

/*
 * Mainloop for autoip supplicant side
 */
void
ni_autoip_run(ni_socket_t *sock)
{
	struct sigaction sa;
	ni_autoip_device_t *dev;

	ni_debug_autoip("IPv4 autoip supplicant starting");
	ni_srandom();

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = catch_fatal_signals;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);

	sock->data_ready = ni_autoip_process_request;
	ni_socket_activate(sock);

	/* event loop */
	while (1) {
		long timeout;

		/* Get timeout from FSM */
		timeout = ni_autoip_fsm_get_timeout();

		/* Wait for activity on any of the sockets.
		 * Incoming IPv4LL packets will have been processed when
		 * we return.
		 */
		if (ni_socket_wait(timeout) < 0)
			ni_fatal("ni_socket_wait failed");

		if (ni_autoip_stop) {
			ni_debug_autoip("received exit signal %d", ni_autoip_stop);
			break;
		}

		/* See if anything timed out */
		ni_autoip_fsm_check_timeout();

		for (dev = ni_autoip_active; dev; dev = dev->next) {
			if (dev->notify) {
				ni_autoip_send_device_event(sock, dev);
				dev->notify = 0;
			}
		}
	}

	exit(0);
}

/*
 * Process an incoming WICKED request
 */
void
ni_autoip_process_request(ni_socket_t *sock)
{
	ni_wicked_request_t req;
	int rv;

	/* Pull the next message from the socket */
	if (ni_socket_pull(sock) < 0) {
		ni_error("unable to receive: %m");
		return;
	}

	/* Process the request */
	rv = ni_wicked_request_parse(sock, &req);
	if (rv >= 0)
		rv = __ni_wicked_call_direct(&req, &ni_autoip_root_node);
	if (rv < 0)
		ni_error("unable to process autoip request");

	ni_wicked_request_destroy(&req);
}

void
ni_autoip_send_device_event(ni_socket_t *sock, const ni_autoip_device_t *dev)
{
	xml_node_t *devnode;
	char event[65536];
	FILE *fp;

	ni_debug_autoip("sending device event for %s", dev->ifname);
	if ((devnode = autoip_device_xml(dev)) == NULL) {
		ni_error("%s: cannot render interface information", dev->ifname);
		return;
	}

	fp = fmemopen(event, sizeof(event), "w");

	fprintf(fp, "POST /system/event/%s\n\n", dev->ifname);
	xml_node_print(devnode, fp);
	fclose(fp);

	if (write(sock->__fd, event, strlen(event)) < 0)
		ni_error("error sending ipv4ll event: %m");
	xml_node_free(devnode);
}

/*
 * Produce XML for device.
 */
static xml_node_t *
autoip_device_xml(const ni_autoip_device_t *dev)
{
	ni_syntax_t *xmlsyntax = ni_default_xml_syntax();
	ni_addrconf_lease_t dummy, *lease;

	/* This could be more elegant. */
	memset(&dummy, 0, sizeof(dummy));
	dummy.type = NI_ADDRCONF_AUTOCONF;
	dummy.family = AF_INET;
	lease = &dummy;

	if (dev->failed) {
		dummy.state = NI_ADDRCONF_STATE_FAILED;
	} else if (dev->lease) {
		lease = dev->lease;
	} else {
		dummy.state = NI_ADDRCONF_STATE_RELEASED;
	}

	return ni_syntax_xml_from_lease(xmlsyntax, lease, NULL);
}

/*
 * PUT /interface.
 * The XML blob uses the standard interface XML description,
 * or an <event> element.
 */
static int
autoip_argument_as_event(const xml_node_t *node)
{
	const char *attrval;

	if (node && node->name == NULL)
		node = node->children;
	if (!node || !node->name || strcmp(node->name, "event"))
		return -1;
	if ((attrval = xml_node_get_attr(node, "type")) == NULL)
		return -1;

	return ni_event_name_to_type(attrval);
}

static int
autoip_interface_put(ni_wicked_request_t *req)
{
	const char *ifname = req->argv[0];
	ni_interface_t *ifp = NULL;
	ni_handle_t *cnih = NULL;
	ni_autoip_device_t *dev = NULL;
	int rv = -1, event;

	if (ifname == NULL) {
		werror(req, "no interface name given");
		return -1;
	}

	/* Open a dummy handle to parse the XML interface description */
	cnih = ni_dummy_open();
	if (cnih == NULL) {
		werror(req, "unable to create netinfo dummy handle");
		goto failed;
	}

	/* Check if this is an event */
	if ((event = autoip_argument_as_event(req->xml_in)) >= 0) {
		ni_debug_autoip("autoip: process %s event on %s",
				ni_event_type_to_name(event), ifname);
		dev = ni_autoip_device_find(ifname);
		if (!dev)
			goto failed;

		switch (event) {
		case NI_EVENT_LINK_DELETE:
			ni_autoip_device_stop(dev);
			break;
		case NI_EVENT_LINK_UP:
			/* We may have lost our address to someone else while we were
			 * off the link. Try to reclaim it, and if that fails, pick a different
			 * address.
			 */
			ni_autoip_fsm_select(dev);

			/* At this point, we may want to drop the lease until we're done
			 * with reacquiring it. Whether we really *want* this depends on
			 * how long the link has been cut, though.
			 * For now, just proceed with fingers crossed.
			 */
			break;
		case NI_EVENT_LINK_DOWN:
			break;
		}
		goto success;
	}

	if (__ni_syntax_xml_to_all(ni_default_xml_syntax(), cnih, req->xml_in) < 0) {
		werror(req, "unable to parse interface configuration");
		goto failed;
	}

	if (!(ifp = ni_interface_by_name(cnih, ifname))) {
		werror(req, "cannot find configuration for interface %s", ifname);
		goto failed;
	}

	/* FIXME: if nothing changed, we don't need to do anything. */

	dev = ni_autoip_device_find(ifp->name);
	if (ni_afinfo_addrconf_test(&ifp->ipv4, NI_ADDRCONF_AUTOCONF)) {
		ni_debug_autoip("%s: received request to acquire IPv4LL lease", ifp->name);

		if (dev == NULL)
			dev = ni_autoip_device_new(ifp->name, ifp->type);
		ni_autoip_device_reconfigure(dev, ifp);

		/* We're asked to (re-)start */
		if (dev->fsm.state == NI_AUTOIP_STATE_INIT)
			ni_autoip_device_start(dev);
	} else {
		ni_debug_autoip("%s: received request to release IPv4LL lease", ifp->name);

		if (dev == NULL)
			goto failed;
		ni_autoip_device_stop(dev);
	}

	/* Even if nothing changed, we should at least inform the master of
	 * the current lease state */
	dev->notify = 1;

success:
	rv = 0;

failed:
	if (cnih)
		ni_close(cnih);
	return rv;
}

/*
 * DELETE /interface/<ifname>
 */
static int
autoip_interface_delete(ni_wicked_request_t *req)
{
	const char *ifname = req->argv[0];
	ni_autoip_device_t *dev;

	if (ifname == NULL) {
		werror(req, "no interface name given");
		return -1;
	}

	if ((dev = ni_autoip_device_find(ifname)) != NULL)
		ni_autoip_device_stop(dev);
	return 0;
}

static ni_rest_node_t  ni_autoip_interface_wildcard_node = {
	.name		= NULL,
	.ops = {
	    .byname = {
		.put	= autoip_interface_put,
		.delete	= autoip_interface_delete,
	    },
	},
};

static ni_rest_node_t  ni_autoip_interface_node = {
	.name		= "interface",
	.wildcard	= &ni_autoip_interface_wildcard_node,
};

static ni_rest_node_t  ni_autoip_root_node = {
	.name		= "/",
	.children = {
		&ni_autoip_interface_node,
	},
};
