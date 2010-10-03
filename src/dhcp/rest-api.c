/*
 * DHCP client for wicked.
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
#include <wicked/logging.h>
#include <wicked/wicked.h>
#include <wicked/xml.h>
#include <wicked/socket.h>
#include "netinfo_priv.h"
#include "kernel.h"
#include "dhcp.h"
#include "protocol.h"

#define MAXFD		64

static ni_rest_node_t	ni_dhcp_root_node;

static void		ni_dhcp_run(ni_socket_t *);
static void		ni_dhcp_process_request(ni_socket_t *);
static void		ni_dhcp_process_event(ni_socket_t *);
static void		ni_dhcp_send_device_event(ni_socket_t *, const ni_dhcp_device_t *);
static void		ni_srandom(void);
static xml_node_t *	dhcp_device_xml(const ni_dhcp_device_t *);

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

ni_addrconf_t ni_dhcp_addrconf = {
	.type = NI_ADDRCONF_DHCP,
	.supported_af = NI_AF_MASK_IPV4,

	.request = ni_dhcp_addrconf_request,
	.release = ni_dhcp_addrconf_release,
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

/*
 * Mainloop for dhcp supplicant side
 */
void
ni_dhcp_run(ni_socket_t *sock)
{
	ni_srandom();

	sock->data_ready = ni_dhcp_process_request;
	ni_socket_activate(sock);

	/* event loop */
	while (1) {
		ni_dhcp_device_t *dev;
		long timeout;

		/* Get timeout from FSM */
		timeout = ni_dhcp_fsm_get_timeout();

		/* Wait for activity on any of the sockets.
		 * Incoming DHCP packets will have been processed when
		 * we return.
		 */
		if (ni_socket_wait(timeout) < 0)
			ni_fatal("ni_socket_wait failed");

		/* See if anything timed out */
		ni_dhcp_fsm_check_timeout();

		while ((dev = ni_dhcp_device_get_changed()) != NULL)
			ni_dhcp_send_device_event(sock, dev);
	}
}

/*
 * Process an incoming WICKED request
 */
void
ni_dhcp_process_request(ni_socket_t *sock)
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
		rv = __ni_wicked_call_direct(&req, &ni_dhcp_root_node);
	if (rv < 0)
		ni_error("unable to process dhcp request");

	ni_wicked_request_destroy(&req);
}

void
ni_dhcp_send_device_event(ni_socket_t *sock, const ni_dhcp_device_t *dev)
{
	xml_node_t *devnode;
	char event[65536];
	FILE *fp;

	ni_debug_dhcp("sending device event for %s", dev->ifname);
	if ((devnode = dhcp_device_xml(dev)) == NULL) {
		ni_error("%s: cannot render interface information", dev->ifname);
		return;
	}

	fp = fmemopen(event, sizeof(event), "w");

	fprintf(fp, "POST /system/event/%s\n\n", dev->ifname);
	xml_node_print(devnode, fp);
	fclose(fp);

	write(sock->__fd, event, strlen(event));
	xml_node_free(devnode);
}

/*
 * Produce XML for device.
 */
static xml_node_t *
dhcp_device_xml(const ni_dhcp_device_t *dev)
{
	ni_syntax_t *xmlsyntax = ni_default_xml_syntax();
	ni_addrconf_lease_t dummy, *lease;

	/* This could be more elegant. */
	memset(&dummy, 0, sizeof(dummy));
	dummy.type = NI_ADDRCONF_DHCP;
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
 * When responding to a /dhcp/interface request, send the interface status as
 * response.
 */
static int
dhcp_device_response(ni_dhcp_device_t *dev, ni_wicked_request_t *req)
{
	if ((req->xml_out = dhcp_device_xml(dev)) == NULL) {
		werror(req, "cannot render interface information");
		return -1;
	}

	return 0;
}

/*
 * Handle GET /device
 */
static int
dhcp_device_get(const char *ifname, ni_wicked_request_t *req)
{
	ni_dhcp_device_t *dev;

	if (ifname == NULL) {
		werror(req, "need to specify interface");
		return -1;
	}

	dev = ni_dhcp_device_find(ifname);
	if (dev == NULL) {
		werror(req, "interface %s not known", ifname);
		return -1;
	}

	return dhcp_device_response(dev, req);
}

/*
 * PUT /interface.
 * The XML blob uses the standard interface XML description.
 */
static int
dhcp_interface_put(const char *ifname, ni_wicked_request_t *req)
{
	ni_interface_t *ifp = NULL;
	ni_handle_t *cnih = NULL;
	ni_dhcp_device_t *dev = NULL;
	int reacquire = 0;
	int rv = -1;

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

	if (__ni_syntax_xml_to_all(ni_default_xml_syntax(), cnih, req->xml_in) < 0) {
		werror(req, "unable to parse interface configuration");
		goto failed;
	}

	if (!(ifp = ni_interface_by_name(cnih, ifname))) {
		werror(req, "cannot find configuration for interface %s", ifname);
		goto failed;
	}

	/* FIXME: if nothing changed, we don't need to do anything. */

	dev = ni_dhcp_device_find(ifp->name);
	if (ifp->flags & IFF_UP) {
		ni_debug_dhcp("%s: received request to acquire lease", ifp->name);
		dev = ni_dhcp_device_find(ifp->name);
		if (dev != NULL) {
			if (ni_dhcp_device_reconfigure(dev, ifp))
				reacquire = 1;
			if (dev->state != NI_DHCP_STATE_BOUND)
				reacquire = 1;
		} else {
			dev = ni_dhcp_device_new(ifp->name, ifp->type);
			ni_dhcp_device_reconfigure(dev, ifp);
			reacquire = 1;
		}
	} else {
		ni_debug_dhcp("%s: received request to release lease", ifp->name);
		ni_dhcp_device_stop(dev);
	}
	if (ifp->flags & IFF_LOWER_UP) {
		/* Link came back. If we're binding, resend next packet right away */
	} else {
		/* Link went away. */
	}
	/* If nothing changed, make sure we at least inform the master of the
	 * current lease state */
	if (!reacquire)
		dev->notify = 1;
	else if (dev->config)
		ni_dhcp_device_start(dev);

	rv = 0;

failed:
	if (cnih)
		ni_close(cnih);
	return rv;
}

/*
 * DELETE /dhcp/interface.
 * The XML blob uses the standard interface XML description.
 */
static int
dhcp_interface_delete(const char *ifname, ni_wicked_request_t *req)
{
	ni_dhcp_device_t *dev;

	if (ifname == NULL) {
		werror(req, "no interface name given");
		return -1;
	}

	if ((dev = ni_dhcp_device_find(ifname)) != NULL)
		ni_dhcp_device_stop(dev);
	return 0;
}

static ni_rest_node_t  ni_dhcp_interface_node = {
	.name		= "interface",
	.ops = {
	    .byname = {
		.put	= dhcp_interface_put,
		.delete	= dhcp_interface_delete,
	    },
	},
};

static ni_rest_node_t  ni_dhcp_device_node = {
	.name		= "device",
	.ops = {
	    .byname = {
		.get	= dhcp_device_get,
	    },
	},
};

static ni_rest_node_t  ni_dhcp_root_node = {
	.name		= "/",
	.children = {
		&ni_dhcp_interface_node,
		&ni_dhcp_device_node,
	},
};

/*
 * Seed the RNG from /dev/urandom
 */
static void
ni_srandom(void)
{
	uint32_t seed = 0;
	int fd;

	if ((fd = open("/dev/urandom", O_RDONLY)) >= 0) {
		if (read(fd, &seed, 4) < 4)
			seed = 0;
		close(fd);
	} else {
		ni_warn("unable to open /dev/random: %m");
	}

	if (seed == 0) {
		struct timeval tv;

		gettimeofday(&tv, NULL);
		seed = tv.tv_usec ^ tv.tv_usec / 1024;
		seed = seed ^ tv.tv_sec;
		seed = seed ^ getpid();
	}

	srandom(seed);
}
