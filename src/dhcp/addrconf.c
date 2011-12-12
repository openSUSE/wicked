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
#include "socket_priv.h"
#include "kernel.h"
#include "dhcp.h"
#include "protocol.h"

static int
ni_dhcp_addrconf_request(const ni_addrconf_t *acm, ni_interface_t *ifp, const xml_node_t *cfg_xml)
{
	DBusError error = DBUS_ERROR_INIT;

	if (!ni_afinfo_addrconf_test(&ifp->ipv4, NI_ADDRCONF_DHCP)) {
		ni_warn("%s: DHCP not enabled", __FUNCTION__);
		ni_afinfo_addrconf_enable(&ifp->ipv4, NI_ADDRCONF_DHCP);
	}

	if (!ni_objectmodel_dhcp4_acquire(ifp, ifp->ipv4.request[NI_ADDRCONF_DHCP], &error)) {
		ni_error("wicked_dbus_dhcp4_acquire_call failed: %s (%s)",
				error.name, error.message);
		/* FIXME: translate error name to wicked error code */
		dbus_error_free(&error);
		return -1;
	}
	return 0;
}

static int
ni_dhcp_addrconf_release(const ni_addrconf_t *acm, ni_interface_t *ifp, ni_addrconf_lease_t *lease)
{
	DBusError error = DBUS_ERROR_INIT;

	if (ni_afinfo_addrconf_test(&ifp->ipv4, NI_ADDRCONF_DHCP)) {
		ni_warn("%s: DHCP still marked enabled", __FUNCTION__);
		ni_afinfo_addrconf_disable(&ifp->ipv4, NI_ADDRCONF_DHCP);
	}

	if (!ni_objectmodel_dhcp4_release(ifp, lease, &error)) {
		ni_error("wicked_dbus_dhcp4_release_call failed: %s (%s)",
				error.name, error.message);
		/* FIXME: translate error name to wicked error code */
		dbus_error_free(&error);
		return -1;
	}
	return 0;
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

ni_addrconf_t ni_dhcp_addrconf = {
	.type = NI_ADDRCONF_DHCP,
	.supported_af = NI_AF_MASK_IPV4,

	.request = ni_dhcp_addrconf_request,
	.release = ni_dhcp_addrconf_release,
	.is_valid = ni_dhcp_is_valid,
	.xml_from_lease = ni_dhcp_xml_from_lease,
	.xml_to_lease = ni_dhcp_xml_to_lease,
};
