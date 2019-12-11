/*
 * Handle LLDP Agent configuration per interface.
 *
 * It might be worth to make the agent a separate process, like in the
 * DHCP supplicant case. But for now, for the sake of simplicity, let's
 * keep it in the main wicked server process.
 *
 * Copyright (C) 2013 Olaf Kirch <okir@suse.de>
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <wicked/types.h>
#include <wicked/lldp.h>
#include <wicked/logging.h>
#include <wicked/netinfo.h>
#include <wicked/socket.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <stdarg.h>

#if defined(HAVE_DCB_ATTR_IEEE_MAXRATE) && defined(HAVE_LINUX_DCBNL_H)
#  include <linux/dcbnl.h>
#else
#  include "linux/dcbnl.h"
#endif
#include "buffer.h"
#include "util_priv.h"
#include "debug.h"
#include "netinfo_priv.h"
#include "socket_priv.h"
#include "lldp-priv.h"

/*
 * Maximum number of LLDP peer entries we keep
 */
#define NI_LLDP_MAX_PEERS	256

typedef struct ni_lldp_agent ni_lldp_agent_t;
typedef struct ni_lldp_peer ni_lldp_peer_t;

struct ni_lldp_agent {
	ni_lldp_agent_t *	next;
	unsigned int		ifindex;

	const ni_timer_t *	txTTR;
	uint16_t		msgFastTx;
	uint16_t		msgTxHold;
	uint16_t		msgTxInterval;
	uint16_t		txCredit;
	uint16_t		txCreditMax;
	uint16_t		txFast;
	uint16_t		txFastInit;
	uint16_t		txNow;
	uint32_t		txTTL;

	struct timeval		tx_timestamp;

	ni_netdev_t *		dev;
	ni_lldp_t *		config;
	ni_dcbx_state_t *	dcbx;

	ni_lldp_peer_t *	peers;

	ni_capture_t *		capture;
	ni_buffer_t		sendbuf;
};

struct ni_lldp_peer {
	ni_lldp_peer_t *	next;
	struct timeval		expires;
	ni_lldp_t *		data;
	unsigned int		raw_id_len;
	unsigned char		raw_id[0];
};

static ni_lldp_agent_t *	ni_lldp_agents;

static ni_hwaddr_t		ni_lldp_destaddr[__NI_LLDP_DEST_MAX] = {
[NI_LLDP_DEST_NEAREST_BRIDGE] = {
		.type = ARPHRD_ETHER,
		.len = ETH_ALEN,
		.data = { 0x00, 0x80, 0xC2, 0x00, 0x00, 0x0E }
	},
[NI_LLDP_DEST_NEAREST_NON_TPMR_BRIDGE] = {
		.type = ARPHRD_ETHER,
		.len = ETH_ALEN,
		.data = { 0x00, 0x80, 0xC2, 0x00, 0x00, 0x03 }
	},
[NI_LLDP_DEST_NEAREST_CUSTOMER_BRIDGE] = {
		.type = ARPHRD_ETHER,
		.len = ETH_ALEN,
		.data = { 0x00, 0x80, 0xC2, 0x00, 0x00, 0x00 }
	},
};

typedef int		ni_lldp_get_fn_t(ni_lldp_t *, ni_buffer_t *);


static int		ni_lldp_agent_start(ni_netdev_t *, ni_lldp_t *, ni_dcbx_state_t *);
static void		ni_lldp_agent_stop(ni_netdev_t *);
static ni_bool_t	ni_lldp_agent_send(ni_lldp_agent_t *);
static int		ni_lldp_agent_send_shutdown(ni_lldp_agent_t *);
static void		ni_lldp_agent_free(ni_lldp_agent_t *);
static int		ni_lldp_agent_update(ni_lldp_agent_t *, ni_lldp_t *, const void *, unsigned int);
static void		ni_lldp_tx_timer_arm(ni_lldp_agent_t *);
static void		ni_lldp_tx_timer_arm_quick(ni_lldp_agent_t *);
static void		ni_lldp_receive(ni_socket_t *);
static ni_lldp_peer_t *	ni_lldp_peer_new(const void *raw_id, unsigned int raw_id_len);
static void		ni_lldp_peer_unlink_and_free(ni_lldp_peer_t **);
static int		ni_lldp_pdu_build(const ni_lldp_t *, ni_dcbx_state_t *, ni_buffer_t *);
static int		ni_lldp_pdu_parse(ni_lldp_t *, ni_buffer_t *);
static int		ni_lldp_pdu_get_raw_id(ni_buffer_t *, const void **, unsigned int *);

static ni_lldp_ieee_802_1_t *ni_lldp_ieee_802_1_clone(const ni_lldp_ieee_802_1_t *);
static void		ni_lldp_ieee_802_1_free(ni_lldp_ieee_802_1_t *);


ni_lldp_t *
ni_lldp_new(void)
{
	ni_lldp_t *lldp;

	lldp = xcalloc(1, sizeof(*lldp));

	/* Fill in some meaningful defaults */
	lldp->destination = NI_LLDP_DEST_NEAREST_BRIDGE;
	lldp->chassis_id.type = NI_LLDP_CHASSIS_ID_MAC_ADDRESS;
	lldp->port_id.type = NI_LLDP_PORT_ID_MAC_ADDRESS;

	return lldp;
}

ni_lldp_t *
ni_lldp_clone(const ni_lldp_t *lldp)
{
	ni_lldp_t *copy = ni_lldp_new();

	copy->destination = lldp->destination;

	copy->chassis_id.type = lldp->chassis_id.type;
	copy->chassis_id.mac_addr_value = lldp->chassis_id.mac_addr_value;
	copy->chassis_id.net_addr_value = lldp->chassis_id.net_addr_value;
	ni_string_dup(&copy->chassis_id.string_value, lldp->chassis_id.string_value);

	copy->port_id.type = lldp->port_id.type;
	copy->port_id.mac_addr_value = lldp->port_id.mac_addr_value;
	copy->port_id.net_addr_value = lldp->port_id.net_addr_value;
	ni_string_dup(&copy->port_id.string_value, lldp->port_id.string_value);

	ni_string_dup(&copy->port_description, lldp->port_description);

	ni_string_dup(&copy->system.name, lldp->system.name);
	ni_string_dup(&copy->system.description, lldp->system.description);
	copy->system.capabilities = lldp->system.capabilities;

	copy->ttl = lldp->ttl;

	if (lldp->ieee_802_1)
		copy->ieee_802_1 = ni_lldp_ieee_802_1_clone(lldp->ieee_802_1);

	return copy;
}

void
ni_lldp_free(ni_lldp_t *lldp)
{
	if (lldp) {
		ni_string_free(&lldp->chassis_id.string_value);
		ni_string_free(&lldp->port_id.string_value);
		ni_string_free(&lldp->port_description);
		ni_string_free(&lldp->system.name);
		ni_string_free(&lldp->system.description);

		if (lldp->ieee_802_1)
			ni_lldp_ieee_802_1_free(lldp->ieee_802_1);

		if (lldp->dcb_attributes)
			ni_dcb_attributes_free(lldp->dcb_attributes);

		free(lldp);
	}
}

static ni_dcb_attributes_t *
ni_lldp_get_dcb_attributes(ni_lldp_t *lldp)
{
	if (lldp->dcb_attributes == NULL)
		lldp->dcb_attributes = ni_dcb_attributes_new();
	return lldp->dcb_attributes;
}

/*
 * LLDP peer
 */
static ni_lldp_peer_t *
ni_lldp_peer_new(const void *raw_id, unsigned int raw_id_len)
{
	ni_lldp_peer_t *peer;

	peer = xcalloc(1, sizeof(*peer) + raw_id_len);
	peer->raw_id_len = raw_id_len;
	memcpy(peer->raw_id, raw_id, raw_id_len);
	return peer;
}

static void
ni_lldp_peer_free(ni_lldp_peer_t *peer)
{
	ni_lldp_free(peer->data);
	free(peer);
}
static void
ni_lldp_peer_unlink_and_free(ni_lldp_peer_t **pos)
{
	ni_lldp_peer_t *peer = *pos;

	if (peer) {
		*pos = peer->next;
		ni_lldp_peer_free(peer);
	}
}

static inline ni_bool_t
ni_lldp_check_interface_alias(char **valuep, ni_netdev_t *dev, const char *what)
{
	if (*valuep == NULL || (*valuep)[0] == '\0')
		ni_string_dup(valuep, dev->link.alias);
	if (*valuep == NULL || (*valuep)[0] == '\0') {
		ni_error("LLDP: %s subtype set to interface alias, but no alias set for device %s",
				what, dev->name);
		return FALSE;
	}
	return TRUE;
}

static inline ni_bool_t
ni_lldp_check_interface_name(char **valuep, ni_netdev_t *dev, const char *what)
{
	if (*valuep == NULL || (*valuep)[0] == '\0')
		ni_string_dup(valuep, dev->name);
	return TRUE;
}

static inline ni_bool_t
ni_lldp_check_mac_address(ni_hwaddr_t *mac_addr, ni_netdev_t *dev, const char *what)
{
	if (mac_addr->len == 0)
		*mac_addr = dev->link.hwaddr;
	if (mac_addr->len == 0) {
		ni_error("LLDP: %s subtype set to mac-address, but cannot determine mac for device %s",
				what, dev->name);
		return FALSE;
	}
	return TRUE;
}

ni_bool_t
ni_system_lldp_available(ni_netdev_t *dev)
{
#if defined(NI_ENABLE_LLDP)
	return dev->link.hwaddr.type == ARPHRD_ETHER;
#else
	return FALSE;
#endif
}

/*
 * Bring up an LLDP agent on this device.
 * A NULL config parameter means: no client-side configuration settings,
 * we should decide for ourselves whether to bring up LLDP on this device.
 */
int
ni_system_lldp_up(ni_netdev_t *dev, const ni_lldp_t *config)
{
	ni_dcbx_state_t *dcbx = NULL;

	ni_debug_lldp("%s(%s, lldp=%p)", __func__, dev->name, config);

	/* if the device is DCB capable, enable DCBX */
	if (ni_dcbx_should_start(dev)) {
		dcbx = ni_dcbx_new();
		ni_dcbx_update_local(dcbx, &dev->dcb->attributes);
	}

	if (config || dcbx) {
		ni_lldp_t *lldp = config? ni_lldp_clone(config) : ni_lldp_new();

		if (ni_lldp_agent_start(dev, lldp, dcbx) < 0)
			return -1;

		/* Record the LLDP config requested by the user */
		ni_netdev_set_lldp(dev, lldp);
	} else {
		/* Else: stop LLDP */
		ni_netdev_set_lldp(dev, NULL);
		ni_lldp_agent_stop(dev);
	}
	return 0;
}

/*
 * Shut down an LLDP agent on this device.
 */
int
ni_system_lldp_down(ni_netdev_t *dev)
{
	ni_debug_lldp("%s(%s)", __func__, dev->name);

	ni_netdev_set_lldp(dev, NULL);
	ni_lldp_agent_stop(dev);
	return 0;
}

static ni_lldp_agent_t *
ni_lldp_agent_new(ni_netdev_t *dev, unsigned int mtu)
{
	ni_lldp_agent_t *agent;

	agent = xcalloc(1, sizeof(*agent) + mtu);
	ni_buffer_init(&agent->sendbuf, (void *) (agent + 1), mtu);

	agent->dev = ni_netdev_get(dev);

	/* init tx state machine variables with recommended defaults */
	agent->msgFastTx = 1;
	agent->msgTxHold = 4;
	agent->msgTxInterval = 30;
	agent->txCredit = 0;
	agent->txCreditMax = 30;
	agent->txFast = 0;
	agent->txFastInit = 4;

	agent->txTTL = agent->msgTxHold * agent->msgTxInterval + 1;
	if (agent->txTTL >= 65535)
		agent->txTTL = 65535;

	return agent;
}

void
ni_lldp_agent_free(ni_lldp_agent_t *agent)
{
	ni_capture_free(agent->capture);
	ni_lldp_free(agent->config);
	if (agent->txTTR)
		ni_timer_cancel(agent->txTTR);
	if (agent->dev)
		ni_netdev_put(agent->dev);
	if (agent->dcbx)
		ni_dcbx_free(agent->dcbx);
	ni_buffer_destroy(&agent->sendbuf);
	while (agent->peers)
		ni_lldp_peer_unlink_and_free(&agent->peers);
	free(agent);
}

static ni_lldp_agent_t *
__ni_lldp_take_agent(unsigned int ifindex, ni_lldp_agent_t ***pos_ret)
{
	ni_lldp_agent_t *agent, **pos;

	for (pos = &ni_lldp_agents; (agent = *pos) != NULL; pos = &agent->next) {
		if (agent->ifindex == ifindex) {
			*pos = agent->next;
			agent->next = NULL;
			break;
		}
	}

	*pos_ret = pos;
	return agent;
}

static int
__ni_lldp_agent_configure(ni_netdev_t *dev, ni_lldp_t *lldp)
{
	switch (lldp->chassis_id.type) {
	case NI_LLDP_CHASSIS_ID_INTERFACE_ALIAS:
		if (!ni_lldp_check_interface_alias(&lldp->chassis_id.string_value, dev, "chassis-id"))
			return -1;
		break;

	case NI_LLDP_CHASSIS_ID_INTERFACE_NAME:
		if (!ni_lldp_check_interface_name(&lldp->chassis_id.string_value, dev, "chassis-id"))
			return -1;
		break;

	case NI_LLDP_CHASSIS_ID_MAC_ADDRESS:
		if (!ni_lldp_check_mac_address(&lldp->chassis_id.mac_addr_value, dev, "chassis-id"))
			return -1;
		break;

	case NI_LLDP_CHASSIS_ID_PORT_COMPONENT:
	case NI_LLDP_CHASSIS_ID_CHASSIS_COMPONENT:
	case NI_LLDP_CHASSIS_ID_LOCALLY_ASSIGNED:
		if (lldp->chassis_id.string_value == NULL) {
			ni_error("missing string value for chassis-id");
			return -1;
		}

	default:
		;
	}

	if (lldp->port_id.type == NI_LLDP_PORT_ID_MAC_ADDRESS
	 && !ni_lldp_check_mac_address(&lldp->port_id.mac_addr_value, dev, "port-id"))
		return -1;

	return 0;
}

static int
ni_lldp_agent_configure(ni_lldp_agent_t *agent, ni_netdev_t *dev, ni_lldp_t *lldp, ni_dcbx_state_t *dcbx)
{
	if (lldp->ttl == 0)
		lldp->ttl = agent->txTTL;

	if (__ni_lldp_agent_configure(dev, lldp) < 0) {
		ni_lldp_free(lldp);
		return -1;
	}

	/* DCBX should only be active if the destination is nearest-bridge */
	if (dcbx) {
		dcbx->running = (lldp->destination == NI_LLDP_DEST_NEAREST_BRIDGE);
	}

	ni_lldp_free(agent->config);
	agent->config = lldp;
	agent->dcbx = dcbx;
	return 0;
}

/*
 * Start an agent, using the client configuration given in @lldp, and the DCBX state
 * given in @dcbx.
 *
 * FIXME: we should allow administrative control over LLDP tx and rx.
 */
static int
ni_lldp_agent_start(ni_netdev_t *dev, ni_lldp_t *lldp, ni_dcbx_state_t *dcbx)
{
	ni_lldp_agent_t *agent, **pos;
	ni_capture_t *capture = NULL;

	if ((agent = __ni_lldp_take_agent(dev->link.ifindex, &pos)) != NULL) {
		capture = agent->capture;
		agent->capture = NULL;
		ni_lldp_agent_free(agent);
	}

	agent = ni_lldp_agent_new(dev, 1500);
	agent->next = *pos;
	*pos = agent;

	if (ni_lldp_agent_configure(agent, dev, lldp, dcbx) < 0)
		return -1;

	if (capture == NULL) {
		ni_capture_devinfo_t devinfo;
		ni_capture_protinfo_t protinfo;

		memset(&protinfo, 0, sizeof(protinfo));
		protinfo.eth_protocol = ETHERTYPE_LLDP;

		if (agent->config->destination >= __NI_LLDP_DEST_MAX)
			return -1;
		protinfo.eth_destaddr = ni_lldp_destaddr[agent->config->destination];

		if (ni_capture_devinfo_init(&devinfo, dev->name, &dev->link) < 0)
			return -1;

		capture = ni_capture_open(&devinfo, &protinfo, ni_lldp_receive);
	}
	agent->capture = capture;

	ni_capture_set_user_data(capture, agent);

	ni_lldp_agent_send(agent);
	return 0;
}

void
ni_lldp_agent_stop(ni_netdev_t *dev)
{
	ni_lldp_agent_t *agent, **pos;

	if ((agent = __ni_lldp_take_agent(dev->link.ifindex, &pos)) != NULL) {
		/* While the device is still up, try to send a shutdown PDU */
		if (ni_netdev_device_is_up(dev))
			ni_lldp_agent_send_shutdown(agent);
		ni_lldp_agent_free(agent);
	}
}

static ni_bool_t
ni_lldp_agent_send(ni_lldp_agent_t *agent)
{
	struct timeval now;
	ni_bool_t rv = FALSE;

	/* build packet and prime sender */
	if (ni_buffer_count(&agent->sendbuf) == 0
	 && ni_lldp_pdu_build(agent->config, agent->dcbx, &agent->sendbuf) < 0) {
		ni_error("%s: error building LLDP PDU", agent->dev->name);
		return -1;
	}

	ni_timer_get_time(&now);
	if (!timerisset(&agent->tx_timestamp)) {
		/* Never sent anything - init txCredits to max */
		agent->txCredit = agent->txCreditMax;
		agent->tx_timestamp = now;
	} else
	if (timercmp(&now, &agent->tx_timestamp, <=)) {
		/* Clock warped back */
		agent->tx_timestamp = now;
	} else {
		struct timeval delta;

		timersub(&now, &agent->tx_timestamp, &delta);
		if (delta.tv_sec > 0) {
			agent->txCredit += delta.tv_sec;
			if (agent->txCredit > agent->txCreditMax)
				agent->txCredit = agent->txCreditMax;
			agent->tx_timestamp.tv_sec += delta.tv_sec;
		}
	}

	if (agent->txCredit > 0) {
		ni_buffer_t *bp = &agent->sendbuf;

		ni_debug_lldp("%s: sending LLDP packet (PDU len=%u)", agent->dev->name, ni_buffer_count(bp));
		/* ni_debug_lldp(PDU=%s", ni_print_hex(ni_buffer_head(bp), ni_buffer_count(bp))); */
		ni_capture_send(agent->capture, &agent->sendbuf, NULL);
		agent->txCredit--;

		/* Decrement txFast if we're in a fast retrans cycle */
		if (agent->txFast)
			agent->txFast--;

		/* Regular timer (re-)arm */
		ni_lldp_tx_timer_arm(agent);
		rv = TRUE;
	} else {
		ni_debug_lldp("%s: cannot send LLDP packet (no credits)", agent->dev->name);
		ni_lldp_tx_timer_arm_quick(agent);
	}

	return rv;
}

int
ni_lldp_agent_send_shutdown(ni_lldp_agent_t *agent)
{
	/* Broadtcase a 0 TTL */
	agent->config->ttl = 0;

	if (ni_lldp_pdu_build(agent->config, NULL, &agent->sendbuf) < 0) {
		ni_error("%s: failed to build LLDP shutdown PDU", agent->dev->name);
		return -1;
	}

	ni_capture_send(agent->capture, &agent->sendbuf, NULL);
	return 0;
}

/*
 * When a new neighbor is detected, we enter what is called fast mode - which is
 * to send several PDUs in fast succession to make sure it is received.
 * Which is a bit bogus; if you have too many LLDP agents on a link connected by
 * a hub, this can cause a packet storm.
 */
void
ni_lldp_agent_enter_fast_rx(ni_lldp_agent_t *agent)
{
	ni_bool_t already_in_fast_mode = !!agent->txFast;

	/* Do nothing if we're already in fast mode */
	agent->txFast = agent->txFastInit;
	if (!already_in_fast_mode)
		ni_lldp_agent_send(agent);
}

static void
ni_lldp_tx_timer_expires(void *user_data, const ni_timer_t *timer)
{
	ni_lldp_agent_t *agent = (ni_lldp_agent_t *) user_data;

	if (agent->txTTR != timer) {
		ni_error("ni_lldp_tx_timer_expires: bad timer handle");
		return;
	}
	agent->txTTR = NULL;

	/* FIXME: rebuild the packet? */
	ni_lldp_agent_send(agent);
}

static void
__ni_lldp_tx_timer_arm(ni_lldp_agent_t *agent, unsigned int timeout)
{
	static const ni_int_range_t jitter = { .min = 0, .max = 400 };

	/* Apply a jitter between 0 and 0.4 sec */
	timeout = ni_timeout_randomize(timeout, &jitter);

	if (agent->txTTR)
		ni_timer_cancel(agent->txTTR);
	agent->txTTR = ni_timer_register(timeout, ni_lldp_tx_timer_expires, agent);
	if (agent->txTTR == NULL)
		ni_error("%s: failed to arm LLDP timer", agent->dev->name);
}

void
ni_lldp_tx_timer_arm(ni_lldp_agent_t *agent)
{
	__ni_lldp_tx_timer_arm(agent, 1000 * (agent->txFast? agent->msgFastTx : agent->msgTxInterval));
}

void
ni_lldp_tx_timer_arm_quick(ni_lldp_agent_t *agent)
{
	/* Ask to be woken up in one second, when we hopefully have a new tx credit */
	__ni_lldp_tx_timer_arm(agent, 1000);
}

/*
 * LLDP rx agent
 */
static int
ni_lldp_agent_update(ni_lldp_agent_t *agent, ni_lldp_t *lldp, const void *raw_id, unsigned int raw_id_len)
{
	ni_lldp_peer_t **pos, *peer, *found = NULL;
	unsigned int npeers = 0;
	struct timeval now;

	ni_timer_get_time(&now);

	pos = &agent->peers;

	/* First, expire any old entries. Note that peers are sorted by order
	 * of increasing expiry timeout. */
	while ((peer = *pos) != NULL && timercmp(&peer->expires, &now, <=))
		ni_lldp_peer_unlink_and_free(pos);

	while ((peer = *pos) != NULL) {
		if (peer->raw_id_len == raw_id_len
		 && !memcmp(peer->raw_id, raw_id, raw_id_len)) {
			found = peer;
			*pos = peer->next;
			peer->next = NULL;
		} else {
			*pos = peer->next;
			npeers++;
		}
	}

	if (found != NULL) {
		ni_lldp_free(found->data);
		found->data = NULL;
	} else {
		if (npeers >= NI_LLDP_MAX_PEERS) {
			ni_debug_lldp("%s: too many LLDP peers, ignoring this PDU", __func__);
			return -1;
		}
		found = ni_lldp_peer_new(raw_id, raw_id_len);

		/* A new agent was found. Enter fast transmission mode */
		ni_lldp_agent_enter_fast_rx(agent);
	}

	if (lldp->ttl == 0) {
		/* The peer agent wanted to say bye */
		ni_lldp_peer_free(found);
		return 0;
	}

	/* Update/init the peer info */
	found->expires = now;
	found->expires.tv_sec += lldp->ttl;
	found->data = lldp;

	/* Insert in order of increasing timeout */
	pos = &agent->peers;
	while ((peer = *pos) != NULL && timercmp(&peer->expires, &found->expires, <))
		*pos = peer->next;

	found->next = *pos;
	*pos = found;
	npeers++;

	/* If there is exactly one peer on the link, and that peer
	 * announces its DCB configuration via DCBX, we should invoke
	 * the DCBX finite state machinery.
	 */
	if (agent->dcbx) {
		if (lldp->dcb_attributes != NULL && npeers == 1) {
			agent->dcbx->running = TRUE;

			/* Pass the received DCBX attributes to the DCB driver.
			 * If the function returns TRUE, the configuration changed
			 * and we're supposed to rebuild the PDU on the next transmit
			 */
			if (ni_dcbx_update_remote(agent->dcbx, lldp->dcb_attributes))
				ni_buffer_reset(&agent->sendbuf);
		} else if (agent->dcbx->running) {
			ni_debug_lldp("%s: more than one LLDP agent on the link, disabling DCBX",
					agent->dev->name);
			agent->dcbx->running = FALSE;
		}
	}

	return 0;
}

/*
 * LLDP receive handling
 */
static void
ni_lldp_receive(ni_socket_t *sock)
{
	ni_capture_t *capture = sock->user_data;
	ni_sockaddr_t from;
	ni_buffer_t buf;

	/* FIXME: we need to store the MAC address we received this packet from.
	 * This is needed for DCBX tie-breaking among other things. */
	if (ni_capture_recv(capture, &buf, &from, "lldp") >= 0) {
		ni_lldp_agent_t *agent = ni_capture_get_user_data(capture);
		ni_buffer_t raw_id_buf;
		const void *raw_id;
		unsigned int raw_id_len;
		ni_lldp_t *lldp;

		/* Get the chassis and port ID TLVs as a raw string
		 * of bytes. */
		raw_id_buf = buf;
		if (ni_lldp_pdu_get_raw_id(&raw_id_buf, &raw_id, &raw_id_len) < 0)
			return;

		lldp = ni_lldp_new();
		if (ni_lldp_pdu_parse(lldp, &buf) < 0) {
			ni_debug_lldp("%s: failed to parse LLDP PDU", agent->dev->name);
			ni_lldp_free(lldp);
			return;
		}

		ni_lldp_agent_update(agent, lldp, raw_id, raw_id_len);
	}

}

/*
 * Handling of IEEE 802.1 org-specific information
 */
static ni_lldp_ieee_802_1_t *
ni_lldp_ieee_802_1_new(void)
{
	ni_lldp_ieee_802_1_t *ieee;

	ieee = xcalloc(1, sizeof(*ieee));
	return ieee;
}

static ni_lldp_ieee_802_1_t *
ni_lldp_ieee_802_1_clone(const ni_lldp_ieee_802_1_t *src)
{
	ni_lldp_ieee_802_1_t *copy;

	copy = xcalloc(1, sizeof(*copy));
	copy->pvid = src->pvid;
	copy->ppvid = src->ppvid;
	copy->ppvlan_flags = src->ppvlan_flags;
	copy->mgmt_vid = src->mgmt_vid;
	ni_string_dup(&copy->vlan_name, src->vlan_name);

	return copy;
}

static void
ni_lldp_ieee_802_1_free(ni_lldp_ieee_802_1_t *spec)
{
	ni_string_free(&spec->vlan_name);
	free(spec);
}

/*
 * Protocol specific stuff
 */
typedef struct ni_lldp_tlv {
	ni_buffer_t *		bp;
	unsigned char *		begin;
	unsigned char		type;
	unsigned char		subtype;
} ni_lldp_tlv_t;

static int
ni_lldp_tlv_begin(ni_lldp_tlv_t *tlv, ni_buffer_t *bp, unsigned int type)
{
	uint16_t dummy = 0;

	memset(tlv, 0, sizeof(*tlv));
	tlv->bp = bp;
	tlv->type = type;
	tlv->begin = ni_buffer_tail(bp);

	if (ni_buffer_put(bp, &dummy, 2) < 0)
		return -1;

	return 0;
}

static int
ni_lldp_tlv_begin_subtype(ni_lldp_tlv_t *tlv, ni_buffer_t *bp, unsigned int type, unsigned int subtype)
{
	if (ni_lldp_tlv_begin(tlv, bp, type) < 0)
		return -1;

	tlv->subtype = subtype;
	if (ni_buffer_putc(bp, subtype) < 0)
		return -1;

	return 0;
}

static int
__ni_lldp_tlv_error(const ni_lldp_tlv_t *tlv, const char *fmt, ...)
{
	char msgbuf[256];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(msgbuf, sizeof(msgbuf), fmt, ap);
	va_end(ap);

	if (tlv->subtype)
		ni_error("LLDP: unable to build TLV (type=%u/%u): %s", tlv->type, tlv->subtype, msgbuf);
	else
		ni_error("LLDP: unable to build TLV (type=%u): %s", tlv->type, msgbuf);

	return -1;
}

static int
ni_lldp_tlv_end(ni_lldp_tlv_t *tlv)
{
	unsigned char *end = ni_buffer_tail(tlv->bp);
	long len = end - tlv->begin;
	uint16_t head;

	/* Compensate for offset added by ni_lldp_tlv_begin */
	len -= 2;
	if (len < 2 || len > 511)
		return __ni_lldp_tlv_error(tlv, "bad TLV size %ld", len);

	head = htons((tlv->type << 9) | len);
	memcpy(tlv->begin, &head, 2);
	return 0;
}

static int
ni_lldp_tlv_add_data(ni_lldp_tlv_t *tlv, const void *ptr, unsigned int len)
{
	if (len > 511 || ni_buffer_put(tlv->bp, ptr, len) < 0)
		return __ni_lldp_tlv_error(tlv, "not enough space in buffer - %u bytes", len);

	return 0;
}

static int
ni_lldp_tlv_add_octet(ni_lldp_tlv_t *tlv, unsigned char octet)
{
	return ni_lldp_tlv_add_data(tlv, &octet, 1);
}

static int
ni_lldp_tlv_add_uint16(ni_lldp_tlv_t *tlv, uint16_t value)
{
	value = htons(value);
	return ni_lldp_tlv_add_data(tlv, &value, 2);
}

static int
ni_lldp_tlv_add_uint32(ni_lldp_tlv_t *tlv, uint32_t value)
{
	value = htonl(value);
	return ni_lldp_tlv_add_data(tlv, &value, 4);
}

static int
ni_lldp_tlv_add_string(ni_lldp_tlv_t *tlv, const char *string)
{
	if (string == NULL || *string == '\0')
		return __ni_lldp_tlv_error(tlv, "empty string");

	return ni_lldp_tlv_add_data(tlv, string, strlen(string));
}

static int
ni_lldp_tlv_put(ni_buffer_t *bp, unsigned int type, const void *data, unsigned int len)
{
	uint16_t head;

	if (len > 0x1FF) {
		ni_error("%s: tlv len too large (type=%u, len=%u)", __func__, type, len);
		return -1;
	}
	head = htons((type << 9) | len);
	if (ni_buffer_put(bp, &head, 2) < 0
	 || ni_buffer_put(bp, data, len) < 0) {
		ni_error("%s: not enough space in buffer (type=%u, len=%u)", __func__, type, len);
		return -1;
	}

	return 0;
}

static int
ni_lldp_tlv_get(ni_buffer_t *bp, ni_buffer_t *vbuf)
{
	uint16_t head;
	unsigned int type, len;
	void *data;

	if (ni_buffer_get(bp, &head, 2) < 0)
		return -1;
	head = ntohs(head);

	type = head >> 9;
	len = head & 0x1FF;
	if (len > ni_buffer_count(bp))
		return -1;

	data = ni_buffer_pull_head(bp, len);
	if (data == NULL)
		return -1;

	if (vbuf)
		ni_buffer_init_reader(vbuf, data, len);
	return type;
}

static int
ni_lldp_tlv_put_end(ni_buffer_t *bp)
{
	uint16_t null = (NI_LLDP_TLV_END << 9) | 0;

	if (ni_buffer_put(bp, &null, 2) < 0) {
		ni_error("LLDP: not enough space in buffer (END of PDU)");
		return -1;
	}
	return 0;
}

static int
ni_lldp_tlv_put_string(ni_buffer_t *bp, unsigned int type, const char *string_value)
{
	ni_lldp_tlv_t tlv;

	if (ni_lldp_tlv_begin(&tlv, bp, type) < 0
	 || ni_lldp_tlv_add_string(&tlv, string_value) < 0
	 || ni_lldp_tlv_end(&tlv) < 0)
		return -1;

	return 0;
}

static int
ni_lldp_tlv_get_uint32(ni_buffer_t *bp, uint32_t *var)
{
	uint32_t temp;

	if (ni_buffer_get(bp, &temp, 4) < 0)
		return -1;
	*var = ntohl(temp);
	return 0;
}

static int
ni_lldp_tlv_get_string(ni_buffer_t *bp, char **var)
{
	unsigned int len = ni_buffer_count(bp);
	char *string;

	if (!(string = malloc(len + 1)))
		return -1;
	memcpy(string, ni_buffer_head(bp), len);
	string[len] = '\0';
	*var = string;

	ni_buffer_pull_head(bp, len); /* consume the buffer */
	return 0;
}

static int
ni_lldp_tlv_put_subtype_string(ni_buffer_t *bp, unsigned int type, unsigned int subtype, const char *string_value)
{
	ni_lldp_tlv_t tlv;

	if (ni_lldp_tlv_begin_subtype(&tlv, bp, type, subtype) < 0
	 || ni_lldp_tlv_add_string(&tlv, string_value) < 0
	 || ni_lldp_tlv_end(&tlv) < 0)
		return -1;

	return 0;
}

static int
ni_lldp_tlv_put_subtype_mac(ni_buffer_t *bp, unsigned int type, unsigned int subtype, const ni_hwaddr_t *mac)
{
	ni_lldp_tlv_t tlv;

	if (ni_lldp_tlv_begin_subtype(&tlv, bp, type, subtype) < 0)
		return -1;

	switch (mac->type) {
	case ARPHRD_ETHER:
		if (mac->len == ETH_ALEN)
			break;
		/* fallthru */
	default:
		return __ni_lldp_tlv_error(&tlv, "invalid hwaddr type 0x%x", mac->type);
	}

	if (ni_lldp_tlv_add_data(&tlv, mac->data, mac->len) < 0
	 || ni_lldp_tlv_end(&tlv) < 0)
		return -1;

	return 0;
}

static int
ni_lldp_tlv_get_mac(ni_buffer_t *bp, ni_hwaddr_t *mac)
{
	void *data;

	if (!(data = ni_buffer_pull_head(bp, ETH_ALEN))) {
		ni_debug_lldp("%s: bad MAC address length %u", __func__, ni_buffer_count(bp));
		return -1;
	}

	memcpy(mac->data, data, ETH_ALEN);
	mac->len = ETH_ALEN;
	mac->type = ARPHRD_ETHER;
	return 0;
}

static int
ni_lldp_tlv_put_subtype_netaddr(ni_buffer_t *bp, unsigned int type, unsigned int subtype, const ni_sockaddr_t *ap)
{
	ni_lldp_tlv_t tlv;
	unsigned int offset, len;

	if (ni_lldp_tlv_begin_subtype(&tlv, bp, type, subtype) < 0)
		return -1;

	if (!ni_af_sockaddr_info(ap->ss_family, &offset, &len))
		return __ni_lldp_tlv_error(&tlv, "unsupported network address type %d", ap->ss_family);

	if (ni_lldp_tlv_add_octet(&tlv, ap->ss_family) < 0
	 || ni_lldp_tlv_add_data(&tlv, ((caddr_t) ap) + offset, len) < 0
	 || ni_lldp_tlv_end(&tlv) < 0)
		return -1;

	return 0;
}

static int
ni_lldp_tlv_get_netaddr(ni_buffer_t *bp, ni_sockaddr_t *ap)
{
	unsigned int offset, len;
	int af;

	memset(ap, 0, sizeof(*ap));
	if ((af = ni_buffer_getc(bp)) < 0)
		return -1;

	if (!ni_af_sockaddr_info(af, &offset, &len)) {
		ni_debug_lldp("%s: unsupported network address type %d", __func__, af);
		return -1;
	}

	if (ni_buffer_count(bp) < len) {
		ni_debug_lldp("%s: truncated network address (af %d, len %u)", __func__, af, len);
		return -1;
	}

	ap->ss_family = af;
	return ni_buffer_get(bp, ((caddr_t) ap) + offset, len);
}

static int
ni_lldp_tlv_begin_org_spec(ni_lldp_tlv_t *tlv, ni_buffer_t *bp, uint32_t oui, unsigned int subtype)
{
	unsigned char data[4];

	data[0] = oui >> 16;
	data[1] = oui >> 8;
	data[2] = oui;
	data[3] = subtype;

	if (ni_lldp_tlv_begin(tlv, bp, NI_LLDP_TLV_ORGSPEC) < 0
	 || ni_lldp_tlv_add_data(tlv, data, 4) < 0)
		return -1;

	return 0;
}

static int
ni_lldp_tlv_put_org_spec_uint16(ni_buffer_t *bp, uint32_t oui, unsigned int subtype, uint16_t value)
{
	ni_lldp_tlv_t tlv;

	if (ni_lldp_tlv_begin_org_spec(&tlv, bp, oui, subtype) < 0
	 || ni_lldp_tlv_add_uint16(&tlv, value) < 0
	 || ni_lldp_tlv_end(&tlv) < 0)
		return -1;
	return 0;
}

static int
ni_lldp_tlv_put_org_spec_string(ni_buffer_t *bp, uint32_t oui, unsigned int subtype, const char *string_value)
{
	ni_lldp_tlv_t tlv;

	if (ni_lldp_tlv_begin_org_spec(&tlv, bp, oui, subtype) < 0
	 || ni_lldp_tlv_add_string(&tlv, string_value) < 0
	 || ni_lldp_tlv_end(&tlv) < 0)
		return -1;
	return 0;
}

static int
ni_lldp_tlv_put_chassis_id(const ni_lldp_t *lldp, ni_buffer_t *bp)
{
	switch (lldp->chassis_id.type) {
	case NI_LLDP_CHASSIS_ID_CHASSIS_COMPONENT:
	case NI_LLDP_CHASSIS_ID_INTERFACE_ALIAS:
	case NI_LLDP_CHASSIS_ID_PORT_COMPONENT:
	case NI_LLDP_CHASSIS_ID_INTERFACE_NAME:
	case NI_LLDP_CHASSIS_ID_LOCALLY_ASSIGNED:
		return ni_lldp_tlv_put_subtype_string(bp, NI_LLDP_TLV_CHASSIS_ID,
				lldp->chassis_id.type, lldp->chassis_id.string_value);

	case NI_LLDP_CHASSIS_ID_MAC_ADDRESS:
		/* FIXME: if no MAC was supplied, get the current MAC from the netdev */
		return ni_lldp_tlv_put_subtype_mac(bp, NI_LLDP_TLV_CHASSIS_ID,
				lldp->chassis_id.type, &lldp->chassis_id.mac_addr_value);

	case NI_LLDP_CHASSIS_ID_NETWORK_ADDRESS:
		/* FIXME: if no MAC was supplied, get "the" current network address from the netdev */
		return ni_lldp_tlv_put_subtype_netaddr(bp, NI_LLDP_TLV_CHASSIS_ID,
				lldp->chassis_id.type, &lldp->chassis_id.net_addr_value);

	default:
		ni_error("%s: unsupported chassis-id subtype %u", __func__, lldp->chassis_id.type);
	}

	return -1;
}

static int
ni_lldp_tlv_get_chassis_id(ni_lldp_t *lldp, ni_buffer_t *bp)
{
	int subtype;

	if ((subtype = ni_buffer_getc(bp)) < 0)
		return -1;

	lldp->chassis_id.type = subtype;
	switch (lldp->chassis_id.type) {
	case NI_LLDP_CHASSIS_ID_CHASSIS_COMPONENT:
	case NI_LLDP_CHASSIS_ID_INTERFACE_ALIAS:
	case NI_LLDP_CHASSIS_ID_PORT_COMPONENT:
	case NI_LLDP_CHASSIS_ID_INTERFACE_NAME:
	case NI_LLDP_CHASSIS_ID_LOCALLY_ASSIGNED:
		return ni_lldp_tlv_get_string(bp, &lldp->chassis_id.string_value);

	case NI_LLDP_CHASSIS_ID_MAC_ADDRESS:
		return ni_lldp_tlv_get_mac(bp, &lldp->chassis_id.mac_addr_value);

	case NI_LLDP_CHASSIS_ID_NETWORK_ADDRESS:
		return ni_lldp_tlv_get_netaddr(bp, &lldp->chassis_id.net_addr_value);

	default:
		ni_error("%s: unsupported chassis-id subtype %u", __func__, lldp->chassis_id.type);
	}

	return -1;
}

static int
ni_lldp_tlv_put_port_id(const ni_lldp_t *lldp, ni_buffer_t *bp)
{
	switch (lldp->port_id.type) {
	case NI_LLDP_PORT_ID_INTERFACE_ALIAS:
	case NI_LLDP_PORT_ID_PORT_COMPONENT:
	case NI_LLDP_PORT_ID_INTERFACE_NAME:
	case NI_LLDP_PORT_ID_AGENT_CIRCUIT_ID:
	case NI_LLDP_PORT_ID_LOCALLY_ASSIGNED:
		return ni_lldp_tlv_put_subtype_string(bp, NI_LLDP_TLV_PORT_ID,
				lldp->port_id.type, lldp->port_id.string_value);

	case NI_LLDP_PORT_ID_MAC_ADDRESS:
		/* FIXME: if no MAC was supplied, get the current MAC from the netdev */
		return ni_lldp_tlv_put_subtype_mac(bp, NI_LLDP_TLV_PORT_ID,
				lldp->port_id.type, &lldp->port_id.mac_addr_value);

	case NI_LLDP_PORT_ID_NETWORK_ADDRESS:
		/* FIXME: if no MAC was supplied, get "the" current network address from the netdev */
		return ni_lldp_tlv_put_subtype_netaddr(bp, NI_LLDP_TLV_PORT_ID,
				lldp->port_id.type, &lldp->port_id.net_addr_value);

	default:
		ni_error("%s: unsupported port-id subtype %u", __func__, lldp->port_id.type);
	}

	return -1;
}

static int
ni_lldp_tlv_get_port_id(ni_lldp_t *lldp, ni_buffer_t *bp)
{
	int subtype;

	if ((subtype = ni_buffer_getc(bp)) < 0)
		return -1;

	lldp->chassis_id.type = subtype;
	switch (lldp->port_id.type) {
	case NI_LLDP_PORT_ID_INTERFACE_ALIAS:
	case NI_LLDP_PORT_ID_PORT_COMPONENT:
	case NI_LLDP_PORT_ID_INTERFACE_NAME:
	case NI_LLDP_PORT_ID_AGENT_CIRCUIT_ID:
	case NI_LLDP_PORT_ID_LOCALLY_ASSIGNED:
		return ni_lldp_tlv_get_string(bp, &lldp->port_id.string_value);

	case NI_LLDP_PORT_ID_MAC_ADDRESS:
		return ni_lldp_tlv_get_mac(bp, &lldp->port_id.mac_addr_value);

	case NI_LLDP_PORT_ID_NETWORK_ADDRESS:
		return ni_lldp_tlv_get_netaddr(bp, &lldp->port_id.net_addr_value);

	default:
		ni_error("%s: unsupported port-id subtype %u", __func__, lldp->port_id.type);
	}

	return -1;
}

static int
ni_lldp_tlv_put_ttl(const ni_lldp_t *lldp, ni_buffer_t *bp)
{
	uint16_t value;

	value = htons(lldp->ttl);
	return ni_lldp_tlv_put(bp, NI_LLDP_TLV_TTL, &value, 2);
}

static int
ni_lldp_tlv_get_ttl(ni_lldp_t *lldp, ni_buffer_t *bp)
{
	uint16_t value;

	if (ni_buffer_get(bp, &value, 2) < 0)
		return -1;
	lldp->ttl = htons(value);
	return 0;
}

static int
ni_lldp_tlv_put_syscaps(const ni_lldp_t *lldp, ni_buffer_t *bp)
{
	uint16_t syscaps[2];

	syscaps[0] = syscaps[1] = htons(lldp->system.capabilities);
	return ni_lldp_tlv_put(bp, NI_LLDP_TLV_SYSTEM_CAPS, syscaps, 4);
}

static int
ni_lldp_tlv_put_ieee_802_1(ni_lldp_ieee_802_1_t *ieee, ni_buffer_t *bp)
{
	/* Port VLAN ID */
	if (ieee->pvid != 0
	 && ni_lldp_tlv_put_org_spec_uint16(bp, NI_LLDP_OUI_IEEE_8021, NI_LLDP_IEEE_802_1_TLV_PVID, ieee->pvid) < 0)
		return -1;

	/* Port and Protocol VLAN ID */
	if (ieee->ppvid != 0) {
		ni_lldp_tlv_t tlv;

		if (ni_lldp_tlv_begin_org_spec(&tlv, bp, NI_LLDP_OUI_IEEE_8021, NI_LLDP_IEEE_802_1_TLV_PPVID) < 0
		 || ni_lldp_tlv_add_octet(&tlv, ieee->ppvlan_flags) < 0
		 || ni_lldp_tlv_add_uint16(&tlv, ieee->ppvid) < 0
		 || ni_lldp_tlv_end(&tlv) < 0)
			return -1;
	}

	if (ieee->vlan_name
	 && ni_lldp_tlv_put_org_spec_string(bp, NI_LLDP_OUI_IEEE_8021, NI_LLDP_IEEE_802_1_TLV_VLAN_NAME, ieee->vlan_name) < 0)
		return -1;

	return 0;
}

static int
ni_dcbx_put_ets(ni_buffer_t *bp, const ni_dcb_ets_t *ets, ni_bool_t is_config)
{
	unsigned int subtype = is_config? NI_LLDP_IEEE_802_1QAZ_TLV_ETS_CFG : NI_LLDP_IEEE_802_1QAZ_TLV_ETS_REC;
	ni_lldp_tlv_t tlv;
	unsigned char octet = 0;
	uint32_t pat;
	int i;

	/* For the ETS config TLV, the first octet contains some additional bits of
	 * information; this octet is reserved in the ETS recommendation TLV */
	if (is_config) {
		if (ets->willing)
			octet |= 0x80;
		if (ets->cbs_supported)
			octet |= 0x40;
		octet |= ets->num_tc_supported & 0x07;	/* a value of 8 is mapped to 0 */
	}

	/* Priority Assignment Table.
	 * The traffic class for priority 0 occupies the most significant bits,
	 * the traffic class for priority 7 the least significant bits.
	 */
	for (i = 0, pat = 0; i < NI_DCBX_MAX_PRIO; ++i)
		pat = (pat << 4) | (ets->prio2tc[i] & 0x0F);

	if (ni_lldp_tlv_begin_org_spec(&tlv, bp, NI_LLDP_OUI_IEEE_8021, subtype) < 0
	 || ni_lldp_tlv_add_octet(&tlv, octet) < 0
	 || ni_lldp_tlv_add_uint32(&tlv, pat) < 0
	 || ni_lldp_tlv_add_data(&tlv, ets->tc_bw, 8) < 0
	 || ni_lldp_tlv_add_data(&tlv, ets->tsa, 8) < 0
	 || ni_lldp_tlv_end(&tlv) < 0)
		return -1;

	return 0;
}

static int
__ni_dcbx_get_ets(ni_lldp_t *lldp, ni_buffer_t *bp, ni_dcb_ets_t *ets, ni_bool_t is_config)
{
	unsigned char octet;
	uint32_t pat;
	unsigned int i;

	if (ni_buffer_get(bp, &octet, 1) < 0)
		return -1;

	if (is_config) {
		if (octet & 0x80)
			ets->willing = TRUE;
		if (octet & 0x40)
			ets->cbs_supported = TRUE;
		ets->num_tc_supported = octet & 0x07;
	} else if (octet != 0) {
		ni_debug_lldp("LLDP: discarding bad ETS_RECOMMENDED TLV (reserved octet is not 0)");
		return -1;
	}

	if (ni_lldp_tlv_get_uint32(bp, &pat) < 0)
		return -1;
	for (i = 0; i < 8; ++i, pat <<= 4)
		ets->prio2tc[i] = pat >> 28;

	if (ni_buffer_get(bp, ets->tc_bw, 8) < 0
	 || ni_buffer_get(bp, ets->tsa, 8) < 0)
		return -1;

	return 0;
}

static int
ni_dcbx_get_ets_config(ni_lldp_t *lldp, ni_buffer_t *bp)
{
	ni_dcb_attributes_t *attrs = ni_lldp_get_dcb_attributes(lldp);

	memset(&attrs->ets_config, 0, sizeof(attrs->ets_config));
	return __ni_dcbx_get_ets(lldp, bp, &attrs->ets_config, TRUE);
}

static int
ni_dcbx_get_ets_recommended(ni_lldp_t *lldp, ni_buffer_t *bp)
{
	ni_dcb_attributes_t *attrs = ni_lldp_get_dcb_attributes(lldp);

	memset(&attrs->ets_recommended, 0, sizeof(attrs->ets_recommended));
	return __ni_dcbx_get_ets(lldp, bp, &attrs->ets_recommended, FALSE);
}

static int
ni_dcbx_put_pfc(ni_buffer_t *bp, const ni_dcb_pfc_t *pfc)
{
	ni_lldp_tlv_t tlv;
	unsigned char octet = 0;

	if (pfc->willing)
		octet |= 0x80;
	if (pfc->mbc)
		octet |= 0x40;
	octet |= pfc->cap & 0x0F;

	if (ni_lldp_tlv_begin_org_spec(&tlv, bp, NI_LLDP_OUI_IEEE_8021, NI_LLDP_IEEE_802_1QAZ_TLV_PFC_CFG) < 0
	 || ni_lldp_tlv_add_octet(&tlv, octet) < 0
	 || ni_lldp_tlv_add_octet(&tlv, pfc->enable) < 0
	 || ni_lldp_tlv_end(&tlv) < 0)
		return -1;

	return 0;
}

static int
ni_dcbx_get_pfc_config(ni_lldp_t *lldp, ni_buffer_t *bp)
{
	ni_dcb_attributes_t *attrs = ni_lldp_get_dcb_attributes(lldp);
	ni_dcb_pfc_t *pfc = &attrs->pfc_config;
	unsigned char octet;

	memset(pfc, 0, sizeof(*pfc));

	if (ni_buffer_get(bp, &octet, 1) < 0)
		return -1;

	if (octet & 0x80)
		pfc->willing = TRUE;
	if (octet & 0x40)
		pfc->mbc = TRUE;
	pfc->cap = octet & 0x0F;

	if (ni_buffer_get(bp, &octet, 1) < 0)
		return -1;
	pfc->enable = octet;

	return 0;
}

static int
ni_dcbx_put_app_priorities(ni_buffer_t *bp, const ni_dcb_app_priorities_t *prio_table)
{
	ni_lldp_tlv_t tlv;
	unsigned int i;

	if (ni_lldp_tlv_begin_org_spec(&tlv, bp, NI_LLDP_OUI_IEEE_8021, NI_LLDP_IEEE_802_1QAZ_TLV_APP) < 0
	 || ni_lldp_tlv_add_octet(&tlv, 0) < 0)
		return -1;

	for (i = 0; i < prio_table->count; ++i) {
		struct dcb_app *app = prio_table->data + i;
		unsigned char octet;

		octet = (app->priority << 5)
		      | (app->selector & 0x07);
		if (ni_lldp_tlv_add_octet(&tlv, octet) < 0
		 || ni_lldp_tlv_add_uint16(&tlv, app->protocol) < 0)
			return -1;
	}

	if (ni_lldp_tlv_end(&tlv) < 0)
		return -1;

	return 0;
}

static int
ni_dcbx_get_app_priorities(ni_lldp_t *lldp, ni_buffer_t *bp)
{
	ni_dcb_attributes_t *attrs = ni_lldp_get_dcb_attributes(lldp);
	ni_dcb_app_priorities_t *table = &attrs->app_priorities;
	unsigned char octet;
	unsigned int i, count;

	/* Reserved octet */
	if (ni_buffer_get(bp, &octet, 1) < 0)
		return -1;

	count = ni_buffer_count(bp) / 3;
	table->data = xrealloc(table->data, count * sizeof(table->data[0]));
	table->count = count;

	for (i = 0; i < count; ++i) {
		struct dcb_app *app = table->data + i;

		if (ni_buffer_get(bp, &octet, 1) < 0
		 || ni_buffer_get_uint16(bp, &app->protocol) < 0)
			return -1;
		app->priority = octet >> 5;
		app->selector = octet & 0x07;
	}
	return 0;
}

static int
ni_lldp_tlv_put_ieee_802_1_qaz(ni_dcbx_state_t *dcbx, ni_buffer_t *bp)
{
	if (ni_dcbx_put_ets(bp, &dcbx->ets.oper_param, TRUE) < 0
	 || ni_dcbx_put_ets(bp, &dcbx->ets.local_recommended, TRUE) < 0
	 || ni_dcbx_put_pfc(bp, &dcbx->pfc.oper_param) < 0
	 || ni_dcbx_put_app_priorities(bp, &dcbx->app_priorities) < 0)
		return -1;

	return 0;
}

static ni_lldp_ieee_802_1_t *
ni_lldp_get_ieee_802_1(ni_lldp_t *lldp)
{
	if (lldp->ieee_802_1 == NULL)
		lldp->ieee_802_1 = ni_lldp_ieee_802_1_new();
	return lldp->ieee_802_1;
}

static int
ni_lldp_tlv_get_ieee_802_1_vlan_name(ni_lldp_t *lldp, ni_buffer_t *bp)
{
	ni_lldp_ieee_802_1_t *ieee = ni_lldp_get_ieee_802_1(lldp);

	return ni_lldp_tlv_get_string(bp, &ieee->vlan_name);
}

static int
ni_lldp_tlv_get_ieee_802_1(ni_lldp_t *lldp, ni_buffer_t *bp, unsigned int subtype)
{
	static ni_lldp_get_fn_t *get_fn_table[NI_LLDP_IEEE_802_1_TLV_MAX] = {
	[NI_LLDP_IEEE_802_1_TLV_VLAN_NAME]	= ni_lldp_tlv_get_ieee_802_1_vlan_name,
	[NI_LLDP_IEEE_802_1QAZ_TLV_ETS_CFG]	= ni_dcbx_get_ets_config,
	[NI_LLDP_IEEE_802_1QAZ_TLV_ETS_REC]	= ni_dcbx_get_ets_recommended,
	[NI_LLDP_IEEE_802_1QAZ_TLV_PFC_CFG]	= ni_dcbx_get_pfc_config,
	[NI_LLDP_IEEE_802_1QAZ_TLV_APP]		= ni_dcbx_get_app_priorities,
	};

	if (subtype < NI_LLDP_IEEE_802_1_TLV_MAX) {
		ni_lldp_get_fn_t *fn = get_fn_table[subtype];
		if (fn)
			return fn(lldp, bp);
	}
	ni_debug_lldp("%s: subtype %u not handled", __func__, subtype);
	return 0;
}

static int
ni_lldp_tlv_get_orgspec(ni_lldp_t *lldp, ni_buffer_t *bp)
{
	unsigned char data[3];
	unsigned int oui, i, subtype;
	int ret;

	if (ni_buffer_get(bp, data, 3) < 0)
		return -1;
	for (oui = i = 0; i < 3; ++i)
		oui = (oui << 8) | data[i];

	if ((ret = ni_buffer_getc(bp)) < 0)
		return -1;
	subtype = ret;

	if (oui == NI_LLDP_OUI_IEEE_8021)
		return ni_lldp_tlv_get_ieee_802_1(lldp, bp, subtype);

	ni_debug_lldp("ignoring unknown org-specific TLV (oui=0x%06x)", oui);
	return 0;
}


int
ni_lldp_pdu_build(const ni_lldp_t *lldp, ni_dcbx_state_t *dcbx, ni_buffer_t *bp)
{
	ni_buffer_reset(bp);

	/* Mandatory parts */
	if (ni_lldp_tlv_put_chassis_id(lldp, bp) < 0
	 || ni_lldp_tlv_put_port_id(lldp, bp) < 0
	 || ni_lldp_tlv_put_ttl(lldp, bp) < 0)
		return -1;

	if (lldp->ttl == 0)
		return 0;

	/* Optional parts */
	ni_debug_lldp("port_description=%s", lldp->port_description);
	if (lldp->port_description
	 && ni_lldp_tlv_put_string(bp, NI_LLDP_TLV_PORT_DESC, lldp->port_description) < 0)
		return -1;

	ni_debug_lldp("system.name=%s", lldp->system.name);
	if (lldp->system.name
	 && ni_lldp_tlv_put_string(bp, NI_LLDP_TLV_SYSTEM_NAME, lldp->system.name) < 0)
		return -1;

	ni_debug_lldp("system.description=%s", lldp->system.description);
	if (lldp->system.description
	 && ni_lldp_tlv_put_string(bp, NI_LLDP_TLV_SYSTEM_DESC, lldp->system.description) < 0)
		return -1;

	ni_debug_lldp("system.capabilities=%04x", lldp->system.capabilities);
	if (lldp->system.capabilities != 0
	 && ni_lldp_tlv_put_syscaps(lldp, bp) < 0)
		return -1;

	if (lldp->ieee_802_1
	 && ni_lldp_tlv_put_ieee_802_1(lldp->ieee_802_1, bp) < 0)
		return -1;

	if (dcbx && dcbx->running
	 && ni_lldp_tlv_put_ieee_802_1_qaz(dcbx, bp) < 0)
		return -1;

	if (ni_lldp_tlv_put_end(bp) < 0)
		return -1;

	return 0;
}

static int
__ni_lldp_pdu_parse(ni_lldp_t *lldp, ni_buffer_t *bp,
			ni_lldp_get_fn_t **get_fn_table,
			unsigned int get_fn_table_max_entries,
			unsigned int *required,
			ni_bool_t end_allowed)
{
	unsigned int index;

	for (index = 0; ni_buffer_count(bp) != 0; ++index) {
		ni_buffer_t tvbuf;
		unsigned int type;
		int ret;
		ni_lldp_get_fn_t *fn;

		ret = ni_lldp_tlv_get(bp, &tvbuf);
		if (ret < 0)
			return -1;
		type = ret;

		if (required) {
			if (*required != type) {
				ni_debug_lldp("LLDP: tlv%u - expected type %u but got %u",
						index, *required, type);
				return -1;
			}
			if (*++required == 0)
				required = NULL;
		}

		if (type == 0) {
			if (ni_buffer_count(&tvbuf) != 0)
				return -1;
			if (!end_allowed)
				return -1; /* End of PDU not allowed here (eg inside a OUI TLV) */
			if (required)
				return -1; /* Not all mandatory parts received */
			return 0;
		}

		ni_assert(type < get_fn_table_max_entries);

		fn = get_fn_table[type];
		if (fn != NULL) {
			if (fn(lldp, &tvbuf) < 0)
				return -1;

			/* FIXME: if we received a TTL of 0, we should stop here */
		} else {
			/* ignore unknown TLV */
			ni_debug_lldp("%s: tlv%u - ignoring unknown TLV type %u", __func__, index, type);
		}
	}

	if (end_allowed) {
		ni_debug_lldp("%s: missing End of LLDPDU TLV", __func__);
		return -1;
	}

	return 0;
}

int
ni_lldp_pdu_parse(ni_lldp_t *lldp, ni_buffer_t *bp)
{
	static unsigned int mandatory_part[4] = {
		NI_LLDP_TLV_CHASSIS_ID,
		NI_LLDP_TLV_PORT_ID,
		NI_LLDP_TLV_TTL,
		0
	};
	static ni_lldp_get_fn_t *get_fn_table[NI_LLDP_TLV_MAX] = {
	[NI_LLDP_TLV_CHASSIS_ID]	= ni_lldp_tlv_get_chassis_id,
	[NI_LLDP_TLV_PORT_ID]		= ni_lldp_tlv_get_port_id,
	[NI_LLDP_TLV_TTL]		= ni_lldp_tlv_get_ttl,
	[NI_LLDP_TLV_ORGSPEC]		= ni_lldp_tlv_get_orgspec,
	};

	return __ni_lldp_pdu_parse(lldp, bp, get_fn_table, NI_LLDP_TLV_MAX, mandatory_part, TRUE);
}

int
ni_lldp_pdu_get_raw_id(ni_buffer_t *bp, const void **raw_id, unsigned int *raw_len)
{
	*raw_id = ni_buffer_head(bp);
	*raw_len = ni_buffer_count(bp);

	if (ni_lldp_tlv_get(bp, NULL) != NI_LLDP_TLV_CHASSIS_ID
	 || ni_lldp_tlv_get(bp, NULL) != NI_LLDP_TLV_PORT_ID)
		return -1;

	*raw_len -= ni_buffer_count(bp);
	return 0;
}
