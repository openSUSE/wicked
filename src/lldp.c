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
#include <net/if_arp.h>

#include "buffer.h"
#include "util_priv.h"
#include "debug.h"
#include "netinfo_priv.h"
#include "lldp-priv.h"

typedef struct ni_lldp_agent ni_lldp_agent_t;

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

	ni_capture_t *		capture;
	ni_buffer_t		sendbuf;
};

static ni_lldp_agent_t *	ni_lldp_agents;

static ni_hwaddr_t		ni_lldp_destaddr[__NI_LLDP_DEST_MAX] = {
[NI_LLDP_DEST_NEAREST_BRIDGE] = {
		.type = NI_IFTYPE_ETHERNET,
		.len = 6,
		.data = { 0x00, 0x80, 0xC2, 0x00, 0x00, 0x0E }
	},
[NI_LLDP_DEST_NEAREST_NON_TPMR_BRIDGE] = {
		.type = NI_IFTYPE_ETHERNET,
		.len = 6,
		.data = { 0x00, 0x80, 0xC2, 0x00, 0x00, 0x03 }
	},
[NI_LLDP_DEST_NEAREST_CUSTOMER_BRIDGE] = {
		.type = NI_IFTYPE_ETHERNET,
		.len = 6,
		.data = { 0x00, 0x80, 0xC2, 0x00, 0x00, 0x00 }
	},
};


static int		ni_lldp_agent_start(ni_netdev_t *, const ni_lldp_t *);
static void		ni_lldp_agent_stop(ni_netdev_t *);
static ni_bool_t	ni_lldp_agent_send(ni_lldp_agent_t *);
static void		ni_lldp_agent_free(ni_lldp_agent_t *);
static void		ni_lldp_tx_timer_arm(ni_lldp_agent_t *);
static void		ni_lldp_tx_timer_arm_quick(ni_lldp_agent_t *);
static int		ni_lldp_pdu_build(const ni_lldp_t *, ni_buffer_t *);

ni_lldp_t *
ni_lldp_new(void)
{
	ni_lldp_t *lldp;

	lldp = xcalloc(1, sizeof(*lldp));
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
		free(lldp);
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

int
ni_system_lldp_setup(ni_netdev_t *dev, const ni_lldp_t *config)
{
	ni_trace("ni_system_lldp_setup(%s, lldp=%p)", dev->name, config);
	if (config) {
		if (dev->link.arp_type != ARPHRD_ETHER) {
			ni_error("Cannot enable LLDP for device %s: incompatible layer 2 protocol", dev->name);
			return -1;
		}

		if (ni_lldp_agent_start(dev, config) < 0)
			return -1;

		ni_netdev_set_lldp(dev, ni_lldp_clone(config));
	} else {
		ni_netdev_set_lldp(dev, NULL);
		ni_lldp_agent_stop(dev);
	}
	return 0;
}

ni_lldp_agent_t *
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
	if (agent->capture)
		ni_capture_free(agent->capture);
	if (agent->config)
		ni_lldp_free(agent->config);
	if (agent->txTTR)
		ni_timer_cancel(agent->txTTR);
	if (agent->dev)
		ni_netdev_put(agent->dev);
	free(agent);
}

static ni_lldp_agent_t *
__ni_lldp_take_agent(int ifindex, ni_lldp_agent_t ***pos_ret)
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
__ni_lldp_agent_configure(ni_lldp_agent_t *agent, ni_netdev_t *dev, ni_lldp_t *lldp)
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

	if (lldp->ttl == 0)
		lldp->ttl = agent->txTTL;

	return 0;
}

static int
ni_lldp_agent_configure(ni_lldp_agent_t *agent, ni_netdev_t *dev, const ni_lldp_t *req)
{
	ni_lldp_t *lldp = ni_lldp_clone(req);

	if (__ni_lldp_agent_configure(agent, dev, lldp) < 0) {
		ni_lldp_free(lldp);
		return -1;
	}

	if (agent->config)
		ni_lldp_free(agent->config);
	agent->config = lldp;
	return 0;
}

static int
ni_lldp_agent_start(ni_netdev_t *dev, const ni_lldp_t *req)
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

	if (ni_lldp_agent_configure(agent, dev, req) < 0)
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

		capture = ni_capture_open(&devinfo, &protinfo, NULL);
	}
	agent->capture = capture;

	/* build packet and prime sender */
	if (ni_lldp_pdu_build(agent->config, &agent->sendbuf) < 0) {
		ni_error("LLDP: error building PDU");
		return -1;
	}

	ni_lldp_agent_send(agent);
	return 0;
}

void
ni_lldp_agent_stop(ni_netdev_t *dev)
{
	ni_lldp_agent_t *agent, **pos;

	if ((agent = __ni_lldp_take_agent(dev->link.ifindex, &pos)) != NULL)
		ni_lldp_agent_free(agent);
}

static ni_bool_t
ni_lldp_agent_send(ni_lldp_agent_t *agent)
{
	struct timeval now;
	ni_bool_t rv = FALSE;

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

		/* Regular timer (re-)arm */
		ni_lldp_tx_timer_arm(agent);
		rv = TRUE;
	} else {
		ni_debug_lldp("%s: cannot send LLDP packet (no credits)", agent->dev->name);
		ni_lldp_tx_timer_arm_quick(agent);
	}

	return rv;
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

	/* Decrement txFast if we're in a fast retrans cycle */
	if (agent->txFast)
		agent->txFast--;

	/* FIXME: rebuild the packet? */
	ni_lldp_agent_send(agent);
}

static void
__ni_lldp_tx_timer_arm(ni_lldp_agent_t *agent, unsigned int timeout)
{
	static const ni_int_range_t jitter = { .min = 0, .max = 400 };

	/* Apply a jitter between 0 and 0.4 sec */
	timeout = ni_timeout_randomize(timeout, &jitter);

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
 * Protocol specific stuff
 */
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
ni_lldp_tlv_put_end(ni_buffer_t *bp)
{
	return ni_lldp_tlv_put(bp, NI_LLDP_TLV_END, NULL, 0);
}

static int
ni_lldp_tlv_put_string(ni_buffer_t *bp, unsigned int type, const char *string_value)
{
	if (string_value == NULL || *string_value == '\0') {
		ni_error("%s: invalid string TLV (type=%u): empty string", __func__, type);
		return -1;
	}

	return ni_lldp_tlv_put(bp, type, string_value, strlen(string_value));
}

static int
ni_lldp_tlv_put_subtype_data(ni_buffer_t *bp, unsigned int type, unsigned int subtype,
				const void *data, unsigned int len, unsigned int maxlen)
{
	unsigned char buffer[512];

	if (maxlen > 511)
		maxlen = 511;
	if (len > maxlen) {
		ni_error("%s: invalid TLV (type=%u, subtype=%u): data too long (%u octets; max len %u)",
				__func__, type, subtype, len, maxlen);
		return -1;
	}

	buffer[0] = subtype;
	memcpy(buffer + 1, data, len);
	return ni_lldp_tlv_put(bp, type, buffer, len + 1);
}

static int
ni_lldp_tlv_put_subtype_string(ni_buffer_t *bp, unsigned int type, unsigned int subtype, const char *string_value)
{
	if (string_value == NULL || *string_value == '\0') {
		ni_error("%s: invalid string TLV (type=%u, subtype=%u): empty string", __func__, type, subtype);
		return -1;
	}

	return ni_lldp_tlv_put_subtype_data(bp, type, subtype, string_value, strlen(string_value), 255);
}

static int
ni_lldp_tlv_put_subtype_mac(ni_buffer_t *bp, unsigned int type, unsigned int subtype, const ni_hwaddr_t *mac)
{
	switch (mac->type) {
	case NI_IFTYPE_ETHERNET:
	case NI_IFTYPE_VLAN:
	case NI_IFTYPE_WIRELESS:
		if (mac->len == 6)
			break;
		/* fallthru */
	default:
		ni_error("%s: invalid hwaddr type %u (0x%x)", __func__, mac->type, mac->type);
		return -1;
	}

	return ni_lldp_tlv_put_subtype_data(bp, type, subtype, mac->data, mac->len, 6);
}

static int
ni_lldp_tlv_put_subtype_netaddr(ni_buffer_t *bp, unsigned int type, unsigned int subtype, const ni_sockaddr_t *ap)
{
	unsigned char temp[64];
	unsigned int offset, len;

	if (!ni_af_sockaddr_info(ap->ss_family, &offset, &len) || len + 1 > sizeof(temp)) {
		ni_error("%s: unsupported network address type %d", __func__, ap->ss_family);
		return -1;
	}

	temp[0] = ap->ss_family;
	memcpy(temp + 1, ((caddr_t) ap) + offset, len);
	return ni_lldp_tlv_put_subtype_data(bp, type, subtype, temp, len + 1, 255);
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
ni_lldp_tlv_put_ttl(const ni_lldp_t *lldp, ni_buffer_t *bp)
{
	uint16_t value;

	value = htons(lldp->ttl);
	return ni_lldp_tlv_put(bp, NI_LLDP_TLV_TTL, &value, 2);
}

static int
ni_lldp_tlv_put_syscaps(const ni_lldp_t *lldp, ni_buffer_t *bp)
{
	uint16_t syscaps[2];

	syscaps[0] = syscaps[1] = htons(lldp->system.capabilities);
	return ni_lldp_tlv_put(bp, NI_LLDP_TLV_SYSTEM_CAPS, syscaps, 4);
}

int
ni_lldp_pdu_build(const ni_lldp_t *lldp, ni_buffer_t *bp)
{
	/* Mandatory parts */
	if (ni_lldp_tlv_put_chassis_id(lldp, bp) < 0
	 || ni_lldp_tlv_put_port_id(lldp, bp) < 0
	 || ni_lldp_tlv_put_ttl(lldp, bp) < 0)
		return -1;

	/* Optional parts */
	ni_trace("port_description=%s", lldp->port_description);
	if (lldp->port_description
	 && ni_lldp_tlv_put_string(bp, NI_LLDP_TLV_PORT_DESC, lldp->port_description) < 0)
		return -1;

	ni_trace("system.name=%s", lldp->system.name);
	if (lldp->system.name
	 && ni_lldp_tlv_put_string(bp, NI_LLDP_TLV_SYSTEM_NAME, lldp->system.name) < 0)
		return -1;

	ni_trace("system.description=%s", lldp->system.description);
	if (lldp->system.description
	 && ni_lldp_tlv_put_string(bp, NI_LLDP_TLV_SYSTEM_DESC, lldp->system.description) < 0)
		return -1;

	ni_trace("system.capabilities=%04x", lldp->system.capabilities);
	if (lldp->system.capabilities != 0
	 && ni_lldp_tlv_put_syscaps(lldp, bp) < 0)
		return -1;

	if (ni_lldp_tlv_put_end(bp) < 0)
		return -1;

	return 0;
}
