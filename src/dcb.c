/*
 * Support IEEE 802.1 Qaz (aka Data Center Bridging).
 *
 * Copyright (C) 2013 Olaf Kirch <okir@suse.de>
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <wicked/logging.h>
#include <wicked/netinfo.h>
#include <wicked/dcb.h>
#include "util_priv.h"
#include "kernel.h"

#include <netlink/msg.h>
#include <linux/dcbnl.h>

static int		ni_dcb_get_capabilities(const char *, ni_dcb_capabilities_t *);
static int		ni_dcb_get_ieee(const char *, ni_dcb_attributes_t *);

ni_dcb_attributes_t *
ni_dcb_attributes_new(void)
{
	ni_dcb_attributes_t *attrs;

	attrs = xcalloc(1, sizeof(*attrs));
	return attrs;
}

void
ni_dcb_attributes_destroy(ni_dcb_attributes_t *attrs)
{
	ni_dcb_app_priorities_destroy(&attrs->app_priorities);
}

void
ni_dcb_attributes_free(ni_dcb_attributes_t *attrs)
{
	ni_dcb_attributes_destroy(attrs);
	free(attrs);
}

void
ni_dcb_app_priorities_destroy(ni_dcb_app_priorities_t *table)
{
	free(table->data);
	memset(table, 0, sizeof(*table));
}

void
ni_dcb_app_priorities_append(ni_dcb_app_priorities_t *table, const struct dcb_app *entry)
{
	unsigned int size = table->count * sizeof(table->data[0]);
	table->data = xrealloc(table->data, size);
	table->data[table->count++] = *entry;
}

void
ni_dcb_app_priorities_copy(ni_dcb_app_priorities_t *dst, const ni_dcb_app_priorities_t *src)
{
	unsigned int size = src->count * sizeof(dst->data[0]);
	dst->data = xrealloc(dst->data, size);
	memcpy(dst->data, src->data, size);
	dst->count = src->count;
}

ni_dcb_t *
ni_dcb_new(void)
{
	ni_dcb_t *dcb;

	dcb = xcalloc(1, sizeof(*dcb));
	return dcb;
}

void
ni_dcb_free(ni_dcb_t *dcb)
{
	ni_dcb_attributes_destroy(&dcb->attributes);
	free(dcb);
}

/*
 * DCBX Support
 */
ni_bool_t
ni_dcbx_should_start(ni_netdev_t *dev)
{
	ni_dcb_t *dcb;

	if (dev->link.type != NI_IFTYPE_ETHERNET)
		return FALSE;

	if ((dcb = dev->dcb) == NULL) {
		ni_dcb_capabilities_t capabilities;

		memset(&capabilities, 0, sizeof(capabilities));
		if (ni_dcb_get_capabilities(dev->name, &capabilities) < 0)
			return FALSE;

		dcb = dev->dcb = ni_dcb_new();
		dcb->capabilities = capabilities;
	}

	/* If this bit isn't set, the card wants to do its own DCBX */
	if (!(dcb->capabilities.dcbx & DCB_CAP_DCBX_HOST)) {
		ni_debug_lldp("%s: card wants to do its own DCBX nego", dev->name);
		return FALSE;
	}

	if (ni_dcb_get_ieee(dev->name, &dev->dcb->attributes) < 0)
		return FALSE;

	ni_debug_lldp("%s: DCBX enabled (auto)", dev->name);
	return TRUE;
}

ni_dcbx_state_t *
ni_dcbx_new(void)
{
	ni_dcbx_state_t *dcbx;

	dcbx = xcalloc(1, sizeof(*dcbx));

#if 0
	dcbx->ets.sm.state = NI_DCBX_STATE_INIT;
	dcbx->ets.sm.local_willing = attrs->ets_config.willing;
	dcbx->ets.local_config = &attrs->ets_config;
	dcbx->ets.local_recommended = &attrs->ets_recommended;

	dcbx->pfc.sm.state = NI_DCBX_STATE_INIT;
	dcbx->pfc.sm.local_willing = attrs->pfc_config.willing;
	dcbx->pfc.local_config = &attrs->pfc_config;

	ni_dcbx_update(dcbx);
#endif

	return dcbx;
}

void
ni_dcbx_free(ni_dcbx_state_t *dcbx)
{
	ni_dcb_app_priorities_destroy(&dcbx->app_priorities);
	free(dcbx);
}

static void
ni_dcbx_symmetric_sm_update(ni_dcbx_symmetric_sm_t *sm)
{
	if (!sm->local_willing || !sm->remote_willing) {
		sm->state = NI_DCBX_STATE_INIT;
	} else {
		sm->state = NI_DCBX_STATE_RX_RECOMMENDED;
	}
}

static void
ni_dcbx_asymmetric_sm_update(ni_dcbx_asymmetric_sm_t *sm, ni_bool_t local_mac_wins)
{
	if (!sm->local_willing || !sm->remote_willing
	 || (sm->local_willing && sm->remote_willing && local_mac_wins)) {
		sm->state = NI_DCBX_STATE_INIT;
	} else {
		sm->state = NI_DCBX_STATE_RX_RECOMMENDED;
	}
}

static void
ni_dcbx_map_ets(ni_dcb_ets_t *oper_param, const ni_dcb_ets_t *remote_param)
{
	/* FIXME: this needs to be more elaborate, I guess */
	*oper_param = *remote_param;
}

static void
ni_dcbx_map_pfc(ni_dcb_pfc_t *oper_param, const ni_dcb_pfc_t *remote_param)
{
	/* FIXME: this needs to be more elaborate, I guess */
	*oper_param = *remote_param;
}

void
ni_dcbx_recv_ets(ni_dcbx_state_t *dcbx, const ni_dcb_ets_t *ets)
{
	if (ets == NULL) {
		dcbx->ets.sm.remote_willing = FALSE;
	} else {
		dcbx->ets.sm.remote_willing = ets->willing;
		dcbx->ets.remote_param = *ets;
	}

	ni_dcbx_symmetric_sm_update(&dcbx->ets.sm);
	if (dcbx->ets.sm.state == NI_DCBX_STATE_INIT)
		dcbx->ets.oper_param = dcbx->ets.local_config;
	else
		ni_dcbx_map_ets(&dcbx->ets.oper_param, &dcbx->ets.remote_param);
}

void
ni_dcbx_recv_pfc(ni_dcbx_state_t *dcbx, const ni_dcb_pfc_t *pfc)
{
	if (pfc == NULL) {
		dcbx->pfc.sm.remote_willing = FALSE;
	} else {
		dcbx->pfc.sm.remote_willing = pfc->willing;
		dcbx->pfc.remote_param = *pfc;
	}

	ni_dcbx_asymmetric_sm_update(&dcbx->pfc.sm, dcbx->local_mac_wins);
	if (dcbx->pfc.sm.state == NI_DCBX_STATE_INIT)
		dcbx->pfc.oper_param = dcbx->pfc.local_config;
	else
		ni_dcbx_map_pfc(&dcbx->pfc.oper_param, &dcbx->pfc.remote_param);
}

void
ni_dcbx_update_local(ni_dcbx_state_t *dcbx, const ni_dcb_attributes_t *local)
{
	dcbx->ets.sm.local_willing = local->ets_config.willing;
	dcbx->ets.local_config = local->ets_config;
	dcbx->ets.local_recommended = local->ets_recommended;
	if (dcbx->ets.sm.state == NI_DCBX_STATE_INIT)
		dcbx->ets.oper_param = dcbx->ets.local_config;

	dcbx->pfc.sm.local_willing = local->pfc_config.willing;
	dcbx->pfc.local_config = local->pfc_config;
	if (dcbx->pfc.sm.state == NI_DCBX_STATE_INIT)
		dcbx->pfc.oper_param = dcbx->pfc.local_config;

	ni_dcb_app_priorities_copy(&dcbx->app_priorities, &local->app_priorities);
}

/*
 * We received an LLDP PDU with DCBX attributes.
 * Process them according to the state machine rules and apply them (ie reconfigure
 * the NIC).
 *
 * This function should return TRUE if the local configuration changed.
 * This tells the LLDP engine to rebuild the PDU on the next transmit
 */
ni_bool_t
ni_dcbx_update_remote(ni_dcbx_state_t *dcbx, const ni_dcb_attributes_t *remote)
{
	ni_dcbx_recv_ets(dcbx, &remote->ets_recommended);
	ni_dcbx_recv_pfc(dcbx, &remote->pfc_config);

	/* For now, we tell LLDP to always rebuild the packet */
	return TRUE;
}

static inline void
__ni_dcb_cap_try_get_bool(struct nlattr *nla, ni_bool_t *var)
{
	if (nla)
		*var = nla_get_u8(nla);
}

static inline void
__ni_dcb_cap_try_get_u8(struct nlattr *nla, unsigned char *var)
{
	if (nla)
		*var = nla_get_u8(nla);
}

static int
ni_dcb_netlink_parse_cap(const char *ifname, struct nlattr *nla, ni_dcb_capabilities_t *caps)
{
	struct nlattr *tb[DCB_CAP_ATTR_MAX + 1];

	memset(tb, 0, sizeof(tb));
	if (nla_parse_nested(tb, DCB_CAP_ATTR_MAX, nla, NULL) < 0) {
		ni_error("%s: failed to parse DCB_ATTR_CAP", ifname);
		return -1;
	}

	__ni_dcb_cap_try_get_bool(tb[DCB_CAP_ATTR_PG], &caps->pg_supported);
	__ni_dcb_cap_try_get_bool(tb[DCB_CAP_ATTR_PFC], &caps->pfc_supported);
	__ni_dcb_cap_try_get_bool(tb[DCB_CAP_ATTR_UP2TC], &caps->up2tc_supported);

	__ni_dcb_cap_try_get_u8(tb[DCB_CAP_ATTR_PG_TCS], &caps->pg_num_classes);
	__ni_dcb_cap_try_get_u8(tb[DCB_CAP_ATTR_PFC_TCS], &caps->pfc_num_classes);
#ifdef DCB_CAP_ATTR_DCBX
	__ni_dcb_cap_try_get_u8(tb[DCB_CAP_ATTR_DCBX], &caps->dcbx);
#else
	/* Assume the host LLDP agent manages this device */
	caps->dcbx = DCB_CAP_DCBX_HOST;
#endif

	__ni_dcb_cap_try_get_bool(tb[DCB_CAP_ATTR_GSP], &caps->gsp_supported);
	__ni_dcb_cap_try_get_bool(tb[DCB_CAP_ATTR_BCN], &caps->bcn_supported);

	return 0;
}

static int
ni_dcb_netlink_parse_ieee(const char *ifname, struct nlattr *nla, ni_dcb_attributes_t *ieee)
{
	struct nlattr *tb[DCB_ATTR_IEEE_MAX + 1];

	memset(tb, 0, sizeof(tb));
	if (nla_parse_nested(tb, DCB_ATTR_IEEE_MAX, nla, NULL) < 0) {
		ni_error("%s: failed to parse DCB_ATTR_IEEE", ifname);
		return -1;
	}

	ni_dcb_app_priorities_destroy(&ieee->app_priorities);
	if (tb[DCB_ATTR_IEEE_APP_TABLE]) {
		struct nlattr *subattr;
		int rem;

		nla_for_each_nested(subattr, tb[DCB_ATTR_IEEE_APP_TABLE], rem) {
			struct dcb_app *entry = nla_data(subattr);

			ni_dcb_app_priorities_append(&ieee->app_priorities, entry);
		}
	}

	if (tb[DCB_ATTR_IEEE_ETS]) {
		struct ieee_ets *nl_ets = nla_data(tb[DCB_ATTR_IEEE_ETS]);
		ni_dcb_ets_t *ets = &ieee->ets_config;
		unsigned int max_tcs, max_prio;

		ets->willing = nl_ets->willing;
		ets->cbs_supported = nl_ets->cbs;
		ets->num_tc_supported = nl_ets->ets_cap;

		max_tcs = min_t(unsigned int, IEEE_8021QAZ_MAX_TCS, NI_DCBX_MAX_TCLASS);
		max_prio = min_t(unsigned int, IEEE_8021QAZ_MAX_TCS, NI_DCBX_MAX_PRIO);

		memcpy(ets->tc_bw, nl_ets->tc_tx_bw, max_tcs);
		memcpy(ets->tsa, nl_ets->tc_tsa, max_tcs);
		memcpy(ets->prio2tc, nl_ets->prio_tc, max_prio);

		/* Now build the recommendation */
		ieee->ets_recommended = ieee->ets_config;
		ets = &ieee->ets_recommended;

		memcpy(ets->tc_bw, nl_ets->tc_reco_bw, max_tcs);
		memcpy(ets->tsa, nl_ets->tc_reco_tsa, max_tcs);
		memcpy(ets->prio2tc, nl_ets->reco_prio_tc, max_prio);
	}
	if (tb[DCB_ATTR_IEEE_PFC]) {
		struct ieee_pfc *nl_pfc = nla_data(tb[DCB_ATTR_IEEE_PFC]);
		ni_dcb_pfc_t *pfc = &ieee->pfc_config;

		pfc->willing = TRUE; /* configure? */
		pfc->mbc = nl_pfc->mbc;
		pfc->cap = nl_pfc->pfc_cap;
		pfc->enable = nl_pfc->pfc_en;
	}

	return 0;
}

static int
__ni_dcb_getdcb(const char *ifname, int cmd, struct nlattr **attrs, unsigned int max_attrs)
{
	struct ni_nlmsg_list nlmsg_list;
	struct dcbmsg dcb, *d;
	struct nl_msg *msg;
	struct nlmsghdr *nlh;
	struct nlattr *nla;
	int err = -NLE_NOMEM;

	ni_nlmsg_list_init(&nlmsg_list);
	memset(attrs, 0, max_attrs * sizeof(attrs[0]));

	memset(&dcb, 0, sizeof(dcb));
	dcb.cmd = cmd;
	dcb.dcb_family = AF_UNSPEC;

	msg = nlmsg_alloc_simple(RTM_GETDCB, NLM_F_REQUEST);
	if (!msg)
		goto failed;
	if ((err = nlmsg_append(msg, &dcb, sizeof(dcb), NLMSG_ALIGNTO)) < 0)
		goto failed;

	NLA_PUT_STRING(msg, DCB_ATTR_IFNAME, ifname);
	if (cmd == DCB_CMD_GCAP) {
		nla = nla_nest_start(msg, DCB_ATTR_CAP);
		NLA_PUT_FLAG(msg, DCB_CAP_ATTR_ALL);
		nla_nest_end(msg, nla);
	}

	if ((err = ni_nl_talk(msg, &nlmsg_list)) < 0) {
		ni_debug_socket("%s: RTM_GETDCB error: %s", ifname,  nl_geterror(err));
		goto failed;
	}

	err = -NLE_PARSE_ERR;
	if (nlmsg_list.head == NULL) {
		ni_error("%s: empty response from kernel", ifname);
		goto failed;
	}

	nlh = &nlmsg_list.head->h;

	d = (struct dcbmsg *) NLMSG_DATA(nlh);
	if (d->cmd != cmd) {
		ni_error("%s: bad cmd %u in RTM_GETDCB response", ifname, d->cmd);
		goto failed;
	}

	if ((err = nlmsg_parse(nlh, sizeof(struct dcbmsg), attrs, max_attrs, NULL)) < 0) {
		ni_error("%s: unable to parse RTM_GETDCB reply", ifname);
		goto failed;
	}

	ni_nlmsg_list_destroy(&nlmsg_list);
	nlmsg_free(msg);
	return 0;

nla_put_failure: ;
failed:
	ni_nlmsg_list_destroy(&nlmsg_list);
	nlmsg_free(msg);
	return err;
}

int
ni_dcb_get_capabilities(const char *ifname, ni_dcb_capabilities_t *caps)
{
	struct nlattr *tb[DCB_ATTR_MAX + 1];
	int rv;

	rv = __ni_dcb_getdcb(ifname, DCB_CMD_GCAP, tb, DCB_ATTR_MAX);
	if (rv < 0)
		return rv;

	if (tb[DCB_ATTR_CAP] == NULL) {
		ni_error("%s: no ATTR_CAP attribute in DCB_GCAP reply", ifname);
		return -1;
	}

	return ni_dcb_netlink_parse_cap(ifname, tb[DCB_ATTR_CAP], caps);
}

int
ni_dcb_get_ieee(const char *ifname, ni_dcb_attributes_t *attrs)
{
	struct nlattr *tb[DCB_ATTR_MAX + 1];
	int rv;

	rv = __ni_dcb_getdcb(ifname, DCB_CMD_IEEE_GET, tb, DCB_ATTR_MAX);
	if (rv < 0)
		return rv;

	if (tb[DCB_ATTR_IEEE] == NULL) {
		ni_error("%s: no IEEE attribute in DCB_CMD_IEEE_GET reply", ifname);
		return -1;
	}

	// Handle these attrs:
	// DCB_ATTR_IEEE_APP_TABLE
	// DCB_ATTR_IEEE_ETS
	// DCB_ATTR_IEEE_PFC

	return ni_dcb_netlink_parse_ieee(ifname, tb[DCB_ATTR_IEEE], attrs);
}
