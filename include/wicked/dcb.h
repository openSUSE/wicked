/*
 * Support IEEE 802.1 Qaz (aka Data Center Bridging).
 *
 * Copyright (C) 2013 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_DCB_H__
#define __WICKED_DCB_H__

#include <wicked/types.h>
#include <wicked/constants.h>

#define NI_DCBX_MAX_PRIO			8
#define NI_DCBX_MAX_TCLASS			8

typedef enum ni_dcbx_tsa {
	NI_DCBX_TSA_STRICTPRIO = 0,
	NI_DCBX_TSA_CREDITBASEDSHAPER = 1,
	NI_DCBX_TSA_VENDORSPECIFIC = 255
} ni_dcbx_tsa_t;

/*
 * ETS: Enhanced transmission selection
 */
typedef struct ni_dcb_ets {
	ni_bool_t				willing;
	ni_bool_t				cbs_supported;	/* Credit based shaper supported */
	unsigned int				num_tc_supported;/* Number of traffic classes supported, 3 .. 8 */

	/* This maps a priority to a traffic class */
	unsigned char				prio2tc[NI_DCBX_MAX_PRIO];

	/* This specifies the ETS bandwidth assigned to each traffic class, as percentage.
	 * Must sum up to 100.
	 */
	unsigned char				tc_bw[NI_DCBX_MAX_TCLASS];

	/* This specifies the Traffic Selection Algorithm for each traffic class.
	 * Uses NI_DCBX_TSA_* values.
	 */
	unsigned char				tsa[NI_DCBX_MAX_TCLASS];
} ni_dcb_ets_t;

/*
 * PFC: Priority-based Flow Control
 */
typedef struct ni_dcb_pfc {
	ni_bool_t				willing;
	ni_bool_t				mbc;		/* MACsec bypass capability */

	unsigned char				cap;		/* max number of traffic classes simultaneously supporting PFC */
	unsigned char				enable;		/* bitN corresponds to traffic class N */
} ni_dcb_pfc_t;

/*
 * Application Priority table
 */
typedef enum ni_dcb_app_type {
	NI_DCBX_APP_TYPE_ETHERTYPE	= 1,
	NI_DCBX_APP_TYPE_IP_STREAM	= 2,	/* TCP or SCTP port number */
	NI_DCBX_APP_TYPE_IP_DGRAM	= 3,	/* UDP or DCCP port number */
	NI_DCBX_APP_TYPE_IP_ALL		= 4,	/* Any TCP, SCTP, UDP or DCCP port number */
} ni_dcb_app_type_t;

typedef struct ni_dcb_app_priorities {
	unsigned int				count;
	struct dcb_app *			data;
} ni_dcb_app_priorities_t;

typedef struct ni_dcb_capabilities {
	ni_bool_t				pg_supported;
	ni_bool_t				pfc_supported;
	ni_bool_t				up2tc_supported;
	ni_bool_t				gsp_supported;
	ni_bool_t				bcn_supported;

	/* These two are weird bitmaps, not a count */
	unsigned char				pg_num_classes;
	unsigned char				pfc_num_classes;
	unsigned char				dcbx;
} ni_dcb_capabilities_t;

typedef struct ni_dcb_attributes		ni_dcb_attributes_t;

struct ni_dcb_attributes {
	ni_dcb_ets_t				ets_config;
	ni_dcb_ets_t				ets_recommended;
	ni_dcb_pfc_t				pfc_config;

	ni_dcb_app_priorities_t			app_priorities;
};

/*
 * This data is attached to a netdev.
 */
struct ni_dcb {
	ni_dcb_capabilities_t			capabilities;
	ni_dcb_attributes_t			attributes;
};


/*
 * State machine handling for DCBX
 * This looks more arcane than it actually is.
 */
typedef enum ni_dcbx_attr_neg_state {
	NI_DCBX_STATE_INIT = 0,
	NI_DCBX_STATE_RX_RECOMMENDED,
} ni_dcbx_attr_neg_state_t;

typedef struct ni_dcbx_symmetric_sm {
	ni_dcbx_attr_neg_state_t		state;
	ni_bool_t				local_willing;
	ni_bool_t				remote_willing;
} ni_dcbx_symmetric_sm_t;

typedef struct ni_dcbx_asymmetric_sm {
	ni_dcbx_attr_neg_state_t		state;
	ni_bool_t				local_willing;
	ni_bool_t				remote_willing;
} ni_dcbx_asymmetric_sm_t;

typedef struct ni_dcbx_state {
	ni_bool_t				running;

	ni_bool_t				local_mac_wins;

	struct {
		ni_dcbx_symmetric_sm_t		sm;

		ni_dcb_ets_t			oper_param;
		ni_dcb_ets_t			local_config;
		ni_dcb_ets_t			local_recommended;
		ni_dcb_ets_t			remote_param;
	} ets;

	struct {
		ni_dcbx_asymmetric_sm_t		sm;

		ni_dcb_pfc_t			oper_param;
		ni_dcb_pfc_t			local_config;
		ni_dcb_pfc_t			remote_param;
	} pfc;

	ni_dcb_app_priorities_t			app_priorities;
} ni_dcbx_state_t;

extern ni_dcb_attributes_t *	ni_dcb_attributes_new(void);
extern void			ni_dcb_attributes_free(ni_dcb_attributes_t *);
extern void			ni_dcb_free(ni_dcb_t *);

extern ni_bool_t		ni_dcbx_should_start(ni_netdev_t *);
extern ni_dcbx_state_t *	ni_dcbx_new(void);
extern void			ni_dcbx_free(ni_dcbx_state_t *);
extern void			ni_dcbx_update_local(ni_dcbx_state_t *, const ni_dcb_attributes_t *);
extern ni_bool_t		ni_dcbx_update_remote(ni_dcbx_state_t *, const ni_dcb_attributes_t *);

extern void			ni_dcb_app_priorities_destroy(ni_dcb_app_priorities_t *);
extern void			ni_dcb_app_priorities_destroy_append(ni_dcb_app_priorities_t *dst, const struct dcb_app *);
extern void			ni_dcb_app_priorities_destroy_copy(ni_dcb_app_priorities_t *dst, const ni_dcb_app_priorities_t *);

#endif /* __WICKED_DCB_H__ */

