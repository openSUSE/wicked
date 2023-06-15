/*
 *	ethtool support
 *
 *	Copyright (C) 2018 SUSE LINUX GmbH, Nuernberg, Germany.
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
 *	You should have received a copy of the GNU General Public License
 *	along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 *	Authors:
 *		Marius Tomaschewski <mt@suse.de>
 *		Nirmoy Das <ndas@suse.de>
 *		Olaf Kirch <okir@suse.de>
 */
#ifndef WICKED_ETHTOOL_H
#define WICKED_ETHTOOL_H

#include <wicked/types.h>

/*
 * driver-info
 */
typedef enum {
	NI_ETHTOOL_DRIVER_SUPP_PRIV_FLAGS,
	NI_ETHTOOL_DRIVER_SUPP_STATS,
	NI_ETHTOOL_DRIVER_SUPP_TEST,
	NI_ETHTOOL_DRIVER_SUPP_EEPROM,
	NI_ETHTOOL_DRIVER_SUPP_REGDUMP,
} ni_ethtool_driver_supports_bit_t;

typedef struct ni_ethtool_driver_info {
	char *			driver;
	char *			version;
	char *			bus_info;
	char *			fw_version;
	char *			erom_version;

	struct {
		unsigned int	bitmap;

		unsigned int	n_priv_flags;
		unsigned int	n_stats;
		unsigned int	testinfo_len;
		unsigned int	eedump_len;
		unsigned int	regdump_len;
	} supports;
} ni_ethtool_driver_info_t;


/*
 * driver specific priv-flags
 */
typedef struct ni_ethtool_priv_flags {
	ni_string_array_t		names;
	unsigned int			bitmap;
} ni_ethtool_priv_flags_t;


/*
 * link control and status settings
 */
typedef enum {
	NI_ETHTOOL_DUPLEX_HALF,
	NI_ETHTOOL_DUPLEX_FULL,
	NI_ETHTOOL_DUPLEX_UNKNOWN	= 0xff,
} ni_ethtool_duplex_t;

typedef enum {
	NI_ETHTOOL_PORT_TP,
	NI_ETHTOOL_PORT_AUI,
	NI_ETHTOOL_PORT_BNC,
	NI_ETHTOOL_PORT_MII,
	NI_ETHTOOL_PORT_FIBRE,
	NI_ETHTOOL_PORT_DA,
	NI_ETHTOOL_PORT_NONE		= 0xfe,
	NI_ETHTOOL_PORT_OTHER		= 0xff,
	NI_ETHTOOL_PORT_DEFAULT		= -1U
} ni_ethtool_port_type_t;

typedef enum {
	NI_ETHTOOL_MDI_INVALID		= 0,
	NI_ETHTOOL_MDI			= 1,
	NI_ETHTOOL_MDI_X,
	NI_ETHTOOL_MDI_AUTO,
	NI_ETHTOOL_MDI_X_AUTO,
} ni_ethtool_mdix_t;

typedef enum {
	NI_ETHTOOL_XCVR_INTERNAL,
	NI_ETHTOOL_XCVR_EXTERNAL,
	NI_ETHTOOL_XCVR_UNKNOWN		= 0xff
} ni_ethtool_xcvr_t;

typedef enum {
	NI_ETHTOOL_MDIO_SUPPORTS_C22	= 1,
	NI_ETHTOOL_MDIO_SUPPORTS_C45	= 2,
} ni_ethtool_mdio_t;

#define NI_ETHTOOL_PHYAD_UNKNOWN	0xff
#define NI_ETHTOOL_SPEED_UNKNOWN	-1U

typedef struct ni_ethtool_link_settings {
	ni_tristate_t			autoneg;
	unsigned int			port;
	unsigned int			speed;
	uint8_t				duplex;

	uint8_t				transceiver;
	uint8_t				phy_address;
	uint8_t				mdio_support;
	uint8_t				tp_mdix;

	int8_t				nwords;
	ni_bitfield_t			supported;
	ni_bitfield_t			advertising;
	ni_bitfield_t			lp_advertising;
} ni_ethtool_link_settings_t;


/*
 * wake-on-lan
 */
typedef enum {
	/* bit index number flags: */
	NI_ETHTOOL_WOL_PHY		= 0,	/* p, phy	*/
	NI_ETHTOOL_WOL_UCAST		= 1,	/* u, unicast	*/
	NI_ETHTOOL_WOL_MCAST		= 2,	/* m, multicast	*/
	NI_ETHTOOL_WOL_BCAST		= 3,	/* b, broadcast	*/
	NI_ETHTOOL_WOL_ARP		= 4,	/* a, arp	*/
	NI_ETHTOOL_WOL_MAGIC		= 5,	/* g, magic	*/
	NI_ETHTOOL_WOL_SECUREON		= 6,	/* s, secure-on	*/

	/* empty & unset bitmasks: */
	NI_ETHTOOL_WOL_DISABLE		= 0,	/* d, disable   */
	NI_ETHTOOL_WOL_DEFAULT		= -1U
} ni_ethtool_wol_flag_t;

typedef struct ni_ethtool_wake_on_lan {
	unsigned int		support;
	unsigned int		options;
	ni_hwaddr_t		sopass;
} ni_ethtool_wake_on_lan_t;


/*
 * offload and other features
 */
typedef enum {
	NI_ETHTOOL_FEATURE_ON		= NI_BIT(0),
	NI_ETHTOOL_FEATURE_FIXED	= NI_BIT(1),
	NI_ETHTOOL_FEATURE_REQUESTED	= NI_BIT(2),
	NI_ETHTOOL_FEATURE_OFF		= 0U	/* !on */
} ni_ethtool_feature_value_t;

typedef struct ni_ethtool_feature {
	ni_intmap_t			map;
	ni_ethtool_feature_value_t	value;
	unsigned int			index;
} ni_ethtool_feature_t;

typedef struct ni_ethtool_features {
	unsigned int			total;
	unsigned int			count;
	ni_ethtool_feature_t **		data;
} ni_ethtool_features_t;


/*
 * energy-efficient ethernet
 */
#define NI_ETHTOOL_EEE_DEFAULT		-1U

typedef struct ni_ethtool_eee {
	struct {
		ni_tristate_t		enabled;
		ni_tristate_t		active;
	} status;
	struct {
		ni_bitfield_t		supported;
		ni_bitfield_t		advertising;
		ni_bitfield_t		lp_advertising;
	} speed;
	struct {
		ni_tristate_t		enabled;
		unsigned int		timer;
	} tx_lpi;
} ni_ethtool_eee_t;


/*
 * ring
 */
#define NI_ETHTOOL_RING_DEFAULT		-1U

typedef struct ni_ethtool_ring {
	unsigned int			tx;
	unsigned int			rx;
	unsigned int			rx_jumbo;
	unsigned int			rx_mini;
} ni_ethtool_ring_t;


/*
 * channels
 */
#define NI_ETHTOOL_CHANNELS_DEFAULT	-1U

typedef struct ni_ethtool_channels {
	unsigned int			tx;
	unsigned int			rx;
	unsigned int			other;
	unsigned int			combined;
} ni_ethtool_channels_t;

/*
 * coalescing
 */
#define NI_ETHTOOL_COALESCE_DEFAULT		-1U

typedef struct ni_ethtool_coalesce {
	ni_tristate_t			adaptive_tx;
	ni_tristate_t			adaptive_rx;

	unsigned int			pkt_rate_low;
	unsigned int			pkt_rate_high;

	unsigned int			sample_interval;
	unsigned int			stats_block_usecs;

	unsigned int			tx_usecs;
	unsigned int			tx_usecs_irq;
	unsigned int			tx_usecs_low;
	unsigned int			tx_usecs_high;

	unsigned int			tx_frames;
	unsigned int			tx_frames_irq;
	unsigned int			tx_frames_low;
	unsigned int			tx_frames_high;

	unsigned int			rx_usecs;
	unsigned int			rx_usecs_irq;
	unsigned int			rx_usecs_low;
	unsigned int			rx_usecs_high;

	unsigned int			rx_frames;
	unsigned int			rx_frames_irq;
	unsigned int			rx_frames_low;
	unsigned int			rx_frames_high;
} ni_ethtool_coalesce_t;

typedef struct ni_ethtool_pause {
	ni_tristate_t			tx;
	ni_tristate_t			rx;
	ni_tristate_t			autoneg;
} ni_ethtool_pause_t;

/*
 * device ethtool structure
 */
struct ni_ethtool {
	ni_bitfield_t			supported;

	/* read-only info        */
	ni_ethtool_driver_info_t *	driver_info;
	ni_tristate_t			link_detected;

	/* configurable          */
	ni_ethtool_priv_flags_t *	priv_flags;
	ni_ethtool_link_settings_t *	link_settings;
	ni_ethtool_wake_on_lan_t *	wake_on_lan;
	ni_ethtool_features_t *		features;
	ni_ethtool_eee_t *		eee;
	ni_ethtool_ring_t *		ring;
	ni_ethtool_channels_t *		channels;
	ni_ethtool_coalesce_t *		coalesce;
	ni_ethtool_pause_t *		pause;
};

extern ni_ethtool_t *			ni_ethtool_new(void);
extern void				ni_ethtool_free(ni_ethtool_t *);

extern ni_ethtool_driver_info_t *	ni_netdev_get_ethtool_driver_info(ni_netdev_t *);
extern ni_ethtool_driver_info_t *	ni_ethtool_driver_info_new(void);
extern void				ni_ethtool_driver_info_free(ni_ethtool_driver_info_t *);
extern const char *			ni_ethtool_driver_supports_map_bit(ni_ethtool_driver_supports_bit_t);
extern int				ni_ethtool_get_driver_info(const ni_netdev_ref_t *, ni_ethtool_t *);
extern int				ni_ethtool_get_permanent_address(const ni_netdev_ref_t *, ni_ethtool_t *, ni_hwaddr_t *);
extern int				ni_ethtool_get_link_detected(const ni_netdev_ref_t *, ni_ethtool_t *);

extern ni_ethtool_priv_flags_t *	ni_netdev_get_ethtool_priv_flags(ni_netdev_t *);
extern ni_ethtool_priv_flags_t *	ni_ethtool_priv_flags_new(void);
extern void				ni_ethtool_priv_flags_free(ni_ethtool_priv_flags_t *);
extern int				ni_ethtool_get_priv_flags(const ni_netdev_ref_t *, ni_ethtool_t *);
extern int				ni_ethtool_set_priv_flags(const ni_netdev_ref_t *, ni_ethtool_t *,
								const ni_ethtool_priv_flags_t *);

extern ni_ethtool_link_settings_t *	ni_netdev_get_ethtool_link_settings(ni_netdev_t *);
extern ni_ethtool_link_settings_t *	ni_ethtool_link_settings_new(void);
extern void				ni_ethtool_link_settings_free(ni_ethtool_link_settings_t *);
extern const char *			ni_ethtool_link_adv_name(unsigned int);
extern ni_bool_t			ni_ethtool_link_adv_type(const char *, unsigned int *);
extern ni_bool_t			ni_ethtool_link_adv_autoneg(const ni_bitfield_t *);
extern ni_bool_t			ni_ethtool_link_adv_set_autoneg(ni_bitfield_t *, ni_bool_t);
extern const char *			ni_ethtool_link_adv_port_name(unsigned int);
extern ni_bool_t			ni_ethtool_link_adv_port_type(const char *, unsigned int *);
extern const char *			ni_ethtool_link_adv_speed_name(unsigned int);
extern ni_bool_t			ni_ethtool_link_adv_speed_type(const char *, unsigned int *);
extern const char *			ni_ethtool_link_adv_pause_name(unsigned int);
extern ni_bool_t			ni_ethtool_link_adv_pause_type(const char *, unsigned int *);
extern const char *			ni_ethtool_link_adv_fec_name(unsigned int);
extern ni_bool_t			ni_ethtool_link_adv_fec_type(const char *, unsigned int *);
extern const char *			ni_ethtool_link_port_name(unsigned int);
extern ni_bool_t			ni_ethtool_link_port_type(const char *, unsigned int *);
extern const char *			ni_ethtool_link_duplex_name(unsigned int);
extern ni_bool_t			ni_ethtool_link_duplex_type(const char *, unsigned int *);
extern const char *			ni_ethtool_link_mdix_name(unsigned int);
extern ni_bool_t			ni_ethtool_link_mdix_type(const char *, unsigned int *);
extern const char *			ni_ethtool_link_mdio_name(unsigned int);
extern ni_bool_t			ni_ethtool_link_mdio_type(const char *, unsigned int *);
extern const char *			ni_ethtool_link_xcvr_name(unsigned int);
extern ni_bool_t			ni_ethtool_link_xcvr_type(const char *, unsigned int *);
extern int				ni_ethtool_get_link_settings(const ni_netdev_ref_t *, ni_ethtool_t *);
extern int				ni_ethtool_set_link_settings(const ni_netdev_ref_t *, ni_ethtool_t *,
								const ni_ethtool_link_settings_t *);

extern ni_ethtool_wake_on_lan_t *	ni_netdev_get_ethtool_wake_on_lan(ni_netdev_t *);
extern ni_ethtool_wake_on_lan_t *	ni_ethtool_wake_on_lan_new(void);
extern void				ni_ethtool_wake_on_lan_free(ni_ethtool_wake_on_lan_t *);
extern const char *			ni_ethtool_wol_flag_name(unsigned int);
extern ni_bool_t			ni_ethtool_wol_flag_type(const char *, unsigned int *);
extern const char *			ni_ethtool_wol_flags_format(ni_stringbuf_t *, unsigned int, const char *);
extern int				ni_ethtool_get_wake_on_lan(const ni_netdev_ref_t *, ni_ethtool_t *);
extern int				ni_ethtool_set_wake_on_lan(const ni_netdev_ref_t *, ni_ethtool_t *,
								const ni_ethtool_wake_on_lan_t *);

extern ni_ethtool_features_t *		ni_netdev_get_ethtool_features(ni_netdev_t *);
extern ni_ethtool_features_t *		ni_ethtool_features_new(void);
extern void				ni_ethtool_features_free(ni_ethtool_features_t *);
extern ni_ethtool_feature_t *		ni_ethtool_features_set(ni_ethtool_features_t *,
					const char *, ni_ethtool_feature_value_t);
extern int				ni_ethtool_get_features(const ni_netdev_ref_t *, ni_ethtool_t *, ni_bool_t);
extern int				ni_ethtool_set_features(const ni_netdev_ref_t *, ni_ethtool_t *,
								const ni_ethtool_features_t *);

extern ni_ethtool_eee_t *		ni_netdev_get_ethtool_eee(ni_netdev_t *);
extern ni_ethtool_eee_t *		ni_ethtool_eee_new(void);
extern void				ni_ethtool_eee_free(ni_ethtool_eee_t *);
extern int				ni_ethtool_get_eee(const ni_netdev_ref_t *, ni_ethtool_t *);
extern int				ni_ethtool_set_eee(const ni_netdev_ref_t *, ni_ethtool_t *,
								const ni_ethtool_eee_t *);

extern ni_ethtool_ring_t *		ni_netdev_get_ethtool_ring(ni_netdev_t *);
extern ni_ethtool_ring_t *		ni_ethtool_ring_new(void);
extern void				ni_ethtool_ring_free(ni_ethtool_ring_t *);
extern int				ni_ethtool_get_ring(const ni_netdev_ref_t *, ni_ethtool_t *);
extern int				ni_ethtool_set_ring(const ni_netdev_ref_t *, ni_ethtool_t *,
								const ni_ethtool_ring_t *);

extern ni_ethtool_channels_t *		ni_netdev_get_ethtool_channels(ni_netdev_t *);
extern ni_ethtool_channels_t *		ni_ethtool_channels_new(void);
extern void				ni_ethtool_channels_free(ni_ethtool_channels_t *);
extern int				ni_ethtool_get_channels(const ni_netdev_ref_t *, ni_ethtool_t *);
extern int				ni_ethtool_set_channels(const ni_netdev_ref_t *, ni_ethtool_t *,
								const ni_ethtool_channels_t *);

extern ni_ethtool_coalesce_t *		ni_netdev_get_ethtool_coalesce(ni_netdev_t *);
extern ni_ethtool_coalesce_t *		ni_ethtool_coalesce_new(void);
extern void				ni_ethtool_coalesce_free(ni_ethtool_coalesce_t *);
extern int				ni_ethtool_get_coalesce(const ni_netdev_ref_t *, ni_ethtool_t *);
extern int				ni_ethtool_set_coalesce(const ni_netdev_ref_t *, ni_ethtool_t *,
								const ni_ethtool_coalesce_t *);

extern ni_ethtool_pause_t *		ni_netdev_get_ethtool_pause(ni_netdev_t *);
extern ni_ethtool_pause_t *		ni_ethtool_pause_new(void);
extern void				ni_ethtool_pause_free(ni_ethtool_pause_t *);
extern int				ni_ethtool_get_pause(const ni_netdev_ref_t *, ni_ethtool_t *);
extern int				ni_ethtool_set_pause(const ni_netdev_ref_t *, ni_ethtool_t *,
								const ni_ethtool_pause_t *);

#endif /* WICKED_ETHTOOL_H */
