/*
 * Global header file for netinfo library
 *
 * Copyright (C) 2009-2012 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_CONSTANTS_H__
#define __WICKED_CONSTANTS_H__

/*
 * Address configuration modes
 */
typedef enum ni_addrconf_mode {
	NI_ADDRCONF_NONE,
	NI_ADDRCONF_DHCP,
	NI_ADDRCONF_STATIC,
	NI_ADDRCONF_AUTOCONF,

	/* many interface types such as PPP, OpenVPN and iBFT use an
	 * intrinsic addrconf mechanism. We do not provide any services
	 * exposing these mechanisms, but we still want to be able to
	 * tag the ownership properly.
	 */
	NI_ADDRCONF_INTRINSIC,

	__NI_ADDRCONF_MAX
} ni_addrconf_mode_t;

/*
 * Interface flags
 */
enum {
	NI_IFF_DEVICE_READY		= 0x00000001,
	NI_IFF_DEVICE_UP		= 0x00000002,
	NI_IFF_LINK_UP			= 0x00000004,
	NI_IFF_POWERSAVE		= 0x00000008,
	NI_IFF_NETWORK_UP		= 0x00000010,
	NI_IFF_POINT_TO_POINT		= 0x00000020,
	NI_IFF_ARP_ENABLED		= 0x00000040,
	NI_IFF_BROADCAST_ENABLED	= 0x00000080,
	NI_IFF_MULTICAST_ENABLED	= 0x00000100,
};

/*
 * Interface types
 */
typedef enum ni_iftype {
	NI_IFTYPE_UNKNOWN = 0,
	NI_IFTYPE_LOOPBACK,
	NI_IFTYPE_ETHERNET,
	NI_IFTYPE_BRIDGE,
	NI_IFTYPE_BOND,
	NI_IFTYPE_VLAN,
	NI_IFTYPE_MACVLAN,
	NI_IFTYPE_MACVTAP,
	NI_IFTYPE_WIRELESS,
	NI_IFTYPE_INFINIBAND,
	NI_IFTYPE_INFINIBAND_CHILD,
	NI_IFTYPE_PPP,
	NI_IFTYPE_SLIP,
	NI_IFTYPE_SIT,
	NI_IFTYPE_GRE,
	NI_IFTYPE_ISDN,
	NI_IFTYPE_IPIP,		/* ipip tunnel */
	NI_IFTYPE_TUNNEL6,	/* ip6ip6 tunnel */
	NI_IFTYPE_TOKENRING,
	NI_IFTYPE_FIREWIRE,
	NI_IFTYPE_TUN,
	NI_IFTYPE_TAP,
	NI_IFTYPE_DUMMY,
	NI_IFTYPE_CTCM,		/* s390 ctcm (slip) devices */
	NI_IFTYPE_IUCV,		/* s390 iucv (slip) devices */
	NI_IFTYPE_TEAM,
	NI_IFTYPE_OVS_SYSTEM,
	NI_IFTYPE_OVS_BRIDGE,
	NI_IFTYPE_OVS_UNSPEC,
	NI_IFTYPE_VXLAN,
	NI_IFTYPE_IPVLAN,
	NI_IFTYPE_IPVTAP,

	__NI_IFTYPE_MAX
} ni_iftype_t;

/*
 * rfkill types
 */
typedef enum {
	NI_RFKILL_TYPE_WIRELESS,
	NI_RFKILL_TYPE_BLUETOOTH,
	NI_RFKILL_TYPE_MOBILE,

	__NI_RFKILL_TYPE_MAX
} ni_rfkill_type_t;

/*
 * Modem types
 */
typedef enum ni_modem_type {
	MM_MODEM_TYPE_UNKNOWN = 0,
	MM_MODEM_TYPE_GSM = 1,
	MM_MODEM_TYPE_CDMA = 2,

	__MM_MODEM_TYPE_MAX,
} ni_modem_type_t;

/*
 * Events generated by the rtnetlink layer, and translated
 * by us.
 */
typedef enum ni_event {
	NI_EVENT_DEVICE_CREATE = 0,
	NI_EVENT_DEVICE_DELETE,
	NI_EVENT_DEVICE_CHANGE,
	NI_EVENT_DEVICE_RENAME,
	NI_EVENT_DEVICE_READY,
	NI_EVENT_DEVICE_UP,
	NI_EVENT_DEVICE_DOWN,
	NI_EVENT_LINK_ASSOCIATED,	/* wireless */
	NI_EVENT_LINK_ASSOCIATION_LOST,	/* wireless */
	NI_EVENT_LINK_SCAN_UPDATED,	/* wireless */
	NI_EVENT_LINK_UP,
	NI_EVENT_LINK_DOWN,
	NI_EVENT_NETWORK_UP,
	NI_EVENT_NETWORK_DOWN,
	NI_EVENT_ADDRESS_ACQUIRED,
	NI_EVENT_ADDRESS_RELEASED,
	NI_EVENT_ADDRESS_DEFERRED,
	NI_EVENT_ADDRESS_LOST,
	NI_EVENT_ADDRESS_UPDATE,
	NI_EVENT_ADDRESS_DELETE,
	NI_EVENT_PREFIX_UPDATE,
	NI_EVENT_PREFIX_DELETE,
	NI_EVENT_RDNSS_UPDATE,
	NI_EVENT_DNSSL_UPDATE,
	NI_EVENT_ROUTE_UPDATE,
	NI_EVENT_ROUTE_DELETE,
	NI_EVENT_RULE_UPDATE,
	NI_EVENT_RULE_DELETE,
	NI_EVENT_RESOLVER_UPDATED,
	NI_EVENT_HOSTNAME_UPDATED,
	NI_EVENT_GENERIC_UPDATED,

	__NI_EVENT_MAX
} ni_event_t;

/*
 * LLDP destination types
 */
typedef enum ni_lldp_destination {
	NI_LLDP_DEST_NEAREST_BRIDGE = 0,
	NI_LLDP_DEST_NEAREST_NON_TPMR_BRIDGE,
	NI_LLDP_DEST_NEAREST_CUSTOMER_BRIDGE,

	__NI_LLDP_DEST_MAX
} ni_lldp_destination_t;

enum ni_lldp_system_capability {
	NI_LLDP_SYSCAP_OTHER				= 1,
	NI_LLDP_SYSCAP_REPEATER				= 2,
	NI_LLDP_SYSCAP_MAC_BRIDGE			= 3,
	NI_LLDP_SYSCAP_WLAN_AP				= 4,
	NI_LLDP_SYSCAP_ROUTER				= 5,
	NI_LLDP_SYSCAP_TELEPHONE			= 6,
	NI_LLDP_SYSCAP_DOCSIS_CABLE_DEV			= 7,
	NI_LLDP_SYSCAP_STATION_ONLY			= 8,
	NI_LLDP_SYSCAP_VLAN_BRIDGE_C_VLAN		= 9,
	NI_LLDP_SYSCAP_VLAN_BRIDGE_S_VLAN		= 10,
	NI_LLDP_SYSCAP_TPMR				= 11,
};

typedef enum {
	NI_SUCCESS = 0,

	NI_ERROR_GENERAL_FAILURE,
	NI_ERROR_RETRY_OPERATION,

	NI_ERROR_INVALID_ARGS,
	NI_ERROR_PERMISSION_DENIED,
	NI_ERROR_DOCUMENT_ERROR,

	NI_ERROR_DEVICE_NOT_KNOWN,
	NI_ERROR_DEVICE_BAD_HIERARCHY,
	NI_ERROR_DEVICE_IN_USE,
	NI_ERROR_DEVICE_NOT_UP,
	NI_ERROR_DEVICE_NOT_DOWN,
	NI_ERROR_DEVICE_NOT_COMPATIBLE,
	NI_ERROR_DEVICE_EXISTS,

	NI_ERROR_AUTH_INFO_MISSING,

	NI_ERROR_ADDRCONF_NO_LEASE,

	NI_ERROR_CANNOT_CONFIGURE_DEVICE,
	NI_ERROR_CANNOT_CONFIGURE_ADDRESS,
	NI_ERROR_CANNOT_CONFIGURE_ROUTE,

	NI_ERROR_DBUS_CALL_FAILED,
	NI_ERROR_CANNOT_MARSHAL,
	NI_ERROR_SERVICE_UNKNOWN,
	NI_ERROR_METHOD_NOT_SUPPORTED,
	NI_ERROR_METHOD_CALL_TIMED_OUT,
	NI_ERROR_PROPERTY_NOT_PRESENT,

	NI_ERROR_UNRESOLVABLE_HOSTNAME,
	NI_ERROR_UNREACHABLE_ADDRESS,

	NI_ERROR_POLICY_EXISTS,
	NI_ERROR_POLICY_DOESNOTEXIST,
	NI_ERROR_RADIO_DISABLED,

	NI_ERROR_ENTRY_EXISTS,
	NI_ERROR_ENTRY_NOT_KNOWN,

	__NI_ERROR_MAX
} ni_error_t;

typedef enum {
	/*
	 * Init Script Action return codes defined in
	 * Linux Standard Base Core Specification 4.1
	 * for all actions except status:
	 *
	 *   0-7        defined LSB return codes
	 *   8-99       reserved for future LSB use
	 * 100-149      reserved for distribution use
	 * 150-199      reserved for application use
	 * 200-254      reserved
	 */
	NI_LSB_RC_SUCCESS		= 0,	/*!< success				*/
	NI_LSB_RC_ERROR			= 1,	/*!< generic or unspecified error	*/
	NI_LSB_RC_USAGE			= 2,	/*!< invalid or excess argument(s)	*/
	NI_LSB_RC_NOT_IMPLEMENTED	= 3,	/*!< unimplemented feature ("reload")	*/
	NI_LSB_RC_NOT_ALLOWED		= 4,	/*!< user had insufficient privilege	*/
	NI_LSB_RC_NOT_INSTALLED		= 5,	/*!< program is not installed		*/
	NI_LSB_RC_NOT_CONFIGURED	= 6,	/*!< program is not configured		*/
	NI_LSB_RC_NOT_RUNNING		= 7,	/*!< program is not running		*/

	/*
	 * Wicked return codes:
	 */
	NI_WICKED_RC_SUCCESS		= NI_LSB_RC_SUCCESS,
	NI_WICKED_RC_ERROR		= NI_LSB_RC_ERROR,
	NI_WICKED_RC_USAGE		= NI_LSB_RC_USAGE,
	NI_WICKED_RC_NOT_IMPLEMENTED	= NI_LSB_RC_NOT_IMPLEMENTED,
	NI_WICKED_RC_NOT_ALLOWED	= NI_LSB_RC_NOT_ALLOWED,
	NI_WICKED_RC_NOT_CONFIGURED	= NI_LSB_RC_NOT_CONFIGURED,
	NI_WICKED_RC_NOT_RUNNING	= NI_LSB_RC_NOT_RUNNING,
	NI_WICKED_RC_NO_DEVICE		= NI_LSB_RC_NOT_RUNNING,
	NI_WICKED_RC_IN_PROGRESS	= 12,	/*!< 12 for SUSE's ifup compatibility	*/
 } ni_return_code_t;

typedef enum {
	/*
	 * Init Script Action return codes defined in
	 * Linux Standard Base Core Specification 4.1
	 * for status action:
	 *
	 *   0-4        defined LSB status codes
	 *   5-99       reserved for future LSB use
	 * 100-149      reserved for distribution use
	 * 150-199      reserved for application use
	 * 200-254      reserved
	 */
	NI_LSB_ST_OK			= 0,	/*!< running / service is OK		*/
	NI_LSB_ST_DEAD_PID_FILE		= 1,	/*!< dead and /var/run pid file exists	*/
	NI_LSB_ST_DEAD_LOCK_FILE	= 2,	/*!< dead and /var/lock lock file exists*/
	NI_LSB_ST_NOT_RUNNING		= 3,	/*!< program / service is not running	*/
	NI_LSB_ST_UNKNOWN		= 4,	/*!< status is unknown			*/

	/*
	 * Wicked mapped status codes:
	 */
	NI_WICKED_ST_OK			= NI_LSB_ST_OK,			/* all fine	*/
	NI_WICKED_ST_ERROR		= NI_LSB_ST_DEAD_PID_FILE,	/* wickedd down	*/
	NI_WICKED_ST_FAILED		= NI_LSB_ST_DEAD_LOCK_FILE,	/* setup failed	*/
	NI_WICKED_ST_UNUSED		= NI_LSB_ST_NOT_RUNNING,	/* dev unused	*/
	NI_WICKED_ST_USAGE		= NI_LSB_ST_UNKNOWN,		/* usage error	*/

	/*
	 * Wicked extended status/check codes:
	 */
	NI_WICKED_ST_DISABLED		= 155,	/*!< dev activation is disabled		*/
	NI_WICKED_ST_UNCONFIGURED	= 156,	/*!< dev is not yet set up / started	*/

	NI_WICKED_ST_NO_DEVICE		= 157,	/*!< dev does not exist yet		*/
	NI_WICKED_ST_NOT_RUNNING	= 158,	/*!< dev is started, but set up failed	*/

	NI_WICKED_ST_NO_CONFIG		= 159,	/*!< no configuration found		*/
	NI_WICKED_ST_IN_PROGRESS	= 162,	/*!< dev is up, but setup is incomplete */
	NI_WICKED_ST_CHANGED_CONFIG	= 163,	/*!< up, config changed, reload advised	*/

	NI_WICKED_ST_ENSLAVED		= 164,	/*!< dev is up and has masterdev	*/

	NI_WICKED_ST_NOT_IN_STATE	= 165,	/*!< ifcheck state lower than expected	*/
	NI_WICKED_ST_PERSISTENT_ON	= 166,	/*!< interface is in persistent mode	*/
	NI_WICKED_ST_USERCONTROL_ON	= 167,	/*!< user is allowed to configure the interface	*/
	NI_WICKED_ST_NO_CARRIER		= 168,	/*!< dev is up, but there is no carrier */
} ni_status_code_t;

#endif /* __WICKED_CONSTANTS_H__ */
