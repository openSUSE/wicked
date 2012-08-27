/*
 * Wicked object model
 *
 * Copyright (C) 2011-2012 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_OBJECTMODEL_H__
#define __WICKED_OBJECTMODEL_H__

#include <wicked/secret.h>
#include <wicked/dbus.h>

extern ni_xs_scope_t *		ni_objectmodel_init(ni_dbus_server_t *);
extern void			ni_objectmodel_register_all(void);
extern void			ni_objectmodel_register_netif_classes(void);
extern void			ni_objectmodel_register_netif_services(void);
extern void			ni_objectmodel_register_modem_classes(void);
extern void			ni_objectmodel_register_modem_services(void);
extern void			ni_objectmodel_register_addrconf_classes(void);
extern void			ni_objectmodel_register_netif_service(ni_iftype_t, ni_dbus_service_t *);
extern ni_dbus_server_t *	ni_objectmodel_create_service(void);
extern ni_bool_t		ni_objectmodel_save_state(const char *);
extern ni_bool_t		ni_objectmodel_recover_state(const char *, const char **);

extern dbus_bool_t		ni_objectmodel_create_initial_objects(ni_dbus_server_t *);
extern ni_dbus_object_t *	ni_objectmodel_register_netif(ni_dbus_server_t *, ni_netdev_t *ifp,
					const ni_dbus_class_t *override_class);
extern dbus_bool_t		ni_objectmodel_unregister_netif(ni_dbus_server_t *, ni_netdev_t *ifp);
extern ni_dbus_object_t *	ni_objectmodel_register_modem(ni_dbus_server_t *, ni_modem_t *);
extern dbus_bool_t		ni_objectmodel_unregister_modem(ni_dbus_server_t *, ni_modem_t *);
extern int			ni_objectmodel_bind_extensions(void);
extern void			ni_objectmodel_register_service(const ni_dbus_service_t *);
extern void			ni_objectmodel_register_class(const ni_dbus_class_t *);
extern const ni_dbus_class_t *	ni_objectmodel_get_class(const char *);
extern ni_dbus_class_t *	ni_objectmodel_class_new(const char *, const ni_dbus_class_t *);

#define NI_OBJECTMODEL_NETIF_CLASS		"netif"
#define NI_OBJECTMODEL_NETIF_LIST_CLASS		"netif-list"
#define NI_OBJECTMODEL_NETIF_REQUEST_CLASS	"netif-request"
#define NI_OBJECTMODEL_ADDRCONF_REQUEST_CLASS	"addrconf-request"
#define NI_OBJECTMODEL_MM_MODEM_CLASS		"mm-modem"
#define NI_OBJECTMODEL_MM_MODEM_GSM_CLASS	"mm-modem-gsm"
#define NI_OBJECTMODEL_MM_MODEM_CDMA_CLASS	"mm-modem-cdma"
#define NI_OBJECTMODEL_MODEM_CLASS		"modem"
#define NI_OBJECTMODEL_MODEM_GSM_CLASS		"modem-gsm"
#define NI_OBJECTMODEL_MODEM_CDMA_CLASS		"modem-cdma"
#define NI_OBJECTMODEL_MODEM_LIST_CLASS		"modem-list"
#define NI_OBJECTMODEL_ADDRCONF_DEVICE_CLASS	"addrconf-device"

#define NI_OBJECTMODEL_NAMESPACE		"org.opensuse.Network"
#define NI_OBJECTMODEL_OBJECT_ROOT		"/org/opensuse/Network"

#define NI_OBJECTMODEL_DBUS_BUS_NAME		NI_OBJECTMODEL_NAMESPACE
#define NI_OBJECTMODEL_DBUS_BUS_NAME_DHCP4	NI_OBJECTMODEL_NAMESPACE ".DHCP4"
#define NI_OBJECTMODEL_DBUS_BUS_NAME_DHCP6	NI_OBJECTMODEL_NAMESPACE ".DHCP6"
#define NI_OBJECTMODEL_DBUS_BUS_NAME_AUTO4	NI_OBJECTMODEL_NAMESPACE ".AUTO4"
#define NI_OBJECTMODEL_DBUS_BUS_NAME_MANAGER	NI_OBJECTMODEL_NAMESPACE ".Manager"

#define NI_OBJECTMODEL_OBJECT_PATH		NI_OBJECTMODEL_OBJECT_ROOT
#define NI_OBJECTMODEL_NETIF_LIST_PATH		NI_OBJECTMODEL_OBJECT_ROOT "/Interface"
#define NI_OBJECTMODEL_MODEM_LIST_PATH		NI_OBJECTMODEL_OBJECT_ROOT "/Modem"
/* The following live in network-nanny */
#define NI_OBJECTMODEL_MANAGER_PATH		NI_OBJECTMODEL_OBJECT_ROOT "/Manager"
#define NI_OBJECTMODEL_MANAGED_NETIF_LIST_PATH	NI_OBJECTMODEL_OBJECT_ROOT "/Manager/Interface"
#define NI_OBJECTMODEL_MANAGED_MODEM_LIST_PATH	NI_OBJECTMODEL_OBJECT_ROOT "/Manager/Modem"
#define NI_OBJECTMODEL_MANAGED_POLICY_LIST_PATH	NI_OBJECTMODEL_OBJECT_ROOT "/Manager/Policy"

#define NI_OBJECTMODEL_INTERFACE		NI_OBJECTMODEL_NAMESPACE
#define NI_OBJECTMODEL_NETIFLIST_INTERFACE	NI_OBJECTMODEL_INTERFACE ".InterfaceList"
#define NI_OBJECTMODEL_NETIF_INTERFACE		NI_OBJECTMODEL_INTERFACE ".Interface"
#define NI_OBJECTMODEL_ETHERNET_INTERFACE	NI_OBJECTMODEL_INTERFACE ".Ethernet"
#define NI_OBJECTMODEL_WIRELESS_INTERFACE	NI_OBJECTMODEL_INTERFACE ".Wireless"
#define NI_OBJECTMODEL_BRIDGE_INTERFACE		NI_OBJECTMODEL_INTERFACE ".Bridge"
#define NI_OBJECTMODEL_VLAN_INTERFACE		NI_OBJECTMODEL_INTERFACE ".VLAN"
#define NI_OBJECTMODEL_BONDING_INTERFACE	NI_OBJECTMODEL_INTERFACE ".Bond"
#define NI_OBJECTMODEL_TUN_INTERFACE		NI_OBJECTMODEL_INTERFACE ".TUN"
#define NI_OBJECTMODEL_OPENVPN_INTERFACE	NI_OBJECTMODEL_INTERFACE ".OpenVPN"
#define NI_OBJECTMODEL_PPP_INTERFACE		NI_OBJECTMODEL_INTERFACE ".PPP"
#define NI_OBJECTMODEL_PPPOE_INTERFACE		NI_OBJECTMODEL_INTERFACE ".PPPoE"
#define NI_OBJECTMODEL_IPV4_INTERFACE		NI_OBJECTMODEL_INTERFACE ".Protocol.IPv4"
#define NI_OBJECTMODEL_IPV6_INTERFACE		NI_OBJECTMODEL_INTERFACE ".Protocol.IPv6"
#define NI_OBJECTMODEL_ADDRCONF_INTERFACE	NI_OBJECTMODEL_INTERFACE ".Addrconf"
#define NI_OBJECTMODEL_DHCP4_INTERFACE		NI_OBJECTMODEL_INTERFACE ".DHCP4"
#define NI_OBJECTMODEL_DHCP6_INTERFACE		NI_OBJECTMODEL_INTERFACE ".DHCP6"
#define NI_OBJECTMODEL_AUTO4_INTERFACE		NI_OBJECTMODEL_INTERFACE ".AUTO4"
#define NI_OBJECTMODEL_MODEM_LIST_INTERFACE	NI_OBJECTMODEL_INTERFACE ".ModemList"
#define NI_OBJECTMODEL_MODEM_INTERFACE		NI_OBJECTMODEL_INTERFACE ".Modem"
#define NI_OBJECTMODEL_MANAGER_INTERFACE	NI_OBJECTMODEL_INTERFACE ".Manager"
#define NI_OBJECTMODEL_MANAGED_NETIF_INTERFACE	NI_OBJECTMODEL_INTERFACE ".ManagedInterface"
#define NI_OBJECTMODEL_MANAGED_MODEM_INTERFACE	NI_OBJECTMODEL_INTERFACE ".ManagedModem"
#define NI_OBJECTMODEL_MANAGED_POLICY_INTERFACE	NI_OBJECTMODEL_INTERFACE ".ManagedPolicy"

/*
 * Signals emitted by addrconf services
 */
#define NI_OBJECTMODEL_LEASE_ACQUIRED_SIGNAL	"LeaseAcquired"
#define NI_OBJECTMODEL_LEASE_RELEASED_SIGNAL	"LeaseReleased"
#define NI_OBJECTMODEL_LEASE_LOST_SIGNAL	"LeaseLost"

extern const ni_dbus_class_t	ni_objectmodel_netif_class;
extern const ni_dbus_class_t	ni_objectmodel_addrconf_device_class;

extern const char *		ni_objectmodel_link_classname(ni_iftype_t);

extern const ni_dbus_service_t *ni_objectmodel_service_by_name(const char *interface_name);
extern const ni_dbus_service_t *ni_objectmodel_service_by_class(const ni_dbus_class_t *);
extern const ni_dbus_service_t *ni_objectmodel_service_by_tag(const char *tag);
extern const ni_dbus_service_t *ni_objectmodel_factory_service(const ni_dbus_service_t *);
extern const ni_dbus_service_t *ni_objectmodel_auth_service(const ni_dbus_service_t *);
extern unsigned int		ni_objectmodel_compatible_services_for_class(const ni_dbus_class_t *query_class,
					const ni_dbus_service_t **list, unsigned int max);
extern dbus_bool_t		ni_objectmodel_bind_compatible_interfaces(ni_dbus_object_t *);

extern dbus_bool_t		ni_objectmodel_get_addrconf_lease(const ni_addrconf_lease_t *, ni_dbus_variant_t *);
extern dbus_bool_t		ni_objectmodel_set_addrconf_lease(ni_addrconf_lease_t *, const ni_dbus_variant_t *);
extern dbus_bool_t		ni_objectmodel_netif_client_info_from_dict(ni_device_clientinfo_t *, const ni_dbus_variant_t *);
extern dbus_bool_t		ni_objectmodel_netif_client_info_to_dict(const ni_device_clientinfo_t *, ni_dbus_variant_t *);

extern ni_dbus_object_t *	ni_objectmodel_object_by_path(const char *path);

extern ni_dbus_object_t *	ni_objectmodel_wrap_netif(ni_netdev_t *ifp);
extern ni_netdev_t *		ni_objectmodel_unwrap_netif(const ni_dbus_object_t *, DBusError *);
extern ni_dbus_object_t *	ni_objectmodel_get_netif_object(ni_dbus_server_t *, const ni_netdev_t *);
extern dbus_bool_t		ni_objectmodel_send_netif_event(ni_dbus_server_t *, ni_dbus_object_t *,
					ni_event_t, const ni_uuid_t *);

extern ni_modem_t *		ni_objectmodel_unwrap_modem(const ni_dbus_object_t *, DBusError *);
extern ni_dbus_object_t *	ni_objectmodel_get_modem_object(ni_dbus_server_t *, const ni_modem_t *);
extern dbus_bool_t		ni_objectmodel_send_modem_event(ni_dbus_server_t *, ni_dbus_object_t *,
					ni_event_t, const ni_uuid_t *);
extern const char *		ni_objectmodel_modem_get_classname(ni_modem_type_t);
extern const ni_dbus_class_t *	ni_objectmodel_modem_get_class(ni_modem_type_t);

extern dbus_bool_t		ni_objectmodel_other_event(ni_dbus_server_t *, ni_event_t, const ni_uuid_t *);

extern dbus_bool_t		ni_objectmodel_marshal_netdev_request(const ni_netdev_req_t *, ni_dbus_variant_t *, DBusError *);
extern dbus_bool_t		ni_objectmodel_unmarshal_netdev_request(ni_netdev_req_t *, const ni_dbus_variant_t *, DBusError *);
extern dbus_bool_t		ni_objectmodel_marshal_security_id(const ni_security_id_t *, ni_dbus_variant_t *);
extern dbus_bool_t		ni_objectmodel_unmarshal_security_id(ni_security_id_t *, const ni_dbus_variant_t *);

extern ni_event_t		ni_objectmodel_signal_to_event(const char *);
extern const char *		ni_objectmodel_event_to_signal(ni_event_t);

typedef struct ni_objectmodel_callback_info ni_objectmodel_callback_info_t;
struct ni_objectmodel_callback_info {
	ni_objectmodel_callback_info_t *next;
	char *			event;
	ni_uuid_t		uuid;
};

ni_objectmodel_callback_info_t *ni_objectmodel_callback_info_from_dict(const ni_dbus_variant_t *);
extern void			ni_objectmodel_callback_info_free(ni_objectmodel_callback_info_t *);

typedef struct ni_objectmodel_ns ni_objectmodel_ns_t;
struct ni_objectmodel_ns {
	const char *		name;
	ni_dbus_object_t *	(*lookup_by_name)(ni_objectmodel_ns_t *, const char *);
	ni_dbus_object_t *	(*lookup_by_attrs)(ni_objectmodel_ns_t *, const ni_var_array_t *);
	dbus_bool_t		(*match_attr)(const ni_dbus_object_t *, const char *, const char *);
};

extern void			ni_objectmodel_register_ns(ni_objectmodel_ns_t *);
extern void			ni_objectmodel_register_ns_builtin(void);
extern void			ni_objectmodel_register_ns_dynamic(void);
extern ni_objectmodel_ns_t *	ni_objectmodel_get_ns(const char *);
extern ni_dbus_object_t *	ni_objectmodel_lookup_by_attrs(ni_dbus_object_t *list_object,
					ni_objectmodel_ns_t *, const ni_var_array_t *);


#endif /* __WICKED_OBJECTMODEL_H__ */

