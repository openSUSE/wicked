/*
 *	wicked xml interface config and policy utilities
 *
 *	Copyright (C) 2010-2014 SUSE LINUX Products GmbH, Nuernberg, Germany.
 *	Copyright (C) 2014-2025 SUSE LLC
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
 */
#ifndef NI_WICKED_CLIENT_IFCONFIG_H
#define NI_WICKED_CLIENT_IFCONFIG_H

#define NI_CONFIG_ORIGIN			"origin"
#define NI_CONFIG_OWNER				"owner"
#define NI_CONFIG_UUID				"uuid"

#define NI_CLIENT_IFCONFIG			"interface"
#define NI_CLIENT_IFCONFIG_ORIGIN		NI_CONFIG_ORIGIN
#define NI_CLIENT_IFCONFIG_OWNER		NI_CONFIG_OWNER
#define NI_CLIENT_IFCONFIG_UUID			NI_CONFIG_UUID
#define NI_CLIENT_IFCONFIG_MATCH_NAME		"name"
#define NI_CLIENT_IFCONFIG_CONTROL		"control"
#define NI_CLIENT_IFCONFIG_MODE			"mode"
#define NI_CLIENT_IFCONFIG_LINK			"link"
#define NI_CLIENT_IFCONFIG_MASTER		"master"
#define NI_CLIENT_IFCONFIG_LINK_PORT		"port"
#define NI_CLIENT_IFCONFIG_PORT_TYPE		"type"
#define NI_CLIENT_IFCONFIG_BRIDGE		"bridge"
#define NI_CLIENT_IFCONFIG_IPV4			"ipv4"
#define NI_CLIENT_IFCONFIG_IPV6			"ipv6"
#define NI_CLIENT_IFCONFIG_IP_ENABLED		"enabled"
#define NI_CLIENT_IFCONFIG_ARP_VERIFY		"arp-verify"

#define NI_NANNY_IFPOLICY			"policy"
#define NI_NANNY_IFTEMPLATE			"template"

#define NI_NANNY_IFPOLICY_MATCH			"match"
#define NI_NANNY_IFPOLICY_MATCH_COND_OR		"or"
#define NI_NANNY_IFPOLICY_MATCH_COND_AND	"and"
#define NI_NANNY_IFPOLICY_MATCH_COND_CHILD	"child"
#define NI_NANNY_IFPOLICY_MATCH_ALWAYS_TRUE	"any"
#define NI_NANNY_IFPOLICY_MATCH_DEV		"device"
#define NI_NANNY_IFPOLICY_MATCH_REF		"reference"
#define NI_NANNY_IFPOLICY_MATCH_MIN_STATE	"minimum-device-state"
#define NI_NANNY_IFPOLICY_MATCH_LINK_TYPE	"link-type"
#define NI_NANNY_IFPOLICY_MERGE			"merge"
#define NI_NANNY_IFPOLICY_REPLACE		"replace"
#define NI_NANNY_IFPOLICY_CREATE		"create"

#define NI_NANNY_IFPOLICY_ORIGIN		NI_CONFIG_ORIGIN
#define NI_NANNY_IFPOLICY_OWNER			NI_CONFIG_OWNER
#define NI_NANNY_IFPOLICY_UUID			NI_CONFIG_UUID
#define NI_NANNY_IFPOLICY_WEIGHT		"weight"
#define NI_NANNY_IFPOLICY_CLASS			"class"
#define NI_NANNY_IFPOLICY_NAME			"name"

extern ni_bool_t		ni_ifpolicy_match_add_min_state(xml_node_t *, ni_fsm_state_t);
extern ni_bool_t		ni_ifpolicy_match_add_link_type(xml_node_t *, unsigned int);
extern xml_node_t *		ni_ifpolicy_generate_match(const ni_string_array_t *, const char *);
extern ni_bool_t		ni_ifpolicy_name_is_valid(const char *);
extern char *			ni_ifpolicy_name_from_ifname(const char *);
extern ni_bool_t		ni_ifpolicy_get_owner_uid(const xml_node_t *, uid_t *);
extern ni_bool_t		ni_ifpolicy_set_owner_uid(xml_node_t *, uid_t);
extern ni_bool_t		ni_ifpolicy_set_owner(xml_node_t *, const char *);
extern ni_bool_t		ni_ifpolicy_set_uuid(xml_node_t *, const ni_uuid_t *);

extern xml_node_t *		ni_convert_cfg_into_policy_node(const xml_node_t *, xml_node_t *, const char *, const char*);
extern xml_document_t *		ni_convert_cfg_into_policy_doc(xml_document_t *);

extern int			ni_nanny_addpolicy_node(const xml_node_t *, const char *);
extern int			ni_nanny_addpolicy(xml_document_t *);

extern ni_dbus_client_t *	ni_nanny_create_client(ni_dbus_object_t **);

extern ni_bool_t		ni_nanny_call_add_policy(const char *, const xml_node_t *);
extern ni_bool_t		ni_nanny_call_del_policy(const char *);
extern ni_bool_t		ni_nanny_call_device_enable(const char *ifname);
extern ni_bool_t		ni_nanny_call_device_disable(const char *ifname);
extern ni_dbus_object_t *	ni_nanny_call_get_device(const char *);
extern ni_bool_t		ni_nanny_call_add_secret(const ni_security_id_t *, const char *, const char *);
extern ni_bool_t		ni_nanny_call_recheck(const ni_string_array_t *);

extern ni_bool_t		ni_ifconfig_generate_uuid(const xml_node_t *, ni_uuid_t *);
extern ni_bool_t		ni_ifxml_node_is_migrated(const xml_node_t *);
extern ni_bool_t		ni_ifxml_node_set_migrated(xml_node_t *, ni_bool_t);
extern ni_bool_t		ni_ifxml_migrate_docs(xml_document_array_t *);

extern ni_bool_t		ni_ifxml_is_config(const xml_node_t *);
extern ni_bool_t		ni_ifxml_is_policy(const xml_node_t *);

static inline const char *
ni_ifconfig_get_uuid(const xml_node_t *ifnode)
{
	return xml_node_get_attr(ifnode, NI_CLIENT_IFCONFIG_UUID);
}

static inline const char *
ni_ifconfig_get_origin(const xml_node_t *ifnode)
{
	return xml_node_get_attr(ifnode, NI_CLIENT_IFCONFIG_ORIGIN);
}

static inline const char *
ni_ifpolicy_get_class(const xml_node_t *pnode)
{
	return xml_node_get_attr(pnode, NI_NANNY_IFPOLICY_CLASS);
}

static inline const char *
ni_ifpolicy_get_name(const xml_node_t *pnode)
{
	return xml_node_get_attr(pnode, NI_NANNY_IFPOLICY_NAME);
}

static inline const char *
ni_ifpolicy_get_uuid(const xml_node_t *pnode)
{
	return xml_node_get_attr(pnode, NI_NANNY_IFPOLICY_UUID);
}

static inline const char *
ni_ifpolicy_get_owner(const xml_node_t *pnode)
{
	return xml_node_get_attr(pnode, NI_NANNY_IFPOLICY_OWNER);
}

static inline const char *
ni_ifpolicy_get_origin(const xml_node_t *pnode)
{
	return xml_node_get_attr(pnode, NI_NANNY_IFPOLICY_ORIGIN);
}

static inline const char *
ni_ifpolicy_get_weight(const xml_node_t *pnode)
{
	return xml_node_get_attr(pnode, NI_NANNY_IFPOLICY_WEIGHT);
}

static inline ni_bool_t
ni_ifpolicy_is_valid(const xml_node_t *pnode)
{
	if (!ni_ifxml_is_policy(pnode))
		return FALSE;

	return ni_ifpolicy_name_is_valid(ni_ifpolicy_get_name(pnode));
}

#endif /* NI_WICKED_CLIENT_IFCONFIG_H */
