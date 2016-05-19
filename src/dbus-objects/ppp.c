/*
 *	DBus encapsulation for ppp interfaces
 *
 *	Copyright (C) 2016 SUSE Linux GmbH, Nuernberg, Germany.
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
 *		Olaf Kirch <okir@suse.de>
 *		Pawel Wieczorkiewicz <pwieczorkiewicz@suse.de>
 *		Marius Tomaschewski <mt@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/system.h>
#include <wicked/ppp.h>
#include <wicked/dbus-errors.h>
#include <wicked/dbus-service.h>
#include "dbus-common.h"
#include "dbus-objects/misc.h"
#include "appconfig.h"
#include "model.h"
#include "debug.h"

static ni_netdev_t *		ni_objectmodel_ppp_device_arg(const ni_dbus_variant_t *);
static ni_netdev_t *		ni_objectmodel_ppp_device_create(ni_netdev_t *, const char *, DBusError *);

/*
 * Create a new ppp interface
 */
static dbus_bool_t
ni_objectmodel_ppp_device_new(ni_dbus_object_t *factory_object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_dbus_server_t *server = ni_dbus_object_get_server(factory_object);
	ni_netdev_t *dev, *cfg;
	const char *ifname = NULL;

	if (argc != 2)
		goto error;

	if (!ni_dbus_variant_get_string(&argv[0], &ifname))
		goto error;

	if (!(cfg = ni_objectmodel_ppp_device_arg(&argv[1])))
		goto error;

	dev = ni_objectmodel_ppp_device_create(cfg, ifname, error);
	ni_netdev_put(cfg);

	if (dev)
		return ni_objectmodel_netif_factory_result(server, reply, dev, NULL, error);
	else
		return FALSE;

error:
	return ni_dbus_error_invalid_args(error, factory_object->path, method->name);
}

static ni_netdev_t *
ni_objectmodel_ppp_device_arg(const ni_dbus_variant_t *dict)
{
	return ni_objectmodel_get_netif_argument(dict, NI_IFTYPE_PPP, &ni_objectmodel_ppp_service);
}

static ni_netdev_t *
ni_objectmodel_ppp_device_create(ni_netdev_t *cfg, const char *ifname, DBusError *error)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_netdev_t *dev = NULL;
	int rv;

	ni_netdev_get_ppp(cfg);
	if (ifname == NULL && !(ifname = ni_netdev_make_name(nc, "ppp", 0))) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
				"Unable to create ppp interface - too many interfaces");
		return NULL;
	}
	ni_string_dup(&cfg->name, ifname);

	if ((rv = ni_system_ppp_create(nc, cfg, &dev)) < 0) {
		dbus_set_error(error, DBUS_ERROR_FAILED, "Unable to create ppp interface '%s'",
				cfg->name);
		return NULL;
	}

	if (dev && dev->link.type != NI_IFTYPE_PPP) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
			"Unable to create ppp interface: new interface is of type %s",
			ni_linktype_type_to_name(dev->link.type));
		return NULL;
	}
	return dev;
}

/*
 * PPP.changeDevice method
 */
static dbus_bool_t
ni_objectmodel_ppp_device_change(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_netdev_t *ifp, *cfg;
	dbus_bool_t rv = FALSE;

	/* we've already checked that argv matches our signature */
	ni_assert(argc == 1);

	if (!(ifp = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	if (!(cfg = ni_objectmodel_ppp_device_arg(&argv[0]))) {
		ni_dbus_error_invalid_args(error, object->path, method->name);
		goto out;
	}

	if (ni_system_ppp_setup(nc, ifp, cfg) < 0) {
		dbus_set_error(error, DBUS_ERROR_FAILED, "failed to set up ppp device");
		goto out;
	}

	rv = TRUE;
out:
	if (cfg)
		ni_netdev_put(cfg);
	return rv;
}

/*
 * PPP.delete method
 */
static dbus_bool_t
ni_objectmodel_ppp_device_delete(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_netdev_t *dev;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	NI_TRACE_ENTER_ARGS("dev=%s", dev->name);
	if (ni_system_ppp_delete(nc, dev) < 0) {
		dbus_set_error(error, DBUS_ERROR_FAILED, "Error deleting ppp interface", dev->name);
		return FALSE;
	}

	ni_client_state_drop(dev->link.ifindex);
	return TRUE;
}

/*
 * Helper function to obtain ppp config from dbus object
 */
static ni_ppp_t *
ni_objectmodel_ppp_handle(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	ni_netdev_t *dev;
	ni_ppp_t *ppp;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return NULL;

	if (!write_access)
		return dev->ppp;

	if (!(ppp = ni_netdev_get_ppp(dev))) {
		if (error)
			dbus_set_error(error, DBUS_ERROR_FAILED,
					"Error getting ppp handle for interface");
		return NULL;
	}
	return ppp;
}

static void *
ni_objectmodel_get_ppp_config(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	ni_ppp_t *ppp;

	if (!(ppp = ni_objectmodel_ppp_handle(object, write_access, error)))
		return NULL;

	return &ppp->config;
}

static dbus_bool_t
ni_objectmodel_ppp_get_mode(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
				ni_dbus_variant_t *result, DBusError *error)
{
	ni_dbus_variant_t *dict;
	const ni_ppp_t *ppp;
	const char *mode;

	if (!(ppp = ni_objectmodel_ppp_handle(object, FALSE, error)))
		return FALSE;

	if (NI_PPP_MODE_UNKNOWN == ppp->mode.type)
		return ni_dbus_error_property_not_present(error, object->path, property->name);

	if (!(mode = ni_ppp_mode_type_to_name(ppp->mode.type))) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"bad property %s; unsupported mode type %u",
				property->name, ppp->mode.type);
		return FALSE;
	}

	ni_dbus_variant_init_struct(result);
	ni_dbus_struct_add_string(result, mode);
	dict = ni_dbus_struct_add(result);
	ni_dbus_variant_init_dict(dict);

	switch (ppp->mode.type) {
	case NI_PPP_MODE_PPPOE: {
			const ni_ppp_mode_pppoe_t *pppoe = &ppp->mode.pppoe;

			if (!ni_string_empty(pppoe->device.name))
				ni_dbus_dict_add_string(dict, "device", pppoe->device.name);
		}
		break;

	default:
		return FALSE;
	}

	return TRUE;
}

static dbus_bool_t
ni_objectmodel_ppp_set_mode(ni_dbus_object_t *object, const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_dbus_variant_t *dict;
	const char *mode;
	ni_ppp_t *ppp;

	if (!(ppp = ni_objectmodel_ppp_handle(object, TRUE, error)))
		return FALSE;

	if (!ni_dbus_struct_get_string(argument, 0, &mode)) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"bad value for property %s; missed subtype", property->name);
		return FALSE;
	}

	if (!ni_ppp_mode_name_to_type(mode, &ppp->mode.type)) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"bad value for property %s; unsupported subtype %s", property->name, mode);
		return FALSE;
	}

	if (!(dict = ni_dbus_struct_get(argument, 1))) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "missed ppp mode member dict");
		return FALSE;
	}
	if (!ni_dbus_variant_is_dict(dict)) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "ppp mode member is not a dict");
		return FALSE;
	}

	ni_ppp_mode_init(&ppp->mode, ppp->mode.type);
	switch (ppp->mode.type) {
	case NI_PPP_MODE_PPPOE: {
			ni_ppp_mode_pppoe_t *pppoe = &ppp->mode.pppoe;
			const char *string;

			if (ni_dbus_dict_get_string(dict, "device", &string))
				ni_netdev_ref_set_ifname(&pppoe->device, string);
		}
		break;

	default:
		return FALSE;
	}

	return TRUE;
}

static dbus_bool_t
ni_objectmodel_ppp_config_get_idle(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
				ni_dbus_variant_t *result, DBusError *error)
{
	const ni_ppp_config_t *conf;

	if (!(conf = ni_objectmodel_get_ppp_config(object, FALSE, error)))
		return FALSE;

	if (conf->idle == -1U)
		return FALSE;

	ni_dbus_variant_set_uint32(result, conf->idle);
	return TRUE;
}

static dbus_bool_t
ni_objectmodel_ppp_config_set_idle(ni_dbus_object_t *object, const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_ppp_config_t *conf;

	if (!(conf = ni_objectmodel_get_ppp_config(object, TRUE, error)))
		return FALSE;

	return ni_dbus_variant_get_uint32(argument, &conf->idle);
}


static dbus_bool_t
ni_objectmodel_ppp_config_get_maxfail(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
				ni_dbus_variant_t *result, DBusError *error)
{
	const ni_ppp_config_t *conf;

	if (!(conf = ni_objectmodel_get_ppp_config(object, FALSE, error)))
		return FALSE;

	if (conf->maxfail == -1U)
		return FALSE;

	ni_dbus_variant_set_uint32(result, conf->maxfail);
	return TRUE;
}

static dbus_bool_t
ni_objectmodel_ppp_config_set_maxfail(ni_dbus_object_t *object, const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_ppp_config_t *conf;

	if (!(conf = ni_objectmodel_get_ppp_config(object, TRUE, error)))
		return FALSE;

	return ni_dbus_variant_get_uint32(argument, &conf->maxfail);
}

static dbus_bool_t
ni_objectmodel_ppp_config_get_holdoff(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
				ni_dbus_variant_t *result, DBusError *error)
{
	const ni_ppp_config_t *conf;

	if (!(conf = ni_objectmodel_get_ppp_config(object, FALSE, error)))
		return FALSE;

	if (conf->holdoff == -1U)
		return FALSE;

	ni_dbus_variant_set_uint32(result, conf->holdoff);
	return TRUE;
}

static dbus_bool_t
ni_objectmodel_ppp_config_set_holdoff(ni_dbus_object_t *object, const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_ppp_config_t *conf;

	if (!(conf = ni_objectmodel_get_ppp_config(object, TRUE, error)))
		return FALSE;

	return ni_dbus_variant_get_uint32(argument, &conf->holdoff);
}

static dbus_bool_t
ni_objectmodel_ppp_config_get_auth(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
				ni_dbus_variant_t *result, DBusError *error)
{
	const ni_ppp_config_t *conf;

	if (!(conf = ni_objectmodel_get_ppp_config(object, FALSE, error)))
		return FALSE;

	if (!ni_string_empty(conf->auth.hostname))
		ni_dbus_dict_add_string(result, "hostname", conf->auth.hostname);

	if (!ni_string_empty(conf->auth.username))
		ni_dbus_dict_add_string(result, "username", conf->auth.username);

	if (!ni_string_empty(conf->auth.password))
		ni_dbus_dict_add_string(result, "password", conf->auth.password);

	return TRUE;
}

static dbus_bool_t
ni_objectmodel_ppp_config_set_auth(ni_dbus_object_t *object, const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_ppp_config_t *conf;
	const char *string;

	if (!ni_dbus_variant_is_dict(argument))
		return FALSE;

	if (!(conf = ni_objectmodel_get_ppp_config(object, TRUE, error)))
		return FALSE;

	if (ni_dbus_dict_get_string(argument, "hostname", &string))
		ni_string_dup(&conf->auth.hostname, string);

	if (ni_dbus_dict_get_string(argument, "username", &string))
		ni_string_dup(&conf->auth.username, string);

	if (ni_dbus_dict_get_string(argument, "password", &string))
		ni_string_dup(&conf->auth.password, string);

	return TRUE;
}

static dbus_bool_t
ni_objectmodel_ppp_config_get_dns(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
				ni_dbus_variant_t *result, DBusError *error)
{
	const ni_ppp_config_t *conf;

	if (!(conf = ni_objectmodel_get_ppp_config(object, FALSE, error)))
		return FALSE;

	ni_dbus_dict_add_bool(result, "usepeerdns", conf->dns.usepeerdns);

	if (ni_sockaddr_is_specified(&conf->dns.dns1)) {
		if (!__ni_objectmodel_dict_add_sockaddr(result, "dns1", &conf->dns.dns1))
			return FALSE;
	}

	if (ni_sockaddr_is_specified(&conf->dns.dns2)) {
		if (!__ni_objectmodel_dict_add_sockaddr(result, "dns2", &conf->dns.dns2))
			return FALSE;
	}

	return TRUE;
}

static dbus_bool_t
ni_objectmodel_ppp_config_set_dns(ni_dbus_object_t *object, const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_ppp_config_t *conf;
	dbus_bool_t b;

	if (!ni_dbus_variant_is_dict(argument))
		return FALSE;

	if (!(conf = ni_objectmodel_get_ppp_config(object, TRUE, error)))
		return FALSE;

	if (ni_dbus_dict_get_bool(argument, "usepeerdns", &b))
		conf->dns.usepeerdns = b;

	__ni_objectmodel_dict_get_sockaddr(argument, "dns1", &conf->dns.dns1);
	__ni_objectmodel_dict_get_sockaddr(argument, "dns2", &conf->dns.dns2);

#if 0	/* limitted to IPv4? */
	if (conf->dns.dns1.ss_family != AF_UNSPEC && conf->dns.dns1.ss_family != AF_INET)
		return FALSE;
	if (conf->dns.dns2.ss_family != AF_UNSPEC && conf->dns.dns2.ss_family != AF_INET)
		return FALSE;
#endif
	return TRUE;
}

static dbus_bool_t
ni_objectmodel_ppp_config_get_ipv4(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
				ni_dbus_variant_t *result, DBusError *error)
{
	const ni_ppp_config_t *conf;
	ni_dbus_variant_t *ipcp;

	if (!(conf = ni_objectmodel_get_ppp_config(object, FALSE, error)))
		return FALSE;

	if (ni_sockaddr_is_specified(&conf->ipv4.local_ip)) {
		if (!__ni_objectmodel_dict_add_sockaddr(result, "local-ip", &conf->ipv4.local_ip))
			return FALSE;
	}

	if (ni_sockaddr_is_specified(&conf->ipv4.remote_ip)) {
		if (!__ni_objectmodel_dict_add_sockaddr(result, "remote-ip", &conf->ipv4.remote_ip))
			return FALSE;
	}

	if (!(ipcp = ni_dbus_dict_add(result, "ipcp")))
		return FALSE;

	ni_dbus_variant_init_dict(ipcp);
	ni_dbus_dict_add_bool(ipcp, "accept-local", conf->ipv4.ipcp.accept_local);
	ni_dbus_dict_add_bool(ipcp, "accept-remote", conf->ipv4.ipcp.accept_remote);

	return TRUE;
}

static dbus_bool_t
ni_objectmodel_ppp_config_set_ipv4(ni_dbus_object_t *object, const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument, DBusError *error)
{
	const ni_dbus_variant_t *ipcp;
	ni_ppp_config_t *conf;
	dbus_bool_t b;

	if (!ni_dbus_variant_is_dict(argument))
		return FALSE;

	if (!(conf = ni_objectmodel_get_ppp_config(object, TRUE, error)))
		return FALSE;

	__ni_objectmodel_dict_get_sockaddr(argument, "local-ip", &conf->ipv4.local_ip);
	if (conf->ipv4.local_ip.ss_family != AF_UNSPEC &&
	    conf->ipv4.local_ip.ss_family != AF_INET)
		return FALSE;
	__ni_objectmodel_dict_get_sockaddr(argument, "remote-ip", &conf->ipv4.remote_ip);
	if (conf->ipv4.remote_ip.ss_family != AF_UNSPEC &&
	    conf->ipv4.remote_ip.ss_family != AF_INET)
		return FALSE;

	if (!(ipcp = ni_dbus_dict_get(argument, "ipcp")))
		return TRUE;
	if (!ni_dbus_variant_is_dict(ipcp))
		return FALSE;

	if (ni_dbus_dict_get_bool(ipcp, "accept-local", &b))
		conf->ipv4.ipcp.accept_local = b;
	if (ni_dbus_dict_get_bool(ipcp, "accept-remote", &b))
		conf->ipv4.ipcp.accept_remote = b;

	return TRUE;
}

static dbus_bool_t
ni_objectmodel_ppp_config_get_ipv6(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
				ni_dbus_variant_t *result, DBusError *error)
{
	const ni_ppp_config_t *conf;
	ni_dbus_variant_t *ipcp;

	if (!(conf = ni_objectmodel_get_ppp_config(object, FALSE, error)))
		return FALSE;

	ni_dbus_dict_add_bool(result, "enabled", conf->ipv6.enabled);
	if (!conf->ipv6.enabled)
		return TRUE;

	if (ni_sockaddr_is_specified(&conf->ipv6.local_ip)) {
		if (!__ni_objectmodel_dict_add_sockaddr(result, "local-ip", &conf->ipv6.local_ip))
			return FALSE;
	}

	if (ni_sockaddr_is_specified(&conf->ipv6.remote_ip)) {
		if (!__ni_objectmodel_dict_add_sockaddr(result, "remote-ip", &conf->ipv6.remote_ip))
			return FALSE;
	}

	if (!(ipcp = ni_dbus_dict_add(result, "ipcp")))
		return FALSE;

	ni_dbus_variant_init_dict(ipcp);
	ni_dbus_dict_add_bool(ipcp, "accept-local", conf->ipv6.ipcp.accept_local);

	return TRUE;
}

static dbus_bool_t
ni_objectmodel_ppp_config_set_ipv6(ni_dbus_object_t *object, const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument, DBusError *error)
{
	const ni_dbus_variant_t *ipcp;
	ni_ppp_config_t *conf;
	dbus_bool_t b;

	if (!ni_dbus_variant_is_dict(argument))
		return FALSE;

	if (!(conf = ni_objectmodel_get_ppp_config(object, TRUE, error)))
		return FALSE;

	if (ni_dbus_dict_get_bool(argument, "enabled", &b))
		conf->ipv6.enabled = b;

	if (!conf->ipv6.enabled)
		return TRUE;

	__ni_objectmodel_dict_get_sockaddr(argument, "local-ip", &conf->ipv6.local_ip);
	if (conf->ipv6.local_ip.ss_family != AF_UNSPEC &&
	    conf->ipv6.local_ip.ss_family != AF_INET6)
		return FALSE;

	__ni_objectmodel_dict_get_sockaddr(argument, "remote-ip", &conf->ipv6.remote_ip);
	if (conf->ipv6.remote_ip.ss_family != AF_UNSPEC &&
	    conf->ipv6.remote_ip.ss_family != AF_INET6)
		return FALSE;

	if (!(ipcp = ni_dbus_dict_get(argument, "ipcp")))
		return TRUE;
	if (!ni_dbus_variant_is_dict(ipcp))
		return FALSE;

	if (ni_dbus_dict_get_bool(ipcp, "accept-local", &b))
		conf->ipv6.ipcp.accept_local = b;

	return TRUE;
}

/* DICT and UINT macro permit to omit a value in get function  */
#define PPP_DICT_PROPERTY(fstem, dbus_name, member_name,rw) \
		___NI_DBUS_PROPERTY(NI_DBUS_DICT_SIGNATURE, dbus_name, \
			member_name, ni_objectmodel_##fstem, RO)
#define PPP_UINT_PROPERTY(fstem, dbus_name, member_name, rw) \
		___NI_DBUS_PROPERTY(DBUS_TYPE_UINT32_AS_STRING, dbus_name, \
			member_name, ni_objectmodel_##fstem, RO)
/* BOOL and STRING are using generic property set/get functions */
#define PPP_BOOL_PROPERTY(struct_name, dbus_name, member_name, rw) \
		NI_DBUS_GENERIC_BOOL_PROPERTY(struct_name, dbus_name, member_name, rw)
#define PPP_STRING_PROPERTY(struct_name, dbus_type, type, rw) \
		NI_DBUS_GENERIC_STRING_PROPERTY(struct_name, dbus_type, type, rw)

static const ni_dbus_property_t	ni_objectmodel_ppp_device_properties[] = {
	PPP_DICT_PROPERTY(ppp,		mode, mode, RO),
	PPP_BOOL_PROPERTY(ppp_config,	debug, debug, RO),
	PPP_BOOL_PROPERTY(ppp_config,	demand, demand, RO),
	PPP_BOOL_PROPERTY(ppp_config,	persist, persist, RO),
	PPP_UINT_PROPERTY(ppp_config,	idle, idle, RO),
	PPP_UINT_PROPERTY(ppp_config,	maxfail, maxfail, RO),
	PPP_UINT_PROPERTY(ppp_config,	holdoff, holdoff, RO),
	PPP_BOOL_PROPERTY(ppp_config,	multilink, multilink, RO),
	PPP_STRING_PROPERTY(ppp_config,	endpoint, endpoint, RO),
	PPP_BOOL_PROPERTY(ppp_config,	defaultroute, defaultroute, RO),
	PPP_DICT_PROPERTY(ppp_config,	dns, dns, RO),
	PPP_DICT_PROPERTY(ppp_config,	auth, auth, RO),
	PPP_DICT_PROPERTY(ppp_config,	ipv4, ipv4, RO),
	PPP_DICT_PROPERTY(ppp_config,	ipv6, ipv6, RO),
	{ NULL }
};

static ni_dbus_method_t		ni_objectmodel_ppp_device_methods[] = {
	{ "changeDevice",	"a{sv}",	ni_objectmodel_ppp_device_change   },
	{ "deleteDevice",	"",		ni_objectmodel_ppp_device_delete   },
	{ NULL }
};

static ni_dbus_method_t		ni_objectmodel_ppp_factory_methods[] = {
	{ "newDevice",		"sa{sv}",	ni_objectmodel_ppp_device_new },
	{ NULL }
};

ni_dbus_service_t		ni_objectmodel_ppp_service = {
	.name			= NI_OBJECTMODEL_PPP_INTERFACE,
	.methods		= ni_objectmodel_ppp_device_methods,
	.properties		= ni_objectmodel_ppp_device_properties,
};

ni_dbus_service_t		ni_objectmodel_ppp_factory_service = {
	.name			= NI_OBJECTMODEL_PPP_INTERFACE ".Factory",
	.methods		= ni_objectmodel_ppp_factory_methods,
};


