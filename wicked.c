/*
 * No REST for the wicked!
 *
 * This command line utility provides an interface to the network
 * configuration/information facilities.
 *
 * It uses a RESTful interface (even though it's a command line utility).
 * The idea is to make it easier to extend this to some smallish daemon
 * with a AF_LOCAL socket interface.
 *
 * Copyright (C) 2010-2011 Olaf Kirch <okir@suse.de>
 */
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <mcheck.h>
#include <stdlib.h>
#include <getopt.h>

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/wicked.h>
#include <wicked/addrconf.h>
#include <wicked/bonding.h>
#include <wicked/bridge.h>
#include <wicked/backend.h>
#include <wicked/xml.h>
#include <wicked/xpath.h>
#include <wicked/dbus.h>

enum {
	OPT_CONFIGFILE,
	OPT_DEBUG,
	OPT_DRYRUN,
	OPT_ROOTDIR,
	OPT_LINK_TIMEOUT,
	OPT_NOPROGMETER,
};

static struct option	options[] = {
	{ "config",		required_argument,	NULL,	OPT_CONFIGFILE },
	{ "dryrun",		no_argument,		NULL,	OPT_DRYRUN },
	{ "dry-run",		no_argument,		NULL,	OPT_DRYRUN },
	{ "link-timeout",	required_argument,	NULL,	OPT_LINK_TIMEOUT },
	{ "no-progress-meter",	no_argument,		NULL,	OPT_NOPROGMETER },
	{ "debug",		required_argument,	NULL,	OPT_DEBUG },
	{ "root-directory",	required_argument,	NULL,	OPT_ROOTDIR },

	{ NULL }
};

static int		opt_dryrun = 0;
static char *		opt_rootdir = NULL;
static unsigned int	opt_link_timeout = 10;
static int		opt_progressmeter = 1;
static int		opt_shutdown_parents = 1;

static int		do_create(int, char **);
static int		do_delete(int, char **);
static int		do_show(int, char **);
static int		do_addport(int, char **);
static int		do_delport(int, char **);
static int		do_ifup(int, char **);
static int		do_ifdown(int, char **);
static int		do_xpath(int, char **);

int
main(int argc, char **argv)
{
	char *cmd;
	int c;

	mtrace();
	while ((c = getopt_long(argc, argv, "+", options, NULL)) != EOF) {
		switch (c) {
		default:
		usage:
			fprintf(stderr,
				"./wicked [options] cmd path\n"
				"This command understands the following options\n"
				"  --config filename\n"
				"        Use alternative configuration file.\n"
				"  --dry-run\n"
				"        Do not change the system in any way.\n"
				"  --debug facility\n"
				"        Enable debugging for debug <facility>.\n"
				"\n"
				"Supported commands:\n"
				"  create <iftype> [<property>=<value> <property>=<value> ...]\n"
				"  ifup [--boot] [--file xmlspec] ifname\n"
				"  ifdown [--delete] ifname\n"
				"  get /config/interface\n"
				"  get /config/interface/ifname\n"
				"  put /config/interface/ifname < cfg.xml\n"
				"  get /system/interface\n"
				"  get /system/interface/ifname\n"
				"  put /system/interface/ifname < cfg.xml\n"
				"  delete /config/interface/ifname\n"
				"  delete /system/interface/ifname\n"
				"  xpath [options] expr ...\n"
			       );
			return 1;

		case OPT_CONFIGFILE:
			ni_set_global_config_path(optarg);
			break;

		case OPT_DRYRUN:
			opt_dryrun = 1;
			break;

		case OPT_ROOTDIR:
			opt_rootdir = optarg;
			break;

		case OPT_LINK_TIMEOUT:
			if (ni_parse_int(optarg, &opt_link_timeout) < 0)
				ni_fatal("unable to parse link timeout value");
			break;

		case OPT_NOPROGMETER:
			opt_progressmeter = 0;
			break;

		case OPT_DEBUG:
			if (!strcmp(optarg, "help")) {
				printf("Supported debug facilities:\n");
				ni_debug_help(stdout);
				return 0;
			}
			if (ni_enable_debug(optarg) < 0) {
				fprintf(stderr, "Bad debug facility \"%s\"\n", optarg);
				return 1;
			}
			break;

		}
	}

	opt_shutdown_parents = 1; /* kill this */

	if (!isatty(1))
		opt_progressmeter = 0;

	if (ni_init() < 0)
		return 1;

	if (optind >= argc) {
		fprintf(stderr, "Missing command\n");
		goto usage;
	}

	cmd = argv[optind++];

	if (!strcmp(cmd, "create"))
		return do_create(argc - optind + 1, argv + optind - 1);

	if (!strcmp(cmd, "show"))
		return do_show(argc - optind + 1, argv + optind - 1);

	if (!strcmp(cmd, "delete"))
		return do_delete(argc - optind + 1, argv + optind - 1);

	if (!strcmp(cmd, "addport"))
		return do_addport(argc - optind + 1, argv + optind - 1);

	if (!strcmp(cmd, "delport"))
		return do_delport(argc - optind + 1, argv + optind - 1);

	if (!strcmp(cmd, "ifup"))
		return do_ifup(argc - optind + 1, argv + optind - 1);

	if (!strcmp(cmd, "ifdown"))
		return do_ifdown(argc - optind + 1, argv + optind - 1);

	/* Old wicked style functions follow */
	if (!strcmp(cmd, "xpath"))
		return do_xpath(argc - optind + 1, argv + optind - 1);

#if 0
	if (!strcmp(cmd, "get")
	 || !strcmp(cmd, "put")
	 || !strcmp(cmd, "post")
	 || !strcmp(cmd, "delete"))
		return do_rest(cmd, argc - optind + 1, argv + optind - 1);
#endif

	fprintf(stderr, "Unsupported command %s\n", cmd);
	goto usage;
}

static dbus_bool_t
wicked_proxy_interface_init_child(ni_dbus_object_t *object)
{
	ni_interface_t *ifp;

	ifp = ni_interface_new(NULL, object->name, 0);
	object->handle = ifp;

	return TRUE;
}

static ni_dbus_class_t		ni_objectmodel_proxy_iflist_class = {
	.name		= "proxy-interface-list",
	.init_child	= wicked_proxy_interface_init_child,
};

static ni_dbus_object_t *
wicked_dbus_client_create(void)
{
	ni_dbus_client_t *client;

	client = ni_dbus_client_open(WICKED_DBUS_BUS_NAME);
	if (!client)
		ni_fatal("Unable to connect to wicked dbus service");

	// ni_dbus_client_set_error_map(dbc, __wicked_error_names);

	return ni_dbus_client_object_new(client,
				&ni_dbus_anonymous_class,
				WICKED_DBUS_OBJECT_PATH,
				WICKED_DBUS_INTERFACE,
				NULL);
}

/*
 * Populate a property dict with parameters
 */
static dbus_bool_t
wicked_properties_from_argv(const ni_dbus_service_t *interface, ni_dbus_variant_t *dict, int argc, char **argv)
{
	int i;

	ni_dbus_variant_init_dict(dict);
	for (i = 0; i < argc; ++i) {
		const ni_dbus_property_t *property;
		ni_dbus_variant_t *var, *var_dict;
		char *property_name = argv[i];
		char *value;

		if ((value = strchr(property_name, '=')) == NULL) {
			ni_error("Cannot parse property \"%s\"", property_name);
			return FALSE;
		}
		*value++ = '\0';

		if (!strcmp(property_name, "name")) {
			ni_dbus_dict_add_string(dict, property_name, value);
			continue;
		}

		/* Using lookup_property will also resolve hierarchical names, such
		 * as foo.bar.baz (which is property baz within a dict named bar,
		 * which is part of dict foo). */
		if (!(property = ni_dbus_service_create_property(interface, property_name, dict, &var_dict))) {
			ni_error("Unsupported property \"%s\"", property_name);
			return FALSE;
		}

		var = ni_dbus_dict_add(var_dict, property->name);
		if (!ni_dbus_variant_init_signature(var, property->signature)) {
			ni_error("Unable to parse property %s=%s (bad type signature)",
					property_name, value);
			return FALSE;
		}

		if (property->parse) {
			if (!property->parse(property, var, value)) {
				ni_error("Unable to parse property %s=%s", property_name, value);
				return FALSE;
			}
		} else {
			/* FIXME: variant_parse should unquote string if needed */
			if (!ni_dbus_variant_parse(var, value, property->signature)) {
				ni_error("Unable to parse property %s=%s", property_name, value);
				return FALSE;
			}
		}
	}

	return TRUE;
}

/*
 * Create a virtual network interface
 */
static char *
wicked_create_interface_argv(ni_dbus_object_t *object, int iftype, int argc, char **argv)
{
	ni_dbus_variant_t call_argv[2], call_resp[1], *dict;
	const ni_dbus_service_t *service;
	DBusError error = DBUS_ERROR_INIT;
	char *result = NULL;

	memset(call_argv, 0, sizeof(call_argv));
	memset(call_resp, 0, sizeof(call_resp));

#ifdef broken
	service = ni_objectmodel_link_layer_service_by_type(iftype);
#else
	service = NULL;
#endif
	if (!service) {
		ni_error("Cannot create network interface for this link layer type");
		return NULL;
	}

	ni_dbus_variant_set_string(&call_argv[0], service->name);

	dict = &call_argv[1];
	ni_dbus_variant_init_dict(dict);
	if (!wicked_properties_from_argv(service, dict, argc, argv)) {
		ni_error("Error parsing properties");
		goto failed;
	}

	if (!ni_dbus_object_call_variant(object, NULL, "create",
				2, call_argv,
				1, call_resp,
				&error)) {
		ni_error("Server refused to create interface. Server responds:");
		fprintf(stderr, /* ni_error_extra */
			"%s: %s\n", error.name, error.message);
		goto failed;
	}

failed:
	ni_dbus_variant_destroy(&call_argv[0]);
	ni_dbus_variant_destroy(&call_argv[1]);
	dbus_error_free(&error);
	return result;
}

/*
 * Obtain an object handle for Wicked.Interface
 */
static ni_dbus_object_t *
wicked_get_interface_object(const char *default_interface)
{
	ni_dbus_object_t *root_object, *child;

	if (!(root_object = wicked_dbus_client_create()))
		return NULL;
	child = ni_dbus_object_create(root_object, "Interface",
			&ni_objectmodel_proxy_iflist_class,
			NULL);

	if (!default_interface)
		default_interface = WICKED_DBUS_INTERFACE ".Interface";
	ni_dbus_object_set_default_interface(child, default_interface);

	return child;
}

/*
 * Handle "create" command
 */
int
do_create(int argc, char **argv)
{
	ni_dbus_object_t *object;
	char *ifname;
	int iftype;

	if (argc < 2) {
		ni_error("wicked create: missing interface type");
		return 1;
	}

	iftype = ni_linktype_name_to_type(argv[1]);
	if (iftype < 0) {
		ni_error("wicked create: unknown link type %s", argv[1]);
		return 1;
	}

	if (!(object = wicked_get_interface_object(WICKED_DBUS_INTERFACE ".Factory")))
		return 1;

	ifname = wicked_create_interface_argv(object, iftype, argc - 2, argv + 2);
	if (!ifname)
		return 1;

	printf("%s\n", ifname);
	return 0;
}

static ni_dbus_object_t *
wicked_get_interface(ni_dbus_object_t *root_object, const char *ifname)
{
	static ni_dbus_object_t *interfaces = NULL;
	ni_dbus_object_t *object;

	if (interfaces == NULL) {
		if (!(interfaces = wicked_get_interface_object(NULL)))
			return NULL;

		/* Call ObjectManager.GetAllObjects to get list of objects and their properties */
		if (!ni_dbus_object_refresh_children(interfaces)) {
			ni_error("Couldn't get list of active network interfaces");
			return NULL;
		}
	}

	if (ifname == NULL)
		return interfaces;

	/* Loop over all interfaces and find the one with matching name */
	/* FIXME: this isn't type-safe at all, and should be done better */
	for (object = interfaces->children; object; object = object->next) {
		ni_interface_t *ifp = object->handle;

		if (!strcmp(ifp->name, ifname))
			return object;
	}

	ni_error("%s: unknown network interface", ifname);
	return NULL;
}

int
do_show(int argc, char **argv)
{
	ni_dbus_object_t *object;

	if (argc != 1 && argc != 2) {
		ni_error("wicked show: missing interface name");
		return 1;
	}

	if (!(object = wicked_dbus_client_create()))
		return 1;

	if (argc == 1) {
		object = wicked_get_interface(object, NULL);
		if (!object)
			return 1;

		for (object = object->children; object; object = object->next) {
			ni_interface_t *ifp = object->handle;
			char buffer[64];
			ni_address_t *ap;
			ni_route_t *rp;

			printf("%-12s %-10s %-10s",
					ifp->name,
					(ifp->link.ifflags & NI_IFF_NETWORK_UP)? "up" :
					 (ifp->link.ifflags & NI_IFF_LINK_UP)? "link-up" :
					  (ifp->link.ifflags & NI_IFF_DEVICE_UP)? "device-up" : "down",
					ni_linktype_type_to_name(ifp->link.type));
			printf("\n");

			for (ap = ifp->addrs; ap; ap = ap->next) {
				snprintf(buffer, sizeof(buffer), "%s addr:",
						ni_addrconf_type_to_name(ap->config_method));
				printf("  %-14s", buffer);
				printf(" %s/%u", ni_address_print(&ap->local_addr), ap->prefixlen);
				printf("\n");
			}
			for (rp = ifp->routes; rp; rp = rp->next) {
				const ni_route_nexthop_t *nh;

				snprintf(buffer, sizeof(buffer), "%s route:",
						ni_addrconf_type_to_name(rp->config_method));
				printf("  %-14s", buffer);

				if (rp->prefixlen)
					printf(" %s/%u", ni_address_print(&rp->destination), rp->prefixlen);
				else
					printf(" default");

				if (rp->nh.gateway.ss_family != AF_UNSPEC) {
					for (nh = &rp->nh; nh; nh = nh->next)
						printf("; via %s", ni_address_print(&nh->gateway));
				}

				printf(" [config=%s]", ni_addrconf_type_to_name(rp->config_method));
				printf("\n");
			}
		}
	} else {
		const char *ifname = argv[1];

		object = wicked_get_interface(object, ifname);
		if (!object)
			return 1;
	}

	return 0;
}

int
do_delete(int argc, char **argv)
{
	const ni_dbus_service_t *interface;
	ni_dbus_object_t *object;
	const char *ifname;

	if (argc != 2) {
		ni_error("wicked delete: missing interface name");
		return 1;
	}
	ifname = argv[1];

	if (!(object = wicked_dbus_client_create()))
		return 1;

	object = wicked_get_interface(object, ifname);
	if (!object)
		return 1;

	if (!(interface = ni_dbus_object_get_service_for_method(object, "delete"))) {
		ni_error("%s: interface does not support deletion", ifname);
		return 1;
	}

	if (ni_dbus_object_call_simple(object,
				interface->name, "delete",
				DBUS_TYPE_INVALID, NULL, DBUS_TYPE_INVALID, NULL) < 0) {
		ni_error("DBus delete call failed");
		return 1;
	}

	ni_debug_dbus("successfully deleted %s", ifname);
	return 0;
}

/*
 * Add a port to a bridge or bond
 */
int
do_addport(int argc, char **argv)
{
	const ni_dbus_service_t *interface;
	ni_dbus_variant_t argument[2], result;
	ni_dbus_object_t *root_object, *bridge, *port;
	const char *bridge_name, *port_name;
	DBusError error = DBUS_ERROR_INIT;
	int rv = 1;

	memset(argument, 0, sizeof(argument));
	memset(&result, 0, sizeof(result));

	if (argc < 3) {
		ni_error("wicked addport: usage: bridge-if port-if [options]");
		return 1;
	}

	bridge_name = argv[1];
	port_name = argv[2];

	if (!(root_object = wicked_dbus_client_create()))
		return 1;

	if (!(bridge = wicked_get_interface(root_object, bridge_name))
	 || !(port = wicked_get_interface(root_object, port_name)))
		return 1;

	if (!(interface = ni_dbus_object_get_service_for_method(bridge, "addPort"))) {
		ni_error("%s: interface does not support adding ports", bridge_name);
		return 1;
	}
 
	ni_dbus_variant_set_string(&argument[0], port->path);

	ni_dbus_variant_init_dict(&argument[1]);
	if (argc == 3) {
		/* No properties, nothing to be done */
	} else {
		ni_interface_t *bridge_if = bridge->handle;
		const ni_dbus_service_t *port_interface;

		/* The "interface" for the ports is usually just a dummy type of
		 * interface; needed only to get the dbus types of all properties
		 */
		port_interface = ni_objectmodel_interface_port_service(bridge_if->link.type);
		if (port_interface == NULL) {
			ni_error("%s: no port properties for this interface type", bridge_name);
			goto out;
		}

		if (!wicked_properties_from_argv(port_interface, &argument[1], argc - 3, argv + 3)) {
			ni_error("Error parsing properties");
			goto out;
		}
	}

	if (!ni_dbus_object_call_variant(bridge, interface->name, "addPort",
				2, argument, 1, &result, &error)) {
		ni_error("Server refused to add port. Server responds:");
		fprintf(stderr, /* ni_error_extra */
			"%s: %s\n", error.name, error.message);
		goto out;
	}

	ni_debug_wicked("successfully added port %s to %s", port_name, bridge_name);
	rv = 0;

out:
	ni_dbus_variant_destroy(&argument[0]);
	ni_dbus_variant_destroy(&argument[1]);
	ni_dbus_variant_destroy(&result);
	dbus_error_free(&error);
	return rv;
}

/*
 * Remove a port from a bridge or bond
 */
int
do_delport(int argc, char **argv)
{
	const ni_dbus_service_t *interface;
	ni_dbus_variant_t argument, result;
	ni_dbus_object_t *root_object, *bridge, *port;
	const char *bridge_name, *port_name;
	DBusError error = DBUS_ERROR_INIT;
	int rv = 1;

	memset(&argument, 0, sizeof(argument));
	memset(&result, 0, sizeof(result));

	if (argc != 3) {
		ni_error("wicked delport: usage: bridge-if port-if");
		return 1;
	}

	bridge_name = argv[1];
	port_name = argv[2];

	if (!(root_object = wicked_dbus_client_create()))
		return 1;

	if (!(bridge = wicked_get_interface(root_object, bridge_name))
	 || !(port = wicked_get_interface(root_object, port_name)))
		return 1;

	if (!(interface = ni_dbus_object_get_service_for_method(bridge, "removePort"))) {
		ni_error("%s: interface does not support removing ports", bridge_name);
		return 1;
	}
 
	ni_dbus_variant_set_string(&argument, port->path);
	if (!ni_dbus_object_call_variant(bridge, interface->name, "removePort",
				1, &argument, 1, &result, &error)) {
		ni_error("Server refused to add port. Server responds:");
		fprintf(stderr, /* ni_error_extra */
			"%s: %s\n", error.name, error.message);
		goto out;
	}

	ni_debug_wicked("successfully removed port %s to %s", port_name, bridge_name);
	rv = 0;

out:
	ni_dbus_variant_destroy(&argument);
	ni_dbus_variant_destroy(&result);
	dbus_error_free(&error);
	return rv;
}

/*
 * Helper function that will go away when done with the redesign of wicked
 */
static ni_afinfo_t *
__build_afinfo(ni_afinfo_t *dev_afi, int family, ni_interface_t *ifp)
{
	ni_afinfo_t *afi;
	unsigned int i;

	if (!dev_afi->enabled)
		return NULL;

	afi = ni_afinfo_new(family);
	afi->forwarding = dev_afi->forwarding;
	afi->addrconf = dev_afi->addrconf;

	for (i = 0; i < __NI_ADDRCONF_MAX; ++i) {
		afi->request[i] = dev_afi->request[i];
		dev_afi->request[i] = NULL;
	}

	if (ni_afinfo_addrconf_test(dev_afi, NI_ADDRCONF_STATIC)) {
		ni_addrconf_request_t *req;
		ni_address_t **apos, **atail, *ap;
		ni_route_t **rpos, **rtail, *rp;

		req = ni_addrconf_request_new(NI_ADDRCONF_STATIC, family);
		afi->request[NI_ADDRCONF_STATIC] = req;

		atail = &req->statik.addrs;
		for (apos = &ifp->addrs; (ap = *apos) != NULL; ) {
			if (ap->family == family) {
				*apos = ap->next;
				*atail = ap;
				atail = &ap->next;
			} else {
				apos = &ap->next;
			}
		}
		*atail = NULL;

		rtail = &req->statik.routes;
		for (rpos = &ifp->routes; (rp = *rpos) != NULL; ) {
			if (rp->family == family) {
				*rpos = rp->next;
				*rtail = rp;
				rtail = &rp->next;
			} else {
				rpos = &rp->next;
			}
		}
		*rtail = NULL;
	}

	return afi;
}

static ni_interface_request_t *
__interface_request_build(ni_interface_t *ifp)
{
	ni_interface_request_t *req;

	req = ni_interface_request_new();
	req->ifflags = ifp->link.ifflags;
	req->mtu = ifp->link.mtu;
	req->metric = ifp->link.metric;
	req->txqlen = ifp->link.txqlen;

	if (ifp->ipv4.enabled)
		req->ipv4 = __build_afinfo(&ifp->ipv4, AF_INET, ifp);
	if (ifp->ipv6.enabled)
		req->ipv6 = __build_afinfo(&ifp->ipv6, AF_INET6, ifp);

	return req;
}

static int
do_ifup(int argc, char **argv)
{
	enum  { OPT_SYSCONFIG, OPT_NETCF, OPT_FILE, OPT_BOOT };
	static struct option ifup_options[] = {
		{ "file", required_argument, NULL, OPT_FILE },
		{ "boot", no_argument, NULL, OPT_BOOT },
		{ NULL }
	};
	ni_dbus_variant_t argument = NI_DBUS_VARIANT_INIT;
	DBusError error = DBUS_ERROR_INIT;
	const char *ifname = NULL;
	const char *opt_file = NULL;
	ni_dbus_object_t *root_object, *dev_object;
	unsigned int ifevent = NI_IFACTION_MANUAL_UP;
	ni_interface_t *config_dev;
	int c, rv = 1;

	optind = 1;
	while ((c = getopt_long(argc, argv, "", ifup_options, NULL)) != EOF) {
		switch (c) {
		case OPT_FILE:
			opt_file = optarg;
			break;

		case OPT_BOOT:
			ifevent = NI_IFACTION_BOOT;
			break;

		default:
usage:
			fprintf(stderr,
				"wicked [options] ifup [ifup-options] all\n"
				"wicked [options] ifup [ifup-options] <ifname> [options ...]\n"
				"\nSupported ifup-options:\n"
				"  --file <filename>\n"
				"      Read interface configuration(s) from file rather than using system config\n"
				"  --boot\n"
				"      Ignore interfaces with startmode != boot\n"
				);
			return 1;
		}
	}

	if (optind + 1 != argc) {
		fprintf(stderr, "Missing interface argument\n");
		goto usage;
	}
	ifname = argv[optind++];

	if (!strcmp(ifname, "boot")) {
		ifevent = NI_IFACTION_BOOT;
		ifname = "all";
	}

	ni_dbus_variant_init_dict(&argument);
	if (opt_file) {
		ni_dbus_object_t *request_object;
		ni_interface_request_t *req;
		ni_netconfig_t *nc;

		nc = ni_netconfig_new();
		if (ni_netcf_parse_file(opt_file, nc) < 0) {
			ni_error("unable to load interface definition from %s", opt_file);
			ni_netconfig_free(nc);
			goto failed;
		}

		if (!(config_dev = ni_interface_by_name(nc, ifname))) {
			ni_error("cannot find interface %s in interface description", ifname);
			ni_netconfig_free(nc);
			goto failed;
		}

		/* Request that the server take the interface up */
		config_dev->link.ifflags = NI_IFF_NETWORK_UP | NI_IFF_LINK_UP | NI_IFF_DEVICE_UP;

		req = __interface_request_build(config_dev);

		request_object = ni_objectmodel_wrap_interface_request(req);
		if (!ni_dbus_object_get_properties_as_dict(request_object, &wicked_dbus_interface_request_service, &argument)) {
			ni_interface_request_free(req);
			ni_dbus_object_free(request_object);
			ni_netconfig_free(nc);
			goto failed;
		}

		ni_interface_request_free(req);
		ni_dbus_object_free(request_object);
		ni_netconfig_free(nc);

		if (config_dev->startmode.ifaction[ifevent].action == NI_INTERFACE_IGNORE) {
			ni_error("not permitted to bring up interface");
			goto failed;
		}
	} else {
		/* No options, just bring up with default options
		 * (which may include dhcp) */
	}

	if (!(root_object = wicked_dbus_client_create()))
		goto failed;

	if (!(dev_object = wicked_get_interface(root_object, ifname)))
		goto failed;

	/* now do the real dbus call to bring it up */
	if (!ni_dbus_object_call_variant(dev_object,
				WICKED_DBUS_NETIF_INTERFACE, "up",
				1, &argument, 0, NULL, &error)) {
		ni_error("Unable to configure interface. Server responds:");
		fprintf(stderr, /* ni_error_extra */
			"%s: %s\n", error.name, error.message);
		dbus_error_free(&error);
		goto failed;
	}

	rv = 0;

	// then wait for a signal from the server to tell us it's actually up

	ni_debug_wicked("successfully configured %s", ifname);
	rv = 0; /* success */

failed:
	if (config_dev)
		ni_interface_put(config_dev);
	ni_dbus_variant_destroy(&argument);
	return rv;
}

static int
do_ifdown(int argc, char **argv)
{
	ni_dbus_variant_t argument = NI_DBUS_VARIANT_INIT;
	DBusError error = DBUS_ERROR_INIT;
	ni_dbus_object_t *root_object, *dev_object;
	int rv = 1;

	if (argc == 1) {
		fprintf(stderr, "wicked ifdown ifname ...\n");
		return 1;
	}

	if (!(root_object = wicked_dbus_client_create()))
		return 1;

	/* All interfaces get the same interface request, which is
	 * ifflags = 0, and empty addrconfig. */
	if (0) {
		ni_dbus_object_t *request_object;
		ni_interface_request_t *req;
		dbus_bool_t okay;

		req = ni_interface_request_new();
		req->ifflags = 0;

		request_object = ni_objectmodel_wrap_interface_request(req);

		ni_dbus_variant_init_dict(&argument);
		okay = ni_dbus_object_get_properties_as_dict(request_object,
				&wicked_dbus_interface_request_service, &argument);

		ni_dbus_object_free(request_object);
		ni_interface_request_free(req);

		if (!okay)
			goto failed;
	}

	for (optind = 1; optind < argc; ++optind) {
		const char *ifname = argv[optind];

		dev_object = wicked_get_interface(root_object, ifname);
		if (!dev_object)
			goto failed;

		/* now do the real dbus call to bring it down */
		if (!ni_dbus_object_call_variant(dev_object,
					WICKED_DBUS_NETIF_INTERFACE, "down",
					0, NULL, 0, NULL, &error)) {
			ni_error("Unable to configure interface. Server responds:");
			fprintf(stderr, /* ni_error_extra */
				"%s: %s\n", error.name, error.message);
			dbus_error_free(&error);
			goto failed;
		}

		ni_debug_wicked("successfully shut down %s", ifname);
	}

	rv = 0;

	// then wait for a signal from the server to tell us it's actually down

	rv = 0; /* success */

failed:
	ni_dbus_variant_destroy(&argument);
	return rv;
}

#if 0
static int
__wicked_request(int rest_op, const char *path,
		/* const */ xml_node_t *send_xml,
		xml_node_t **recv_xml)
{
	ni_wicked_request_t req;
	int rv;

	if (opt_dryrun && rest_op != NI_REST_OP_GET) {
		printf("Would send request %s %s\n",
				ni_wicked_rest_op_print(rest_op), path);
		if (send_xml)
			xml_node_print(send_xml, stdout);
		return 0;
	}

	ni_wicked_request_init(&req);
	req.cmd = rest_op;
	req.path = strdup(path);
	req.xml_in = send_xml;

	if (opt_rootdir)
		ni_wicked_request_add_option(&req, "Root", opt_rootdir);

	rv = ni_wicked_call_indirect(&req);
	if (rv < 0) {
		ni_error("%s", req.error_msg);
	} else if (recv_xml) {
		*recv_xml = req.xml_out;
		req.xml_out = NULL;
	}

	ni_wicked_request_destroy(&req);
	return rv;
}
#endif

#if 0
enum {
	STATE_UNKNOWN = 0,
	STATE_DEVICE_DOWN,
	STATE_DEVICE_UP,
	STATE_LINK_UP,
	STATE_NETWORK_UP,
};

/*
 * Interface state information
 */
typedef struct ni_interface_state ni_interface_state_t;

typedef struct ni_interface_state_array {
	unsigned int		count;
	ni_interface_state_t **	data;
} ni_interface_state_array_t;

typedef struct ni_interface_op {
	const char *		name;
	int			(*call)(ni_interface_state_t *, ni_netconfig_t *);
	int			(*check)(ni_interface_state_t *, ni_netconfig_t *, unsigned int);
	int			(*timeout)(ni_interface_state_t *);
} ni_interface_op_t;

struct ni_interface_state {
	unsigned int		refcount;

	int			state;
	char *			ifname;
	ni_interface_t *	config;
	unsigned int		done      : 1,
				is_slave  : 1,
				is_policy : 1,
				waiting   : 1,
				called    : 1;
	int			result;

	int			have_state;
	unsigned int		timeout;
	ni_ifaction_t		behavior;

	const ni_interface_op_t	*fsm;

	ni_interface_state_t *	parent;
	ni_interface_state_array_t children;
};

static ni_interface_state_t *ni_interface_state_array_find(ni_interface_state_array_t *, const char *);
static void	ni_interface_state_array_append(ni_interface_state_array_t *, ni_interface_state_t *);
static void	ni_interface_state_array_destroy(ni_interface_state_array_t *);

static ni_intmap_t __state_names[] = {
	{ "unknown",		STATE_UNKNOWN		},
	{ "device-down",	STATE_DEVICE_DOWN	},
	{ "device-up",		STATE_DEVICE_UP		},
	{ "link-up",		STATE_LINK_UP		},
	{ "network-up",		STATE_NETWORK_UP	},

	{ NULL }
};

static const char *
ni_interface_state_name(int state)
{
	return ni_format_int_mapped(state, __state_names);
}

static ni_interface_state_t *
ni_interface_state_new(const char *name, ni_interface_t *dev)
{
	ni_interface_state_t *state;

	state = calloc(1, sizeof(*state));
	ni_string_dup(&state->ifname, name);
	if (dev)
		state->config = ni_interface_get(dev);
	return state;
}

static ni_interface_state_t *
ni_interface_state_add_child(ni_interface_state_t *parent, const char *slave_name, ni_interface_t *slave_dev)
{
	ni_interface_state_t *slave_state;

	if ((slave_state = ni_interface_state_array_find(&parent->children, slave_name)) == NULL) {
		slave_state = ni_interface_state_new(slave_name, slave_dev);
		ni_interface_state_array_append(&parent->children, slave_state);
	}

	if (parent->behavior.mandatory)
		slave_state->behavior.mandatory = 1;
	slave_state->is_slave = 1;

	return slave_state;
}

static void
ni_interface_state_free(ni_interface_state_t *state)
{
	ni_string_free(&state->ifname);
	if (state->config)
		ni_interface_put(state->config);
	ni_interface_state_array_destroy(&state->children);
}

static inline void
ni_interface_state_release(ni_interface_state_t *state)
{
	if (--(state->refcount) == 0)
		ni_interface_state_free(state);
}

static void
ni_interface_state_array_append(ni_interface_state_array_t *array, ni_interface_state_t *state)
{
	array->data = realloc(array->data, (array->count + 1) * sizeof(array->data[0]));
	array->data[array->count++] = state;
	state->refcount++;
}

static ni_interface_state_t *
ni_interface_state_array_find(ni_interface_state_array_t *array, const char *ifname)
{
	unsigned int i;

	for (i = 0; i < array->count; ++i) {
		ni_interface_state_t *state = array->data[i];

		if (!strcmp(state->ifname, ifname))
			return state;
	}
	return NULL;
}

static void
ni_interface_state_array_destroy(ni_interface_state_array_t *array)
{
	while (array->count)
		ni_interface_state_release(array->data[--(array->count)]);
	free(array->data);
	array->data = NULL;
}

static int
get_managed_interfaces(ni_netconfig_t *config, int filter, ni_evaction_t ifaction, ni_interface_state_array_t *result)
{
	ni_interface_t *pos = NULL, *ifp;

	for (ifp = ni_interface_first(config, &pos); ifp; ifp = ni_interface_next(config, &pos)) {
		const ni_ifaction_t *ifa = &ifp->startmode.ifaction[filter];
		ni_interface_state_t *state;

		if (ifa->action != ifaction)
			continue;

		state = ni_interface_state_new(ifp->name, ifp);
		state->behavior = *ifa;

		ni_interface_state_array_append(result, state);
	}

	return 0;
}

static int
interface_topology_build(ni_netconfig_t *config, ni_interface_state_array_t *state_array)
{
	unsigned int i;

	for (i = 0; i < state_array->count; ++i) {
		ni_interface_state_t *master_state = state_array->data[i];
		ni_interface_state_t *slave_state;
		ni_interface_t *master, *slave;
		const char *slave_name;
		ni_bonding_t *bond;
		ni_bridge_t *bridge;
		ni_vlan_t *vlan;
		unsigned int i;

		if ((master = master_state->config) == NULL)
			continue;

		switch (master->link.type) {
		case NI_IFTYPE_VLAN:
			if ((vlan = master->link.vlan) == NULL)
				continue;

			slave_name = vlan->physdev_name;

			slave = ni_interface_by_name(config, slave_name);
			if (slave != NULL) {
				/* VLANs are special, real device must be an ether device,
				 * and can be referenced by more than one vlan */
				if (slave->link.type != NI_IFTYPE_ETHERNET) {
					ni_error("vlan interface %s references non-ethernet device", master->name);
					goto failed;
				}
			}

			slave_state = ni_interface_state_add_child(master_state, slave_name, slave);
			if (slave_state->parent)
				goto multiple_masters;
			break;

		case NI_IFTYPE_BOND:
			if ((bond = master->bonding) == NULL)
				continue;

			for (i = 0; i < bond->slave_names.count; ++i) {
				slave_name = bond->slave_names.data[i];

				slave = ni_interface_by_name(config, slave_name);

				slave_state = ni_interface_state_add_child(master_state, slave_name, slave);
				if (slave_state->parent)
					goto multiple_masters;
				slave_state->parent = master_state;
			}
			break;

		case NI_IFTYPE_BRIDGE:
			if ((bridge = master->bridge) == NULL)
				continue;

			for (i = 0; i < bridge->ports.count; ++i) {
				ni_bridge_port_t *port = bridge->ports.data[i];

				slave = ni_interface_by_name(config, port->name);

				slave_state = ni_interface_state_add_child(master_state, port->name, slave);
				if (slave_state->parent)
					goto multiple_masters;
				slave_state->parent = master_state;
			}
			break;

		default:
			break;

		multiple_masters:
			ni_error("interface %s used by more than one device (%s and %s)",
					slave_state->ifname, master_state->ifname,
					slave_state->parent->ifname);
		failed:
			return -1;
		}

		if (master_state->children.count
		 && interface_topology_build(config, &master_state->children) < 0)
			return -1;
	}

	return 0;
}

/*
 * Check whether we have all requested leases
 */
static int
ni_interface_network_is_up_afinfo(const char *ifname, const ni_afinfo_t *cfg_afi, const ni_afinfo_t *cur_afi)
{
	unsigned int type;

	for (type = 0; type < __NI_ADDRCONF_MAX; ++type) {
		if (type == NI_ADDRCONF_STATIC || !ni_afinfo_addrconf_test(cfg_afi, type))
			continue;
		if (!ni_afinfo_addrconf_test(cur_afi, type)) {
			ni_debug_wicked("%s: addrconf mode %s/%s not enabled", ifname,
					ni_addrfamily_type_to_name(cfg_afi->family),
					ni_addrconf_type_to_name(type));
			return 0;
		}
		if (!ni_addrconf_lease_is_valid(cur_afi->lease[type])) {
			ni_debug_wicked("%s: addrconf mode %s/%s enabled; no lease yet", ifname,
					ni_addrfamily_type_to_name(cfg_afi->family),
					ni_addrconf_type_to_name(type));
			return 0;
		}
	}

	return 1;
}

static void
interface_update(ni_interface_state_t *state, ni_netconfig_t *system)
{
	const ni_interface_t *have, *want = state->config;
	int new_state = STATE_UNKNOWN;

	/* Interface may not be present yet (eg for bridge or bond interfaces) */
	if ((have = ni_interface_by_name(system, state->ifname)) == NULL)
		goto out;

	new_state = STATE_DEVICE_DOWN;
	if (!(have->link.ifflags & NI_IFF_DEVICE_UP))
		goto out;

	if (want != NULL) {
		/* FIXME: here we should check the ethernet/link/bond/bridge
		 * composition. */
	}

	new_state = STATE_DEVICE_UP;
	if (!(have->link.ifflags & NI_IFF_LINK_UP))
		goto out;

	new_state = STATE_LINK_UP;
	if (!(have->link.ifflags & NI_IFF_NETWORK_UP))
		goto out;

	if (want != NULL) {
		if (!ni_interface_network_is_up_afinfo(want->name, &want->ipv4, &have->ipv4)
		 || !ni_interface_network_is_up_afinfo(want->name, &want->ipv6, &have->ipv6))
			goto out;
	}

	new_state = STATE_NETWORK_UP;

out:
	if (state->have_state != new_state)
		ni_debug_wicked("%s: state changed from %s to %s, fsm=%s%s",
				state->ifname,
				ni_interface_state_name(state->have_state),
				ni_interface_state_name(new_state),
				state->fsm->name,
				state->waiting? ", waiting": "");
	else
		ni_debug_wicked("%s: state is current=%s, fsm=%s%s", state->ifname,
				ni_interface_state_name(state->have_state),
				state->fsm->name,
				state->waiting? ", waiting": "");

	state->have_state = new_state;
}

static int
interface_request_state(ni_interface_state_t *state, ni_netconfig_t *system, ni_interface_t *ifp,
			int next_state, unsigned int timeout)
{
	unsigned int ifflags;

	switch (next_state) {
	case STATE_DEVICE_DOWN:
		ni_debug_wicked("%s: trying to shut down device", state->ifname);
		ifflags = 0;
		break;

	case STATE_DEVICE_UP:
		ni_debug_wicked("%s: trying to bring device up", state->ifname);
		ifflags = NI_IFF_DEVICE_UP;
		break;

	case STATE_LINK_UP:
		ni_debug_wicked("%s: trying to bring link up", state->ifname);
		ifflags = NI_IFF_DEVICE_UP | NI_IFF_LINK_UP;
		break;

	case STATE_NETWORK_UP:
		ni_debug_wicked("%s: trying to bring network up", state->ifname);
		ifflags = NI_IFF_DEVICE_UP | NI_IFF_LINK_UP | NI_IFF_NETWORK_UP;
		break;

	default:
		ni_error("%s: bad next_state=%s", state->ifname,
				ni_interface_state_name(next_state));
		return -1;
	}

	if (ifp == NULL) {
		ni_error("%s: unknown device", state->ifname);
		return -1;
	}

	ifp->link.ifflags &= ~(NI_IFF_DEVICE_UP | NI_IFF_LINK_UP | NI_IFF_NETWORK_UP);
	ifp->link.ifflags |= ifflags;

	if (ni_interface_configure(system, ifp) < 0) {
		ni_error("%s: unable to configure", ifp->name);
		return -1;
	}

	state->timeout = timeout;
	if (state->timeout == 0)
		state->timeout = 10;
	state->waiting = 1;

	return 0;
}

#ifdef disabled
static int
send_policy(ni_interface_state_t *state, ni_netconfig_t *system, ni_interface_t *ifp)
{
	ni_policy_t policy;

	memset(&policy, 0, sizeof(policy));
	policy.event = NI_EVENT_LINK_UP;
	policy.interface = ifp;
	return ni_policy_update(system, &policy);
}
#endif

static int
interface_failed(ni_interface_state_t *state, const char *how)
{
	printf("%s: %s\n", state->ifname, how?: "failed");
	state->result = -1;
	state->done = 1;
	return -1;
}

static int
__fsm_next(ni_interface_state_t *state)
{
	if (state->fsm == NULL)
		return interface_failed(state, "FSM bug");

	state->waiting = 0;
	state->called = 0;
	state->fsm++;
	if (state->fsm->call == NULL && state->fsm->check == NULL) {
		printf("%s: %s\n", state->ifname, ni_interface_state_name(state->have_state));
		ni_debug_wicked("%s: reached FSM final state", state->ifname);
		state->result = 0;
		state->done = 1;
	} else {
		ni_debug_wicked("%s: enter FSM state %s", state->ifname, state->fsm->name);
	}

	return 0;
}

static int
__interface_check_timeout(ni_interface_state_t *state, unsigned int waited)
{
	if (waited > state->timeout) {
		ni_debug_wicked("%s: TIMEOUT: state is current=%s, fsm=%s%s", state->ifname,
				ni_interface_state_name(state->have_state),
				state->fsm->name,
				state->behavior.only_if_link? " (only-if-link)" : "");

		if (state->fsm->timeout)
			return state->fsm->timeout(state);

		interface_failed(state, "timed out");
		if (state->behavior.mandatory)
			return -1;
	}

	return 0;
}

static inline int
__fsm_interface_check(ni_interface_state_t *state, ni_netconfig_t *system, unsigned int waited)
{
	int rv = 1;

	/* During ifdown, not all interface have an FSM associated with them. */
	if (state->fsm == NULL) {
		state->done = 1;
		return 0;
	}

	while (1) {
		if (state->done)
			return state->result;

		if (state->fsm->name == NULL)
			return interface_failed(state, "BUG: ran past end of FSM state array");

		if (!state->called && state->fsm->call) {
			rv = state->fsm->call(state, system);

			ni_debug_wicked("%s: called %s() = %d", state->ifname, state->fsm->name, rv);
			if (rv < 0)
				break;

			state->called = 1;
		}

		if (state->waiting && __interface_check_timeout(state, waited) < 0)
			return -1;

		if (state->fsm->check != NULL) {
			/* Check whether we're done. Negative return value
			 * means error, 0 means we're still waiting to proceed,
			 * and positive means we moved to the next FSM state,
			 * and should retry.
			 */
			rv = state->fsm->check(state, system, waited);
			if (rv <= 0)
				break;
		} else {
			rv = __fsm_next(state);
			if (rv < 0)
				break;
		}
	}
	return rv;
}

static int
__fsm_children_check(ni_interface_state_t *state, ni_netconfig_t *system, unsigned int waited)
{
	int child_failed = 0, all_done = 1;
	unsigned int i;

	for (i = 0; i < state->children.count; ++i) {
		ni_interface_state_t *slave_state = state->children.data[i];

		if (__fsm_interface_check(slave_state, system, waited) < 0)
			child_failed = 1;

		if (!slave_state->done)
			all_done = 0;
	}

	if (!all_done)
		return 0;

	if (child_failed)
		return interface_failed(state, "could not bring up all subordinate interfaces");

	return __fsm_next(state);
}

static int
__fsm_network_up_call(ni_interface_state_t *state, ni_netconfig_t *system)
{
	ni_interface_t *ifp;

	if ((ifp = state->config) == NULL)
		ifp = ni_interface_by_name(system, state->ifname);

	if  (interface_request_state(state, system, ifp, STATE_NETWORK_UP, state->behavior.wait) < 0)
		return interface_failed(state, "could not send device config");

	return 0;
}

static int
__fsm_network_up_check(ni_interface_state_t *state, ni_netconfig_t *system, unsigned int waited)
{
	interface_update(state, system);

	if (state->have_state != STATE_NETWORK_UP)
		return 0;

	return __fsm_next(state);
}

static int
__fsm_network_down_call(ni_interface_state_t *state, ni_netconfig_t *system)
{
	ni_interface_t *ifp;

	if ((ifp = state->config) == NULL)
		ifp = ni_interface_by_name(system, state->ifname);

	if  (interface_request_state(state, system, ifp, STATE_DEVICE_DOWN, state->behavior.wait) < 0)
		return interface_failed(state, "could not send device config");

	return 0;
}

static int
__fsm_network_down_check(ni_interface_state_t *state, ni_netconfig_t *system, unsigned int waited)
{
	interface_update(state, system);

	if (state->have_state != STATE_DEVICE_DOWN)
		return 0;

	return __fsm_next(state);
}

static int
__fsm_device_delete_call(ni_interface_state_t *state, ni_netconfig_t *system)
{
	ni_interface_t *ifp;

	ifp = ni_interface_by_name(system, state->ifname);
	if (ifp == NULL)
		return 0; /* already deleted */

	switch (ifp->link.type) {
	case NI_IFTYPE_VLAN:
	case NI_IFTYPE_BRIDGE:
	case NI_IFTYPE_BOND:
		ni_debug_wicked("%s: trying to delete device", state->ifname);
		return ni_interface_delete(system, state->ifname);

	default: ;
	}

	return 0;
}

static int
__fsm_link_up_call(ni_interface_state_t *state, ni_netconfig_t *system)
{
	ni_interface_t *cfg;
	ni_interface_t *ifp;

	ifp = ni_interface_by_name(system, state->ifname);
	if (ifp != NULL) {
		if (ifp->link.ifflags & NI_IFF_LINK_UP)
			return 0;
	} else {
		/* FIXME: we should create the device here. */
		return interface_failed(state, "interface doesn't exist");
	}

	/* Send the device our desired device configuration.
	 * This includes VLAN, bridge and bonding topology info, as
	 * well as ethtool settings etc, but none of the network config.
	 */
	if ((cfg = state->config) != NULL) {
		if (cfg->ethernet)
			ni_interface_set_ethernet(ifp, ni_ethernet_clone(cfg->ethernet));
		if (cfg->link.vlan)
			ni_interface_set_vlan(ifp, ni_vlan_clone(cfg->link.vlan));
		if (cfg->bridge)
			ni_interface_set_bridge(ifp, ni_bridge_clone(cfg->bridge));
		if (cfg->bonding)
			ni_interface_set_bonding(ifp, ni_bonding_clone(cfg->bonding));

		if (cfg->link.hwaddr.len)
			ifp->link.hwaddr = cfg->link.hwaddr;
		ifp->link.mtu = cfg->link.mtu;
	}
	return interface_request_state(state, system, ifp, STATE_LINK_UP, opt_link_timeout);
}

static int
__fsm_link_up_check(ni_interface_state_t *state, ni_netconfig_t *system, unsigned int waited)
{
	interface_update(state, system);

	if (state->have_state < STATE_LINK_UP)
		return 0;

	return __fsm_next(state);
}

static int
__fsm_link_up_timeout(ni_interface_state_t *state)
{
	if (state->behavior.only_if_link) {
		/* Dang, link didn't come up. We're supposed to bring up
		 * the network later, when the link comes up, so trigger that now. */
		printf("%s: no link\n", state->ifname);
		state->done = 1;
		return 0;
	}

	if (state->behavior.mandatory)
		return interface_failed(state, "timed out");

	printf("%s: no link (optional interface)\n", state->ifname);
	state->done = 1;
	return 0;
}

static int
__fsm_policy_call(ni_interface_state_t *state, ni_netconfig_t *system)
{
	ni_interface_t *ifp;
	ni_policy_t policy;

	if ((ifp = state->config) == NULL)
		return interface_failed(state, "no policy for interface?"); /* this would be a bug */

	memset(&policy, 0, sizeof(policy));
	policy.event = NI_EVENT_LINK_UP;
	policy.interface = ifp;
	if (ni_policy_update(system, &policy) < 0)
		return -1;

	/* Note: don't set state->waiting = 1 here, as we're not waiting for
	 * anything (yet). */
	state->timeout = 0;
	return 1;
}

#define __NI_INTERFACE_OP(__name, __call, __check, __timeout) { \
		.name = __name, \
		.call = __call, \
		.check = __check, \
		.timeout = __timeout, \
	}
#define NI_INTERFACE_OP(__name, __call, __check) \
		__NI_INTERFACE_OP(__name, __call, __check, NULL)
#define NI_FSM_DONE	{ .name = NULL }

/*
 * Bring up the network by sending the network config right away.
 */
static ni_interface_op_t	__fsm_network_up_generic[] = {
	NI_INTERFACE_OP("children-up",	NULL,				__fsm_children_check),
	NI_INTERFACE_OP("network-up",	__fsm_network_up_call,		__fsm_network_up_check),

	NI_FSM_DONE
};

/*
 * Ask interface to bring up the link, and wait for it.
 * Do not try to bring up the network unless the link is up.
 */
static ni_interface_op_t	__fsm_network_up_iflink[] = {
	NI_INTERFACE_OP("children-up",	NULL,				__fsm_children_check),
	__NI_INTERFACE_OP("link-up",	__fsm_link_up_call,		__fsm_link_up_check,	__fsm_link_up_timeout),
	NI_INTERFACE_OP("network-up",	__fsm_network_up_call,		__fsm_network_up_check),

	NI_FSM_DONE
};

/*
 * Bring up an "auto" interface by sending the server the network
 * configuration as policy, then pull up the link and wait for the
 * network to be configured.
 */
static ni_interface_op_t	__fsm_network_up_policy[] = {
	NI_INTERFACE_OP("children-up",	NULL,				__fsm_children_check),
	NI_INTERFACE_OP("policy",	__fsm_policy_call,		NULL),
	__NI_INTERFACE_OP("link-up",	__fsm_link_up_call,		__fsm_link_up_check,	__fsm_link_up_timeout),
	NI_INTERFACE_OP("network-up",	NULL,				__fsm_network_up_check),

	NI_FSM_DONE
};

static ni_interface_op_t	__fsm_link_up_generic[] = {
	NI_INTERFACE_OP("children-up",	NULL,				__fsm_children_check),
	__NI_INTERFACE_OP("link-up",	__fsm_link_up_call,		__fsm_link_up_check,	__fsm_link_up_timeout),

	NI_FSM_DONE
};

static ni_interface_op_t	__fsm_network_down_generic[] = {
	NI_INTERFACE_OP("device-down",	__fsm_network_down_call,	__fsm_network_down_check),
	NI_INTERFACE_OP("children-down",NULL,				__fsm_children_check),

	NI_FSM_DONE
};

static ni_interface_op_t	__fsm_network_down_delete[] = {
	NI_INTERFACE_OP("device-down",	__fsm_network_down_call,	__fsm_network_down_check),
	NI_INTERFACE_OP("device-delete", __fsm_device_delete_call,	NULL),
	NI_INTERFACE_OP("children-down",NULL,				__fsm_children_check),

	NI_FSM_DONE
};

static int
interface_mark_up(ni_interface_state_t *state)
{
	unsigned int i;

	if (state->fsm == NULL && state->config != NULL) {
		ni_interface_t *ifp = state->config;

		if (ifp->startmode.ifaction[NI_IFACTION_LINK_UP].action == NI_INTERFACE_START) {
			ni_debug_wicked("%s: will bring up interface via policy", ifp->name);
			state->is_policy = 1;
			state->fsm = __fsm_network_up_policy;
			ifp->link.ifflags |= (NI_IFF_DEVICE_UP | NI_IFF_LINK_UP | NI_IFF_NETWORK_UP);
		}
	}

	if (state->fsm == NULL && state->behavior.only_if_link) {
		ni_debug_wicked("%s: will bring up interface if link is present", state->ifname);
		state->fsm = __fsm_network_up_iflink;
	}

	if (state->fsm == NULL && state->config) {
		ni_debug_wicked("%s: will bring up interface and configure network", state->ifname);
		state->fsm =  __fsm_network_up_generic;
	}

	if (state->fsm == NULL) {
		ni_debug_wicked("%s: will bring up interface (link layer only)", state->ifname);
		state->fsm = __fsm_link_up_generic;
	}

	for (i = 0; i < state->children.count; ++i) {
		ni_interface_state_t *slave_state = state->children.data[i];

		/* Subordinate device which we're not explicitly asked to configure
		 * should have their link brought up, however.
		 * Bonding slave devices should never have their network configured.
		 * Note, we should tear down any network config on such devices.
		 */
		if (state->config && state->config->link.type == NI_IFTYPE_BOND)
			slave_state->fsm = __fsm_link_up_generic;

		interface_mark_up(slave_state);
	}

	return 0;
}

static int
interface_mark_down(ni_interface_state_t *state, int delete)
{
	ni_interface_state_t *ancestor = state;

	state->fsm = __fsm_network_down_generic;
	if (delete)
		state->fsm = __fsm_network_down_delete;

	while ((ancestor = ancestor->parent) != NULL) {
		if (opt_shutdown_parents) {
			ancestor->fsm = __fsm_network_down_generic;
		} else if (ancestor->fsm == NULL) {
			ni_error("cannot shut down %s: ancestor %s still active",
					state->ifname, ancestor->ifname);
			return -1;
		}
	}

	return 0;
}

static int
ni_interfaces_wait(ni_netconfig_t *system, ni_interface_state_array_t *state_array)
{
	static const unsigned int TEST_FREQ = 4;
	static const char rotate[4] = "-\\|/";
	unsigned int waited = 0, dots = 0;
	int rv;

	setvbuf(stdout, NULL,_IONBF,  0);
	while (1) {
		unsigned int i, all_done = 1;

		if ((rv = ni_refresh(system, NULL)) < 0) {
			ni_error("failed to get system state");
			return -1;
		}

		for (rv = i = 0; i < state_array->count; ++i) {
			ni_interface_state_t *state = state_array->data[i];

			/* Do not explicitly drive slave devices - they are
			 * already covered by the device tree they're part of. */
			if (state->is_slave)
				continue;

			if (__fsm_interface_check(state, system, waited / TEST_FREQ) < 0)
				rv = -1;
			if (!state->done)
				all_done = 0;
		}

		if (all_done)
			break;

		usleep(1000000 / TEST_FREQ);
		if (opt_progressmeter)
			printf("%c\r", rotate[dots%4]);
		waited++;
		dots++;
	}

	return rv;
}

/*
 * Handle "ifup" command
 */
int
do_ifup_old(int argc, char **argv)
{
	static struct option ifup_options[] = {
		{ "file", required_argument, NULL, 'f' },
		{ NULL }
	};
	ni_interface_state_array_t state_array = { 0 };
	const char *ifname = NULL;
	const char *opt_file = NULL;
	unsigned int ifevent = NI_IFACTION_MANUAL_UP;
	ni_netconfig_t *config = NULL;
	ni_netconfig_t *system = NULL;
	int c, rv = -1;

	optind = 1;
	while ((c = getopt_long(argc, argv, "", ifup_options, NULL)) != EOF) {
		switch (c) {
		case 'f':
			opt_file = optarg;
			break;

		default:
usage:
			fprintf(stderr,
				"wicked [options] ifup [ifup-options] all\n"
				"wicked [options] ifup [ifup-options] <ifname>\n"
				"\nSupported ifup-options:\n"
				"  --file <filename>\n"
				"      Read interface configuration(s) from file rather than using system config\n"
				"  --boot\n"
				"      Ignore interfaces with startmode != boot\n"
				);
			return 1;
		}
	}

	if (optind + 1 != argc) {
		fprintf(stderr, "Bad number of arguments\n");
		goto usage;
	}
	ifname = argv[optind++];

	if (!strcmp(ifname, "boot")) {
		ifevent = NI_IFACTION_BOOT;
		ifname = "all";
	}

	/* Using --file means, read the interface definition from a local file.
	 * Otherwise, first retrieve /config/interface/<ifname> from the server,
	 * change <status> to up, and send it back.
	 */
	if (opt_file) {
		ni_syntax_t *syntax = NULL;//ni_syntax_new("netcf", opt_file);

		config = ni_netconfig_open(syntax);
		if ((rv = ni_refresh(config, NULL)) < 0) {
			ni_error("unable to load interface definition from %s", opt_file);
			goto failed;
		}
	} else {
		config = NULL; // ni_indirect_open("/config");
		if (!strcmp(ifname, "all")) {
			rv = ni_refresh(config, NULL);
		} else {
			rv = ni_interface_refresh_one(config, ifname);
		}

		if (rv < 0) {
			ni_error("unable to obtain interface configuration");
			goto failed;
		}
	}

	system = NULL; // ni_indirect_open("/system");
	if ((rv = ni_refresh(system, NULL)) < 0) {
		ni_error("cannot refresh interface state");
		goto failed;
	}

	if (!strcmp(ifname, "all")) {
		if (get_managed_interfaces(config, ifevent, NI_INTERFACE_START, &state_array) < 0) {
			ni_error("failed to build interface hierarchy");
			goto failed;
		}
	} else {
		ni_interface_state_t *state;
		ni_interface_t *ifp;

		if (!(ifp = ni_interface_by_name(config, ifname))) {
			ni_error("cannot find interface %s in interface description", ifname);
			goto failed;
		}

		if (ifp->startmode.ifaction[ifevent].action == NI_INTERFACE_IGNORE) {
			ni_error("not permitted to bring up interface");
			goto failed;
		}

		state = ni_interface_state_new(ifname, ifp);
		state->behavior = ifp->startmode.ifaction[ifevent];
		state->behavior.only_if_link = 0;
		ni_interface_state_array_append(&state_array, state);
	}

	if (state_array.count == 0) {
		printf("Nothing to be done\n");
		rv = 0;
	} else {
		unsigned int i, ifcount = state_array.count;

		rv = interface_topology_build(config, &state_array);
		for (i = 0; rv >= 0 && i < ifcount; ++i)
			rv = interface_mark_up(state_array.data[i]);

		if (rv < 0)
			goto failed;

		rv = ni_interfaces_wait(system, &state_array);
	}

failed:
	if (config)
		ni_close(config);
	if (system)
		ni_close(system);
	ni_interface_state_array_destroy(&state_array);
	return (rv == 0);
}

/*
 * Handle "ifdown" command
 */
int
do_ifdown_old(int argc, char **argv)
{
	static struct option ifdown_options[] = {
		{ "delete", no_argument, NULL, 'd' },
		{ NULL }
	};
	int opt_delete = 0;
	const char *ifname = NULL;
	unsigned int ifevent = NI_IFACTION_MANUAL_DOWN;
	ni_netconfig_t *system = NULL;
	ni_interface_state_array_t state_array = { 0 };
	int c, rv;

	optind = 1;
	while ((c = getopt_long(argc, argv, "", ifdown_options, NULL)) != EOF) {
		switch (c) {
		case 'd':
			opt_delete = 1;
			break;

		default:
usage:
			fprintf(stderr,
				"Usage:\n"
				"wicked [options] ifdown [ifdown-options] all\n"
				"wicked [options] ifdown [ifdown-options] <ifname>\n"
				"\nSupported ifdown-options:\n"
				"  --delete\n"
				"      Delete virtual interfaces in addition to shutting them down\n"
				);
			return 1;
		}
	}

	if (optind + 1 != argc) {
		fprintf(stderr, "Bad number of arguments\n");
		goto usage;
	}
	ifname = argv[optind++];

	/* Otherwise, first retrieve /system/interface/<ifname> from the server,
	 * change <status> to down, and send it back.
	 */
	{
		system = NULL; // ni_indirect_open("/system");
		if (!strcmp(ifname, "all") || !strcmp(ifname, "shutdown")) {
			rv = ni_refresh(system, NULL);
		} else {
			rv = ni_interface_refresh_one(system, ifname);
		}

		if (rv < 0) {
			ni_error("unable to obtain interface configuration");
			goto failed;
		}
	}

	ifevent = NI_IFACTION_MANUAL_DOWN;
	if (!strcmp(ifname, "shutdown")) {
		ifevent = NI_IFACTION_SHUTDOWN;
		ifname = "all";
	}

	if (!strcmp(ifname, "all")) {
		if (get_managed_interfaces(system, ifevent, NI_INTERFACE_STOP, &state_array) < 0) {
			ni_error("failed to build interface hierarchy");
			goto failed;
		}
	} else {
		ni_interface_state_t *state;
		ni_interface_t *ifp;

		if (!(ifp = ni_interface_by_name(system, ifname))) {
			ni_error("cannot find interface %s in interface description", ifname);
			goto failed;
		}

		state = ni_interface_state_new(ifname, ifp);
		state->behavior = ifp->startmode.ifaction[ifevent];
		ni_interface_state_array_append(&state_array, state);
	}

	if (state_array.count == 0) {
		printf("Nothing to be done\n");
		rv = 0;
		goto failed;
	} else {
		unsigned int i, ifcount = state_array.count;

		rv = interface_topology_build(system, &state_array);
		for (i = 0; rv >= 0 && i < ifcount; ++i)
			rv = interface_mark_down(state_array.data[i], opt_delete);

		if (rv < 0)
			goto failed;
	}

	rv = ni_interfaces_wait(system, &state_array);

failed:
	if (system)
		ni_close(system);
	ni_interface_state_array_destroy(&state_array);
	return (rv == 0);
}

/*
 * We also allow the user to send raw REST commands to the server,
 * if s/he so desires
 */
static int
do_rest(const char *cmd, int argc, char **argv)
{
	xml_node_t *send_xml = NULL, *recv_xml = NULL, **recvp = NULL;
	int rest_op;
	char *path;

	if (argc != 2) {
		ni_error("Missing path name\n");
		fprintf(stderr,
			"Usage:\n"
			"wicked [options] get /path\n"
			"wicked [options] put /path\n"
			"wicked [options] post /path\n"
			"wicked [options] delete /path\n"
			"\nput and post commands expect an XML document on standard input\n");
		return 1;
	}

	path = argv[1];

	rest_op = ni_wicked_rest_op_parse(cmd);
	if (rest_op < 0)
		return 1;

	if (rest_op == NI_REST_OP_PUT || rest_op == NI_REST_OP_POST) {
		send_xml = xml_node_scan(stdin);
		if (send_xml == NULL) {
			ni_error("unable to read XML from standard input");
			return 1;
		}
	}
	if (rest_op != NI_REST_OP_DELETE)
		recvp = &recv_xml;
	if (__wicked_request(rest_op, path, send_xml, recvp) < 0)
		return 1;

	if (recv_xml)
		xml_node_print(recv_xml, stdout);

	if (send_xml)
		xml_node_free(send_xml);
	if (recv_xml)
		xml_node_free(recv_xml);

	return 0;
}
#endif

/*
 * xpath
 * This is a utility that can be used by network scripts to extracts bits and
 * pieces of information from an XML file.
 * This is still a bit inconvenient, especially if you need to extract more than
 * one of two elements, since we have to parse and reparse the XML file every
 * time you invoke this program.
 * On the other hand, there's a few rather nifty things you can do. For instance,
 * the following will extract addres/prefixlen pairs for every IPv4 address
 * listed in an XML network config:
 *
 * wicked xpath \
 *	--reference "interface/protocol[@family = 'ipv4']/ip" \
 *	--file vlan.xml \
 *	'%{@address}/%{@prefix}'
 *
 * The "reference" argument tells wicked to look up the <protocol>
 * element with a "family" attribute of "ipv4", and within that,
 * any <ip> elements. For each of these, it obtains the address
 * and prefix attribute, and prints it separated by a slash.
 */
int
do_xpath(int argc, char **argv)
{
	static struct option xpath_options[] = {
		{ "reference", required_argument, NULL, 'r' },
		{ "file", required_argument, NULL, 'f' },
		{ NULL }
	};
	const char *opt_reference = NULL, *opt_file = "-";
	xpath_result_t *input;
	xml_document_t *doc;
	int c;

	optind = 1;
	while ((c = getopt_long(argc, argv, "", xpath_options, NULL)) != EOF) {
		switch (c) {
		case 'r':
			opt_reference = optarg;
			break;

		case 'f':
			opt_file = optarg;
			break;

		default:
			fprintf(stderr,
				"wicked [options] xpath [--reference <expr>] [--file <path>] expr ...\n");
			return 1;
		}
	}

	doc = xml_document_read(opt_file);
	if (!doc) {
		fprintf(stderr, "Error parsing XML document %s\n", opt_file);
		return 1;
	}

	if (opt_reference) {
		xpath_enode_t *enode;

		enode = xpath_expression_parse(opt_reference);
		if (!enode) {
			fprintf(stderr, "Error parsing XPATH expression %s\n", opt_reference);
			return 1;
		}

		input = xpath_expression_eval(enode, doc->root);
		if (!input) {
			fprintf(stderr, "Error evaluating XPATH expression\n");
			return 1;
		}

		if (input->type != XPATH_ELEMENT) {
			fprintf(stderr, "Failed to look up reference node - returned non-element result\n");
			return 1;
		}
		if (input->count == 0) {
			fprintf(stderr, "Failed to look up reference node - returned empty list\n");
			return 1;
		}
		xpath_expression_free(enode);
	} else {
		input = xpath_result_new(XPATH_ELEMENT);
		xpath_result_append_element(input, doc->root);
	}

	while (optind < argc) {
		const char *expression = argv[optind++];
		ni_string_array_t result;
		xpath_format_t *format;
		unsigned int n;

		format = xpath_format_parse(expression);
		if (!format) {
			fprintf(stderr, "Error parsing XPATH format string %s\n", expression);
			return 1;
		}

		ni_string_array_init(&result);
		for (n = 0; n < input->count; ++n) {
			xml_node_t *refnode = input->node[n].value.node;

			if (!xpath_format_eval(format, refnode, &result)) {
				fprintf(stderr, "Error evaluating XPATH expression\n");
				ni_string_array_destroy(&result);
				return 1;
			}
		}

		for (n = 0; n < result.count; ++n)
			printf("%s\n", result.data[n]);

		ni_string_array_destroy(&result);
		xpath_format_free(format);
	}

	return 0;
}
