
CLEANFILES			= *~
MAINTAINERCLEANFILES		= Makefile.in

wicked_lib_LTLIBRARIES		= libwicked.la
noinst_LTLIBRARIES		= libwicked-dbus-objects.la	\
				  libwicked-dhcp4.la		\
				  libwicked-dhcp6.la		\
				  libwicked-client.la

libwicked_la_CPPFLAGS		= -DWICKED_CONFIGDIR=\"$(wicked_configdir)\" \
				  -DWICKED_STOREDIR=\"$(wicked_storedir)\" \
				  -DWICKED_STATEDIR=\"$(wicked_statedir)\" \
				  -DWICKED_PIDDIR=\"$(wicked_piddir)\" \
				  -DWICKED_SBINDIR=\"$(wicked_sbindir)\" \
				  -DREQUIRE_LIBGCRYPT=\"$(REQUIRE_LIBGCRYPT)\"

libwicked_la_CFLAGS		= -I$(top_srcdir)		\
				  -I$(top_srcdir)/include	\
				  $(LIBNL_CFLAGS)		\
				  $(LIBDBUS_CFLAGS)		\
				  $(LIBGCRYPT_CFLAGS)

libwicked_la_LDFLAGS		= -lm			\
				  $(LIBDL_LIBS)		\
				  $(LIBNL_LIBS)		\
				  $(LIBANL_LIBS)	\
				  $(LIBDBUS_LIBS)	\
				  $(LIBGCRYPT_LIBS)	\
				  $(LIBWICKED_LTLINK_VERSION)

libwicked_la_LIBADD		= libwicked-dbus-objects.la	\
				  libwicked-dhcp4.la		\
				  libwicked-dhcp6.la		\
				  libwicked-client.la

libwicked_la_SOURCES		= \
	address.c		\
	arp.c			\
	async-resolver.c	\
	bonding.c		\
	bridge.c		\
	buffer.c		\
	calls.c			\
	capture.c		\
	config.c		\
	dcb.c			\
	dbus-client.c		\
	dbus-common.c		\
	dbus-connection.c	\
	dbus-dict.c		\
	dbus-errors.c		\
	dbus-introspect.c	\
	dbus-message.c		\
	dbus-object.c		\
	dbus-server.c		\
	dbus-xml.c		\
	duid.c			\
	errors.c		\
	ethernet.c		\
	extension.c		\
	firmware.c		\
	fsm.c			\
	fsm-policy.c		\
	ibft.c			\
	icmpv6.c		\
	ifconfig.c		\
	ifevent.c		\
	iflist.c		\
	infiniband.c		\
	ipv4.c			\
	ipv6.c			\
	json.c			\
	kernel.c		\
	leasefile.c		\
	leaseinfo.c		\
	lldp.c			\
	logging.c		\
	macvlan.c		\
	hashcsum.c		\
	modem-manager.c		\
	modprobe.c		\
	names.c			\
	netdev.c		\
	netinfo.c		\
	nis.c			\
	openvpn.c		\
	ovs.c			\
	ppp.c			\
	pppd.c			\
	process.c		\
	resolver.c		\
	rfkill.c		\
	route.c			\
	secret.c		\
	socket.c		\
	state.c			\
	sysconfig.c		\
	sysfs.c			\
	systemctl.c		\
	team.c			\
	teamd.c			\
	timer.c			\
	tunneling.c		\
	tuntap.c		\
	uevent.c		\
	udev-utils.c		\
	update.c		\
	util.c			\
	vlan.c			\
	wireless.c		\
	wpa-supplicant.c	\
	xml.c			\
	xml-reader.c		\
	xml-schema.c		\
	xml-writer.c		\
	xpath.c			\
	xpath-fmt.c

libwicked_dbus_objects_la_CFLAGS	= $(libwicked_la_CFLAGS)
libwicked_dbus_objects_la_SOURCES	= \
	dbus-objects/addrconf.c	\
	dbus-objects/bonding.c	\
	dbus-objects/bridge.c	\
	dbus-objects/ethernet.c	\
	dbus-objects/infiniband.c\
	dbus-objects/interface.c\
	dbus-objects/ipv4.c	\
	dbus-objects/ipv6.c	\
	dbus-objects/lldp.c	\
	dbus-objects/macvlan.c	\
	dbus-objects/dummy.c	\
	dbus-objects/misc.c	\
	dbus-objects/model.c	\
	dbus-objects/modem.c	\
	dbus-objects/naming.c	\
	dbus-objects/openvpn.c	\
	dbus-objects/ovs.c	\
	dbus-objects/ppp.c	\
	dbus-objects/state.c	\
	dbus-objects/team.c	\
	dbus-objects/tuntap.c	\
	dbus-objects/sit.c	\
	dbus-objects/ipip.c	\
	dbus-objects/gre.c	\
	dbus-objects/vlan.c	\
	dbus-objects/wireless.c

libwicked_dhcp4_la_CFLAGS		= $(libwicked_la_CFLAGS)
libwicked_dhcp4_la_SOURCES		= \
	dhcp4/device.c		\
	dhcp4/fsm.c		\
	dhcp4/lease.c		\
	dhcp4/protocol.c	\
	dhcp4/tester.c

libwicked_dhcp6_la_CFLAGS		= $(libwicked_la_CFLAGS)
libwicked_dhcp6_la_SOURCES		= \
	dhcp6/device.c		\
	dhcp6/fsm.c		\
	dhcp6/lease.c		\
	dhcp6/options.c		\
	dhcp6/protocol.c	\
	dhcp6/tester.c

libwicked_client_la_CFLAGS		= $(libwicked_la_CFLAGS)
libwicked_client_la_SOURCES		= \
	client/client_state.c	\
	client/policy.c

noinst_HEADERS			= \
	$(wicked_headers)	\
	$(system_headers)

system_headers			= \
	linux/dcbnl.h		\
	linux/ethtool.h		\
	linux/if_addr.h		\
	linux/if_link.h		\
	linux/if_tunnel.h

wicked_headers			= \
	appconfig.h		\
	buffer.h		\
	client/client_state.h	\
	client/ifconfig.h	\
	dbus-common.h		\
	dbus-connection.h	\
	dbus-dict.h		\
	dbus-object.h		\
	dbus-objects/misc.h	\
	dbus-objects/model.h	\
	dbus-server.h		\
	debug.h			\
	dhcp4/dhcp.h		\
	dhcp4/lease.h		\
	dhcp4/protocol.h	\
	dhcp4/tester.h		\
	dhcp6/device.h		\
	dhcp6/dhcp.h		\
	dhcp6/lease.h		\
	dhcp6/fsm.h		\
	dhcp6/options.h		\
	dhcp6/protocol.h	\
	dhcp6/tester.h		\
	duid.h			\
	ibft.h			\
	ipv6_priv.h		\
	json.h			\
	kernel.h		\
	leasefile.h		\
	lldp-priv.h             \
	modem-manager.h		\
	modprobe.h		\
	netinfo_priv.h		\
	ovs.h			\
	pppd.h			\
	process.h		\
	socket_priv.h		\
	sysfs.h			\
	systemctl.h		\
	teamd.h			\
	uevent.h		\
	udev-utils.h		\
	util_priv.h		\
	wireless_priv.h		\
	wpa-supplicant.h	\
	xml-schema.h

# vim: ai
