
CLEANFILES			= *~ constants.xml
MAINTAINERCLEANFILES		= Makefile.in

wicked_schema_DATA		= \
	$(wicked_schema_files)	\
	$(wicked_schema_built)

wicked_schema_files		= \
	addrconf.xml		\
	bond.xml		\
	bridge.xml		\
	ethtool.xml		\
	ethernet.xml		\
	firewall.xml		\
	infiniband.xml		\
	interface.xml		\
	lldp.xml		\
	macvlan.xml		\
	ipvlan.xml		\
	dummy.xml		\
	ovs-bridge.xml		\
	ppp.xml			\
	protocol.xml		\
	team.xml		\
	types.xml		\
	tuntap.xml		\
	scripts.xml		\
	sit.xml			\
	ipip.xml		\
	gre.xml			\
	vlan.xml		\
	vxlan.xml		\
	wicked.xml		\
	wireless.xml

wicked_schema_built		= constants.xml
wicked_schema_sources		= constants.xml.in

EXTRA_DIST			= $(wicked_schema_files)	\
				  $(wicked_schema_sources)

$(top_builddir)/util/mkconst:
	cd $(top_builddir)/util && $(MAKE) mkconst

constants.xml: constants.xml.in $(top_builddir)/util/mkconst
	$(top_builddir)/util/mkconst < $< > $@

# vim: ai
