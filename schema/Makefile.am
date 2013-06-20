
CLEANFILES			= *~ constants.xml
MAINTAINERCLEANFILES		= Makefile.in

wicked_schema_DATA		= \
	$(wicked_schema_files)	\
	$(wicked_schema_built)

wicked_schema_files		= \
	addrconf.xml		\
	bonding.xml		\
	bridge.xml		\
	ethernet.xml		\
	firewall.xml		\
	infiniband.xml		\
	interface.xml		\
	lldp.xml		\
	modem.xml		\
	openvpn.xml		\
	ppp.xml			\
	protocol.xml		\
	types.xml		\
	vlan.xml		\
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
