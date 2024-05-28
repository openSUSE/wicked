
CLEANFILES			= *~
MAINTAINERCLEANFILES		= Makefile.in
DISTCLEANFILES			= $(generated)
BUILT_SOURCES			= $(generated)
EXTRA_DIST			= $(templates)

man_MANS			= \
	$(generated)

generated			= \
	wicked-config.5		\
	wicked.7		\
	wicked.8		\
	wickedd.8		\
	wicked-ethtool.8	\
	wicked-firmware.8	\
	wicked-redfish.8	\
	routes.5		\
	ifcfg-bonding.5		\
	ifcfg-bridge.5		\
	ifcfg-dummy.5		\
	ifcfg-ipoib.5		\
	ifcfg-infiniband.5	\
	ifcfg-macvlan.5		\
	ifcfg-macvtap.5		\
	ifcfg-ovs-bridge.5	\
	ifcfg-ppp.5		\
	ifcfg-team.5		\
	ifcfg-tunnel.5		\
	ifcfg-vlan.5		\
	ifcfg-vxlan.5		\
	ifcfg-wireless.5	\
	ifcfg-dhcp.5		\
	ifcfg-lo.5		\
	ifcfg.5			\
	ifroute.5		\
	ifrule.5		\
	ifsysctl.5		\
	ifdown.8		\
	ifstatus.8		\
	ifup.8


templates			= $(generated:=.in)

substitute_vars			= \
	$(AM_V_GEN)sed						\
	-e "s|[@]wicked_piddir[@]|$(wicked_piddir)|g"		\
	-e "s|[@]wicked_sbindir[@]|$(wicked_sbindir)|g"		\
	-e "s|[@]wicked_statedir[@]|$(wicked_statedir)|g"	\
	-e "s|[@]wicked_storedir[@]|$(wicked_storedir)|g"	\
	-e "s|[@]wicked_schemadir[@]|$(wicked_schemadir)|g"	\
	-e "s|[@]wicked_configdir[@]|$(wicked_configdir)|g"	\
	-e "s|[@]wicked_supplicantdir[@]|$(wicked_supplicantdir)|g"\
	-e "s|[@]wicked_extensionsdir[@]|$(wicked_extensionsdir)|g"\
	-e "s|[@]PACKAGE_BUGREPORT[@]|$(PACKAGE_BUGREPORT)|g"

%: %.in $(top_builddir)/config.status
	@if $(AM_V_P); then echo "substituting variables: $< > $@" ; fi
	@rm -f $@ $@.tmp
	@$(substitute_vars) < $< > $@.tmp && mv $@.tmp $@

# vim: ai
