
CLEANFILES			= *~ $(generated_in_man) $(generated_md_man)
DISTCLEANFILES			= $(CLEANFILES)
MAINTAINERCLEANFILES		= Makefile.in

BUILT_SOURCES			=
EXTRA_DIST			= $(generated_in_man) $(generated_md_man) \
				  $(templates_md_in)  $(templates_md_src) \
				  $(templates_in)

if pandoc
DISTCLEANFILES			+= $(templates_md_in)
MAINTAINERCLEANFILES		+= $(templates_md_in)
BUILT_SOURCES			+= $(templates_md_in)
endif

man_MANS			= \
	$(generated_md_man)	\
	$(generated_in_man)

generated_in_man		= \
	ifcfg-bond.5		\
	ifcfg-bonding.5		\
	ifcfg-bridge.5		\
	ifcfg-dhcp.5		\
	ifcfg-infiniband.5	\
	ifcfg-lo.5		\
	ifcfg-macvlan.5		\
	ifcfg-macvtap.5		\
	ifcfg-ovs-bridge.5	\
	ifcfg-ppp.5		\
	ifcfg-tunnel.5		\
	ifcfg-vlan.5		\
	ifcfg-vxlan.5		\
	ifcfg.5			\
	ifdown.8		\
	ifroute.5		\
	ifrule.5		\
	ifstatus.8		\
	ifsysctl.5		\
	ifup.8			\
	routes.5		\
	wicked-config.5		\
	wicked-ethtool.8	\
	wicked.7		\
	wicked.8		\
	wickedd.8

generated_md_man		= \
	ifcfg-dummy.5		\
	ifcfg-ipoib.5		\
	ifcfg-team.5		\
	ifcfg-wireless.5	\
	wicked-firmware.8	\
	wicked-redfish.8


templates_md_src		= $(addprefix src/,$(generated_md_man:=.md))
templates_md_in			= $(generated_md_man:=.in)
templates_in			= $(generated_in_man:=.in)

# pandoc would write @VAR@ as [at]VAR[at] to .in:
#   .md sources are using %VAR% variables, while
#   .in templates are using common autoconf @VAR@
substitute_md_vars		= \
	$(AM_V_GEN)sed -E			\
	-e "s|%(wicked_piddir)%|@\1@|g"		\
	-e "s|%(wicked_sbindir)%|@\1@|g"	\
	-e "s|%(wicked_statedir)%|@\1@|g"	\
	-e "s|%(wicked_storedir)%|@\1@|g"	\
	-e "s|%(wicked_schemadir)%|@\1@|g"	\
	-e "s|%(wicked_configdir)%|@\1@|g"	\
	-e "s|%(wicked_supplicantdir)%|@\1@|g"	\
	-e "s|%(wicked_extensionsdir)%|@\1@|g"	\
	-e "s|%(PACKAGE_BUGREPORT)%|@\1@|g"

substitute_vars			= \
	$(AM_V_GEN)sed		\
	-e "s|[@]wicked_piddir[@]|$(wicked_piddir)|g"			\
	-e "s|[@]wicked_sbindir[@]|$(wicked_sbindir)|g"			\
	-e "s|[@]wicked_statedir[@]|$(wicked_statedir)|g"		\
	-e "s|[@]wicked_storedir[@]|$(wicked_storedir)|g"		\
	-e "s|[@]wicked_schemadir[@]|$(wicked_schemadir)|g"		\
	-e "s|[@]wicked_configdir[@]|$(wicked_configdir)|g"		\
	-e "s|[@]wicked_supplicantdir[@]|$(wicked_supplicantdir)|g"	\
	-e "s|[@]wicked_extensionsdir[@]|$(wicked_extensionsdir)|g"	\
	-e "s|[@]PACKAGE_BUGREPORT[@]|$(PACKAGE_BUGREPORT)|g"

%: %.in $(top_builddir)/config.status
	@if $(AM_V_P); then echo "substituting variables: $< > $@" ; fi
	@rm -f $@ $@.tmp
	@$(substitute_vars) < $< > $@.tmp && mv $@.tmp $@

if pandoc
%.in: src/%.md $(top_builddir)/config.status
	@if $(AM_V_P); then echo "generating manual page: $< > $@" ; fi
	@rm -f $@ $@.tmp
	@$(AM_V_GEN)$(PANDOC) -s -f markdown -t man $< -o $@.tmp
	@$(substitute_md_vars) -i $@.tmp && mv $@.tmp $@
endif

# vim: ai
