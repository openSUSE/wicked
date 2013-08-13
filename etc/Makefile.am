
CLEANFILES			= *~
MAINTAINERCLEANFILES		= Makefile.in
DISTCLEANFILES			= $(BUILT_SOURCES)
EXTRA_DIST			= $(dbus_config_DATA) $(templates)

BUILT_SOURCES			= \
	$(wicked_config_DATA)	\
	$(dbus_service_DATA)	\
	$(systemd_unit_DATA)	\
	$(systemv_init_SCRIPTS)

wicked_config_DATA		= \
	common.xml		\
	client.xml		\
	server.xml		\
	network-nanny.xml

dbus_config_DATA		= \
	wicked.conf		\
	wicked-autoip4.conf	\
	wicked-dhcp4.conf	\
	wicked-dhcp6.conf	\
	network-nanny.conf

systemd_unit_files		= \
	systemd/wicked.service		\
	systemd/wickedd.service		\
	systemd/wickedd-auto4.service	\
	systemd/wickedd-dhcp4.service	\
	systemd/wickedd-dhcp6.service

systemd_dbus_files		= \
	systemd/org.opensuse.Network.AUTO4.service \
	systemd/org.opensuse.Network.DHCP4.service \
	systemd/org.opensuse.Network.DHCP6.service

systemv_init_files		= \
	systemv/wickedd		\
	systemv/network

systemv_dbus_files		= \
	systemv/org.opensuse.Network.AUTO4.service \
	systemv/org.opensuse.Network.DHCP4.service \
	systemv/org.opensuse.Network.DHCP6.service

if systemd_service
systemd_unit_DATA		= $(systemd_unit_files)

if dbus_service
dbus_service_DATA		= $(systemd_dbus_files)
endif
endif

if systemv_service
systemv_init_SCRIPTS		= $(systemv_init_files)

if dbus_service
dbus_service_DATA		= $(systemv_dbus_files)
endif
endif

templates			= \
	$(wicked_config_DATA:=.in)	\
	$(systemd_dbus_files:=.in)	\
	$(systemd_unit_files:=.in)	\
	$(systemv_dbus_files:=.in)	\
	$(systemv_init_files:=.in)

substitute_vars			= \
	$(AM_V_GEN)sed						\
	-e "s|[@]wicked_piddir[@]|$(wicked_piddir)|g"		\
	-e "s|[@]wicked_sbindir[@]|$(wicked_sbindir)|g"		\
	-e "s|[@]wicked_statedir[@]|$(wicked_statedir)|g"	\
	-e "s|[@]wicked_storedir[@]|$(wicked_storedir)|g"	\
	-e "s|[@]wicked_schemadir[@]|$(wicked_schemadir)|g"	\
	-e "s|[@]wicked_configdir[@]|$(wicked_configdir)|g"	\
	-e "s|[@]wicked_supplicantdir[@]|$(wicked_supplicantdir)|g"\
	-e "s|[@]wicked_extensionsdir[@]|$(wicked_extensionsdir)|g"

%.xml: %.xml.in $(top_builddir)/config.status
	@echo "substituting variables in $< > $@"
	@rm -f $@ $@.tmp
	@$(substitute_vars) < $< > $@.tmp && mv $@.tmp $@

systemd/%.service: systemd/%.service.in $(top_builddir)/config.status
	@echo "substituting variables in $< > $@"
	@test -d $(@D) || $(MKDIR_P) $(@D)
	@rm -f $@ $@.tmp
	@$(substitute_vars) < $< > $@.tmp && mv $@.tmp $@

systemv/%.service: %.service.in $(top_builddir)/config.status
	@echo "substituting variables in $< > $@"
	@test -d $(@D) || $(MKDIR_P) $(@D)
	@rm -f $@ $@.tmp
	@$(substitute_vars) < $< > $@.tmp && mv $@.tmp $@

systemv/wickedd: systemv/wickedd.in $(top_builddir)/config.status
	@echo "substituting variables in $< > $@"
	@test -d $(@D) || $(MKDIR_P) $(@D)
	@rm -f $@ $@.tmp
	@$(substitute_vars) < $< > $@.tmp && mv $@.tmp $@

systemv/network: systemv/network.in $(top_builddir)/config.status
	@echo "substituting variables in $< > $@"
	@test -d $(@D) || $(MKDIR_P) $(@D)
	@rm -f $@ $@.tmp
	@$(substitute_vars) < $< > $@.tmp && mv $@.tmp $@

install-data-hook:
if systemv_service
	$(MKDIR_P) "$(DESTDIR)$(wicked_sbindir)"
	$(LN_S) -f "$(systemv_initdir)/wickedd" "$(DESTDIR)$(wicked_sbindir)/rcwickedd"
	$(LN_S) -f "$(systemv_initdir)/network" "$(DESTDIR)$(wicked_sbindir)/rcnetwork"
endif

uninstall-hook:
if systemv_service
	rm -f "$(DESTDIR)$(wicked_sbindir)/rcwickedd"
	rm -f "$(DESTDIR)$(wicked_sbindir)/rcnetwork"
endif

check-local:
	@for i in $(systemv_init_SCRIPTS) ; \
	do \
		bash -n "$(srcdir)/$$i" \
			&& printf 'etc/%-30s %s\n' "$$i" "Syntax OK" \
			|| exit 1 ; \
	done

# vim: ai
