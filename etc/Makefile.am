
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

dbus_service_files		= \
	org.opensuse.Network.AUTO4.service \
	org.opensuse.Network.DHCP4.service \
	org.opensuse.Network.DHCP6.service
if dbus_service
dbus_service_DATA		= $(dbus_service_files)
endif

systemd_unit_files		= \
	systemd/wicked.service		\
	systemd/wickedd.service		\
	systemd/wicked-dhcp4.service	\
	systemd/wicked-dhcp6.service	\
	systemd/wicked-autoip4.service

if systemd_service
systemd_unit_DATA		= $(systemd_unit_files)
endif

systemv_init_files		= \
	init.d/wickedd		\
	init.d/network
if systemv_service
systemv_init_SCRIPTS		= $(systemv_init_files)
endif

templates			= \
	$(wicked_config_DATA:=.in)	\
	$(dbus_service_files:=.in)	\
	$(systemd_unit_files:=.in)	\
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

%.service: %.service.in $(top_builddir)/config.status
	@echo "substituting variables in $< > $@"
	@rm -f $@ $@.tmp
	@$(substitute_vars) < $< > $@.tmp && mv $@.tmp $@

systemd/%.service: systemd/%service.in $(top_builddir)/config.status
	@echo "substituting variables in $< > $@"
	@rm -f $@ $@.tmp
	@$(substitute_vars) < $< > $@.tmp && mv $@.tmp $@

init.d/wickedd: init.d/wickedd.in $(top_builddir)/config.status
	@echo "substituting variables in $< > $@"
	@rm -f $@ $@.tmp
	@$(substitute_vars) < $< > $@.tmp && mv $@.tmp $@

init.d/network: init.d/network.in $(top_builddir)/config.status
	@echo "substituting variables in $< > $@"
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
