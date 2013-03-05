
CLEANFILES			= *~
MAINTAINERCLEANFILES		= Makefile.in

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

systemd_unit_files		=
if systemd_service
systemd_unit_DATA		= $(systemd_unit_files)
endif

systemv_init_files		= \
	init.d/wickedd		\
	init.d/network
if systemv_service
systemv_init_SCRIPTS		= $(systemv_init_files)
endif

EXTRA_DIST			= $(wicked_config_DATA) \
				  $(dbus_config_DATA)	\
				  $(dbus_service_files)	\
				  $(systemd_unit_files)	\
				  $(systemv_init_files)

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

check:
	@for i in $(systemv_init_SCRIPTS) ; \
	do \
		bash -n "$(srcdir)/$$i" \
			&& printf 'etc/%-30s %s\n' "$$i" "Syntax OK" \
			|| exit 1 ; \
	done

# vim: ai
