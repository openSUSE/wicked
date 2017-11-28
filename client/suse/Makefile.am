
CLEANFILES					= *~
MAINTAINERCLEANFILES				= Makefile.in
DISTCLEANFILES					= $(BUILT_SOURCES)
EXTRA_DIST					= $(suse_config_DATA) \
						  $(suse_fillup_DATA) \
						  scripts/ifup.in
BUILT_SOURCES					= scripts/ifup

noinst_LTLIBRARIES				= libwicked-client-suse.la

libwicked_client_suse_la_CPPFLAGS		= \
						  -I$(top_srcdir)       \
						  -I$(top_srcdir)/src   \
						  -I$(top_srcdir)/include

libwicked_client_suse_la_CFLAGS			= $(LIBNL_CFLAGS)       \
						  $(LIBDBUS_CFLAGS)     \
						  $(LIBGCRYPT_CFLAGS)

libwicked_client_suse_la_LDFLAGS		= -rdynamic

libwicked_client_suse_la_SOURCES		= \
						  compat-suse.c	\
						  ifsysctl.c

noinst_HEADERS					= \
						  ifsysctl.h

suse_fillupdir					= ${fillup_templatesdir}
suse_fillup_DATA				= config/sysconfig.config-wicked \
						  config/sysconfig.dhcp-wicked

suse_configdir					= $(sysconfdir)/sysconfig/network
suse_config_DATA				= config/ifcfg-lo

suse_sbindir					= $(wicked_sbindir)
suse_sbin_SCRIPTS				= scripts/ifup


substitute_vars					= \
	$(AM_V_GEN)sed				\
	-e "s|[@]wicked_sbindir[@]|$(wicked_sbindir)|g"

scripts/ifup: scripts/ifup.in $(top_builddir)/config.status
	@echo "substituting variables in $< > $@"
	@test -d $(@D) || $(MKDIR_P) $(@D)
	@rm -f $@ $@.tmp
	@$(substitute_vars) < $< > $@.tmp && mv $@.tmp $@

install-data-local:
	-chmod 0600 "$(DESTDIR)$(suse_configdir)/ifcfg-lo"

check-local:
	@for i in $(suse_sbin_SCRIPTS) ; \
	do \
		bash -n "$(builddir)/$$i" \
			&& printf 'client/%-30s %s\n' "$$i" "Syntax OK" \
			|| exit 1 ; \
	done

# vim: ai
