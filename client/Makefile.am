
CLEANFILES			= *~
MAINTAINERCLEANFILES		= Makefile.in
DISTCLEANFILES			= $(BUILT_SOURCES)
EXTRA_DIST			= wicked-client.h	\
				  $(templates)
BUILT_SOURCES			= $(compat_scripts)


wicked_sbin_PROGRAMS		= wicked

wicked_CPPFLAGS			= -I$(top_srcdir)	\
				  -I$(top_srcdir)/src	\
				  -I$(top_srcdir)/include

wicked_CFLAGS			= $(LIBNL_CFLAGS)	\
				  $(LIBDBUS_CFLAGS)	\
				  $(LIBGCRYPT_CFLAGS)

wicked_LDFLAGS			= -rdynamic
wicked_LDADD			= $(top_builddir)/src/libwicked.la
wicked_SOURCES			= \
	compat.c		\
	compat-redhat.c		\
	compat-suse.c		\
	ifup.c			\
	main.c			\
	nanny.c			\
	reachable.c


system_sbin_SCRIPTS		= $(compat_scripts)

compat_scripts			= scripts/ifup
templates			= $(compat_scripts:=.in)

substitute_vars			= \
	$(AM_V_GEN)sed						\
	-e "s|[@]wicked_sbindir[@]|$(wicked_sbindir)|g"

scripts/ifup: scripts/ifup.in $(top_builddir)/config.status
	@echo "substituting variables in $< > $@"
	@test -d $(@D) || $(MKDIR_P) $(@D)
	@rm -f $@ $@.tmp
	@$(substitute_vars) < $< > $@.tmp && mv $@.tmp $@


install-data-hook:
	$(mkinstalldirs) "$(DESTDIR)$(wicked_configdir)/ifconfig"
	$(LN_S) -f ifup  "$(DESTDIR)$(system_sbindir)/ifdown"
	$(LN_S) -f ifup  "$(DESTDIR)$(system_sbindir)/ifstatus"

uninstall-hook:
	rm -f "$(DESTDIR)$(system_sbindir)/ifdown"
	rm -f "$(DESTDIR)$(system_sbindir)/ifstatus"


check-local:
	@for i in $(system_sbin_SCRIPTS) ; \
	do \
		bash -n "$(builddir)/$$i" \
			&& printf 'client/%-30s %s\n' "$$i" "Syntax OK" \
			|| exit 1 ; \
	done

# vim: ai
