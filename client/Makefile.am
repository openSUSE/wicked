
CLEANFILES			= *~
MAINTAINERCLEANFILES		= Makefile.in
DISTCLEANFILES			= $(BUILT_SOURCES)
EXTRA_DIST			= $(wicked_headers) \
				  scripts/ifup.in

BUILT_SOURCES			= scripts/ifup

wicked_sbin_SCRIPTS		= scripts/ifup

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
	ifdown.c		\
	ifcheck.c		\
	ifreload.c		\
	ifstatus.c		\
	read-config.c		\
	main.c			\
	nanny.c			\
	reachable.c

wicked_headers			= \
	ifup.h			\
	ifdown.h		\
	ifcheck.h		\
	ifreload.h		\
	ifstatus.h		\
	reachable.h		\
	wicked-client.h

substitute_vars			= \
	$(AM_V_GEN)sed						\
	-e "s|[@]wicked_sbindir[@]|$(wicked_sbindir)|g"

scripts/ifup: scripts/ifup.in $(top_builddir)/config.status
	@echo "substituting variables in $< > $@"
	@test -d $(@D) || $(MKDIR_P) $(@D)
	@rm -f $@ $@.tmp
	@$(substitute_vars) < $< > $@.tmp && mv $@.tmp $@

install-data-local:
	$(MKDIR_P) "$(DESTDIR)$(wicked_configdir)/ifconfig"

check-local:
	@for i in $(wicked_sbin_SCRIPTS) ; \
	do \
		bash -n "$(builddir)/$$i" \
			&& printf 'client/%-30s %s\n' "$$i" "Syntax OK" \
			|| exit 1 ; \
	done

# vim: ai
