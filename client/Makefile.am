
CLEANFILES			= *~
MAINTAINERCLEANFILES		= Makefile.in

wicked_sbin_PROGRAMS		= wicked

INCLUDES			= -I$(top_srcdir)	\
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

EXTRA_DIST			= \
	wicked-client.h

install-data-hook:
	$(mkinstalldirs) "$(DESTDIR)$(wicked_configdir)/ifconfig"

# vim: ai
