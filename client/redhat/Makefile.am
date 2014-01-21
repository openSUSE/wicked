
CLEANFILES				= *~
MAINTAINERCLEANFILES			= Makefile.in
DISTCLEANFILES				= $(BUILT_SOURCES)
EXTRA_DIST				=
BUILT_SOURCES				=

noinst_LTLIBRARIES			= libwicked-client-redhat.la

libwicked_client_redhat_la_CPPFLAGS	= \
					  -I$(top_srcdir)       \
					  -I$(top_srcdir)/src   \
					  -I$(top_srcdir)/include

libwicked_client_redhat_la_CFLAGS	= $(LIBNL_CFLAGS)       \
					  $(LIBDBUS_CFLAGS)     \
					  $(LIBGCRYPT_CFLAGS)

libwicked_client_redhat_la_LDFLAGS	= -rdynamic

libwicked_client_redhat_la_SOURCES	= \
					  compat-redhat.c

# vim: ai
