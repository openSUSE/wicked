
CLEANFILES			= *~
MAINTAINERCLEANFILES		= Makefile.in

wicked_sbin_PROGRAMS		= wickedd

INCLUDES			= -I$(top_srcdir)/src	\
				  -I$(top_srcdir)/include

wickedd_CFLAGS			= $(LIBNL_CFLAGS)	\
				  $(LIBDBUS_CFLAGS)	\
				  $(LIBGCRYPT_FLAGS)
wickedd_LDFLAGS			= $(top_builddir)/src/libwicked.la
wickedd_DEPENDENCIES		= $(top_builddir)/src/libwicked.la
wickedd_SOURCES			= \
	main.c

EXTRA_DIST			=

# vim: ai
