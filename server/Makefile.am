
CLEANFILES			= *~
MAINTAINERCLEANFILES		= Makefile.in

wicked_sbin_PROGRAMS		= wickedd

wickedd_CPPFLAGS		= -I$(top_srcdir)/src	\
				  -I$(top_srcdir)/include

wickedd_CFLAGS			= $(LIBNL_CFLAGS)	\
				  $(LIBDBUS_CFLAGS)	\
				  $(LIBGCRYPT_CFLAGS)

wickedd_LDFLAGS			= -rdynamic
wickedd_LDADD			= $(top_builddir)/src/libwicked.la
wickedd_SOURCES			= \
	main.c

EXTRA_DIST			=

# vim: ai
