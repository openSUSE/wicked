
CLEANFILES			= *~
MAINTAINERCLEANFILES		= Makefile.in

wicked_sbin_PROGRAMS		= network-nanny

INCLUDES			= -I$(top_srcdir)/src	\
				  -I$(top_srcdir)/include

network_nanny_CFLAGS		= $(LIBNL_CFLAGS)	\
				  $(LIBDBUS_CFLAGS)	\
				  $(LIBGCRYPT_FLAGS)
network_nanny_LDFLAGS		= $(top_builddir)/src/libwicked.la
network_nanny_DEPENDENCIES	= $(top_builddir)/src/libwicked.la
network_nanny_SOURCES		= \
	device.c	\
	interface.c	\
	main.c		\
	modem.c		\
	nanny.c		\
	policy.c

EXTRA_DIST			= \
	nanny.h

# vim: ai
