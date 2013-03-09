
CLEANFILES			= *~
MAINTAINERCLEANFILES		= Makefile.in

wicked_supplicant_PROGRAMS	= dhcp4-supplicant

INCLUDES			= -I$(top_srcdir)	\
				  -I$(top_srcdir)/src	\
				  -I$(top_srcdir)/include

dhcp4_supplicant_CFLAGS		= $(LIBNL_CFLAGS)	\
				  $(LIBDBUS_CFLAGS)	\
				  $(LIBGCRYPT_CFLAGS)
dhcp4_supplicant_LDFLAGS	= -rdynamic
dhcp4_supplicant_LDADD		= $(top_builddir)/src/libwicked.la
dhcp4_supplicant_SOURCES	= \
	dbus-api.c	\
	device.c	\
	fsm.c		\
	main.c		\
	protocol.c

EXTRA_DIST			= \
	dhcp.h		\
	protocol.h

# vim: ai
