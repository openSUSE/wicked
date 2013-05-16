
CLEANFILES			= *~
MAINTAINERCLEANFILES		= Makefile.in

wicked_supplicant_PROGRAMS	= wicked-dhcp4

INCLUDES			= -I$(top_srcdir)	\
				  -I$(top_srcdir)/src	\
				  -I$(top_srcdir)/include

wicked_dhcp4_CFLAGS		= $(LIBNL_CFLAGS)	\
				  $(LIBDBUS_CFLAGS)	\
				  $(LIBGCRYPT_CFLAGS)
wicked_dhcp4_LDFLAGS	= -rdynamic
wicked_dhcp4_LDADD	= $(top_builddir)/src/libwicked.la
wicked_dhcp4_SOURCES	= \
	dbus-api.c	\
	device.c	\
	fsm.c		\
	main.c		\
	protocol.c

EXTRA_DIST			= \
	dhcp.h		\
	protocol.h

# vim: ai
