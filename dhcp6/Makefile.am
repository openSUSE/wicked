
CLEANFILES			= *~
MAINTAINERCLEANFILES		= Makefile.in

wicked_supplicant_PROGRAMS	= wicked-dhcp6

INCLUDES			= -I$(top_srcdir)	\
				  -I$(top_srcdir)/src	\
				  -I$(top_srcdir)/include

wicked_dhcp6_CFLAGS		= $(LIBNL_CFLAGS)	\
				  $(LIBDBUS_CFLAGS)	\
				  $(LIBGCRYPT_CFLAGS)
wicked_dhcp6_LDFLAGS	= -rdynamic
wicked_dhcp6_LDADD	= $(top_builddir)/src/libwicked.la
wicked_dhcp6_SOURCES	= \
	dbus-api.c	\
	device.c	\
	duid.c		\
	fsm.c		\
	main.c		\
	protocol.c	\
	state.c

EXTRA_DIST			= \
	dbus-api.h	\
	device.h	\
	dhcp6.h		\
	duid.h		\
	fsm.h		\
	protocol.h

# vim: ai
