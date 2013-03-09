
CLEANFILES			= *~
MAINTAINERCLEANFILES		= Makefile.in

wicked_supplicant_PROGRAMS	= dhcp6-supplicant

INCLUDES			= -I$(top_srcdir)	\
				  -I$(top_srcdir)/src	\
				  -I$(top_srcdir)/include

dhcp6_supplicant_CFLAGS		= $(LIBNL_CFLAGS)	\
				  $(LIBDBUS_CFLAGS)	\
				  $(LIBGCRYPT_CFLAGS)
dhcp6_supplicant_LDFLAGS	= -rdynamic
dhcp6_supplicant_LDADD		= $(top_builddir)/src/libwicked.la
dhcp6_supplicant_SOURCES	= \
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
