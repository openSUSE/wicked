
CLEANFILES			= *~
MAINTAINERCLEANFILES		= Makefile.in

wicked_supplicant_PROGRAMS	= wickedd-dhcp4

wickedd_dhcp4_CPPFLAGS		= -I$(top_srcdir)	\
				  -I$(top_srcdir)/src	\
				  -I$(top_srcdir)/include

wickedd_dhcp4_CFLAGS		= $(LIBNL_CFLAGS)	\
				  $(LIBDBUS_CFLAGS)	\
				  $(LIBGCRYPT_CFLAGS)

wickedd_dhcp4_LDFLAGS	= -rdynamic
wickedd_dhcp4_LDADD	= $(top_builddir)/src/libwicked.la
wickedd_dhcp4_SOURCES	= \
	dbus-api.c	\
	device.c	\
	fsm.c		\
	main.c		\
	tester.c	\
	protocol.c

noinst_HEADERS		= \
	dhcp.h		\
	tester.h	\
	protocol.h

# vim: ai
